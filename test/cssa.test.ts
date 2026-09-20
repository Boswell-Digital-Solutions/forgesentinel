import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ControlDirectiveIssuer,
  CssaControlRegistry,
  ReceiptService,
  EvidenceLedger,
  cssaFindingToSourceFinding,
  validateCloudSecurityFinding,
  validateFinding,
  CLOUD_SECURITY_FINDING_SCHEMA,
  type CloudSecurityFinding,
  type PolicyDecision,
  type ApprovalRecord,
} from "../src/index.js";

const NOW = "2026-06-09T17:10:00.000Z";
const SIGNING_KEY = "test-forge-command-policy-key";

const decision: PolicyDecision = {
  policy_decision_id: "pdec_c1",
  incident_id: "inc_c1",
  policy_id: "sentinel_account_compromise",
  policy_version: "3.1.0",
  result: "REQUEST_OPERATOR",
  allowed_actions: [],
  denied_actions: [],
  evaluated_at: NOW,
};
const approval: ApprovalRecord = { level: "single_operator", approver_type: "operator", approver_id: "op_17", approved_at: NOW };
const target = { tenant_id: "ten_demo", principal_id: "usr_owner", executor_id: "agt_01", cloud_service: "neuroforge", provider: "provider_a" };

function setup() {
  const ledger = new EvidenceLedger();
  const receipts = new ReceiptService(ledger);
  const issuer = new ControlDirectiveIssuer(SIGNING_KEY);
  const registry = new CssaControlRegistry(receipts);
  registry.trustIssuer("forge-command-policy", "key_fc_policy_01", SIGNING_KEY);
  return { ledger, receipts, issuer, registry };
}

test("a raw Sentinel incident cannot alter CSSA decisions (ADR-021, Gate D)", () => {
  const { registry } = setup();
  const submission = registry.submitRawIncident({ incident_id: "inc_c1", title: "compromise!", risk: { likelihood: 0.99 } });
  assert.equal(submission.accepted, false);
  assert.equal(submission.issues[0]?.code, "non_authoritative_artifact");
});

test("a valid narrow directive is applied exactly once with receipt and lineage", () => {
  const { issuer, registry } = setup();
  const directive = issuer.issue(decision, "cssa.cloud_route.hold", target, approval, ["SENTINEL_COMPOUND_COMPROMISE"], NOW);
  const submission = registry.submitDirective(directive, NOW);
  assert.equal(submission.accepted, true, JSON.stringify(submission.issues));
  assert.ok(submission.receipt);
  assert.equal(submission.receipt.action.result, "success");
  assert.ok(submission.lineage);
  assert.equal(submission.lineage.policy_generated_effect, true);
  assert.equal(submission.lineage.control_id, directive.control_id);
  assert.equal(submission.lineage.sentinel_incident_id, "inc_c1");
  assert.equal(registry.isActive(directive.control_id), true);

  const replay = registry.submitDirective(directive, NOW);
  assert.equal(replay.accepted, false, "single-use directive cannot be replayed");
  assert.ok(replay.issues.some((issue) => issue.code === "replayed"));
});

test("a directive widened after signing is rejected", () => {
  const { issuer, registry } = setup();
  const directive = issuer.issue(decision, "cssa.cloud_route.hold", target, approval, ["SENTINEL_COMPOUND_COMPROMISE"], NOW);
  const widenedTarget = { ...directive, target: { ...directive.target, executor_id: undefined as unknown as string } };
  const result = registry.submitDirective(widenedTarget, NOW);
  assert.equal(result.accepted, false);
  assert.ok(result.issues.some((issue) => issue.code === "signature_invalid"));

  const widenedScope = { ...directive, scope: "all_executors" };
  const scopeResult = registry.submitDirective(widenedScope, NOW);
  assert.equal(scopeResult.accepted, false);
});

test("expired and unknown-issuer directives are rejected", () => {
  const { issuer, registry, receipts } = setup();
  const expired = issuer.issue(decision, "cssa.cloud_route.hold", target, approval, ["SENTINEL_COMPOUND_COMPROMISE"], "2026-06-09T10:00:00.000Z", 60);
  const expiredResult = registry.submitDirective(expired, NOW);
  assert.equal(expiredResult.accepted, false);
  assert.ok(expiredResult.issues.some((issue) => issue.code === "expired"));

  const rogueIssuer = new ControlDirectiveIssuer("some-other-key", "key_rogue_01");
  const rogue = rogueIssuer.issue(decision, "cssa.cloud_route.hold", target, approval, ["X"], NOW);
  const rogueResult = registry.submitDirective(rogue, NOW);
  assert.equal(rogueResult.accepted, false);
  assert.ok(rogueResult.issues.some((issue) => issue.code === "unknown_issuer"));
  assert.ok(receipts.byIncident("inc_c1").length >= 2, "rejections also leave receipts");
});

test("non-allowlisted actions cannot be issued or applied", () => {
  const { issuer, registry } = setup();
  assert.throws(() => issuer.issue(decision, "cssa.tenant.terminate", target, approval, ["X"], NOW), /not an allowlisted/);
  const directive = issuer.issue(decision, "cssa.cloud_route.hold", target, approval, ["X"], NOW);
  const mutated = { ...directive, action: "cssa.tenant.terminate" };
  const result = registry.submitDirective(mutated, NOW);
  assert.equal(result.accepted, false);
});

test("rollback creates its own receipt and deactivates the control", () => {
  const { issuer, registry } = setup();
  const directive = issuer.issue(decision, "cssa.cloud_route.hold", target, approval, ["SENTINEL_COMPOUND_COMPROMISE"], NOW);
  registry.submitDirective(directive, NOW);
  const rollbackReceipt = registry.rollback(directive.control_id, "2026-06-09T17:20:00.000Z");
  assert.equal(rollbackReceipt.action.result, "rolled_back");
  assert.equal(rollbackReceipt.action.requested, "cssa.cloud_route.release");
  assert.equal(registry.isActive(directive.control_id), false);
});

test("CSSA watchdog finding maps to a source finding without seizing incident lifecycle (ADR-020)", () => {
  const watchdog: CloudSecurityFinding = {
    schema_version: CLOUD_SECURITY_FINDING_SCHEMA,
    finding_id: "wd_001",
    detector: "broker_bypass_attempt",
    severity: "S3",
    scope: { tenant_id: "ten_demo", executor_id: "agt_01" },
    window: { from: "2026-06-09T17:00:00.000Z", to: NOW },
    evidence_refs: ["dataforge:cssa_decision:dec_991"],
    metrics: { observed: 4, baseline: 2, threshold: 3 },
    reason_codes: ["CSSA_WATCHDOG_DENIAL_STREAK"],
    summary: "4 block/quarantine decisions for executor agt_01 within 15m (threshold 3).",
    emitted_at: NOW,
    expires_at: "2026-06-10T17:10:00.000Z",
    finding_hash: `sha256:${"a".repeat(64)}`,
  };
  assert.equal(validateCloudSecurityFinding(watchdog).ok, true, JSON.stringify(validateCloudSecurityFinding(watchdog).issues));
  const sourceFinding = cssaFindingToSourceFinding(watchdog, NOW);
  assert.equal(validateFinding(sourceFinding).ok, true, "adapter output satisfies the Sentinel finding contract");
  assert.equal(sourceFinding.finding_type, "cssa.broker_bypass_attempt");
  assert.equal(sourceFinding.recommendation.action_class, "RECOMMEND_ONLY", "a source finding recommends, it does not enforce");
  assert.equal(sourceFinding.policy_generated_effect, false);

  const legacy = { ...watchdog, schema_version: "SecurityIncident.v1" };
  assert.equal(validateCloudSecurityFinding(legacy).ok, false, "legacy incidents cannot enter as canonical findings");
});
