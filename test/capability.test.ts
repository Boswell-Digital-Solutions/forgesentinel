import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ACCOUNT_COMPROMISE_POLICY,
  CapabilityService,
  IdentityAuthority,
  PolicyService,
  ReceiptService,
  EvidenceLedger,
  validateActionReceipt,
  type Incident,
  type PolicyDecision,
  type AllowedAction,
  type ApprovalRecord,
} from "../src/index.js";

const NOW = "2026-06-09T17:10:00.000Z";
const KEY_FP = "sha256:newkey7fa2";

const decision: PolicyDecision = {
  policy_decision_id: "pdec_t1",
  incident_id: "inc_t1",
  policy_id: "sentinel_account_compromise",
  policy_version: "3.1.0",
  result: "REQUEST_OPERATOR",
  allowed_actions: [
    { action_type: "identity.api_key.pause", scope: "single_key", expires_in_seconds: 900, requires_approval: "single_operator", reversible: true },
  ],
  denied_actions: [],
  evaluated_at: NOW,
};
const pauseAction: AllowedAction = decision.allowed_actions[0]!;
const operatorApproval: ApprovalRecord = { level: "single_operator", approver_type: "operator", approver_id: "op_17", approved_at: NOW };

function setup() {
  const ledger = new EvidenceLedger();
  const capabilities = new CapabilityService("test-capability-signing-key");
  const receipts = new ReceiptService(ledger);
  const policy = new PolicyService();
  const authority = new IdentityAuthority(capabilities, receipts, policy);
  authority.registerKey(KEY_FP);
  return { ledger, capabilities, receipts, policy, authority };
}

test("approved action executes with receipt, then rollback restores state with its own receipt", () => {
  const { authority, capabilities, receipts } = setup();
  const token = capabilities.issue(decision, pauseAction, KEY_FP, "identity-service", operatorApproval, NOW);
  const receipt = authority.execute(token, { action: "identity.api_key.pause", target: KEY_FP, scope: "single_key" }, NOW);
  assert.equal(receipt.action.result, "success");
  assert.equal(authority.keyState(KEY_FP), "paused");
  assert.equal(receipt.rollback.supported, true);
  assert.equal(receipt.rollback.action_type, "identity.api_key.resume");
  assert.equal(validateActionReceipt(receipt).ok, true, "receipt satisfies the contract");

  const rollbackReceipt = authority.rollback(receipt, "2026-06-09T18:00:00.000Z");
  assert.equal(rollbackReceipt.action.result, "rolled_back");
  assert.equal(authority.keyState(KEY_FP), "active");
  assert.equal(rollbackReceipt.rollback.rollback_of, receipt.receipt_id);
  assert.equal(receipts.byIncident("inc_t1").length, 2, "every attempt has a receipt");
});

test("receipt reflects the real decision/approval, not a hardcoded literal", () => {
  const { authority, capabilities } = setup();
  // Same required "single_operator" level as `pauseAction` demands, but a
  // distinct approver identity — proves the receipt reflects the real
  // approval rather than the previously-hardcoded {type:"operator", id:"via_capability"}.
  const namedApproval: ApprovalRecord = { level: "single_operator", approver_type: "operator", approver_id: "op_99", approved_at: NOW };
  const otherDecision: PolicyDecision = { ...decision, policy_id: "sentinel_account_compromise", policy_version: "3.2.0" };
  const token = capabilities.issue(otherDecision, pauseAction, KEY_FP, "identity-service", namedApproval, NOW);
  const receipt = authority.execute(token, { action: "identity.api_key.pause", target: KEY_FP, scope: "single_key" }, NOW);
  assert.equal(receipt.decision.policy_version, "3.2.0", "reflects the decision actually presented, not a hardcoded version");
  assert.deepEqual(receipt.decision.approver, { type: "operator", id: "op_99" }, "approver reflects the real approval, not a hardcoded \"via_capability\"");
});

test("a successful execution feeds cooldown hysteresis (06) for real, not just in the unit test that calls recordExecutedAction by hand", () => {
  const { capabilities, receipts, policy } = setup();
  const authority = new IdentityAuthority(capabilities, receipts, policy);
  authority.registerKey(KEY_FP);
  policy.register(ACCOUNT_COMPROMISE_POLICY);
  const now: Incident = {
    incident_id: "inc_t1",
    title: "t",
    incident_type: "compound.account_compromise",
    status: "open",
    priority: "high",
    origin: ["sentinel-cloud"],
    subject: { tenant_id: "ten_a", account_id: "acct_1" },
    risk: { likelihood: 0.9, impact: 0.85, confidence: 0.85, evidence_quality: 0.95 },
    briefing: { issue: "i", where: "w", recommended_fix: "f", why_now: "y" },
    finding_ids: ["fnd_1"],
    evidence_ids: ["evd_1"],
    independent_signal_count: 4,
    signals: ["cost.usage_change_extreme", "cloud.new_api_key", "cloud.new_region", "cloud.login_failure_burst"],
    required_authority: ["identity_service", "forge_command_operator"],
    recommended_actions: [{ action_type: "identity.api_key.pause", target_id: KEY_FP, scope: "single_key", reversible: true, approval: "single_operator" }],
    conflicts: [],
    missing_telemetry: [],
    version: 1,
    created_at: NOW,
    updated_at: NOW,
    status_history: [{ status: "open", at: NOW }],
  };
  const firstDecision = policy.evaluate(now, { environment: "production" }, NOW);
  assert.ok(firstDecision.allowed_actions.some((action) => action.action_type === "identity.api_key.pause"));
  const token = capabilities.issue(firstDecision, firstDecision.allowed_actions[0]!, KEY_FP, "identity-service", operatorApproval, NOW);
  const receipt = authority.execute(token, { action: "identity.api_key.pause", target: KEY_FP, scope: "single_key" }, NOW);
  assert.equal(receipt.action.result, "success");
  const secondDecision = policy.evaluate(now, { environment: "production" }, "2026-06-09T17:08:00.000Z");
  assert.ok(
    secondDecision.denied_actions.some((action) => action.action_type === "identity.api_key.pause" && action.reason.includes("cooldown")),
    "the executor's own successful action engages cooldown on the next policy evaluation",
  );
});

test("executor rejects expanded scope and records the rejection (12 capability expansion scenario)", () => {
  const { authority, capabilities } = setup();
  const token = capabilities.issue(decision, pauseAction, KEY_FP, "identity-service", operatorApproval, NOW);
  const receipt = authority.execute(token, { action: "identity.api_key.pause", target: KEY_FP, scope: "all_keys" }, NOW);
  assert.equal(receipt.action.result, "rejected");
  assert.match(receipt.action.failure_reason ?? "", /scope_mismatch/);
  assert.equal(authority.keyState(KEY_FP), "active", "no partial broad action");
});

test("executor rejects a changed action or target", () => {
  const { authority, capabilities } = setup();
  const token = capabilities.issue(decision, pauseAction, KEY_FP, "identity-service", operatorApproval, NOW);
  const changedAction = authority.execute(token, { action: "identity.api_key.revoke", target: KEY_FP, scope: "single_key" }, NOW);
  assert.equal(changedAction.action.result, "rejected");
  const token2 = capabilities.issue(decision, pauseAction, KEY_FP, "identity-service", operatorApproval, NOW);
  const changedTarget = authority.execute(token2, { action: "identity.api_key.pause", target: "sha256:otherkey", scope: "single_key" }, NOW);
  assert.equal(changedTarget.action.result, "rejected");
  assert.equal(authority.keyState(KEY_FP), "active");
});

test("replayed capability is rejected after max_attempts", () => {
  const { authority, capabilities } = setup();
  const token = capabilities.issue(decision, pauseAction, KEY_FP, "identity-service", operatorApproval, NOW);
  const first = authority.execute(token, { action: "identity.api_key.pause", target: KEY_FP, scope: "single_key" }, NOW);
  assert.equal(first.action.result, "success");
  const replay = authority.execute(token, { action: "identity.api_key.pause", target: KEY_FP, scope: "single_key" }, NOW);
  assert.equal(replay.action.result, "rejected");
  assert.match(replay.action.failure_reason ?? "", /replayed/);
});

test("expired capability is rejected", () => {
  const { authority, capabilities } = setup();
  const token = capabilities.issue(decision, pauseAction, KEY_FP, "identity-service", operatorApproval, NOW);
  const receipt = authority.execute(token, { action: "identity.api_key.pause", target: KEY_FP, scope: "single_key" }, "2026-06-09T18:00:00.000Z");
  assert.equal(receipt.action.result, "rejected");
  assert.match(receipt.action.failure_reason ?? "", /expired/);
});

test("tampered claims fail signature verification", () => {
  const { authority, capabilities } = setup();
  const token = capabilities.issue(decision, pauseAction, KEY_FP, "identity-service", operatorApproval, NOW);
  const tampered = { ...token, claims: { ...token.claims, target: "sha256:otherkey" } };
  const receipt = authority.execute(tampered, { action: "identity.api_key.pause", target: "sha256:otherkey", scope: "single_key" }, NOW);
  assert.equal(receipt.action.result, "rejected");
  assert.match(receipt.action.failure_reason ?? "", /signature_invalid/);
});

test("issuance requires the approval level demanded by policy", () => {
  const { capabilities } = setup();
  const policyOnly: ApprovalRecord = { level: "policy_allowed", approver_type: "policy", approver_id: "policy", approved_at: NOW };
  assert.throws(() => capabilities.issue(decision, pauseAction, KEY_FP, "identity-service", policyOnly, NOW), /requires single_operator/);
});

test("issuance refuses actions outside the policy decision", () => {
  const { capabilities } = setup();
  const rogue: AllowedAction = { action_type: "identity.session.revoke", scope: "all_sessions", expires_in_seconds: 900, requires_approval: "single_operator", reversible: false };
  assert.throws(() => capabilities.issue(decision, rogue, "acct_1", "identity-service", operatorApproval, NOW), /not allowed by decision/);
});
