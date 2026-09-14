import { test } from "node:test";
import assert from "node:assert/strict";
import { SentinelProviderNode, buildEvent, standardProducers, validateFinding, type ModelFingerprint, type TrustVector } from "../src/index.js";

const NOW = "2026-06-09T12:00:00.000Z";

function fingerprint(id: string, snapshot: string, overrides: Partial<ModelFingerprint> = {}): ModelFingerprint {
  return {
    fingerprint_id: id,
    provider: "provider_a",
    endpoint: "https://api.provider-a.example/v1",
    region: "us-east",
    declared_model_name: "atlas-large",
    provider_model_id: `atlas-large-${snapshot}`,
    snapshot,
    context_window: 200000,
    tool_configuration: "tools_v2",
    structured_output_mode: "json_schema",
    prompt_bundle_hash: "sha256:promptaaa",
    gateway_version: "4.2.0",
    first_seen_at: NOW,
    ...overrides,
  };
}

function normalTrust(fingerprintId: string, taskCategory: string): TrustVector {
  return {
    provider: "provider_a",
    model_snapshot: "2026-05-01",
    fingerprint_id: fingerprintId,
    task_category: taskCategory,
    route_class: "code_mutation_supervised",
    tool_profile: "read_patch_test_v2",
    evaluation_suite: "codefix-v7",
    window: "last_500_eligible_runs",
    state: "normal",
    dimensions: {
      reliability: 0.96,
      task_success: 0.93,
      evaluation_quality: 0.9,
      latency_score: 0.72,
      cost_efficiency: 0.64,
      security_compliance: 0.95,
      privacy_compatibility: 0.9,
      contract_validity: 0.99,
      tool_policy_compliance: 1.0,
      rollback_risk: 0.02,
      availability: 0.98,
      evidence_quality: 0.92,
    },
  };
}

test("a changed alias cannot silently inherit mature trust (Wave 6 exit gate, ADR-006)", () => {
  const node = new SentinelProviderNode();
  const oldFp = fingerprint("fp_old", "2026-05-01");
  node.observe(oldFp);
  node.setTrust(normalTrust("fp_old", "security.auth_change"));
  assert.equal(node.sensitiveEligible("fp_old", "security.auth_change", "code_mutation_supervised"), true);

  const newFp = fingerprint("fp_new", "2026-06-09", { provider_model_id: "atlas-large-2026-06-09", prompt_bundle_hash: "sha256:promptbbb" });
  const output = node.observe(newFp);
  assert.equal(output.findings.length, 1);
  const finding = output.findings[0]!;
  assert.equal(finding.finding_type, "provider.fingerprint_changed");
  assert.equal(validateFinding(finding).ok, true);
  assert.match(finding.explanation.summary, /provisional/);

  const inherited = node.trustFor("fp_new", "security.auth_change", "code_mutation_supervised");
  assert.ok(inherited, "a successor vector exists so the reset is visible");
  assert.equal(inherited.state, "provisional");
  assert.equal(inherited.dimensions.task_success, 0, "task performance is never inherited");
  assert.equal(node.sensitiveEligible("fp_new", "security.auth_change", "code_mutation_supervised"), false, "sensitive categories require a verified fingerprint");

  const historical = node.trustFor("fp_old", "security.auth_change", "code_mutation_supervised");
  assert.ok(historical, "historical identity is retained");
  assert.equal(historical.state, "reduced");
});

test("re-observing the same fingerprint emits nothing", () => {
  const node = new SentinelProviderNode();
  const fp = fingerprint("fp_same", "2026-05-01");
  node.observe(fp);
  const output = node.observe(fp);
  assert.equal(output.findings.length, 0);
});

test("node consumes neuroforge.model_fingerprint.changed events from the ledger", () => {
  const producers = Object.fromEntries(standardProducers("production").map((producer) => [producer.service, producer]));
  const node = new SentinelProviderNode();
  node.setTrust(normalTrust("fp_old", "typescript.type_fix"));
  const { event } = buildEvent(producers["neuroforge"]!, {
    event_id: "evt_fp_change",
    event_type: "neuroforge.model_fingerprint.changed",
    occurred_at: NOW,
    tenant: { tenant_id: "ten_platform" },
    actor: { actor_type: "service", actor_id: "neuroforge-catalog-monitor" },
    subject: { subject_type: "model_route", subject_id: "provider_a/atlas-large" },
    correlation: { trace_id: "trc_fp_change" },
    payload: {
      previous: fingerprint("fp_old", "2026-05-01"),
      current: fingerprint("fp_new", "2026-06-09"),
    },
  });
  const output = node.process([event]);
  assert.equal(output.findings.length, 1);
  assert.equal(output.findings[0]!.correlation_hints.model_fingerprint, "fp_new");
  assert.equal(output.evidence.length, 1, "finding is backed by the catalog-change event evidence");
  assert.equal(node.trustFor("fp_new", "typescript.type_fix", "code_mutation_supervised")?.state, "provisional");
});
