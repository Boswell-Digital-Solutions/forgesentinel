import { test } from "node:test";
import assert from "node:assert/strict";
import { AGENT_DRIFT_COMPOUND, SentinelPrime, type Finding } from "../src/index.js";

function finding(overrides: Partial<Finding> & { finding_id: string; finding_type: string }): Finding {
  return {
    node: { name: "sentinel-test", version: "1.0.0" },
    subject: { type: "account", id: "acct_1" },
    tenant_id: "ten_a",
    window: { start: "2026-06-09T16:00:00.000Z", end: "2026-06-09T17:00:00.000Z" },
    risk: { likelihood: 0.5, impact: 0.5, confidence: 0.6, evidence_quality: 0.9 },
    evidence_ids: [`evd_${overrides.finding_id}`],
    source_event_roots: [`root_${overrides.finding_id}`],
    explanation: { summary: "test", top_factors: [], uncertainties: [] },
    recommendation: { action_class: "OBSERVE" },
    expires_at: "2026-06-10T17:00:00.000Z",
    correlation_hints: { account_id: "acct_1" },
    policy_generated_effect: false,
    ...overrides,
  };
}

const NOW = "2026-06-09T17:04:00.000Z";

function compoundSet(): Finding[] {
  return [
    finding({ finding_id: "f_cost", finding_type: "cost.usage_change_extreme", risk: { likelihood: 0.74, impact: 0.81, confidence: 0.7, evidence_quality: 0.96 }, baseline: { baseline_id: "b", expected: 100000, observed: 15000000, change_ratio: 150 } }),
    finding({ finding_id: "f_key", finding_type: "cloud.new_api_key", risk: { likelihood: 0.3, impact: 0.5, confidence: 0.6, evidence_quality: 0.95 }, correlation_hints: { account_id: "acct_1", api_key_fingerprint: "sha256:newkey" } }),
    finding({ finding_id: "f_region", finding_type: "cloud.new_region", risk: { likelihood: 0.3, impact: 0.5, confidence: 0.6, evidence_quality: 0.95 }, source_event_roots: ["root_session"] }),
    finding({ finding_id: "f_device", finding_type: "cloud.new_device", risk: { likelihood: 0.25, impact: 0.5, confidence: 0.6, evidence_quality: 0.95 }, source_event_roots: ["root_session"] }),
    finding({ finding_id: "f_login", finding_type: "cloud.login_failure_burst", risk: { likelihood: 0.61, impact: 0.5, confidence: 0.7, evidence_quality: 0.96 } }),
  ];
}

test("compound correlation forms one incident with correct independence accounting", () => {
  const prime = new SentinelPrime();
  prime.submitFindings(compoundSet());
  const incidents = prime.correlate(NOW);
  assert.equal(incidents.length, 1);
  const incident = incidents[0]!;
  assert.equal(incident.incident_type, "compound.account_compromise");
  // new_region and new_device derive from the same session event: one root.
  assert.equal(incident.independent_signal_count, 4, "shared source is not double-counted");
  assert.ok(incident.risk.likelihood >= 0.8);
  assert.ok(incident.risk.confidence >= 0.75);
  assert.ok(incident.risk.evidence_quality >= 0.85);
  assert.ok(incident.finding_ids.length === 5, "all findings preserved even when roots collapse");
  assert.ok(incident.recommended_actions.some((action) => action.action_type === "identity.api_key.pause" && action.scope === "single_key" && action.reversible));
});

test("policy-generated effects are excluded from independence (ADR-022 feedback-loop defense)", () => {
  const prime = new SentinelPrime();
  // Two organic weak signals + a flood of policy-caused deny findings.
  const organic = [
    finding({ finding_id: "f_key2", finding_type: "cloud.new_api_key", risk: { likelihood: 0.3, impact: 0.5, confidence: 0.6, evidence_quality: 0.95 } }),
    finding({ finding_id: "f_region2", finding_type: "cloud.new_region", risk: { likelihood: 0.3, impact: 0.5, confidence: 0.6, evidence_quality: 0.95 } }),
  ];
  const policyEffects = [0, 1, 2, 3].map((index) =>
    finding({
      finding_id: `f_pol_${index}`,
      finding_type: "cloud.login_failure_burst",
      policy_generated_effect: true,
      source_event_roots: [`root_pol_${index}`],
    }),
  );
  prime.submitFindings([...organic, ...policyEffects]);
  const incidents = prime.correlate(NOW);
  assert.equal(
    incidents.filter((incident) => incident.incident_type === "compound.account_compromise").length,
    0,
    "control-generated denials must not satisfy the minimum independent group count",
  );
});

test("an approved change window lowers risk and preserves the conflict (12 bulk migration scenario)", () => {
  const prime = new SentinelPrime();
  prime.registerChangeWindow({
    tenant_id: "ten_a",
    subject_field: "account_id",
    subject_id: "acct_1",
    start: "2026-06-09T00:00:00.000Z",
    end: "2026-06-10T00:00:00.000Z",
    reason: "approved bulk migration",
    approved_by: "op_17",
  });
  prime.submitFindings(compoundSet());
  const incidents = prime.correlate(NOW);
  assert.equal(incidents.length, 1);
  const incident = incidents[0]!;
  assert.ok(incident.conflicts.some((conflict) => conflict.includes("approved_change_window")), "conflict is visible, not hidden");
  assert.ok(incident.risk.likelihood < 0.8, "approved window lowers likelihood below containment thresholds");
  assert.equal(incident.recommended_actions.length, 0, "no containment is recommended during an approved window");
});

test("an unrecognized incident_type gets no recommended actions, not account-compromise's by accident", () => {
  const unknownRule = {
    correlation_id: "prime.test_unknown_compound",
    version: "1.0.0",
    subject_field: "account_id" as const,
    window_ms: 2 * 3600 * 1000,
    supporting: [
      { finding_type: "cloud.new_api_key", weight: 0.5 },
      { finding_type: "cloud.new_region", weight: 0.5 },
    ],
    independence: { minimum_groups: 2 },
    emit: { incident_type: "compound.not_yet_wired", playbook: "PB-TEST-01", title: "Unwired test rule", required_authority: ["forge_command_operator"] },
  };
  const prime = new SentinelPrime([unknownRule]);
  prime.submitFindings([
    finding({ finding_id: "f_key3", finding_type: "cloud.new_api_key", correlation_hints: { account_id: "acct_1", api_key_fingerprint: "sha256:shouldnotbeused" } }),
    finding({ finding_id: "f_region3", finding_type: "cloud.new_region", source_event_roots: ["root_f_region3"] }),
  ]);
  const incidents = prime.correlate(NOW);
  assert.equal(incidents.length, 1);
  const incident = incidents[0]!;
  assert.equal(incident.incident_type, "compound.not_yet_wired");
  assert.equal(incident.recommended_actions.length, 0, "no incident_type-specific recommendation logic exists for this rule; it must not fall through to account-compromise's");
});

test("an approved change window also suppresses containment for a non-account-scoped rule (agent drift)", () => {
  const prime = new SentinelPrime([AGENT_DRIFT_COMPOUND]);
  prime.registerChangeWindow({
    tenant_id: "ten_a",
    subject_field: "agent_fingerprint",
    subject_id: "agt_forge-smithy",
    start: "2026-06-09T00:00:00.000Z",
    end: "2026-06-10T00:00:00.000Z",
    reason: "approved sandbox drill",
    approved_by: "op_17",
  });
  prime.submitFindings([
    finding({
      finding_id: "f_boundary",
      finding_type: "agent.boundary_violation",
      subject: { type: "agent", id: "agt_forge-smithy" },
      risk: { likelihood: 0.6, impact: 0.6, confidence: 0.75, evidence_quality: 0.9 },
    }),
    finding({
      finding_id: "f_patch",
      finding_type: "agent.patch_burst",
      subject: { type: "agent", id: "agt_forge-smithy" },
      source_event_roots: ["root_f_patch"],
      risk: { likelihood: 0.6, impact: 0.55, confidence: 0.7, evidence_quality: 0.9 },
    }),
  ]);
  const incidents = prime.correlate(NOW);
  assert.equal(incidents.length, 1);
  const incident = incidents[0]!;
  assert.equal(incident.incident_type, "compound.agent_drift");
  assert.ok(incident.conflicts.some((conflict) => conflict.includes("approved_change_window")), "conflict is visible, not hidden");
  assert.equal(incident.recommended_actions.length, 0, "no containment recommended: this rule type is no longer exempt from change-window suppression");
});

test("duplicate incidents merge while preserving all evidence", () => {
  const prime = new SentinelPrime();
  prime.submitFindings(compoundSet());
  const first = prime.correlate(NOW);
  assert.equal(first.length, 1);
  prime.submitFindings([
    finding({ finding_id: "f_login_late", finding_type: "cloud.login_failure_burst", window: { start: "2026-06-09T17:10:00.000Z", end: "2026-06-09T17:20:00.000Z" } }),
  ]);
  const second = prime.correlate("2026-06-09T17:21:00.000Z");
  assert.equal(second.length, 0, "no second incident for the same subject and type");
  const incident = prime.allIncidents()[0]!;
  assert.equal(incident.version, 2);
  assert.ok(incident.finding_ids.includes("f_login_late"));
  assert.ok(incident.finding_ids.includes("f_cost"), "original findings retained");
});

test("a usage spike alone caps confidence and recommends no containment", () => {
  const prime = new SentinelPrime();
  prime.submitFindings([
    finding({ finding_id: "f_solo", finding_type: "cost.usage_change_extreme", risk: { likelihood: 0.74, impact: 0.81, confidence: 0.7, evidence_quality: 0.96 } }),
  ]);
  const incidents = prime.correlate(NOW);
  assert.equal(incidents.length, 1);
  const incident = incidents[0]!;
  assert.equal(incident.incident_type, "cost.usage_runaway");
  assert.equal(incident.independent_signal_count, 1);
  assert.ok(incident.risk.confidence <= 0.7);
  assert.equal(incident.recommended_actions.length, 0);
  assert.ok(incident.missing_telemetry.length > 0, "missing corroboration is visible");
});

test("a lone CSSA denial-streak finding promotes to a capped-confidence watch incident", () => {
  const prime = new SentinelPrime();
  prime.submitFindings([
    finding({
      finding_id: "f_denial",
      finding_type: "cssa.denial_streak",
      subject: { type: "principal", id: "usr_watched" },
      risk: { likelihood: 0.75, impact: 0.75, confidence: 0.9, evidence_quality: 0.95 },
    }),
  ]);
  const incidents = prime.correlate(NOW);
  assert.equal(incidents.length, 1);
  const incident = incidents[0]!;
  assert.equal(incident.incident_type, "cssa.denial_streak_watch");
  assert.equal(incident.independent_signal_count, 1);
  assert.ok(incident.risk.confidence <= 0.7, "a single decisions-only signal caps confidence");
  assert.equal(incident.recommended_actions.length, 0, "recommend-only: no containment from a lone decisions-only signal");
  assert.ok(incident.missing_telemetry.length > 0, "missing corroboration is visible");
});

test("a lone CSSA quota-exceeded-burst finding promotes to a capped-confidence watch incident", () => {
  const prime = new SentinelPrime();
  prime.submitFindings([
    finding({
      finding_id: "f_quota",
      finding_type: "cssa.quota_exceeded_burst",
      subject: { type: "principal", id: "usr_watched" },
      risk: { likelihood: 0.75, impact: 0.75, confidence: 0.9, evidence_quality: 0.95 },
    }),
  ]);
  const incidents = prime.correlate(NOW);
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0]!.incident_type, "cssa.quota_exceeded_watch");
});

test("a lone CSSA approval-pending-burst finding promotes to a capped-confidence watch incident", () => {
  const prime = new SentinelPrime();
  prime.submitFindings([
    finding({
      finding_id: "f_approval",
      finding_type: "cssa.approval_pending_burst",
      subject: { type: "principal", id: "usr_watched" },
      risk: { likelihood: 0.75, impact: 0.75, confidence: 0.9, evidence_quality: 0.95 },
    }),
  ]);
  const incidents = prime.correlate(NOW);
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0]!.incident_type, "cssa.approval_pending_watch");
});

test("a lone CSSA execution-failure-burst finding promotes to a capped-confidence watch incident", () => {
  const prime = new SentinelPrime();
  prime.submitFindings([
    finding({
      finding_id: "f_exec_failure",
      finding_type: "cssa.execution_failure_burst",
      subject: { type: "principal", id: "usr_watched" },
      risk: { likelihood: 0.75, impact: 0.75, confidence: 0.9, evidence_quality: 0.95 },
    }),
  ]);
  const incidents = prime.correlate(NOW);
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0]!.incident_type, "cssa.execution_failure_watch");
});

test("a policy-generated-effect CSSA finding never self-promotes", () => {
  const prime = new SentinelPrime();
  prime.submitFindings([
    finding({
      finding_id: "f_denial_effect",
      finding_type: "cssa.denial_streak",
      policy_generated_effect: true,
    }),
  ]);
  assert.equal(prime.correlate(NOW).length, 0);
});

test("lifecycle: dismissal requires a reason and reopen links the prior version", () => {
  const prime = new SentinelPrime();
  prime.submitFindings(compoundSet());
  const incident = prime.correlate(NOW)[0]!;
  assert.throws(() => prime.transition(incident.incident_id, "dismissed", "op_17"));
  prime.transition(incident.incident_id, "dismissed", "op_17", "verified as customer load test");
  const reopened = prime.transition(incident.incident_id, "reopened", "op_18", "new evidence arrived");
  assert.ok(reopened.reopened_from?.startsWith(incident.incident_id));
  assert.equal(reopened.status_history.length, 3);
});
