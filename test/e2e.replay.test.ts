import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import {
  SentinelRuntime,
  loadReplayFile,
  buildEvent,
  standardProducers,
  validateFinding,
  validateIncident,
  COST_FORBIDDEN_ACTIONS,
  type ReplayLine,
  type ShadowReport,
} from "../src/index.js";

const FIXTURES = join(process.cwd(), "fixtures", "replay");
const COMPOUND = loadReplayFile(join(FIXTURES, "compound_account_compromise.jsonl"));
const SPIKE_ONLY = loadReplayFile(join(FIXTURES, "usage_spike_only.jsonl"));
const AGENT_DRIFT = loadReplayFile(join(FIXTURES, "agent_drift.jsonl"));

function run(lines: ReplayLine[]): ShadowReport {
  return new SentinelRuntime("production").runShadow(lines);
}

test("end-to-end compound compromise: evidence -> findings -> incident -> REQUEST_OPERATOR (12 scenario)", () => {
  const report = run(COMPOUND);
  assert.equal(report.replay.rejected, 0);
  assert.equal(report.shadow, true);

  for (const finding of report.findings) {
    assert.equal(validateFinding(finding).ok, true, `finding contract: ${finding.finding_id}`);
  }
  const types = report.findings.map((finding) => finding.finding_type);
  for (const expected of ["cost.usage_change_extreme", "cloud.new_api_key", "cloud.new_region", "cloud.new_device", "cloud.login_failure_burst"]) {
    assert.ok(types.includes(expected), `missing finding ${expected}`);
  }

  assert.equal(report.incidents.length, 1);
  const incident = report.incidents[0]!;
  assert.equal(validateIncident(incident).ok, true, JSON.stringify(validateIncident(incident).issues));
  assert.equal(incident.incident_type, "compound.account_compromise");
  assert.equal(incident.independent_signal_count, 4, "region+device share the session root; no double counting");
  assert.ok(incident.risk.likelihood >= 0.8 && incident.risk.confidence >= 0.75 && incident.risk.evidence_quality >= 0.85);
  assert.equal(incident.playbook, "PB-ACCOUNT-COMPROMISE-01");

  const decision = report.decisions[0]!;
  assert.equal(decision.result, "REQUEST_OPERATOR");
  const pause = decision.allowed_actions.find((action) => action.action_type === "identity.api_key.pause");
  assert.ok(pause && pause.scope === "single_key" && pause.reversible, "containment is the smallest reversible scope");

  const pauseTarget = incident.recommended_actions.find((action) => action.action_type === "identity.api_key.pause");
  assert.ok(pauseTarget?.target_id.endsWith("7fa2"), "action targets the exact new key");
});

test("end-to-end agent drift: patch burst + denials + boundary violation -> quarantine exact version (12 scenario)", () => {
  const report = run(AGENT_DRIFT);
  assert.equal(report.replay.rejected, 0);
  const types = report.findings.map((finding) => finding.finding_type);
  for (const expected of ["agent.boundary_violation", "agent.patch_burst", "agent.denied_action_burst"]) {
    assert.ok(types.includes(expected), `missing finding ${expected}`);
  }
  assert.equal(report.incidents.length, 1);
  const incident = report.incidents[0]!;
  assert.equal(validateIncident(incident).ok, true, JSON.stringify(validateIncident(incident).issues));
  assert.equal(incident.incident_type, "compound.agent_drift");
  assert.equal(incident.independent_signal_count, 3);
  assert.deepEqual(incident.required_authority, ["yellowjacket", "forge_command_operator"]);

  // SentinelAgentNode scopes findings by actor_id (event.actor.actor_id), not
  // a separate versioned fingerprint identity, so the quarantine target is
  // the actor id rather than the fixture's agent_fingerprint payload field.
  const quarantine = incident.recommended_actions.find((action) => action.action_type === "yellowjacket.agent_version.quarantine");
  assert.ok(quarantine, "quarantine is recommended");
  assert.equal(quarantine.target_id, "forge-smithy", "quarantine targets the agent actor id");
  assert.equal(quarantine.scope, "single_agent_version");
  assert.equal(quarantine.reversible, true, "re-enable path exists");
  const stop = incident.recommended_actions.find((action) => action.action_type === "yellowjacket.run.stop");
  assert.ok(stop && stop.target_id === "run_smith_771" && stop.scope === "single_run");

  const decision = report.decisions[0]!;
  assert.equal(decision.policy_id, "sentinel_agent_drift");
  assert.equal(decision.result, "REQUEST_OPERATOR");
  assert.ok(
    !incident.recommended_actions.some((action) => action.action_type.startsWith("agent.patch")) &&
      !decision.allowed_actions.some((action) => action.action_type.startsWith("agent.patch")),
    "Sentinel never patches code (ADR-007)",
  );
});

test("usage spike alone: finding, monitor-grade incident, no containment (12 scenario)", () => {
  const report = run(SPIKE_ONLY);
  assert.equal(report.findings.length, 1);
  assert.equal(report.incidents.length, 1);
  const incident = report.incidents[0]!;
  assert.equal(incident.incident_type, "cost.usage_runaway");
  assert.ok(incident.risk.confidence <= 0.7, "single-source confidence is capped");
  assert.equal(incident.recommended_actions.length, 0, "no suspension from usage alone");
  assert.equal(report.decisions[0]!.result, "RECOMMEND_ONLY");
});

test("replay is deterministic across runs (Wave 1 exit gate)", () => {
  const first = run(COMPOUND);
  const second = run(COMPOUND);
  assert.equal(second.replay.accepted, first.replay.accepted);
  assert.deepEqual(
    second.findings.map((finding) => [finding.finding_type, finding.risk]),
    first.findings.map((finding) => [finding.finding_type, finding.risk]),
  );
  assert.deepEqual(second.incidents[0]!.risk, first.incidents[0]!.risk);
  assert.equal(second.decisions[0]!.result, first.decisions[0]!.result);
});

test("duplicated fixture lines are safe (idempotent ingestion)", () => {
  const doubled = [...COMPOUND, ...COMPOUND];
  const report = run(doubled);
  assert.equal(report.replay.duplicates, COMPOUND.length);
  assert.equal(report.incidents.length, 1, "duplicates do not inflate incidents");
  assert.equal(report.incidents[0]!.independent_signal_count, 4, "duplicates do not inflate independence");
});

test("policy-caused denials do not feed back as fresh compromise evidence (ADR-022, Gate D proof)", () => {
  const producers = Object.fromEntries(standardProducers("production").map((producer) => [producer.service, producer]));
  const lineage = {
    control_origin: "sentinel_policy" as const,
    sentinel_incident_id: "inc_0001",
    policy_decision_id: "pdec_0001",
    control_id: "ctl_applied_01",
    policy_generated_effect: true,
  };
  // After a key hold, the attacker retries from yet another region: those
  // denials carry control lineage and must not mint new independent signals.
  const followOn: ReplayLine[] = [0, 1, 2].map((index) =>
    buildEvent(producers["identity-service"]!, {
      event_id: `evt_post_control_${index}`,
      event_type: "identity.session.created",
      occurred_at: `2026-06-09T17:3${index}:00.000Z`,
      tenant: { tenant_id: "ten_demo", account_id: "acct_2041" },
      actor: { actor_type: "user", actor_id: "usr_owner" },
      subject: { subject_type: "session", subject_id: `ses_post_${index}` },
      correlation: { trace_id: `trc_post_${index}` },
      location: { execution_lane: "cloud", region: `region_x${index}` },
      payload: { region: `region_x${index}`, device_fingerprint: `dev_x${index}` },
      control_lineage: lineage,
    }),
  );

  const report = run([...COMPOUND, ...followOn]);
  const policyEffectFindings = report.findings.filter((finding) => finding.policy_generated_effect);
  assert.ok(policyEffectFindings.length >= 3, "lineage-carrying events still produce findings, flagged");
  const incident = report.incidents.find((candidate) => candidate.incident_type === "compound.account_compromise")!;
  assert.equal(incident.independent_signal_count, 4, "independence count unchanged by policy-generated effects");
});

test("Sentinel-Cost cannot recommend forbidden commercial actions (03)", () => {
  const report = run(COMPOUND);
  const forbidden = new Set<string>(COST_FORBIDDEN_ACTIONS);
  for (const incident of report.incidents) {
    for (const action of incident.recommended_actions) {
      assert.ok(!forbidden.has(action.action_type), `forbidden action recommended: ${action.action_type}`);
    }
  }
  for (const decision of report.decisions) {
    for (const action of decision.allowed_actions) {
      assert.ok(!forbidden.has(action.action_type));
    }
  }
});

test("cold-start account produces no spike finding (05 cold start)", () => {
  const producers = Object.fromEntries(standardProducers("production").map((producer) => [producer.service, producer]));
  const newAccount: ReplayLine[] = [0, 1, 2].map((index) =>
    buildEvent(producers["usage-metering"]!, {
      event_id: `evt_cold_${index}`,
      event_type: "usage.tokens.recorded",
      occurred_at: `2026-06-09T1${index}:00:00.000Z`,
      tenant: { tenant_id: "ten_new", account_id: "acct_new" },
      actor: { actor_type: "service", actor_id: "neuroforge-gateway" },
      subject: { subject_type: "account", subject_id: "acct_new" },
      correlation: { trace_id: `trc_cold_${index}` },
      payload: { total_tokens: 5000000, route_class: "general_cloud" },
    }),
  );
  const report = run(newAccount);
  assert.equal(report.findings.length, 0, "onboarding growth is not called compromise");
  assert.equal(report.incidents.length, 0);
});

test("every finding and incident is reconstructable from ledger evidence (definition of done)", () => {
  const runtime = new SentinelRuntime("production");
  const report = runtime.runShadow(COMPOUND);
  const ledgerEvidenceIds = new Set(
    runtime.ledger
      .all()
      .filter((record) => record.kind === "evidence")
      .map((record) => (record.body as { evidence_id: string }).evidence_id),
  );
  for (const finding of report.findings) {
    for (const evidenceId of finding.evidence_ids) {
      assert.ok(ledgerEvidenceIds.has(evidenceId), `evidence ${evidenceId} of ${finding.finding_id} is durable`);
    }
  }
  for (const incident of report.incidents) {
    for (const evidenceId of incident.evidence_ids) {
      assert.ok(ledgerEvidenceIds.has(evidenceId));
    }
  }
  assert.ok(runtime.ledger.integrityCheck().every((check) => check.ok));
});
