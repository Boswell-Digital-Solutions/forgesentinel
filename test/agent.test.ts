import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildEvent,
  validateFinding,
  AGENT_FORBIDDEN_ACTIONS,
  type ReplayLine,
  type ShadowReport,
} from "../src/index.js";
import { byService, productionRuntime, testProducers } from "./support/producers.js";

/**
 * Wave 5 (Sentinel-Agent): patch burst, repository/permission boundary
 * violation, and denied-action burst. Shadow / recommend-only — the node never
 * applies or promotes a patch.
 */

const RECOMMEND_CLASSES = new Set(["RECOMMEND_ONLY", "REQUEST_OPERATOR"]);
const PRODUCERS = testProducers("production");
const producers = byService(PRODUCERS);
const agents = producers["forgeagents"]!;
const TENANT = { tenant_id: "ten_agent", account_id: "acct_agent_1" };
const BASE = Date.parse("2026-06-09T12:00:00.000Z");

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

function run(lines: ReplayLine[]): ShadowReport {
  return productionRuntime(PRODUCERS).runShadow(lines);
}

function patchApplied(id: string, occurredAt: string, agentId: string): ReplayLine {
  return buildEvent(agents, {
    event_id: `evt_${id}`,
    event_type: "agent.patch.applied",
    occurred_at: occurredAt,
    tenant: TENANT,
    actor: { actor_type: "agent", actor_id: agentId },
    subject: { subject_type: "patch", subject_id: `patch_${id}` },
    correlation: { trace_id: `trc_${id}`, run_id: "run_1" },
    payload: { files_changed: 2 },
  });
}

function boundaryViolated(id: string, occurredAt: string, agentId: string): ReplayLine {
  return buildEvent(agents, {
    event_id: `evt_${id}`,
    event_type: "agent.boundary.violated",
    occurred_at: occurredAt,
    tenant: TENANT,
    actor: { actor_type: "agent", actor_id: agentId },
    subject: { subject_type: "repository", subject_id: "repo_core" },
    correlation: { trace_id: `trc_${id}` },
    payload: { boundary: "repo:forbidden/secrets" },
  });
}

function permissionDenied(id: string, occurredAt: string, agentId: string): ReplayLine {
  return buildEvent(agents, {
    event_id: `evt_${id}`,
    event_type: "agent.permission.denied",
    occurred_at: occurredAt,
    tenant: TENANT,
    actor: { actor_type: "agent", actor_id: agentId },
    subject: { subject_type: "permission", subject_id: "fs.write" },
    correlation: { trace_id: `trc_${id}` },
    payload: { permission: "fs.write" },
  });
}

function patches(count: number, agentId: string): ReplayLine[] {
  return Array.from({ length: count }, (_, index) => patchApplied(`patch_${agentId}_${index}`, iso(BASE + index * 3 * 60_000), agentId));
}

test("patch burst: many patches in an hour raise a REQUEST_OPERATOR finding on the exact agent", () => {
  const report = run(patches(10, "agt_coder"));
  const burst = report.findings.filter((finding) => finding.finding_type === "agent.patch_burst");
  assert.equal(burst.length, 1);
  assert.equal(validateFinding(burst[0]!).ok, true, JSON.stringify(validateFinding(burst[0]!).issues));
  assert.equal(burst[0]!.recommendation.action_class, "REQUEST_OPERATOR");
  assert.equal(burst[0]!.subject.type, "agent");
  assert.equal(burst[0]!.subject.id, "agt_coder", "recommendation targets the exact agent");
});

test("a few patches do not fire", () => {
  const report = run(patches(3, "agt_coder"));
  assert.equal(report.findings.filter((finding) => finding.finding_type === "agent.patch_burst").length, 0);
});

test("a repository boundary violation raises a REQUEST_OPERATOR finding", () => {
  const report = run([boundaryViolated("bnd_1", iso(BASE), "agt_explorer")]);
  const boundary = report.findings.filter((finding) => finding.finding_type === "agent.boundary_violation");
  assert.equal(boundary.length, 1);
  assert.equal(validateFinding(boundary[0]!).ok, true, JSON.stringify(validateFinding(boundary[0]!).issues));
  assert.equal(boundary[0]!.recommendation.action_class, "REQUEST_OPERATOR");
  assert.equal(boundary[0]!.recommendation.playbook, "PB-AGENT-BOUNDARY-01");
});

test("repeated denied actions raise a RECOMMEND_ONLY burst finding", () => {
  const lines = Array.from({ length: 5 }, (_, index) => permissionDenied(`deny_${index}`, iso(BASE + index * 2 * 60_000), "agt_coder"));
  const report = run(lines);
  const denied = report.findings.filter((finding) => finding.finding_type === "agent.denied_action_burst");
  assert.equal(denied.length, 1);
  assert.equal(validateFinding(denied[0]!).ok, true, JSON.stringify(validateFinding(denied[0]!).issues));
  assert.equal(denied[0]!.recommendation.action_class, "RECOMMEND_ONLY");
});

test("Sentinel-Agent stays shadow / recommend-only and cannot apply or promote a patch", () => {
  const report = run([...patches(10, "agt_coder"), boundaryViolated("bnd_x", iso(BASE + 40 * 60_000), "agt_coder")]);
  assert.ok(report.findings.length >= 2);
  const forbidden = new Set<string>(AGENT_FORBIDDEN_ACTIONS);
  assert.ok(forbidden.has("agent.patch.apply") && forbidden.has("agent.patch.promote"));
  for (const finding of report.findings) {
    assert.ok(
      RECOMMEND_CLASSES.has(finding.recommendation.action_class),
      `${finding.finding_type} must be recommend-only, got ${finding.recommendation.action_class}`,
    );
    assert.equal(finding.policy_generated_effect, false);
    // The recommendation is advisory; it never names a forbidden mutate/promote action.
    assert.ok(!finding.recommendation.playbook || !forbidden.has(finding.recommendation.playbook));
  }
});

test("agent detectors are deterministic across runs (Wave 5 exit gate)", () => {
  const lines = patches(10, "agt_coder");
  const first = run(lines);
  const second = run(lines);
  assert.deepEqual(
    second.findings.map((finding) => [finding.finding_type, finding.risk]),
    first.findings.map((finding) => [finding.finding_type, finding.risk]),
  );
});
