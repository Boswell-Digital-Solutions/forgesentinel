import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { validateForgeCommandObservationReturn, type ForgeCommandMissionAdmission } from "../src/integration/forge-command-adapter.js";
import { runSyntheticForgeCommandHarness } from "../src/integration/synthetic-forge-command-harness.js";
import type { ObservationRule } from "../src/integration/deterministic-observation-pipeline.js";

const root = mkdtempSync(join(tmpdir(), "forgesentinel-cp4e-"));
mkdirSync(join(root, "docs", "sentinel"), { recursive: true });
writeFileSync(join(root, "docs", "sentinel", "synthetic.txt"), "security-ok truth-ok accuracy-ok\n", "utf8");
after(() => rmSync(root, { recursive: true, force: true }));

const SHA = "1".repeat(40);
const TREE = "2".repeat(40);
const now = "2026-09-14T12:01:00.000Z";
const admission = (): ForgeCommandMissionAdmission => ({
  schemaVersion: "forgesentinel.forge-command-adapter.mission.v1",
  missionId: "mis_cp4e_001",
  runId: "run_cp4e_001",
  intentId: "int_cp4e_001",
  authorizationId: "auth_cp4e_001",
  issuerId: "forge_command.synthetic",
  nonce: "nonce_cp4e_001",
  issuedAt: "2026-09-14T12:00:00.000Z",
  notBefore: "2026-09-14T12:00:00.000Z",
  expiresAt: "2026-09-14T12:05:00.000Z",
  freshnessDeadline: "2026-09-14T12:04:00.000Z",
  target: { registryId: "reg_forgesentinel", repository: "Boswell-Digital-Solutions/forgesentinel", registryState: "admitted", commitSha: SHA, treeSha: TREE },
  procedure: { id: "eas_governed_observation", major: 1 },
  lanes: ["security", "truthfulness", "accuracy"],
  caps: { wallTimeMs: 60_000, evidenceBytes: 2_097_152, fileCount: 250, readOps: 300, retries: 1 },
  identities: { analyzerId: "forgesentinel.analyzer.v1", analyzerStateToken: "state_analyzer_cp4e", verifierId: "hephaestus.verifier.v1", verifierStateToken: "state_verifier_cp4e" },
  redactionPolicyId: "redaction_cp4e_v1",
  stop: { channelId: "fc_stop_cp4e", state: "active" },
});
const rules: ObservationRule[] = [
  { ruleId: "sec", lane: "security", severity: "S1", surface: "synthetic", evidencePath: "docs/sentinel/synthetic.txt", needle: "security-ok", expected: "present", oracleExpectedClassification: "SUPPORTED" },
  { ruleId: "tru", lane: "truthfulness", severity: "S2", surface: "synthetic", evidencePath: "docs/sentinel/synthetic.txt", needle: "truth-ok", expected: "present", oracleExpectedClassification: "SUPPORTED" },
  { ruleId: "acc", lane: "accuracy", severity: "S2", surface: "synthetic", evidencePath: "docs/sentinel/synthetic.txt", needle: "accuracy-ok", expected: "present", oracleExpectedClassification: "SUPPORTED" },
];
const execute = (overrides: Record<string, unknown> = {}) => runSyntheticForgeCommandHarness({
  admission: admission(),
  root,
  manifest: { paths: ["docs/sentinel/synthetic.txt"] },
  rules,
  dependencies: { now: () => now, control: () => "active", revision: () => ({ commitSha: SHA, treeSha: TREE }) },
  ...overrides,
});

test("healthy synthetic mission is correlated and hash-bound", () => {
  const result = execute();
  assert.equal(result.accepted, true);
  if (!result.accepted) return;
  assert.equal(result.pipeline.posture, "HEALTHY");
  assert.equal(result.observationReturn.missionId, admission().missionId);
  assert.equal(result.observationReturn.commitSha, SHA);
  assert.equal(result.observationReturn.treeSha, TREE);
  assert.equal(result.observationReturn.acceptedEffects, 0);
  assert.equal(validateForgeCommandObservationReturn(result.observationReturn).ok, true);
});
test("identical mission replay is byte-stable", () => assert.deepEqual(execute(), execute()));
test("seen admission is rejected as replay", () => {
  const first = execute();
  assert.equal(first.accepted, true);
  if (!first.accepted) return;
  const replay = execute({ seenAdmissionIds: new Set([first.admissionId]) });
  assert.equal(replay.accepted, false);
  if (!replay.accepted) assert.ok(replay.issues.some((item) => item.code === "replay"));
});
test("stale authority is rejected before collection", () => {
  const stale = { ...admission(), freshnessDeadline: now };
  const result = execute({ admission: stale });
  assert.equal(result.accepted, false);
  if (!result.accepted) assert.ok(result.issues.some((item) => item.code === "stale"));
});
test("revoked stop is rejected before collection", () => {
  const revoked = { ...admission(), stop: { ...admission().stop, state: "revoked" } };
  const result = execute({ admission: revoked });
  assert.equal(result.accepted, false);
});
test("unknown procedure major is rejected", () => {
  const substituted = { ...admission(), procedure: { id: "eas_governed_observation", major: 2 } };
  assert.equal(execute({ admission: substituted }).accepted, false);
});
test("target revision mismatch halts without analysis", () => {
  const result = execute({ dependencies: { now: () => now, control: () => "active", revision: () => ({ commitSha: "3".repeat(40), treeSha: TREE }) } });
  assert.equal(result.accepted, true);
  if (!result.accepted) return;
  assert.equal(result.collection.state, "HALTED");
  assert.equal(result.pipeline.posture, "BLOCKED");
  assert.equal(result.observationReturn.state, "HALTED");
});
test("lost control channel fails closed", () => {
  const result = execute({ dependencies: { now: () => now, control: () => "channel_lost", revision: () => ({ commitSha: SHA, treeSha: TREE }) } });
  assert.equal(result.accepted, true);
  if (result.accepted) assert.equal(result.observationReturn.state, "FAILED");
});
test("missing evidence cannot produce health", () => {
  const result = execute({ manifest: { paths: ["docs/sentinel/missing.txt"] } });
  assert.equal(result.accepted, true);
  if (!result.accepted) return;
  assert.notEqual(result.pipeline.posture, "HEALTHY");
  assert.notEqual(result.observationReturn.reason, "healthy");
});
test("unavailable verifier blocks without fallback", () => {
  const result = execute({ verifierAvailable: false });
  assert.equal(result.accepted, true);
  if (result.accepted) assert.equal(result.observationReturn.state, "BLOCKED");
});
test("verifier disagreement remains incomplete", () => {
  const disagreeing = rules.map((rule, index) => index === 0 ? { ...rule, oracleExpectedClassification: "FINDING" as const } : rule);
  const result = execute({ rules: disagreeing });
  assert.equal(result.accepted, true);
  if (!result.accepted) return;
  assert.equal(result.pipeline.posture, "INCOMPLETE");
  assert.ok(result.observationReturn.disagreementCount > 0);
});
test("unknown mission major and identity collision fail admission", () => {
  assert.equal(execute({ admission: { ...admission(), schemaVersion: "forgesentinel.forge-command-adapter.mission.v2" } }).accepted, false);
  const collided = { ...admission(), identities: { ...admission().identities, verifierId: admission().identities.analyzerId } };
  assert.equal(execute({ admission: collided }).accepted, false);
});
