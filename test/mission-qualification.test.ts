import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { compareReplay, qualifyMission, type InventoryTarget, type MissionGrant, type MissionInput, type MissionOperation } from "../src/mission/qualification.js";

const base = JSON.parse(readFileSync("fixtures/mission/AUTH-FOUNDATION-001.json", "utf8")) as MissionInput;

function input(overrides: Partial<MissionInput> = {}, grantOverrides: Partial<MissionGrant> = {}): MissionInput {
  assert.ok(base.grant !== undefined);
  return { ...base, ...overrides, grant: { ...base.grant, ...grantOverrides } };
}

function withoutGrant(): MissionInput {
  const { grant: _grant, ...rest } = base;
  return rest;
}

function target(overrides: Partial<InventoryTarget> = {}): InventoryTarget {
  return { targetId: "syn_repo_alpha", state: "admitted", revision: "syn_revision_a", freshUntil: "2026-09-15T00:00:00.000Z", ...overrides };
}

function operation(overrides: Partial<MissionOperation> = {}): MissionOperation {
  return { operationId: "syn_op", targetId: "syn_repo_alpha", kind: "read", at: "2026-09-14T12:00:01.000Z", elapsedMs: 10, evidenceBytes: 10, ...overrides };
}

test("AUTH-001 valid authority completes exact scope", () => {
  const result = qualifyMission(input());
  assert.equal(result.state, "COMPLETED");
  assert.deepEqual(result.coverage.inspectedTargets, ["syn_repo_alpha"]);
});

test("AUTH-002 missing authority blocks before collection", () => {
  const result = qualifyMission(withoutGrant());
  assert.equal(result.state, "BLOCKED");
  assert.equal(result.reason, "missing_authority");
  assert.equal(result.receipts[0]?.usage.toolCalls, 0);
});

test("AUTH-003 expired authority prevents start", () => {
  assert.equal(qualifyMission(input({ now: "2026-09-14T14:00:00.000Z" })).state, "EXPIRED");
});

test("AUTH-004 authority expiry mid-stage stops before operation", () => {
  const result = qualifyMission(input({ operations: [operation({ at: "2026-09-14T13:00:00.000Z" })] }));
  assert.equal(result.reason, "authorization_expired_mid_stage");
  assert.equal(result.receipts[0]?.usage.toolCalls, 0);
});

test("AUTH-005 revoked authority halts", () => {
  assert.equal(qualifyMission(input({}, { revoked: true })).reason, "authorization_revoked");
});

test("AUTH-006 scope mismatch blocks unlisted target", () => {
  const result = qualifyMission(input({ operations: [operation({ targetId: "syn_repo_outside" })] }));
  assert.equal(result.reason, "scope_mismatch");
});

test("AUTH-008 kill switch halts with zero work", () => {
  const result = qualifyMission(input({ control: "kill" }));
  assert.equal(result.state, "HALTED");
  assert.equal(result.receipts[0]?.usage.toolCalls, 0);
});

test("AUTH-010 restart creates new mission identity and parent lineage", () => {
  const result = qualifyMission(input({ restartOf: "syn_prior_receipt" }, { missionId: "syn_mission_restart" }));
  assert.equal(result.receipts[0]?.missionId, "syn_mission_restart");
  assert.equal(result.receipts[0]?.parentReceiptId, "syn_prior_receipt");
});

test("INV-001 admitted target is inspected", () => {
  assert.deepEqual(qualifyMission(input()).coverage.inspectedTargets, ["syn_repo_alpha"]);
});

test("INV-002 unknown target remains uninspected and visible", () => {
  const result = qualifyMission(input({ inventory: [] }));
  assert.deepEqual(result.coverage.inspectedTargets, []);
  assert.equal(result.coverage.gaps[0]?.reason, "unknown_target");
});

test("INV-003 authority conflict blocks target inspection", () => {
  const result = qualifyMission(input({ inventory: [target({ state: "conflicted" })] }));
  assert.equal(result.coverage.gaps[0]?.reason, "conflicted_target");
});

test("INV-004 stale inventory blocks target inspection", () => {
  const result = qualifyMission(input({ inventory: [target({ freshUntil: "2026-09-14T12:00:00.000Z" })] }));
  assert.equal(result.coverage.gaps[0]?.reason, "stale_inventory");
});

test("INV-005 revision drift blocks target inspection", () => {
  const result = qualifyMission(input({ inventory: [target({ revision: "syn_revision_other" })] }));
  assert.equal(result.coverage.gaps[0]?.reason, "revision_drift");
});

test("COV-001 complete collection reports complete coverage", () => {
  assert.equal(qualifyMission(input()).coverage.gaps.length, 0);
});

test("COV-002 partial collection exposes required missing target", () => {
  const result = qualifyMission(input({ inventory: [target(), target({ targetId: "syn_repo_beta" })] }, { targets: ["syn_repo_alpha", "syn_repo_beta"] }));
  assert.equal(result.coverage.gaps.some((gap) => gap.targetId === "syn_repo_beta"), true);
  assert.equal(result.reason, "mission_complete_with_coverage_gaps");
});

test("COV-003 rejected access remains a coverage gap", () => {
  const result = qualifyMission(input({ operations: [operation({ failureClass: "authority" })] }));
  assert.equal(result.state, "FAILED");
  assert.equal(result.coverage.gaps[0]?.reason, "authority_failure");
});

test("COV-004 collector failure never becomes health pass", () => {
  const result = qualifyMission(input({ operations: [] }));
  assert.equal(result.reason, "mission_complete_with_coverage_gaps");
  assert.equal(result.coverage.gaps[0]?.reason, "collector_failure");
  assert.equal(JSON.stringify(result).includes('"PASS"'), false);
});

test("CAP-001 wall-time cap stops before overshoot", () => {
  const result = qualifyMission(input({ operations: [operation({ elapsedMs: 1001 })] }));
  assert.equal(result.reason, "wall_time_cap");
  assert.equal(result.receipts[0]?.usage.elapsedMs, 0);
});

test("CAP-002 evidence-byte cap stops before overshoot", () => {
  const result = qualifyMission(input({ operations: [operation({ evidenceBytes: 1025 })] }));
  assert.equal(result.reason, "evidence_byte_cap");
  assert.equal(result.receipts[0]?.usage.evidenceBytes, 0);
});

test("CAP-003 tool-call cap stops before overshoot", () => {
  const ops = [operation({ operationId: "syn_1" }), operation({ operationId: "syn_2" }), operation({ operationId: "syn_3" })];
  const result = qualifyMission(input({ operations: ops }));
  assert.equal(result.reason, "tool_call_cap");
  assert.equal(result.receipts[0]?.usage.toolCalls, 2);
});

test("CAP-004 transient retry is bounded and receipted", () => {
  const result = qualifyMission(input({ operations: [operation({ failureClass: "transient" }), operation()] }));
  assert.equal(result.state, "COMPLETED");
  assert.equal(result.receipts[0]?.usage.retries, 1);
});

test("CAP-005 non-retryable integrity failure fails once", () => {
  const result = qualifyMission(input({ operations: [operation({ failureClass: "integrity" })] }));
  assert.equal(result.state, "FAILED");
  assert.equal(result.receipts[0]?.usage.retries, 0);
  assert.equal(result.receipts[0]?.usage.toolCalls, 1);
});

test("RCP-001 completed mission has content-hashed identity receipt", () => {
  const receipt = qualifyMission(input()).receipts[0];
  assert.match(receipt?.receiptId ?? "", /^mrcpt_[0-9a-f]{24}$/);
  assert.match(receipt?.integrity.hash ?? "", /^sha256:[0-9a-f]{64}$/);
});

test("RCP-002 blocked mission retains terminal evidence", () => {
  const result = qualifyMission(withoutGrant());
  assert.equal(result.receipts[0]?.state, "BLOCKED");
  assert.equal(result.receipts[0]?.reason, "missing_authority");
});

test("RCP-003 halted expired and failed states have receipts", () => {
  const states = [qualifyMission(input({ control: "stop" })), qualifyMission(input({ now: "2026-09-14T14:00:00.000Z" })), qualifyMission(input({ operations: [operation({ failureClass: "schema" })] }))];
  assert.deepEqual(states.map((item) => item.receipts[0]?.state), ["HALTED", "EXPIRED", "FAILED"]);
});

test("RCP-004 paused mission produces checkpoint not completion", () => {
  const result = qualifyMission(input({ control: "pause" }));
  assert.equal(result.state, "PAUSED");
  assert.notEqual(result.state, "COMPLETED");
});

test("ZERO-001 write attempt is intercepted with zero accepted effects", () => {
  const result = qualifyMission(input({ operations: [operation({ kind: "write" })] }));
  assert.equal(result.reason, "intercepted_write_effect");
  assert.equal(result.acceptedEffects, 0);
});

test("ZERO-002 network attempt is intercepted with zero accepted effects", () => {
  const result = qualifyMission(input({ operations: [operation({ kind: "network" })] }));
  assert.equal(result.reason, "intercepted_network_effect");
  assert.equal(result.acceptedEffects, 0);
});

test("RCP-004 identical deterministic replay agrees semantically and by digest", () => {
  const replay = compareReplay(input(), input());
  assert.equal(replay.identical, true);
  assert.equal(replay.first.receipts[0]?.integrity.hash, replay.second.receipts[0]?.integrity.hash);
});

test("RCP-005 procedure or source substitution rejects replay identity", () => {
  const replay = compareReplay(input(), input({}, { procedureId: "syn_procedure_2" }));
  assert.equal(replay.identical, false);
  assert.equal(replay.reason, "source_or_procedure_substitution");
});
