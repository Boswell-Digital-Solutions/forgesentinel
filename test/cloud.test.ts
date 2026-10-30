import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildEvent,
  validateFinding,
  type ReplayLine,
  type ShadowReport,
} from "../src/index.js";
import { byService, productionRuntime, testProducers } from "./support/producers.js";

/**
 * Wave 3 (Sentinel-Cloud) completion: implausible travel, session replay, and
 * service-identity misuse. Shadow; historical events only train (learning
 * cutoff); replay is deterministic.
 */

const RECOMMEND_CLASSES = new Set(["OBSERVE", "RECOMMEND_ONLY", "REQUEST_OPERATOR"]);
const PRODUCERS = testProducers("production");
const producers = byService(PRODUCERS);
const identity = producers["identity-service"]!;
const TENANT = { tenant_id: "ten_cloud", account_id: "acct_cloud_1" };

function run(lines: ReplayLine[]): ShadowReport {
  return productionRuntime(PRODUCERS).runShadow(lines);
}

function sessionEvent(
  id: string,
  occurredAt: string,
  region: string,
  opts: { device?: string; sessionId?: string } = {},
): ReplayLine {
  return buildEvent(identity, {
    event_id: `evt_${id}`,
    event_type: "identity.session.created",
    occurred_at: occurredAt,
    tenant: TENANT,
    actor: { actor_type: "user", actor_id: "usr_owner", ...(opts.sessionId ? { session_id: opts.sessionId } : {}) },
    subject: { subject_type: "session", subject_id: `ses_${id}` },
    correlation: { trace_id: `trc_${id}` },
    location: { execution_lane: "cloud", region, country: region.slice(0, 2).toUpperCase() },
    payload: { region, ...(opts.device ? { device_fingerprint: opts.device } : {}) },
  });
}

function apiKeyCreated(id: string, occurredAt: string, actorType: "user" | "service"): ReplayLine {
  const fingerprint = "sha256:" + "a".repeat(64);
  return buildEvent(identity, {
    event_id: `evt_${id}`,
    event_type: "identity.api_key.created",
    occurred_at: occurredAt,
    tenant: TENANT,
    actor: { actor_type: actorType, actor_id: actorType === "service" ? "svc_worker" : "usr_owner", api_key_fingerprint: fingerprint },
    subject: { subject_type: "api_key", subject_id: `key_${id}` },
    correlation: { trace_id: `trc_${id}` },
    location: { execution_lane: "cloud", region: "us-east" },
    payload: { api_key_fingerprint: fingerprint },
  });
}

test("implausible travel: two distant regions in one hour raise a RECOMMEND_ONLY finding", () => {
  const report = run([
    sessionEvent("travel_a", "2026-06-09T12:00:00.000Z", "us-east"),
    sessionEvent("travel_b", "2026-06-09T13:00:00.000Z", "ap-south"),
  ]);
  const travel = report.findings.filter((finding) => finding.finding_type === "cloud.implausible_travel");
  assert.equal(travel.length, 1);
  assert.equal(validateFinding(travel[0]!).ok, true, JSON.stringify(validateFinding(travel[0]!).issues));
  assert.equal(travel[0]!.recommendation.action_class, "RECOMMEND_ONLY");
});

test("plausible travel over many hours does not fire", () => {
  const report = run([
    sessionEvent("slow_a", "2026-06-08T16:00:00.000Z", "us-east"),
    sessionEvent("slow_b", "2026-06-09T12:00:00.000Z", "eu-central"),
  ]);
  assert.equal(report.findings.filter((finding) => finding.finding_type === "cloud.implausible_travel").length, 0);
});

test("session replay: one session id from two devices raises a REQUEST_OPERATOR finding", () => {
  const report = run([
    sessionEvent("repl_a", "2026-06-09T12:00:00.000Z", "us-east", { sessionId: "ses_repl", device: "dev_known_aa" }),
    sessionEvent("repl_b", "2026-06-09T12:05:00.000Z", "us-east", { sessionId: "ses_repl", device: "dev_attacker_bb" }),
  ]);
  const replay = report.findings.filter((finding) => finding.finding_type === "cloud.session_replay");
  assert.equal(replay.length, 1);
  assert.equal(validateFinding(replay[0]!).ok, true, JSON.stringify(validateFinding(replay[0]!).issues));
  assert.equal(replay[0]!.recommendation.action_class, "REQUEST_OPERATOR");
  assert.equal(replay[0]!.recommendation.playbook, "PB-CLOUD-SESSION-01");
});

test("a session reused from the same device does not fire", () => {
  const report = run([
    sessionEvent("same_a", "2026-06-09T12:00:00.000Z", "us-east", { sessionId: "ses_same", device: "dev_known_aa" }),
    sessionEvent("same_b", "2026-06-09T12:05:00.000Z", "us-east", { sessionId: "ses_same", device: "dev_known_aa" }),
  ]);
  assert.equal(report.findings.filter((finding) => finding.finding_type === "cloud.session_replay").length, 0);
});

test("service identity misuse: a service identity creating an API key raises a REQUEST_OPERATOR finding", () => {
  const report = run([apiKeyCreated("svc_key", "2026-06-09T12:00:00.000Z", "service")]);
  const misuse = report.findings.filter((finding) => finding.finding_type === "cloud.service_identity_misuse");
  assert.equal(misuse.length, 1);
  assert.equal(validateFinding(misuse[0]!).ok, true, JSON.stringify(validateFinding(misuse[0]!).issues));
  assert.equal(misuse[0]!.recommendation.action_class, "REQUEST_OPERATOR");
  assert.equal(misuse[0]!.recommendation.playbook, "PB-CLOUD-SVCID-01");
});

test("a user creating an API key is not service-identity misuse", () => {
  const report = run([apiKeyCreated("usr_key", "2026-06-09T12:00:00.000Z", "user")]);
  assert.equal(report.findings.filter((finding) => finding.finding_type === "cloud.service_identity_misuse").length, 0);
});

test("Wave 3 cloud detectors stay shadow / recommend-only", () => {
  const report = run([
    sessionEvent("rc_a", "2026-06-09T12:00:00.000Z", "us-east", { sessionId: "ses_rc", device: "dev_aa" }),
    sessionEvent("rc_b", "2026-06-09T13:00:00.000Z", "ap-south", { sessionId: "ses_rc", device: "dev_bb" }),
    apiKeyCreated("rc_key", "2026-06-09T13:10:00.000Z", "service"),
  ]);
  assert.ok(report.findings.length >= 3);
  for (const finding of report.findings) {
    assert.ok(
      RECOMMEND_CLASSES.has(finding.recommendation.action_class),
      `${finding.finding_type} must be recommend-only, got ${finding.recommendation.action_class}`,
    );
    assert.equal(finding.policy_generated_effect, false);
  }
});

test("cloud detectors are deterministic across runs (Wave 3 exit gate)", () => {
  const lines = [
    sessionEvent("det_a", "2026-06-09T12:00:00.000Z", "us-east", { sessionId: "ses_det", device: "dev_aa" }),
    sessionEvent("det_b", "2026-06-09T13:00:00.000Z", "ap-south", { sessionId: "ses_det", device: "dev_bb" }),
  ];
  const first = run(lines);
  const second = run(lines);
  assert.deepEqual(
    second.findings.map((finding) => [finding.finding_type, finding.risk]),
    first.findings.map((finding) => [finding.finding_type, finding.risk]),
  );
});
