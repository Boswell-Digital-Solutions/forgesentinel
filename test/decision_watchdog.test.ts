import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CLOUD_SECURITY_DECISION_SCHEMA,
  DENIAL_STREAK_THRESHOLD,
  QUOTA_EXCEEDED_BURST_THRESHOLD,
  DecisionWatchdog,
  emptyWatchdogState,
  validateCloudSecurityFinding,
  type CloudSecurityDecision,
} from "../src/index.js";

const TENANT = "ten_demo";
const PRINCIPAL = "usr_watched";

function decisionAt(iso: string, overrides: Partial<CloudSecurityDecision> = {}): CloudSecurityDecision {
  return {
    schema_version: CLOUD_SECURITY_DECISION_SCHEMA,
    decision_id: `dec_${iso}`,
    attempt_id: `att_${iso}`,
    correlation_id: `cor_${iso}`,
    occurred_at: iso,
    principal: { principal_id: PRINCIPAL, tenant_id: TENANT },
    decision: "block",
    quota_status: "not_applicable",
    reason_codes: [],
    ...overrides,
  };
}

function minutesAfter(baseIso: string, minutes: number): string {
  return new Date(Date.parse(baseIso) + minutes * 60_000).toISOString();
}

const BASE = "2026-09-20T12:00:00.000Z";

test("denial streak stays quiet below threshold, fires once it crosses (deterministic, evidence-backed)", () => {
  const watchdog = new DecisionWatchdog();
  let lastFindings: ReturnType<DecisionWatchdog["observe"]> = [];
  for (let i = 0; i < DENIAL_STREAK_THRESHOLD; i++) {
    const at = minutesAfter(BASE, i);
    lastFindings = watchdog.observe(decisionAt(at, { decision_id: `dec_${i}` }), at);
    if (i < DENIAL_STREAK_THRESHOLD - 1) {
      assert.equal(lastFindings.length, 0, `no finding before threshold (i=${i})`);
    }
  }
  assert.equal(lastFindings.length, 1, "exactly one finding the moment the threshold is crossed");
  const finding = lastFindings[0]!;
  assert.equal(finding.detector, "denial_streak");
  assert.equal(finding.scope.tenant_id, TENANT);
  assert.equal(finding.scope.principal_id, PRINCIPAL);
  assert.equal(finding.metrics.observed, DENIAL_STREAK_THRESHOLD);
  assert.equal(finding.evidence_refs.length, DENIAL_STREAK_THRESHOLD, "one evidence ref per contributing decision");
  assert.equal(validateCloudSecurityFinding(finding).ok, true, JSON.stringify(validateCloudSecurityFinding(finding).issues));
});

test("the same burst is never re-emitted (idempotent within a bucket)", () => {
  const watchdog = new DecisionWatchdog();
  const findings = [];
  for (let i = 0; i < DENIAL_STREAK_THRESHOLD + 3; i++) {
    const at = minutesAfter(BASE, i);
    findings.push(...watchdog.observe(decisionAt(at, { decision_id: `dec_${i}` }), at));
  }
  assert.equal(findings.length, 1, "crossing the threshold once, then staying above it, emits exactly one finding for that bucket");
});

test("quota-exceeded burst fires independently of the denial-streak detector", () => {
  const watchdog = new DecisionWatchdog();
  let lastFindings: ReturnType<DecisionWatchdog["observe"]> = [];
  for (let i = 0; i < QUOTA_EXCEEDED_BURST_THRESHOLD; i++) {
    const at = minutesAfter(BASE, i);
    lastFindings = watchdog.observe(decisionAt(at, { decision_id: `dec_q_${i}`, decision: "allow", quota_status: "exceeded" }), at);
  }
  assert.equal(lastFindings.length, 1);
  assert.equal(lastFindings[0]!.detector, "quota_exceeded_burst");
});

test("decisions outside the window drop off (sliding window, not a lifetime counter)", () => {
  const watchdog = new DecisionWatchdog();
  for (let i = 0; i < DENIAL_STREAK_THRESHOLD - 1; i++) {
    const at = minutesAfter(BASE, i);
    watchdog.observe(decisionAt(at, { decision_id: `dec_${i}` }), at);
  }
  // Far outside the 15-minute window: the earlier decisions must not count toward this one.
  const farLater = minutesAfter(BASE, 120);
  const findings = watchdog.observe(decisionAt(farLater, { decision_id: "dec_far" }), farLater);
  assert.equal(findings.length, 0, "the window reset; one decision alone never crosses the threshold");
});

test("policy_generated_effect decisions are excluded entirely (ADR-022 self-reinforcement guard)", () => {
  const watchdog = new DecisionWatchdog();
  let findings: ReturnType<DecisionWatchdog["observe"]> = [];
  for (let i = 0; i < DENIAL_STREAK_THRESHOLD + 2; i++) {
    const at = minutesAfter(BASE, i);
    findings = watchdog.observe(
      decisionAt(at, {
        decision_id: `dec_${i}`,
        control_lineage: { control_origin: "sentinel", control_id: "ctl_1", policy_generated_effect: true },
      }),
      at,
    );
  }
  assert.equal(findings.length, 0, "Sentinel's own past enforcement never counts as fresh evidence of an anomaly");
});

test("durable state exports and reimports to identical future behavior (crash-restart safety)", () => {
  const watchdog = new DecisionWatchdog();
  for (let i = 0; i < DENIAL_STREAK_THRESHOLD - 1; i++) {
    const at = minutesAfter(BASE, i);
    watchdog.observe(decisionAt(at, { decision_id: `dec_${i}` }), at);
  }
  const exported = watchdog.export();
  assert.notDeepEqual(exported, emptyWatchdogState(), "state actually captured the partial streak");

  // Simulate a process restart: a brand-new watchdog loaded from the saved state.
  const reloaded = new DecisionWatchdog(JSON.parse(JSON.stringify(exported)));
  const at = minutesAfter(BASE, DENIAL_STREAK_THRESHOLD - 1);
  const findings = reloaded.observe(decisionAt(at, { decision_id: "dec_final" }), at);
  assert.equal(findings.length, 1, "the restarted watchdog remembers the partial streak and completes it");
});
