import { test } from "node:test";
import assert from "node:assert/strict";
import {
  APPROVAL_PENDING_BURST_THRESHOLD,
  CLOUD_SECURITY_AUTHORIZATION_SCHEMA,
  AuthorizationWatchdog,
  emptyAuthorizationWatchdogState,
  validateCloudSecurityFinding,
  type CloudSecurityAuthorization,
} from "../src/index.js";

const TENANT = "ten_demo";
const PRINCIPAL = "usr_watched";
const BASE = "2026-09-20T12:00:00.000Z";

function authorizationAt(iso: string, overrides: Partial<CloudSecurityAuthorization> = {}): CloudSecurityAuthorization {
  return {
    schema_version: CLOUD_SECURITY_AUTHORIZATION_SCHEMA,
    authorization_id: `auth_${iso}`,
    attempt_id: `att_${iso}`,
    correlation_id: `cor_${iso}`,
    created_at: iso,
    principal_id: PRINCIPAL,
    tenant_id: TENANT,
    authorization_state: "approval_pending",
    ...overrides,
  };
}

function minutesAfter(baseIso: string, minutes: number): string {
  return new Date(Date.parse(baseIso) + minutes * 60_000).toISOString();
}

test("approval-pending burst stays quiet below threshold, fires once it crosses", () => {
  const watchdog = new AuthorizationWatchdog();
  let lastFindings: ReturnType<AuthorizationWatchdog["observe"]> = [];
  for (let i = 0; i < APPROVAL_PENDING_BURST_THRESHOLD; i++) {
    const at = minutesAfter(BASE, i);
    lastFindings = watchdog.observe(authorizationAt(at, { authorization_id: `auth_${i}` }), at);
    if (i < APPROVAL_PENDING_BURST_THRESHOLD - 1) {
      assert.equal(lastFindings.length, 0, `no finding before threshold (i=${i})`);
    }
  }
  assert.equal(lastFindings.length, 1, "exactly one finding the moment the threshold is crossed");
  const finding = lastFindings[0]!;
  assert.equal(finding.detector, "approval_pending_burst");
  assert.equal(finding.scope.tenant_id, TENANT);
  assert.equal(finding.scope.principal_id, PRINCIPAL);
  assert.equal(finding.metrics.observed, APPROVAL_PENDING_BURST_THRESHOLD);
  assert.equal(validateCloudSecurityFinding(finding).ok, true, JSON.stringify(validateCloudSecurityFinding(finding).issues));
});

test("issued and denied authorizations never count toward the approval-pending window", () => {
  const watchdog = new AuthorizationWatchdog();
  const findings = [];
  for (let i = 0; i < APPROVAL_PENDING_BURST_THRESHOLD + 5; i++) {
    const at = minutesAfter(BASE, i);
    findings.push(...watchdog.observe(authorizationAt(at, { authorization_id: `auth_${i}`, authorization_state: "issued" }), at));
  }
  assert.equal(findings.length, 0);
});

test("the same burst is never re-emitted (idempotent within a bucket)", () => {
  const watchdog = new AuthorizationWatchdog();
  const findings = [];
  for (let i = 0; i < APPROVAL_PENDING_BURST_THRESHOLD + 3; i++) {
    const at = minutesAfter(BASE, i);
    findings.push(...watchdog.observe(authorizationAt(at, { authorization_id: `auth_${i}` }), at));
  }
  assert.equal(findings.length, 1);
});

test("policy_generated_effect authorizations are excluded entirely (ADR-022 self-reinforcement guard)", () => {
  const watchdog = new AuthorizationWatchdog();
  let findings: ReturnType<AuthorizationWatchdog["observe"]> = [];
  for (let i = 0; i < APPROVAL_PENDING_BURST_THRESHOLD + 2; i++) {
    const at = minutesAfter(BASE, i);
    findings = watchdog.observe(
      authorizationAt(at, {
        authorization_id: `auth_${i}`,
        control_lineage: { control_origin: "sentinel", control_id: "ctl_1", policy_generated_effect: true },
      }),
      at,
    );
  }
  assert.equal(findings.length, 0);
});

test("durable state exports and reimports to identical future behavior (crash-restart safety)", () => {
  const watchdog = new AuthorizationWatchdog();
  for (let i = 0; i < APPROVAL_PENDING_BURST_THRESHOLD - 1; i++) {
    const at = minutesAfter(BASE, i);
    watchdog.observe(authorizationAt(at, { authorization_id: `auth_${i}` }), at);
  }
  const exported = watchdog.export();
  assert.notDeepEqual(exported, emptyAuthorizationWatchdogState());

  const reloaded = new AuthorizationWatchdog(JSON.parse(JSON.stringify(exported)));
  const at = minutesAfter(BASE, APPROVAL_PENDING_BURST_THRESHOLD - 1);
  const findings = reloaded.observe(authorizationAt(at, { authorization_id: "auth_final" }), at);
  assert.equal(findings.length, 1, "the restarted watchdog remembers the partial burst and completes it");
});
