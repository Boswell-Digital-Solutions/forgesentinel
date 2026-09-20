import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AUTHORIZATION_INDEX_MAX_AGE_MS,
  AuthorizationIndex,
  CLOUD_SECURITY_AUTHORIZATION_SCHEMA,
  CLOUD_SECURITY_OUTCOME_SCHEMA,
  EXECUTION_FAILURE_BURST_THRESHOLD,
  OutcomeWatchdog,
  emptyOutcomeWatchdogState,
  validateCloudSecurityFinding,
  type CloudSecurityAuthorization,
  type CloudSecurityOutcome,
} from "../src/index.js";

const TENANT = "ten_demo";
const PRINCIPAL = "usr_watched";
const BASE = "2026-09-20T12:00:00.000Z";
const SUBJECT = { tenantId: TENANT, principalId: PRINCIPAL };

function outcomeAt(iso: string, overrides: Partial<CloudSecurityOutcome> = {}): CloudSecurityOutcome {
  return {
    schema_version: CLOUD_SECURITY_OUTCOME_SCHEMA,
    outcome_id: `out_${iso}`,
    attempt_id: `att_${iso}`,
    authorization_id: "auth_0",
    correlation_id: `cor_${iso}`,
    created_at: iso,
    execution_state: "failed",
    ...overrides,
  };
}

function authorizationAt(iso: string, id: string, overrides: Partial<CloudSecurityAuthorization> = {}): CloudSecurityAuthorization {
  return {
    schema_version: CLOUD_SECURITY_AUTHORIZATION_SCHEMA,
    authorization_id: id,
    attempt_id: `att_${id}`,
    correlation_id: `cor_${id}`,
    created_at: iso,
    principal_id: PRINCIPAL,
    tenant_id: TENANT,
    authorization_state: "issued",
    ...overrides,
  };
}

function minutesAfter(baseIso: string, minutes: number): string {
  return new Date(Date.parse(baseIso) + minutes * 60_000).toISOString();
}

test("execution-failure burst stays quiet below threshold, fires once it crosses", () => {
  const watchdog = new OutcomeWatchdog();
  let lastFindings: ReturnType<OutcomeWatchdog["observe"]> = [];
  for (let i = 0; i < EXECUTION_FAILURE_BURST_THRESHOLD; i++) {
    const at = minutesAfter(BASE, i);
    lastFindings = watchdog.observe(outcomeAt(at, { outcome_id: `out_${i}` }), SUBJECT, at);
    if (i < EXECUTION_FAILURE_BURST_THRESHOLD - 1) {
      assert.equal(lastFindings.length, 0, `no finding before threshold (i=${i})`);
    }
  }
  assert.equal(lastFindings.length, 1);
  const finding = lastFindings[0]!;
  assert.equal(finding.detector, "execution_failure_burst");
  assert.equal(finding.scope.tenant_id, TENANT);
  assert.equal(finding.scope.principal_id, PRINCIPAL);
  assert.equal(validateCloudSecurityFinding(finding).ok, true, JSON.stringify(validateCloudSecurityFinding(finding).issues));
});

test("non-failed executions never count toward the failure window", () => {
  const watchdog = new OutcomeWatchdog();
  const findings = [];
  for (let i = 0; i < EXECUTION_FAILURE_BURST_THRESHOLD + 5; i++) {
    const at = minutesAfter(BASE, i);
    findings.push(...watchdog.observe(outcomeAt(at, { outcome_id: `out_${i}`, execution_state: "completed" }), SUBJECT, at));
  }
  assert.equal(findings.length, 0);
});

test("policy_generated_effect outcomes are excluded entirely (ADR-022 self-reinforcement guard)", () => {
  const watchdog = new OutcomeWatchdog();
  let findings: ReturnType<OutcomeWatchdog["observe"]> = [];
  for (let i = 0; i < EXECUTION_FAILURE_BURST_THRESHOLD + 2; i++) {
    const at = minutesAfter(BASE, i);
    findings = watchdog.observe(
      outcomeAt(at, { outcome_id: `out_${i}`, control_lineage: { control_origin: "sentinel", control_id: "ctl_1", policy_generated_effect: true } }),
      SUBJECT,
      at,
    );
  }
  assert.equal(findings.length, 0);
});

test("durable state exports and reimports to identical future behavior (crash-restart safety)", () => {
  const watchdog = new OutcomeWatchdog();
  for (let i = 0; i < EXECUTION_FAILURE_BURST_THRESHOLD - 1; i++) {
    const at = minutesAfter(BASE, i);
    watchdog.observe(outcomeAt(at, { outcome_id: `out_${i}` }), SUBJECT, at);
  }
  const exported = watchdog.export();
  assert.notDeepEqual(exported, emptyOutcomeWatchdogState());

  const reloaded = new OutcomeWatchdog(JSON.parse(JSON.stringify(exported)));
  const at = minutesAfter(BASE, EXECUTION_FAILURE_BURST_THRESHOLD - 1);
  const findings = reloaded.observe(outcomeAt(at, { outcome_id: "out_final" }), SUBJECT, at);
  assert.equal(findings.length, 1, "the restarted watchdog remembers the partial burst and completes it");
});

test("AuthorizationIndex: an observed authorization resolves an outcome's subject", () => {
  const index = new AuthorizationIndex();
  index.record(authorizationAt(BASE, "auth_0"), Date.parse(BASE));
  const resolved = index.resolve("auth_0");
  assert.deepEqual(resolved, { tenantId: TENANT, principalId: PRINCIPAL });
});

test("AuthorizationIndex: an unseen authorization resolves to undefined, never guessed", () => {
  const index = new AuthorizationIndex();
  assert.equal(index.resolve("auth_never_seen"), undefined);
});

test("AuthorizationIndex: entries older than the max age are pruned", () => {
  const index = new AuthorizationIndex();
  const seenAtMs = Date.parse(BASE);
  index.record(authorizationAt(BASE, "auth_0"), seenAtMs);
  index.prune(seenAtMs + AUTHORIZATION_INDEX_MAX_AGE_MS + 1);
  assert.equal(index.resolve("auth_0"), undefined, "an authorization with no timely outcome does not linger forever");
});

test("AuthorizationIndex: entries within the max age survive a prune", () => {
  const index = new AuthorizationIndex();
  const seenAtMs = Date.parse(BASE);
  index.record(authorizationAt(BASE, "auth_0"), seenAtMs);
  index.prune(seenAtMs + AUTHORIZATION_INDEX_MAX_AGE_MS - 1);
  assert.deepEqual(index.resolve("auth_0"), { tenantId: TENANT, principalId: PRINCIPAL });
});
