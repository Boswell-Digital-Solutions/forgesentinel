import { test } from "node:test";
import assert from "node:assert/strict";
import { CLOUD_SECURITY_OUTCOME_SCHEMA, validateCloudSecurityOutcome, type CloudSecurityOutcome } from "../src/index.js";

const NOW = "2026-09-20T12:00:00.000Z";

function outcome(overrides: Partial<CloudSecurityOutcome> = {}): CloudSecurityOutcome {
  return {
    schema_version: CLOUD_SECURITY_OUTCOME_SCHEMA,
    outcome_id: "out_001",
    attempt_id: "att_001",
    authorization_id: "auth_001",
    correlation_id: "cor_001",
    created_at: NOW,
    execution_state: "completed",
    ...overrides,
  };
}

test("a well-formed outcome validates", () => {
  const result = validateCloudSecurityOutcome(outcome());
  assert.equal(result.ok, true, JSON.stringify(result.issues));
});

test("an outcome without authorization_id is rejected -- it is the only way back to a subject", () => {
  const untied = outcome();
  // @ts-expect-error -- deliberately malformed for the test
  delete untied.authorization_id;
  const result = validateCloudSecurityOutcome(untied);
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.path === "authorization_id"));
});

test("an unknown schema_version is rejected", () => {
  const result = validateCloudSecurityOutcome(outcome({ schema_version: "cloud_security.outcome.v2" as typeof CLOUD_SECURITY_OUTCOME_SCHEMA }));
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.code === "unsupported_schema"));
});

test("an invalid execution_state enum value is rejected", () => {
  const result = validateCloudSecurityOutcome(outcome({ execution_state: "succeeded" as unknown as CloudSecurityOutcome["execution_state"] }));
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.path === "execution_state"));
});

test("control_lineage, when present, requires policy_generated_effect to be explicit", () => {
  const missingFlag = outcome({
    control_lineage: { control_origin: "sentinel", control_id: "ctl_1" } as unknown as NonNullable<CloudSecurityOutcome["control_lineage"]>,
  });
  const result = validateCloudSecurityOutcome(missingFlag);
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.path === "control_lineage.policy_generated_effect"));

  const withFlag = outcome({
    control_lineage: { control_origin: "sentinel", control_id: "ctl_1", policy_generated_effect: true },
  });
  assert.equal(validateCloudSecurityOutcome(withFlag).ok, true);
});
