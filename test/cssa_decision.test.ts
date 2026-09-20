import { test } from "node:test";
import assert from "node:assert/strict";
import { CLOUD_SECURITY_DECISION_SCHEMA, validateCloudSecurityDecision, type CloudSecurityDecision } from "../src/index.js";

const NOW = "2026-09-20T12:00:00.000Z";

function decision(overrides: Partial<CloudSecurityDecision> = {}): CloudSecurityDecision {
  return {
    schema_version: CLOUD_SECURITY_DECISION_SCHEMA,
    decision_id: "dec_001",
    attempt_id: "att_001",
    correlation_id: "cor_001",
    occurred_at: NOW,
    principal: { principal_id: "usr_1", tenant_id: "ten_demo" },
    decision: "allow",
    quota_status: "not_applicable",
    reason_codes: [],
    ...overrides,
  };
}

test("a well-formed decision validates", () => {
  const result = validateCloudSecurityDecision(decision());
  assert.equal(result.ok, true, JSON.stringify(result.issues));
});

test("a decision without principal.tenant_id is rejected, not guessed", () => {
  const untenanted = decision();
  // @ts-expect-error -- deliberately malformed for the test
  delete untenanted.principal.tenant_id;
  const result = validateCloudSecurityDecision(untenanted);
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.path === "principal.tenant_id"));
});

test("an unknown schema_version is rejected", () => {
  const result = validateCloudSecurityDecision(decision({ schema_version: "cloud_security.decision.v2" as typeof CLOUD_SECURITY_DECISION_SCHEMA }));
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.code === "unsupported_schema"));
});

test("an invalid decision/quota_status enum value is rejected", () => {
  const badDecision = validateCloudSecurityDecision(decision({ decision: "denied" as unknown as CloudSecurityDecision["decision"] }));
  assert.equal(badDecision.ok, false);
  assert.ok(badDecision.issues.some((issue) => issue.path === "decision"));

  const badQuota = validateCloudSecurityDecision(decision({ quota_status: "over" as unknown as CloudSecurityDecision["quota_status"] }));
  assert.equal(badQuota.ok, false);
});

test("control_lineage, when present, requires policy_generated_effect to be explicit", () => {
  const missingFlag = decision({
    control_lineage: { control_origin: "sentinel", control_id: "ctl_1" } as unknown as NonNullable<CloudSecurityDecision["control_lineage"]>,
  });
  const result = validateCloudSecurityDecision(missingFlag);
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.path === "control_lineage.policy_generated_effect"));

  const withFlag = decision({
    control_lineage: { control_origin: "sentinel", control_id: "ctl_1", policy_generated_effect: true },
  });
  assert.equal(validateCloudSecurityDecision(withFlag).ok, true);
});
