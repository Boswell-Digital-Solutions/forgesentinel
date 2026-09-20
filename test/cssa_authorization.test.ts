import { test } from "node:test";
import assert from "node:assert/strict";
import { CLOUD_SECURITY_AUTHORIZATION_SCHEMA, validateCloudSecurityAuthorization, type CloudSecurityAuthorization } from "../src/index.js";

const NOW = "2026-09-20T12:00:00.000Z";

function authorization(overrides: Partial<CloudSecurityAuthorization> = {}): CloudSecurityAuthorization {
  return {
    schema_version: CLOUD_SECURITY_AUTHORIZATION_SCHEMA,
    authorization_id: "auth_001",
    attempt_id: "att_001",
    correlation_id: "cor_001",
    created_at: NOW,
    principal_id: "usr_1",
    tenant_id: "ten_demo",
    authorization_state: "issued",
    ...overrides,
  };
}

test("a well-formed authorization validates", () => {
  const result = validateCloudSecurityAuthorization(authorization());
  assert.equal(result.ok, true, JSON.stringify(result.issues));
});

test("an authorization without tenant_id is rejected, not guessed", () => {
  const untenanted = authorization();
  // @ts-expect-error -- deliberately malformed for the test
  delete untenanted.tenant_id;
  const result = validateCloudSecurityAuthorization(untenanted);
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.path === "tenant_id"));
});

test("an unknown schema_version is rejected", () => {
  const result = validateCloudSecurityAuthorization(
    authorization({ schema_version: "cloud_security.authorization.v2" as typeof CLOUD_SECURITY_AUTHORIZATION_SCHEMA }),
  );
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.code === "unsupported_schema"));
});

test("an invalid authorization_state enum value is rejected", () => {
  const result = validateCloudSecurityAuthorization(
    authorization({ authorization_state: "granted" as unknown as CloudSecurityAuthorization["authorization_state"] }),
  );
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.path === "authorization_state"));
});

test("control_lineage, when present, requires policy_generated_effect to be explicit", () => {
  const missingFlag = authorization({
    control_lineage: { control_origin: "sentinel", control_id: "ctl_1" } as unknown as NonNullable<CloudSecurityAuthorization["control_lineage"]>,
  });
  const result = validateCloudSecurityAuthorization(missingFlag);
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.path === "control_lineage.policy_generated_effect"));

  const withFlag = authorization({
    control_lineage: { control_origin: "sentinel", control_id: "ctl_1", policy_generated_effect: true },
  });
  assert.equal(validateCloudSecurityAuthorization(withFlag).ok, true);
});
