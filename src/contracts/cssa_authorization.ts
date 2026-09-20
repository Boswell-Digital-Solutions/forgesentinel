import {
  Issues,
  isRecord,
  requireIsoTimestamp,
  requireObject,
  requireString,
  type ValidationResult,
} from "./common.js";
import type { CloudSecurityControlLineage } from "./cssa_decision.js";

export const CLOUD_SECURITY_AUTHORIZATION_SCHEMA = "cloud_security.authorization.v1";

/** Forge-Agents `app/security/contracts.py::AuthorizationState` (05 §18). */
export const CLOUD_SECURITY_AUTHORIZATION_STATES = ["issued", "denied", "approval_pending", "quarantined"] as const;
export type CloudSecurityAuthorizationState = (typeof CLOUD_SECURITY_AUTHORIZATION_STATES)[number];

/**
 * The subset of Forge-Agents' `CloudActionAuthorization` (`app/security/
 * contracts.py`, 05 §18 -- the literal shape DataForge stores as each
 * `authorizations` record's `payload`) that the CSSA watchdog's
 * approval-pending-burst detector depends on. This is a consumer-side
 * contract, matching `cssa_decision.ts`'s convention: fields irrelevant to
 * that detector (request_digest, redaction_count, quota_reservation_id,
 * single_use, ...) are intentionally not modeled or validated here.
 *
 * Unlike `CloudSecurityDecision`, `principal_id`/`tenant_id` are top-level
 * here, not nested under a `principal` object -- matching §18's own shape.
 */
export interface CloudSecurityAuthorization {
  schema_version: typeof CLOUD_SECURITY_AUTHORIZATION_SCHEMA;
  authorization_id: string;
  attempt_id: string;
  correlation_id: string;
  created_at: string;
  principal_id: string;
  tenant_id: string;
  authorization_state: CloudSecurityAuthorizationState;
  control_lineage?: CloudSecurityControlLineage;
}

/**
 * `tenant_id` is optional in Forge-Agents' own §18 schema but required here,
 * matching `validateCloudSecurityDecision`'s fail-closed convention: an
 * authorization that cannot be attributed to a tenant is rejected, not
 * guessed, and can never feed the watchdog's per-tenant subject key.
 */
export function validateCloudSecurityAuthorization(value: unknown): ValidationResult {
  const issues = new Issues();
  if (!isRecord(value)) {
    issues.add("", "required_object", "cloud security authorization must be an object");
    return issues.result();
  }
  if (value["schema_version"] !== CLOUD_SECURITY_AUTHORIZATION_SCHEMA) {
    issues.add("schema_version", "unsupported_schema", `expected ${CLOUD_SECURITY_AUTHORIZATION_SCHEMA}`);
  }
  requireString(issues, value, "authorization_id");
  requireString(issues, value, "attempt_id");
  requireString(issues, value, "correlation_id");
  requireIsoTimestamp(issues, value, "created_at");
  requireString(issues, value, "principal_id");
  requireString(issues, value, "tenant_id");
  requireString(issues, value, "authorization_state", { enum: CLOUD_SECURITY_AUTHORIZATION_STATES });
  const controlLineage = value["control_lineage"];
  if (controlLineage !== undefined) {
    const lineage = requireObject(issues, value, "control_lineage");
    if (lineage) {
      requireString(issues, lineage, "control_origin", { prefix: "control_lineage" });
      requireString(issues, lineage, "control_id", { prefix: "control_lineage" });
      if (typeof lineage["policy_generated_effect"] !== "boolean") {
        issues.add("control_lineage.policy_generated_effect", "required_boolean", "policy_generated_effect must be explicit when control_lineage is present");
      }
    }
  }
  return issues.result();
}
