import {
  Issues,
  isRecord,
  requireIsoTimestamp,
  requireObject,
  requireString,
  type ValidationResult,
} from "./common.js";
import type { CloudSecurityControlLineage } from "./cssa_decision.js";

export const CLOUD_SECURITY_OUTCOME_SCHEMA = "cloud_security.outcome.v1";

/** Forge-Agents `app/security/contracts.py::ExecutionState` (05 §19). */
export const CLOUD_SECURITY_EXECUTION_STATES = ["started", "completed", "failed", "cancelled", "partially_delivered"] as const;
export type CloudSecurityExecutionState = (typeof CLOUD_SECURITY_EXECUTION_STATES)[number];

/**
 * The subset of Forge-Agents' `CloudActionOutcome` (`app/security/
 * contracts.py`, 05 §19 -- the literal shape DataForge stores as each
 * `outcomes` record's `payload`) that the CSSA watchdog's
 * execution-failure-burst detector depends on. This is a consumer-side
 * contract, matching `cssa_decision.ts`'s convention.
 *
 * Deliberately has no `principal_id`/`tenant_id` field: §19 does not carry
 * one -- an outcome only ties back to a subject indirectly, through the
 * `authorization_id` of the authorization it resulted from. Attribution is
 * the caller's job (`AuthorizationIndex`, `src/watchdog/authorization_index.ts`),
 * not this contract's.
 */
export interface CloudSecurityOutcome {
  schema_version: typeof CLOUD_SECURITY_OUTCOME_SCHEMA;
  outcome_id: string;
  attempt_id: string;
  authorization_id: string;
  correlation_id: string;
  created_at: string;
  execution_state: CloudSecurityExecutionState;
  control_lineage?: CloudSecurityControlLineage;
}

export function validateCloudSecurityOutcome(value: unknown): ValidationResult {
  const issues = new Issues();
  if (!isRecord(value)) {
    issues.add("", "required_object", "cloud security outcome must be an object");
    return issues.result();
  }
  if (value["schema_version"] !== CLOUD_SECURITY_OUTCOME_SCHEMA) {
    issues.add("schema_version", "unsupported_schema", `expected ${CLOUD_SECURITY_OUTCOME_SCHEMA}`);
  }
  requireString(issues, value, "outcome_id");
  requireString(issues, value, "attempt_id");
  requireString(issues, value, "authorization_id");
  requireString(issues, value, "correlation_id");
  requireIsoTimestamp(issues, value, "created_at");
  requireString(issues, value, "execution_state", { enum: CLOUD_SECURITY_EXECUTION_STATES });
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
