import {
  Issues,
  isRecord,
  requireIsoTimestamp,
  requireObject,
  requireString,
  type ValidationResult,
} from "./common.js";

export const CLOUD_SECURITY_DECISION_SCHEMA = "cloud_security.decision.v1";

/** Forge-Agents `app/security/contracts.py::DecisionType` (05 §15.2). */
export const CLOUD_SECURITY_DECISION_TYPES = ["allow", "allow_redacted", "approval_required", "quarantine", "block"] as const;
export type CloudSecurityDecisionType = (typeof CLOUD_SECURITY_DECISION_TYPES)[number];

/** Forge-Agents `app/security/contracts.py::QuotaStatus`. */
export const CLOUD_SECURITY_QUOTA_STATUSES = ["reserved", "exceeded", "unknown", "not_applicable"] as const;
export type CloudSecurityQuotaStatus = (typeof CLOUD_SECURITY_QUOTA_STATUSES)[number];

export interface CloudSecurityDecisionPrincipal {
  principal_id: string;
  tenant_id: string;
}

/**
 * `08 §3` feedback-loop fields. When `policy_generated_effect` is true, this
 * decision was itself caused by an earlier Sentinel-issued directive and
 * must never count as fresh evidence of an anomaly (ADR-022) -- the same
 * rule `SentinelPrime.independenceGroups()` already enforces for findings
 * that already made it into the pipeline; here it has to be enforced one
 * step earlier, before a finding is even formed.
 */
export interface CloudSecurityControlLineage {
  control_origin: string;
  control_id: string;
  sentinel_incident_id?: string;
  policy_decision_id?: string;
  policy_generated_effect: boolean;
}

/**
 * The subset of Forge-Agents' `CloudSecurityDecision` (`app/security/
 * contracts.py`, 05 §17 -- the literal shape DataForge stores as each
 * `decisions` record's `payload`) that the CSSA watchdog detectors depend
 * on. This is a consumer-side contract, not a full mirror of §17: fields
 * irrelevant to denial-streak/quota-burst detection (classification,
 * policy_bundle, provider_constraints, ...) are intentionally not modeled
 * or validated here.
 */
export interface CloudSecurityDecision {
  schema_version: typeof CLOUD_SECURITY_DECISION_SCHEMA;
  decision_id: string;
  attempt_id: string;
  correlation_id: string;
  occurred_at: string;
  principal: CloudSecurityDecisionPrincipal;
  decision: CloudSecurityDecisionType;
  quota_status: CloudSecurityQuotaStatus;
  reason_codes: string[];
  control_lineage?: CloudSecurityControlLineage;
}

/**
 * A decision record without `principal.tenant_id` cannot be attributed to a
 * tenant and is rejected rather than guessed (fail-closed, matching this
 * repo's own `validateControlDirectiveShape` convention for unknown
 * fields) -- `Principal.tenant_id` is optional in Forge-Agents' own §17
 * schema, so this is a real, expected rejection path, not a defensive
 * placeholder.
 */
export function validateCloudSecurityDecision(value: unknown): ValidationResult {
  const issues = new Issues();
  if (!isRecord(value)) {
    issues.add("", "required_object", "cloud security decision must be an object");
    return issues.result();
  }
  if (value["schema_version"] !== CLOUD_SECURITY_DECISION_SCHEMA) {
    issues.add("schema_version", "unsupported_schema", `expected ${CLOUD_SECURITY_DECISION_SCHEMA}`);
  }
  requireString(issues, value, "decision_id");
  requireString(issues, value, "attempt_id");
  requireString(issues, value, "correlation_id");
  requireIsoTimestamp(issues, value, "occurred_at");
  const principal = requireObject(issues, value, "principal");
  if (principal) {
    requireString(issues, principal, "principal_id", { prefix: "principal" });
    requireString(issues, principal, "tenant_id", { prefix: "principal" });
  }
  requireString(issues, value, "decision", { enum: CLOUD_SECURITY_DECISION_TYPES });
  requireString(issues, value, "quota_status", { enum: CLOUD_SECURITY_QUOTA_STATUSES });
  if (!Array.isArray(value["reason_codes"])) {
    issues.add("reason_codes", "required_array", "reason_codes must be an array (may be empty)");
  }
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
