import { Issues, isRecord, requireNumber, requireString, type ValidationResult } from "./common.js";

/**
 * Scoped capability token claims (06, 13). Executors validate the exact
 * action and target (ADR-008); anything widened, replayed, expired, or
 * carrying unknown scope-affecting fields is rejected.
 */
export interface CapabilityClaims {
  iss: string;
  aud: string;
  jti: string;
  incident_id: string;
  policy_decision_id: string;
  /** Carried from the authorizing PolicyDecision so an executor's receipt never has to guess or hardcode it. */
  policy_id: string;
  policy_version: string;
  approver_type: string;
  approver_id: string;
  action: string;
  target: string;
  scope: string;
  max_attempts: number;
  rollback_required: boolean;
  /** Unix epoch seconds. */
  exp: number;
}

export interface CapabilityToken {
  claims: CapabilityClaims;
  signature: string;
  signature_key_id: string;
}

export const CAPABILITY_CLAIM_FIELDS = new Set([
  "iss",
  "aud",
  "jti",
  "incident_id",
  "policy_decision_id",
  "policy_id",
  "policy_version",
  "approver_type",
  "approver_id",
  "action",
  "target",
  "scope",
  "max_attempts",
  "rollback_required",
  "exp",
]);

export function validateCapabilityClaims(value: unknown): ValidationResult {
  const issues = new Issues();
  if (!isRecord(value)) {
    issues.add("", "required_object", "capability claims must be an object");
    return issues.result();
  }
  requireString(issues, value, "iss");
  requireString(issues, value, "aud");
  requireString(issues, value, "jti", { pattern: /^cap_[A-Za-z0-9_-]+$/ });
  requireString(issues, value, "incident_id");
  requireString(issues, value, "policy_decision_id");
  requireString(issues, value, "policy_id");
  requireString(issues, value, "policy_version");
  requireString(issues, value, "approver_type");
  requireString(issues, value, "approver_id");
  requireString(issues, value, "action");
  requireString(issues, value, "target");
  requireString(issues, value, "scope");
  requireNumber(issues, value, "max_attempts", { min: 1 });
  if (typeof value["rollback_required"] !== "boolean") {
    issues.add("rollback_required", "required_boolean", "rollback_required must be explicit");
  }
  requireNumber(issues, value, "exp", { min: 0 });
  // Confused-deputy defense: a claim set with unknown fields could smuggle
  // widened scope past an executor that only checks known fields.
  for (const key of Object.keys(value)) {
    if (!CAPABILITY_CLAIM_FIELDS.has(key)) {
      issues.add(key, "unknown_critical_field", `unknown capability claim field "${key}" may affect scope; rejecting`);
    }
  }
  return issues.result();
}
