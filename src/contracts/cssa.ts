import {
  Issues,
  isRecord,
  requireIsoTimestamp,
  requireNumber,
  requireObject,
  requireString,
  type ValidationResult,
} from "./common.js";
import type { Finding } from "./finding.js";

export const CLOUD_SECURITY_FINDING_SCHEMA = "cloud_security.finding.v1";
export const CONTROL_DIRECTIVE_SCHEMA = "cloud_security.control_directive.v1";

/** Forge-Agents `app/security/contracts.py::Severity` (05 §.., canonical). */
export const CLOUD_SECURITY_SEVERITIES = ["S0", "S1", "S2", "S3", "S4"] as const;
export type CloudSecuritySeverity = (typeof CLOUD_SECURITY_SEVERITIES)[number];

export interface CloudSecurityFindingScope {
  tenant_id: string;
  principal_id?: string;
  executor_id?: string;
  app_id?: string;
  cloud_service?: string;
}

export interface CloudSecurityFindingWindow {
  from: string;
  to: string;
}

export interface CloudSecurityFindingMetrics {
  observed: number;
  baseline: number;
  threshold: number;
}

/**
 * CSSA watchdog output. Canonical wire shape per Forge-Agents'
 * `app/security/contracts.py::CloudSecurityFinding` (06 §4) — pinned at
 * Forge-Agents `672cec5`, forgesentinel is a consumer of this contract, not
 * its owner; a schema_version bump on either side re-opens reconciliation.
 * It is a SOURCE finding: it cannot create or mutate Sentinel incident
 * lifecycle state directly (ADR-020).
 */
export interface CloudSecurityFinding {
  schema_version: typeof CLOUD_SECURITY_FINDING_SCHEMA;
  finding_id: string;
  detector: string;
  severity: CloudSecuritySeverity;
  scope: CloudSecurityFindingScope;
  window: CloudSecurityFindingWindow;
  evidence_refs: string[];
  metrics: CloudSecurityFindingMetrics;
  reason_codes: string[];
  summary: string;
  emitted_at: string;
  expires_at: string;
  finding_hash: string;
}

export function validateCloudSecurityFinding(value: unknown): ValidationResult {
  const issues = new Issues();
  if (!isRecord(value)) {
    issues.add("", "required_object", "cloud security finding must be an object");
    return issues.result();
  }
  const schema = value["schema_version"];
  if (schema !== CLOUD_SECURITY_FINDING_SCHEMA) {
    issues.add("schema_version", "unsupported_schema", `expected ${CLOUD_SECURITY_FINDING_SCHEMA}; legacy SecurityIncident.v1 payloads must come through the legacy adapter`);
  }
  requireString(issues, value, "finding_id");
  requireString(issues, value, "detector");
  requireString(issues, value, "severity", { enum: CLOUD_SECURITY_SEVERITIES });
  const scope = requireObject(issues, value, "scope");
  if (scope) {
    requireString(issues, scope, "tenant_id", { prefix: "scope" });
  }
  const window = requireObject(issues, value, "window");
  if (window) {
    requireIsoTimestamp(issues, window, "from", "window");
    requireIsoTimestamp(issues, window, "to", "window");
  }
  if (!Array.isArray(value["evidence_refs"]) || value["evidence_refs"].length === 0) {
    issues.add("evidence_refs", "required_array", "CSSA finding must reference immutable evidence");
  }
  const metrics = requireObject(issues, value, "metrics");
  if (metrics) {
    requireNumber(issues, metrics, "observed", { prefix: "metrics" });
    requireNumber(issues, metrics, "baseline", { prefix: "metrics" });
    requireNumber(issues, metrics, "threshold", { prefix: "metrics" });
  }
  if (!Array.isArray(value["reason_codes"]) || value["reason_codes"].length === 0) {
    issues.add("reason_codes", "required_array", "CSSA finding must carry at least one reason code");
  }
  requireString(issues, value, "summary");
  requireIsoTimestamp(issues, value, "emitted_at");
  requireIsoTimestamp(issues, value, "expires_at");
  requireString(issues, value, "finding_hash", { pattern: /^sha256:[0-9a-f]{64}$/ });
  return issues.result();
}

/** S0 (informational) .. S4 (severe) -> a 0-1 risk score (ADR-010: kept separate from confidence/evidence_quality). */
const SEVERITY_RISK_SCORE: Record<CloudSecuritySeverity, number> = {
  S0: 0.1,
  S1: 0.3,
  S2: 0.55,
  S3: 0.75,
  S4: 0.95,
};

/**
 * Adapter: CSSA watchdog finding (Forge-Agents §4 wire shape) -> Sentinel
 * internal SOURCE finding. Promotion to an incident remains with Sentinel
 * Prime or a deterministic formation rule; this adapter never sets
 * `policy_generated_effect: true` -- a finding only reaches here once its
 * producing detector has already excluded policy-generated evidence
 * (ADR-022), so by construction nothing it emits rests on enforcement
 * effects.
 */
export function cssaFindingToSourceFinding(cssa: CloudSecurityFinding, _nowIso: string): Finding {
  const risk = SEVERITY_RISK_SCORE[cssa.severity];
  const subjectId = cssa.scope.principal_id ?? cssa.scope.executor_id ?? cssa.scope.app_id ?? "unknown";
  const subjectType = cssa.scope.principal_id ? "principal" : cssa.scope.executor_id ? "executor" : "app";
  return {
    finding_id: `fnd_cssa_${cssa.finding_id}`,
    finding_type: `cssa.${cssa.detector}`,
    node: { name: "cssa-watchdog-adapter", version: "2.0.0" },
    subject: { type: subjectType, id: subjectId },
    tenant_id: cssa.scope.tenant_id,
    window: { start: cssa.window.from, end: cssa.window.to },
    risk: {
      likelihood: risk,
      impact: risk,
      // Deterministic edge detection is high confidence in WHAT it saw; the
      // ecosystem interpretation is Prime's job.
      confidence: 0.9,
      evidence_quality: 0.95,
    },
    evidence_ids: cssa.evidence_refs,
    source_event_roots: cssa.evidence_refs,
    explanation: {
      summary: cssa.summary,
      top_factors: cssa.reason_codes.map((code) => ({ factor: code, contribution: 1 / cssa.reason_codes.length })),
      uncertainties: ["Source finding from the enforcement boundary; cross-domain interpretation pending correlation."],
      observed: cssa.metrics.observed,
      expected: cssa.metrics.baseline,
    },
    recommendation: { action_class: "RECOMMEND_ONLY" },
    expires_at: cssa.expires_at,
    correlation_hints: cssa.scope.principal_id ? { actor_id: cssa.scope.principal_id } : {},
    policy_generated_effect: false,
  };
}

export interface ControlDirectiveTarget {
  tenant_id: string;
  principal_id?: string;
  executor_id?: string;
  app_id?: string;
  cloud_service?: string;
  provider?: string;
  model_fingerprint?: string;
}

/**
 * Signed, scoped, expiring control artifact (06, 07 §8). A raw incident is
 * never an authorization artifact (ADR-021).
 */
export interface CloudSecurityControlDirective {
  schema_version: typeof CONTROL_DIRECTIVE_SCHEMA;
  control_id: string;
  incident_id: string;
  policy_decision_id: string;
  issuer: string;
  issued_at: string;
  expires_at: string;
  action: string;
  target: ControlDirectiveTarget;
  scope: string;
  max_uses: number;
  approval: { level: string; approval_id: string };
  rollback: { required: boolean; action: string; restore_state_ref?: string };
  reason_codes: string[];
  integrity: { algorithm: string; key_id: string; signature: string };
}

export const DIRECTIVE_FIELDS = new Set([
  "schema_version",
  "control_id",
  "incident_id",
  "policy_decision_id",
  "issuer",
  "issued_at",
  "expires_at",
  "action",
  "target",
  "scope",
  "max_uses",
  "approval",
  "rollback",
  "reason_codes",
  "integrity",
]);

/** Initial allowlisted controls with their maximum scope (07 §10). */
export const DIRECTIVE_ACTION_ALLOWLIST: Record<string, { max_scope: string; rollback_action: string }> = {
  "cssa.cloud_route.hold": { max_scope: "single_executor_single_route", rollback_action: "cssa.cloud_route.release" },
  "cssa.executor_service.hold": { max_scope: "single_executor_single_service", rollback_action: "cssa.executor_service.release" },
  "cssa.action.require_approval": { max_scope: "single_principal_single_action", rollback_action: "cssa.action.release_approval_requirement" },
  "cssa.model_fingerprint.deny_category": { max_scope: "single_fingerprint_single_category", rollback_action: "cssa.model_fingerprint.allow_category" },
  "cssa.retry_ceiling.lower": { max_scope: "single_route", rollback_action: "cssa.retry_ceiling.restore" },
  "cssa.redaction.require": { max_scope: "single_action_single_data_class", rollback_action: "cssa.redaction.release_requirement" },
  "cssa.destination.block_temporary": { max_scope: "single_destination_single_tenant", rollback_action: "cssa.destination.unblock" },
  "identity.reauthentication.require": { max_scope: "single_account", rollback_action: "identity.reauthentication.release" },
};

export function validateControlDirectiveShape(value: unknown): ValidationResult {
  const issues = new Issues();
  if (!isRecord(value)) {
    issues.add("", "required_object", "control directive must be an object");
    return issues.result();
  }
  if (value["schema_version"] !== CONTROL_DIRECTIVE_SCHEMA) {
    issues.add("schema_version", "unsupported_schema", `expected ${CONTROL_DIRECTIVE_SCHEMA}`);
  }
  requireString(issues, value, "control_id", { pattern: /^ctl_[A-Za-z0-9_-]+$/ });
  requireString(issues, value, "incident_id");
  requireString(issues, value, "policy_decision_id");
  requireString(issues, value, "issuer");
  requireIsoTimestamp(issues, value, "issued_at");
  requireIsoTimestamp(issues, value, "expires_at");
  const action = requireString(issues, value, "action");
  if (action && !DIRECTIVE_ACTION_ALLOWLIST[action]) {
    issues.add("action", "action_not_allowlisted", `"${action}" is not an allowlisted CSSA control action`);
  }
  const target = requireObject(issues, value, "target");
  if (target) {
    requireString(issues, target, "tenant_id", { prefix: "target" });
  }
  requireString(issues, value, "scope");
  requireNumber(issues, value, "max_uses", { min: 1 });
  const approval = requireObject(issues, value, "approval");
  if (approval) {
    requireString(issues, approval, "level", { prefix: "approval" });
    requireString(issues, approval, "approval_id", { prefix: "approval" });
  }
  const rollback = requireObject(issues, value, "rollback");
  if (rollback) {
    if (typeof rollback["required"] !== "boolean") {
      issues.add("rollback.required", "required_boolean", "rollback requirement must be explicit");
    }
    requireString(issues, rollback, "action", { prefix: "rollback" });
  }
  if (!Array.isArray(value["reason_codes"]) || value["reason_codes"].length === 0) {
    issues.add("reason_codes", "required_array", "reason codes are required");
  }
  const integrity = requireObject(issues, value, "integrity");
  if (integrity) {
    requireString(issues, integrity, "algorithm", { prefix: "integrity" });
    requireString(issues, integrity, "key_id", { prefix: "integrity" });
    requireString(issues, integrity, "signature", { prefix: "integrity" });
  }
  // Critical unknown fields are a rejection condition (07 §9).
  for (const key of Object.keys(value)) {
    if (!DIRECTIVE_FIELDS.has(key)) {
      issues.add(key, "unknown_critical_field", `unknown directive field "${key}"; rejecting rather than guessing`);
    }
  }
  return issues.result();
}
