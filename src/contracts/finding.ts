import {
  Issues,
  isRecord,
  requireIsoTimestamp,
  requireObject,
  requireString,
  validateRiskDimensions,
  type RiskDimensions,
  type ValidationResult,
} from "./common.js";

/** Action classes from 06_POLICY_ENFORCEMENT_AND_AUTHORITY. */
export const ACTION_CLASSES = ["OBSERVE", "RECOMMEND", "GUARD", "RESTRICT", "SUSPEND", "REVOKE_OR_DESTRUCT"] as const;
export type ActionClass = (typeof ACTION_CLASSES)[number];

export const RECOMMENDATION_ACTION_CLASSES = [
  "OBSERVE",
  "RECOMMEND_ONLY",
  "REQUEST_OPERATOR",
  "REQUEST_BOUNDED_ACTION",
] as const;

export interface FindingExplanationFactor {
  factor: string;
  contribution: number;
}

/**
 * Explainability is a product requirement (01): generated prose may only
 * summarize these recorded factors, never invent a justification.
 */
export interface FindingExplanation {
  summary: string;
  top_factors: FindingExplanationFactor[];
  uncertainties: string[];
  expected?: number;
  observed?: number;
  missing_sources?: string[];
}

export interface Finding {
  finding_id: string;
  finding_type: string;
  node: { name: string; version: string };
  subject: { type: string; id: string };
  tenant_id: string;
  window: { start: string; end: string };
  risk: RiskDimensions;
  baseline?: { baseline_id: string; expected: number; observed: number; change_ratio: number };
  evidence_ids: string[];
  /** Independence grouping keys carried up from evidence (one per root). */
  source_event_roots: string[];
  explanation: FindingExplanation;
  recommendation: { action_class: (typeof RECOMMENDATION_ACTION_CLASSES)[number]; playbook?: string };
  expires_at: string;
  correlation_hints: {
    account_id?: string;
    actor_id?: string;
    api_key_fingerprint?: string;
    route_class?: string;
    agent_fingerprint?: string;
    run_id?: string;
    provider?: string;
    model_fingerprint?: string;
    destination?: string;
  };
  policy_generated_effect: boolean;
}

export function validateFinding(value: unknown): ValidationResult {
  const issues = new Issues();
  if (!isRecord(value)) {
    issues.add("", "required_object", "finding must be an object");
    return issues.result();
  }
  requireString(issues, value, "finding_id", { pattern: /^fnd_[A-Za-z0-9_-]+$/ });
  requireString(issues, value, "finding_type");
  requireString(issues, value, "tenant_id");
  const node = requireObject(issues, value, "node");
  if (node) {
    requireString(issues, node, "name", { prefix: "node" });
    requireString(issues, node, "version", { prefix: "node" });
  }
  const subject = requireObject(issues, value, "subject");
  if (subject) {
    requireString(issues, subject, "type", { prefix: "subject" });
    requireString(issues, subject, "id", { prefix: "subject" });
  }
  const window = requireObject(issues, value, "window");
  if (window) {
    requireIsoTimestamp(issues, window, "start", "window");
    requireIsoTimestamp(issues, window, "end", "window");
  }
  issues.merge(validateRiskDimensions(value["risk"], "risk"));
  if (!Array.isArray(value["evidence_ids"]) || value["evidence_ids"].length === 0) {
    issues.add("evidence_ids", "required_array", "a finding without evidence references is not a finding (01: evidence before inference)");
  }
  if (!Array.isArray(value["source_event_roots"]) || value["source_event_roots"].length === 0) {
    issues.add("source_event_roots", "required_array", "finding must carry independence roots");
  }
  const explanation = requireObject(issues, value, "explanation");
  if (explanation) {
    requireString(issues, explanation, "summary", { prefix: "explanation" });
    if (!Array.isArray(explanation["top_factors"])) {
      issues.add("explanation.top_factors", "required_array", "explanation.top_factors must be an array");
    }
    if (!Array.isArray(explanation["uncertainties"])) {
      issues.add("explanation.uncertainties", "required_array", "explanation.uncertainties must be an array (uncertainty is never hidden)");
    }
  }
  const recommendation = requireObject(issues, value, "recommendation");
  if (recommendation) {
    requireString(issues, recommendation, "action_class", { prefix: "recommendation", enum: RECOMMENDATION_ACTION_CLASSES });
  }
  requireIsoTimestamp(issues, value, "expires_at");
  if (typeof value["policy_generated_effect"] !== "boolean") {
    issues.add("policy_generated_effect", "required_boolean", "policy_generated_effect must be explicit (ADR-022)");
  }
  return issues.result();
}
