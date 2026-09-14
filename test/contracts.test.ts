import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  validateEventEnvelope,
  validateFinding,
  validateIncident,
  validateActionReceipt,
  validateControlDirectiveShape,
  validateCapabilityClaims,
  validateFeedbackLabel,
  validateTrustVector,
  checkSchemaVersion,
  type ValidationResult,
} from "../src/index.js";

const GOLDEN_DIR = join(process.cwd(), "fixtures", "golden");

const validators: Record<string, (value: unknown) => ValidationResult> = {
  event: validateEventEnvelope,
  finding: validateFinding,
  incident: validateIncident,
  receipt: validateActionReceipt,
  directive: validateControlDirectiveShape,
};

test("golden fixtures validate per manifest (Wave 0 exit gate)", () => {
  const manifest = JSON.parse(readFileSync(join(GOLDEN_DIR, "manifest.json"), "utf8")) as {
    file: string;
    contract: string;
    expect_valid: boolean;
  }[];
  assert.ok(manifest.length >= 8, "expected at least 8 golden fixtures");
  for (const entry of manifest) {
    const body = JSON.parse(readFileSync(join(GOLDEN_DIR, entry.file), "utf8"));
    const validator = validators[entry.contract];
    assert.ok(validator, `unknown contract ${entry.contract}`);
    const result = validator(body);
    assert.equal(result.ok, entry.expect_valid, `${entry.file}: ${JSON.stringify(result.issues)}`);
  }
});

test("unknown major schema version fails safely", () => {
  const result = checkSchemaVersion("2.0.0", 1);
  assert.equal(result.ok, false);
  assert.equal(result.issues[0]?.code, "unsupported_major_version");
});

test("additive minor version is accepted", () => {
  assert.equal(checkSchemaVersion("1.4.0", 1).ok, true);
  const event = JSON.parse(readFileSync(join(GOLDEN_DIR, "event.usage_tokens_recorded.json"), "utf8"));
  event.schema_version = "1.9.3";
  event.some_new_optional_field = "additive";
  assert.equal(validateEventEnvelope(event).ok, true);
});

test("restricted content marked cloud_allowed is a forbidden combination", () => {
  const event = JSON.parse(readFileSync(join(GOLDEN_DIR, "event.invalid_restricted_content_cloud.json"), "utf8"));
  const result = validateEventEnvelope(event);
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.code === "forbidden_content_policy"));
});

test("risk dimensions must each be present and bounded (ADR-010)", () => {
  const finding = JSON.parse(readFileSync(join(GOLDEN_DIR, "finding.cost_usage_change_extreme.json"), "utf8"));
  finding.risk = { likelihood: 0.9, impact: 1.5, confidence: 0.5, evidence_quality: 0.9 };
  assert.equal(validateFinding(finding).ok, false);
  delete finding.risk;
  assert.equal(validateFinding(finding).ok, false);
});

test("capability claims with unknown fields are rejected (confused deputy defense)", () => {
  const claims = {
    iss: "sentinel-policy-service",
    aud: "identity-service",
    jti: "cap_x1",
    incident_id: "inc_1",
    policy_decision_id: "pdec_1",
    policy_id: "sentinel_account_compromise",
    policy_version: "3.1.0",
    approver_type: "operator",
    approver_id: "op_17",
    action: "identity.api_key.pause",
    target: "key_1",
    scope: "single_key",
    max_attempts: 1,
    rollback_required: true,
    exp: 1781026740,
  };
  assert.equal(validateCapabilityClaims(claims).ok, true);
  const widened = { ...claims, extra_scope: "all_keys" };
  const result = validateCapabilityClaims(widened);
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.code === "unknown_critical_field"));
});

test("feedback label cannot be training-eligible without privacy approval (ADR-004)", () => {
  const label = {
    label_id: "lbl_1",
    incident_id: "inc_1",
    incident_version: 1,
    label: "confirmed_true_positive",
    reviewer: "op_17",
    confidence: 0.9,
    reason: "verified with the customer",
    evidence_available_at_review: ["evd_1"],
    signal_origins: {
      origin_signal: true,
      standing_policy_effect: false,
      sentinel_control_effect: false,
      operator_effect: true,
      rollback_effect: false,
      later_external_outcome: true,
    },
    privacy_approved: false,
    calibration_eligible: true,
    training_eligible: true,
    reviewed_at: "2026-06-10T12:00:00.000Z",
  };
  const result = validateFeedbackLabel(label);
  assert.equal(result.ok, false);
  assert.ok(result.issues.some((issue) => issue.code === "training_without_privacy"));
  assert.equal(validateFeedbackLabel({ ...label, privacy_approved: true }).ok, true);
});

test("trust vector is scoped and multi-dimensional (ADR-005)", () => {
  const vector = {
    provider: "provider_a",
    model_snapshot: "model-2026-06-01",
    fingerprint_id: "fp_001",
    task_category: "typescript.type_fix",
    route_class: "code_mutation_supervised",
    tool_profile: "read_patch_test_v2",
    evaluation_suite: "codefix-v7",
    window: "last_500_eligible_runs",
    state: "normal",
    dimensions: {
      reliability: 0.96,
      task_success: 0.93,
      evaluation_quality: 0.9,
      latency_score: 0.72,
      cost_efficiency: 0.64,
      security_compliance: 0.95,
      privacy_compatibility: 0.9,
      contract_validity: 0.99,
      tool_policy_compliance: 1.0,
      rollback_risk: 0.02,
      availability: 0.98,
      evidence_quality: 0.92,
    },
  };
  assert.equal(validateTrustVector(vector).ok, true);
  const flat = { ...vector, dimensions: undefined, score: 94 };
  assert.equal(validateTrustVector(flat).ok, false);
});
