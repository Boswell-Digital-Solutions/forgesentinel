import { test } from "node:test";
import assert from "node:assert/strict";
import { FeedbackStore, EvidenceLedger, type FeedbackLabel, type Incident, type CalibrationSignalOrigins } from "../src/index.js";

const NOW = "2026-06-10T12:00:00.000Z";

const ORGANIC: CalibrationSignalOrigins = {
  origin_signal: true,
  standing_policy_effect: false,
  sentinel_control_effect: false,
  operator_effect: true,
  rollback_effect: false,
  later_external_outcome: true,
};

function label(overrides: Partial<FeedbackLabel> & { label_id: string; incident_id: string; label: FeedbackLabel["label"] }): FeedbackLabel {
  return {
    incident_version: 1,
    reviewer: "op_17",
    confidence: 0.9,
    reason: "reviewed with account owner",
    evidence_available_at_review: ["evd_1"],
    signal_origins: ORGANIC,
    privacy_approved: true,
    calibration_eligible: true,
    training_eligible: false,
    reviewed_at: NOW,
    ...overrides,
  };
}

function incident(id: string, likelihood: number): Incident {
  return {
    incident_id: id,
    title: "t",
    incident_type: "compound.account_compromise",
    status: "resolved",
    priority: "high",
    origin: ["sentinel-cost"],
    subject: { tenant_id: "ten_a", account_id: "acct_1" },
    risk: { likelihood, impact: 0.8, confidence: 0.8, evidence_quality: 0.9 },
    briefing: { issue: "i", where: "w", recommended_fix: "f", why_now: "y" },
    finding_ids: ["fnd_1"],
    evidence_ids: ["evd_1"],
    independent_signal_count: 3,
    signals: ["cloud.new_api_key"],
    required_authority: ["forge_command_operator"],
    recommended_actions: [],
    conflicts: [],
    missing_telemetry: [],
    version: 1,
    created_at: NOW,
    updated_at: NOW,
    status_history: [{ status: "open", at: NOW }],
  };
}

test("labels are validated on submission and persisted to the ledger", () => {
  const ledger = new EvidenceLedger();
  const store = new FeedbackStore(ledger);
  const good = store.submit(label({ label_id: "lbl_1", incident_id: "inc_1", label: "confirmed_true_positive" }));
  assert.equal(good.ok, true);
  const bad = store.submit(label({ label_id: "lbl_2", incident_id: "inc_1", label: "confirmed_true_positive", privacy_approved: false, training_eligible: true }));
  assert.equal(bad.ok, false, "training without privacy approval is rejected at the contract");
  assert.equal(store.all().length, 1);
  assert.equal(ledger.all().filter((record) => record.kind === "feedback_label").length, 1);
});

test("training set requires explicit eligibility and privacy approval (ADR-004)", () => {
  const store = new FeedbackStore();
  store.submit(label({ label_id: "lbl_a", incident_id: "inc_1", label: "confirmed_true_positive", training_eligible: true, privacy_approved: true }));
  store.submit(label({ label_id: "lbl_b", incident_id: "inc_2", label: "confirmed_true_positive", training_eligible: false, privacy_approved: true }));
  const trainingSet = store.trainingSet();
  assert.equal(trainingSet.length, 1);
  assert.equal(trainingSet[0]!.label_id, "lbl_a");
});

test("calibration separates control-effect labels and measures predicted vs observed (SNT-405)", () => {
  const store = new FeedbackStore();
  const incidents = [incident("inc_1", 0.9), incident("inc_2", 0.85), incident("inc_3", 0.8), incident("inc_4", 0.95)];
  store.submit(label({ label_id: "lbl_1", incident_id: "inc_1", label: "confirmed_true_positive" }));
  store.submit(label({ label_id: "lbl_2", incident_id: "inc_2", label: "confirmed_false_positive" }));
  store.submit(label({ label_id: "lbl_3", incident_id: "inc_3", label: "confirmed_true_positive" }));
  // A label whose only signal is a Sentinel-control effect: tracked, not counted.
  store.submit(
    label({
      label_id: "lbl_4",
      incident_id: "inc_4",
      label: "confirmed_true_positive",
      signal_origins: { ...ORGANIC, origin_signal: false, sentinel_control_effect: true },
    }),
  );

  const report = store.calibrationReport(incidents, "compound.account_compromise");
  assert.equal(report.labeled, 4);
  assert.equal(report.decided, 3, "control-effect-only label is excluded from outcome rates");
  assert.equal(report.true_positive, 2);
  assert.equal(report.false_positive, 1);
  assert.equal(report.control_effect_only_labels, 1);
  assert.ok(report.precision !== null && Math.abs(report.precision - 2 / 3) < 1e-9);
  assert.ok(report.calibration_gap !== null && report.calibration_gap >= 0);
});
