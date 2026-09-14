import { validateFeedbackLabel, type FeedbackLabel } from "../contracts/feedback.js";
import type { Incident } from "../contracts/incident.js";
import type { ValidationResult } from "../contracts/common.js";
import type { EvidenceLedger } from "../spine/ledger.js";

/**
 * Reviewed-feedback store (05, SNT-400/405). Operator actions are receipts,
 * not labels (ADR-012); labels enter here only after review, and a record
 * is training-eligible only with explicit privacy approval (ADR-004).
 * Policy-generated effects are tracked separately and never count toward
 * observed outcome rates (SNT-405).
 */
export class FeedbackStore {
  private readonly labels: FeedbackLabel[] = [];

  constructor(private readonly ledger?: EvidenceLedger) {}

  submit(label: FeedbackLabel): ValidationResult {
    const result = validateFeedbackLabel(label);
    if (!result.ok) return result;
    this.labels.push(label);
    this.ledger?.append({
      kind: "feedback_label",
      gateway_version: "feedback-store.1.0.0",
      validation: "accepted",
      transformation_version: "1.0.0",
      body: label,
    });
    return result;
  }

  all(): readonly FeedbackLabel[] {
    return this.labels;
  }

  /** No record is automatically eligible: both flags must be explicit. */
  trainingSet(): FeedbackLabel[] {
    return this.labels.filter((label) => label.training_eligible && label.privacy_approved);
  }

  calibrationReport(incidents: Incident[], incidentType: string): CalibrationReport {
    const byId = new Map(incidents.map((incident) => [incident.incident_id, incident]));
    const eligible = this.labels.filter((label) => {
      const incident = byId.get(label.incident_id);
      return incident !== undefined && incident.incident_type === incidentType && label.calibration_eligible;
    });

    // Control-effect-only labels are reported, never mixed into outcome rates.
    const controlEffectOnly = eligible.filter((label) => label.signal_origins.sentinel_control_effect && !label.signal_origins.origin_signal);
    const organic = eligible.filter((label) => !(label.signal_origins.sentinel_control_effect && !label.signal_origins.origin_signal));

    const positives = organic.filter((label) => POSITIVE_LABELS.has(label.label));
    const negatives = organic.filter((label) => NEGATIVE_LABELS.has(label.label));
    const decided = positives.length + negatives.length;
    const likelihoods = organic
      .map((label) => byId.get(label.incident_id)?.risk.likelihood)
      .filter((value): value is number => value !== undefined);
    const meanPredicted = likelihoods.length > 0 ? likelihoods.reduce((sum, value) => sum + value, 0) / likelihoods.length : 0;
    const observedRate = decided > 0 ? positives.length / decided : 0;

    return {
      incident_type: incidentType,
      labeled: eligible.length,
      decided,
      true_positive: positives.length,
      false_positive: negatives.length,
      undecided: organic.length - decided,
      precision: decided > 0 ? positives.length / decided : null,
      mean_predicted_likelihood: Number(meanPredicted.toFixed(4)),
      observed_positive_rate: Number(observedRate.toFixed(4)),
      calibration_gap: decided > 0 ? Number(Math.abs(meanPredicted - observedRate).toFixed(4)) : null,
      control_effect_only_labels: controlEffectOnly.length,
    };
  }
}

const POSITIVE_LABELS = new Set<FeedbackLabel["label"]>(["confirmed_true_positive", "action_effective"]);
const NEGATIVE_LABELS = new Set<FeedbackLabel["label"]>(["confirmed_false_positive", "benign_expected_change", "duplicate"]);

export interface CalibrationReport {
  incident_type: string;
  labeled: number;
  decided: number;
  true_positive: number;
  false_positive: number;
  undecided: number;
  precision: number | null;
  mean_predicted_likelihood: number;
  observed_positive_rate: number;
  calibration_gap: number | null;
  control_effect_only_labels: number;
}
