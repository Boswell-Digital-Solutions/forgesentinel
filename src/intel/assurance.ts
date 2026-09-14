/**
 * CP2A replay-only assurance analyzers.
 *
 * These types are implementation-local projections. They are not normative
 * shared contracts; forge_contract_core remains the shared contract owner.
 */

export const ASSURANCE_ANALYZER_ID = "forgesentinel.assurance-analyzer.v0.1";

export type AssuranceLane = "coverage" | "truthfulness" | "accuracy";
export type AssuranceClassification =
  | "COVERAGE_GAP"
  | "SUPPORTED"
  | "CONTRADICTED"
  | "INSUFFICIENT_EVIDENCE"
  | "STALE_EVIDENCE"
  | "MATCH"
  | "SOURCE_DRIFT"
  | "UNVERIFIABLE";

export interface AssuranceResult {
  readonly fixtureId: string;
  readonly lane: AssuranceLane;
  readonly classification: AssuranceClassification;
  readonly subject: string;
  readonly evidenceRefs: readonly string[];
  readonly analyzerId: typeof ASSURANCE_ANALYZER_ID;
  readonly summary: string;
  readonly prohibitedInferences: readonly string[];
  readonly contractProjection: "local-finding" | "source_drift_finding.v1";
}

export interface CoverageInput {
  readonly fixtureId: string;
  readonly subject: string;
  readonly admittedTargets: readonly string[];
  readonly observations: readonly {
    readonly source: string;
    readonly observedTargets: readonly string[];
    readonly evidenceRef: string;
  }[];
}

export interface TruthfulnessInput {
  readonly fixtureId: string;
  readonly subject: string;
  readonly claim: {
    readonly statement: string;
    readonly assertedState: string;
    readonly evidenceRef: string;
  };
  readonly implementationEvidence: readonly {
    readonly state: string;
    readonly evidenceRef: string;
    readonly stale?: boolean;
  }[];
}

export interface AccuracyInput {
  readonly fixtureId: string;
  readonly subject: string;
  readonly pinnedCommit: string | null;
  readonly observedCommit: string | null;
  readonly planEvidenceRef: string;
  readonly observationEvidenceRef: string;
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

export function analyzeCoverage(input: CoverageInput): AssuranceResult {
  const admitted = new Set(input.admittedTargets);
  const observed = new Set(input.observations.flatMap((item) => item.observedTargets));
  const missing = [...admitted].filter((target) => !observed.has(target)).sort();
  const sourceDisagreement = input.observations.some((observation) =>
    input.observations.some((other) =>
      observation.observedTargets.some((target) => !other.observedTargets.includes(target)),
    ),
  );

  const hasGap = missing.length > 0 || sourceDisagreement;
  return {
    fixtureId: input.fixtureId,
    lane: "coverage",
    classification: hasGap ? "COVERAGE_GAP" : "SUPPORTED",
    subject: input.subject,
    evidenceRefs: sortedUnique(input.observations.map((item) => item.evidenceRef)),
    analyzerId: ASSURANCE_ANALYZER_ID,
    summary: hasGap
      ? `Coverage is partial: missing admitted targets [${missing.join(", ")}] or inventory sources disagree.`
      : "Every admitted target is observed consistently by the supplied inventory sources.",
    prohibitedInferences: [
      "An unobserved target does not prove that it is absent or nonexistent.",
      "A single inventory source does not prove complete estate coverage.",
      "This result does not authorize repair or mutation.",
    ],
    contractProjection: "local-finding",
  };
}

export function analyzeTruthfulness(input: TruthfulnessInput): AssuranceResult {
  const evidenceRefs = sortedUnique([
    input.claim.evidenceRef,
    ...input.implementationEvidence.map((item) => item.evidenceRef),
  ]);
  let classification: AssuranceClassification;
  let summary: string;

  if (input.implementationEvidence.length === 0) {
    classification = "INSUFFICIENT_EVIDENCE";
    summary = "The scoped claim has no admissible implementation evidence.";
  } else if (input.implementationEvidence.every((item) => item.stale === true)) {
    classification = "STALE_EVIDENCE";
    summary = "The scoped claim cannot be assessed from stale implementation evidence.";
  } else if (
    input.implementationEvidence.some(
      (item) => item.stale !== true && item.state !== input.claim.assertedState,
    )
  ) {
    classification = "CONTRADICTED";
    summary = `The scoped claim asserts '${input.claim.assertedState}' but current evidence reports an incompatible implementation state.`;
  } else {
    classification = "SUPPORTED";
    summary = "The scoped claim corresponds with the supplied current implementation evidence.";
  }

  return {
    fixtureId: input.fixtureId,
    lane: "truthfulness",
    classification,
    subject: input.subject,
    evidenceRefs,
    analyzerId: ASSURANCE_ANALYZER_ID,
    summary,
    prohibitedInferences: [
      "A claim mismatch does not establish intent or deception.",
      "A scoped mismatch does not establish general system unreliability.",
      "This result does not authorize repair or mutation.",
    ],
    contractProjection: "local-finding",
  };
}

export function analyzeAccuracy(input: AccuracyInput): AssuranceResult {
  let classification: AssuranceClassification;
  let summary: string;

  if (input.pinnedCommit === null || input.observedCommit === null) {
    classification = "UNVERIFIABLE";
    summary = "Source alignment cannot be verified because a commit observation is missing.";
  } else if (input.pinnedCommit === input.observedCommit) {
    classification = "MATCH";
    summary = "The source-locked commit matches the observed protected-branch commit.";
  } else {
    classification = "SOURCE_DRIFT";
    summary = "The source-locked commit differs from the observed protected-branch commit.";
  }

  return {
    fixtureId: input.fixtureId,
    lane: "accuracy",
    classification,
    subject: input.subject,
    evidenceRefs: sortedUnique([input.planEvidenceRef, input.observationEvidenceRef]),
    analyzerId: ASSURANCE_ANALYZER_ID,
    summary,
    prohibitedInferences: [
      "Source drift alone does not establish that the plan is substantively wrong.",
      "Source drift alone does not establish that the observed commit is unsafe.",
      "This result does not authorize repair or mutation.",
    ],
    contractProjection: "source_drift_finding.v1",
  };
}

