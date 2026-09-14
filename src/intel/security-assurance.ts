import { canonicalJson, sha256Hex } from "../contracts/common.js";

export const EXPANSION_ANALYZER_ID = "forgesentinel.assurance-expansion.v0.1";

export type ExpansionLane = "security" | "truthfulness" | "accuracy";
export type ExpansionSeverity = "S0" | "S1" | "S2" | "S3" | "S4";

export interface ExpansionInput {
  readonly fixtureId: string;
  readonly lane: ExpansionLane;
  readonly ruleId: string;
  readonly targetId: string;
  readonly surface: string;
  readonly severity: ExpansionSeverity;
  readonly expected: string;
  readonly observed: string;
  readonly evidenceRefs: readonly string[];
  readonly analyzerStateToken: string;
}

export interface ExpansionCandidate {
  readonly candidateId: string;
  readonly fixtureId: string;
  readonly lane: ExpansionLane;
  readonly ruleId: string;
  readonly targetId: string;
  readonly surface: string;
  readonly severity: ExpansionSeverity;
  readonly classification: "FINDING" | "SUPPORTED";
  readonly evidenceRefs: readonly string[];
  readonly analyzerId: typeof EXPANSION_ANALYZER_ID;
  readonly analyzerStateToken: string;
  readonly summary: string;
  readonly acceptedEffects: 0;
}

export function evaluateAssurance(input: ExpansionInput): ExpansionCandidate {
  const classification = input.expected === input.observed ? "SUPPORTED" : "FINDING";
  const identity = canonicalJson({
    fixtureId: input.fixtureId,
    lane: input.lane,
    ruleId: input.ruleId,
    targetId: input.targetId,
    surface: input.surface,
    expected: input.expected,
    observed: input.observed,
  });
  return {
    candidateId: `acand_${sha256Hex(identity).slice(0, 24)}`,
    fixtureId: input.fixtureId,
    lane: input.lane,
    ruleId: input.ruleId,
    targetId: input.targetId,
    surface: input.surface,
    severity: input.severity,
    classification,
    evidenceRefs: [...new Set(input.evidenceRefs)].sort(),
    analyzerId: EXPANSION_ANALYZER_ID,
    analyzerStateToken: input.analyzerStateToken,
    summary: classification === "SUPPORTED"
      ? `The scoped ${input.lane} expectation is supported by the supplied evidence.`
      : `The scoped ${input.lane} expectation is contradicted by the supplied evidence.`,
    acceptedEffects: 0,
  };
}
