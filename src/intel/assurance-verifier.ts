import { canonicalJson, sha256Hex } from "../contracts/common.js";
import type { ExpansionCandidate } from "./security-assurance.js";

export const EXPANSION_VERIFIER_ID = "hephaestus.assurance-verifier.v0.1";

export type VerificationState =
  | "CONFIRMED"
  | "NOT_CONFIRMED"
  | "INCONCLUSIVE"
  | "BLOCKED"
  | "INDEPENDENCE_VIOLATION";

export interface VerificationInput {
  readonly candidate: ExpansionCandidate;
  readonly verifierId: string;
  readonly verifierStateToken: string;
  readonly oracleRuleId: string;
  readonly expectedClassification: "FINDING" | "SUPPORTED";
  readonly evidenceAvailable: boolean;
  readonly verifierAvailable: boolean;
  readonly requiredEvidenceMissing?: boolean;
  readonly candidateSource?: "deterministic" | "model-shaped";
}

export interface VerificationResult {
  readonly verificationId: string;
  readonly candidateId: string;
  readonly verifierId: string;
  readonly oracleRuleId: string;
  readonly state: VerificationState;
  readonly reason: string;
  readonly disagreementVisible: boolean;
  readonly acceptedEffects: 0;
  readonly integrity: { readonly hash: string };
}

export function verifyCandidate(input: VerificationInput): VerificationResult {
  let state: VerificationState;
  let reason: string;
  if (
    input.candidate.analyzerId === input.verifierId ||
    input.candidate.analyzerStateToken === input.verifierStateToken
  ) {
    state = "INDEPENDENCE_VIOLATION";
    reason = "analyzer_and_verifier_not_independent";
  } else if (!input.verifierAvailable) {
    state = "BLOCKED";
    reason = "verifier_unavailable";
  } else if (!input.evidenceAvailable) {
    state = "INCONCLUSIVE";
    reason = "evidence_unavailable";
  } else if (
    input.requiredEvidenceMissing === true &&
    input.candidate.classification === "SUPPORTED"
  ) {
    state = "NOT_CONFIRMED";
    reason = "false_completion_rejected";
  } else if (input.candidate.classification === input.expectedClassification) {
    state = "CONFIRMED";
    reason = "independent_rule_agrees";
  } else {
    state = "NOT_CONFIRMED";
    reason = "independent_rule_disagrees";
  }
  const disagreementVisible =
    state === "NOT_CONFIRMED" ||
    (input.candidateSource === "model-shaped" && state !== "CONFIRMED");
  const body = {
    candidateId: input.candidate.candidateId,
    verifierId: input.verifierId,
    oracleRuleId: input.oracleRuleId,
    state,
    reason,
    disagreementVisible,
    acceptedEffects: 0 as const,
  };
  const hash = sha256Hex(canonicalJson(body));
  return {
    ...body,
    verificationId: `aver_${hash.slice(0, 24)}`,
    integrity: { hash: `sha256:${hash}` },
  };
}

const CANARY = /syn_secret_marker_[A-Za-z0-9_-]+/g;

export function redactGeneralOutput(value: unknown): unknown {
  if (typeof value === "string") {
    return value.replace(CANARY, (match) => `[REDACTED:sha256:${sha256Hex(match).slice(0, 16)}]`);
  }
  if (Array.isArray(value)) return value.map(redactGeneralOutput);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => [key, redactGeneralOutput(item)]),
    );
  }
  return value;
}

export function containsRestrictedCanary(value: unknown): boolean {
  return canonicalJson(value).includes("syn_secret_marker_");
}
