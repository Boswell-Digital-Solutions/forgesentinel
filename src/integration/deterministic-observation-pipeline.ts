import { canonicalJson, sha256Hex } from "../contracts/common.js";
import type { CollectionResult } from "./bounded-local-collector.js";
import { containsRestrictedCanary, redactGeneralOutput, verifyCandidate, type VerificationResult } from "../intel/assurance-verifier.js";
import { evaluateAssurance, type ExpansionCandidate, type ExpansionLane, type ExpansionSeverity } from "../intel/security-assurance.js";
import { calculateMetrics, type QualificationMetrics } from "../intel/qualification-metrics.js";
import { createFinding, updateFinding, type FindingVersion } from "../intel/finding-lineage.js";

export const OBSERVATION_PIPELINE_ID = "forgesentinel.deterministic-observation-pipeline.v0.1";

export interface ObservationRule {
  readonly ruleId: string;
  readonly lane: ExpansionLane;
  readonly severity: ExpansionSeverity;
  readonly surface: string;
  readonly evidencePath: string;
  readonly needle: string;
  readonly expected: "present" | "absent";
  readonly oracleExpectedClassification: "FINDING" | "SUPPORTED";
}

export interface ObservationPipelineInput {
  readonly collection: CollectionResult;
  readonly targetId: string;
  readonly procedureMajor: number;
  readonly analyzerStateToken: string;
  readonly verifierId: string;
  readonly verifierStateToken: string;
  readonly verifierAvailable: boolean;
  readonly rules: readonly ObservationRule[];
  readonly priorFindings?: Readonly<Record<string, FindingVersion>>;
  readonly reopenFindingIds?: readonly string[];
}

export interface PipelineGap { readonly lane: ExpansionLane | "all"; readonly ruleId: string; readonly reason: string; readonly evidencePath?: string; }
export interface GeneralFindingView { readonly findingId: string; readonly lane: ExpansionLane; readonly severity: ExpansionSeverity; readonly state: FindingVersion["state"]; readonly summary: string; }
export interface ObservationPipelineResult {
  readonly pipelineId: typeof OBSERVATION_PIPELINE_ID;
  readonly pipelineRunId: string;
  readonly collectionRunId: string;
  readonly posture: "HEALTHY" | "FINDINGS" | "INCOMPLETE" | "BLOCKED";
  readonly candidates: readonly ExpansionCandidate[];
  readonly verifications: readonly VerificationResult[];
  readonly findings: readonly FindingVersion[];
  readonly gaps: readonly PipelineGap[];
  readonly metrics: QualificationMetrics;
  readonly generalOutput: readonly GeneralFindingView[];
  readonly redactionLeaks: 0;
  readonly acceptedEffects: 0;
  readonly integrity: { readonly hash: string };
}

function emptyMetrics(): QualificationMetrics {
  return { strata: [], s0s1Recall: 1, disagreementVisibility: 1, hiddenFailedStrata: [] };
}

function finish(body: Omit<ObservationPipelineResult, "pipelineRunId" | "integrity">): ObservationPipelineResult {
  const hash = sha256Hex(canonicalJson(body));
  return { ...body, pipelineRunId: `opipe_${hash.slice(0, 24)}`, integrity: { hash: `sha256:${hash}` } };
}

export function runDeterministicObservationPipeline(input: ObservationPipelineInput): ObservationPipelineResult {
  const base = {
    pipelineId: OBSERVATION_PIPELINE_ID as typeof OBSERVATION_PIPELINE_ID,
    collectionRunId: input.collection.runId,
    acceptedEffects: 0 as const,
    redactionLeaks: 0 as const,
  };
  if (input.collection.state !== "COMPLETED") {
    return finish({ ...base, posture: "BLOCKED", candidates: [], verifications: [], findings: [], gaps: input.collection.gaps.map((gap) => ({ lane: "all" as const, ruleId: "collection", reason: gap.reason, evidencePath: gap.path })), metrics: emptyMetrics(), generalOutput: [] });
  }
  if (input.rules.length === 0) {
    return finish({ ...base, posture: "INCOMPLETE", candidates: [], verifications: [], findings: [], gaps: [{ lane: "all", ruleId: "rules", reason: "no_rules" }], metrics: emptyMetrics(), generalOutput: [] });
  }
  const evidence = new Map(input.collection.observations.map((item) => [item.path, item]));
  const candidates: ExpansionCandidate[] = [];
  const verifications: VerificationResult[] = [];
  const findings: FindingVersion[] = [];
  const gaps: PipelineGap[] = input.collection.gaps.map((gap) => ({ lane: "all", ruleId: "collection", reason: gap.reason, evidencePath: gap.path }));
  const metricRows = [];
  const seenRules = new Set<string>();

  for (const rule of [...input.rules].sort((a, b) => a.lane.localeCompare(b.lane) || a.ruleId.localeCompare(b.ruleId))) {
    const ruleKey = `${rule.lane}|${rule.ruleId}`;
    if (seenRules.has(ruleKey)) { gaps.push({ lane: rule.lane, ruleId: rule.ruleId, reason: "duplicate_rule", evidencePath: rule.evidencePath }); continue; }
    seenRules.add(ruleKey);
    if (!rule.needle) { gaps.push({ lane: rule.lane, ruleId: rule.ruleId, reason: "empty_needle", evidencePath: rule.evidencePath }); continue; }
    const observation = evidence.get(rule.evidencePath);
    if (!observation) { gaps.push({ lane: rule.lane, ruleId: rule.ruleId, reason: "evidence_missing", evidencePath: rule.evidencePath }); continue; }
    const observed = observation.content.includes(rule.needle) ? "present" : "absent";
    const candidate = evaluateAssurance({ fixtureId: input.collection.runId, lane: rule.lane, ruleId: rule.ruleId, targetId: input.targetId, surface: rule.surface, severity: rule.severity, expected: rule.expected, observed, evidenceRefs: [observation.digest], analyzerStateToken: input.analyzerStateToken });
    const verification = verifyCandidate({ candidate, verifierId: input.verifierId, verifierStateToken: input.verifierStateToken, oracleRuleId: `oracle.${rule.ruleId}.v1`, expectedClassification: rule.oracleExpectedClassification, evidenceAvailable: true, verifierAvailable: input.verifierAvailable, candidateSource: "deterministic" });
    candidates.push(candidate); verifications.push(verification);
    const disagreement = verification.state === "NOT_CONFIRMED" || verification.state === "INDEPENDENCE_VIOLATION";
    metricRows.push({ fixtureId: candidate.fixtureId, lane: candidate.lane, severity: candidate.severity, expectedFinding: rule.oracleExpectedClassification === "FINDING", observedFinding: candidate.classification === "FINDING", disagreementIntroduced: disagreement, disagreementVisible: !disagreement || verification.disagreementVisible || verification.state === "INDEPENDENCE_VIOLATION" });
    if (candidate.classification === "FINDING" && verification.state === "CONFIRMED") {
      const identity = { targetId: candidate.targetId, lane: candidate.lane, ruleId: candidate.ruleId, surface: candidate.surface, procedureMajor: input.procedureMajor };
      const created = createFinding(identity, candidate.evidenceRefs, candidate.severity);
      const prior = input.priorFindings?.[created.findingId];
      findings.push(prior ? updateFinding(prior, { identity, evidenceRefs: candidate.evidenceRefs, severity: candidate.severity, duplicate: prior.evidenceRefs.every((ref) => candidate.evidenceRefs.includes(ref)), reopen: input.reopenFindingIds?.includes(prior.findingId) === true }) : created);
    }
  }
  for (const verification of verifications) {
    if (verification.state !== "CONFIRMED") gaps.push({ lane: candidates.find((candidate) => candidate.candidateId === verification.candidateId)?.lane ?? "all", ruleId: verification.oracleRuleId, reason: verification.reason });
  }
  const metrics = calculateMetrics(metricRows);
  for (const stratum of metrics.hiddenFailedStrata) gaps.push({ lane: stratum.split("|")[0] as ExpansionLane, ruleId: "metrics", reason: `hidden_failed_stratum:${stratum}` });
  const rawGeneral = findings.map((finding) => ({ findingId: finding.findingId, lane: finding.lane, severity: finding.severity, state: finding.state, summary: candidates.find((candidate) => candidate.ruleId === finding.ruleId && candidate.lane === finding.lane)?.summary ?? "Confirmed scoped finding." }));
  const generalOutput = redactGeneralOutput(rawGeneral) as GeneralFindingView[];
  if (containsRestrictedCanary(generalOutput)) gaps.push({ lane: "all", ruleId: "redaction", reason: "redaction_failure" });
  const criticalVerificationFailure = verifications.some((item) => item.state === "BLOCKED" || item.state === "INDEPENDENCE_VIOLATION");
  const posture = criticalVerificationFailure ? "BLOCKED" : gaps.length > 0 || verifications.some((item) => item.state !== "CONFIRMED") ? "INCOMPLETE" : findings.length > 0 ? "FINDINGS" : "HEALTHY";
  return finish({ ...base, posture, candidates, verifications, findings, gaps: gaps.sort((a,b)=>`${a.lane}|${a.ruleId}|${a.reason}`.localeCompare(`${b.lane}|${b.ruleId}|${b.reason}`)), metrics, generalOutput, acceptedEffects: 0, redactionLeaks: 0 });
}
