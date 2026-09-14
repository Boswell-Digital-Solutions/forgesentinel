import type { ValidationIssue } from "../contracts/common.js";
import {
  admissionIdentity,
  FC_ADAPTER_ID,
  FC_RETURN_SCHEMA,
  observationReturnHash,
  REQUIRED_LANES,
  validateForgeCommandMissionAdmission,
  validateForgeCommandObservationReturn,
  type ForgeCommandMissionAdmission,
  type ForgeCommandObservationReturn,
} from "./forge-command-adapter.js";
import {
  collectBoundedLocalText,
  type CollectionResult,
  type CollectorDependencies,
  type CollectorManifest,
} from "./bounded-local-collector.js";
import {
  runDeterministicObservationPipeline,
  type ObservationPipelineResult,
  type ObservationRule,
} from "./deterministic-observation-pipeline.js";

export const SYNTHETIC_FC_HARNESS_ID = "forgesentinel.synthetic-forge-command-harness.v0.1";

export interface SyntheticHarnessInput {
  readonly admission: unknown;
  readonly root: string;
  readonly manifest: CollectorManifest;
  readonly rules: readonly ObservationRule[];
  readonly dependencies: CollectorDependencies;
  readonly seenAdmissionIds?: ReadonlySet<string>;
  readonly verifierAvailable?: boolean;
}

export type SyntheticHarnessResult =
  | {
      readonly harnessId: typeof SYNTHETIC_FC_HARNESS_ID;
      readonly accepted: false;
      readonly admissionId?: string;
      readonly issues: readonly ValidationIssue[];
      readonly acceptedEffects: 0;
    }
  | {
      readonly harnessId: typeof SYNTHETIC_FC_HARNESS_ID;
      readonly accepted: true;
      readonly admissionId: string;
      readonly collection: CollectionResult;
      readonly pipeline: ObservationPipelineResult;
      readonly observationReturn: ForgeCommandObservationReturn;
      readonly acceptedEffects: 0;
    };

function rejected(issues: readonly ValidationIssue[], admissionId?: string): SyntheticHarnessResult {
  return admissionId === undefined
    ? { harnessId: SYNTHETIC_FC_HARNESS_ID, accepted: false, issues, acceptedEffects: 0 }
    : { harnessId: SYNTHETIC_FC_HARNESS_ID, accepted: false, admissionId, issues, acceptedEffects: 0 };
}

function terminalState(collection: CollectionResult, pipeline: ObservationPipelineResult): ForgeCommandObservationReturn["state"] {
  if (collection.state === "HALTED") return "HALTED";
  if (collection.state === "EXPIRED") return "EXPIRED";
  if (collection.state === "FAILED") return "FAILED";
  if (collection.state === "BLOCKED" || pipeline.posture === "BLOCKED") return "BLOCKED";
  return "COMPLETED";
}

function terminalReason(collection: CollectionResult, pipeline: ObservationPipelineResult): string {
  if (collection.state !== "COMPLETED") return collection.reason;
  if (pipeline.posture === "HEALTHY") return "healthy";
  if (pipeline.posture === "FINDINGS") return "confirmed_findings";
  if (pipeline.posture === "INCOMPLETE") return "incomplete_analysis";
  return "analysis_blocked";
}

export function runSyntheticForgeCommandHarness(input: SyntheticHarnessInput): SyntheticHarnessResult {
  const validation = validateForgeCommandMissionAdmission(input.admission, input.dependencies.now());
  if (!validation.ok) return rejected(validation.issues);
  const admission = input.admission as ForgeCommandMissionAdmission;
  const admissionId = admissionIdentity(admission);
  if (input.seenAdmissionIds?.has(admissionId) === true) {
    return rejected([{ path: "$", code: "replay", message: "synthetic admission was already consumed" }], admissionId);
  }

  const collection = collectBoundedLocalText(input.root, admission, input.manifest, input.dependencies);
  const pipeline = runDeterministicObservationPipeline({
    collection,
    targetId: admission.target.registryId,
    procedureMajor: admission.procedure.major,
    analyzerStateToken: admission.identities.analyzerStateToken,
    verifierId: admission.identities.verifierId,
    verifierStateToken: admission.identities.verifierStateToken,
    verifierAvailable: input.verifierAvailable ?? true,
    rules: input.rules,
  });
  const inspectedLanes = [...new Set(pipeline.candidates.map((candidate) => candidate.lane))].sort();
  const body: Omit<ForgeCommandObservationReturn, "integrity"> = {
    schemaVersion: FC_RETURN_SCHEMA,
    adapterId: FC_ADAPTER_ID,
    missionId: admission.missionId,
    runId: admission.runId,
    intentId: admission.intentId,
    authorizationId: admission.authorizationId,
    registryId: admission.target.registryId,
    commitSha: admission.target.commitSha,
    treeSha: admission.target.treeSha,
    procedureId: admission.procedure.id,
    procedureMajor: admission.procedure.major,
    state: terminalState(collection, pipeline),
    reason: terminalReason(collection, pipeline),
    coverage: {
      requiredLanes: [...REQUIRED_LANES].sort(),
      inspectedLanes,
      gaps: pipeline.gaps.map((gap) => ({ lane: gap.lane, reason: `${gap.ruleId}:${gap.reason}` })),
    },
    usage: collection.usage,
    disagreementCount: pipeline.verifications.filter((item) => item.state === "NOT_CONFIRMED" || item.state === "INDEPENDENCE_VIOLATION").length,
    inconclusiveCount: pipeline.gaps.length,
    redactionLeaks: pipeline.redactionLeaks,
    acceptedEffects: 0,
  };
  const observationReturn: ForgeCommandObservationReturn = { ...body, integrity: { hash: observationReturnHash(body) } };
  const returnValidation = validateForgeCommandObservationReturn(observationReturn);
  if (!returnValidation.ok) return rejected(returnValidation.issues, admissionId);
  return { harnessId: SYNTHETIC_FC_HARNESS_ID, accepted: true, admissionId, collection, pipeline, observationReturn, acceptedEffects: 0 };
}
