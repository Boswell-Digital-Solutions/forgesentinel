import { canonicalJson, sha256Hex } from "../contracts/common.js";
import type { ExpansionLane, ExpansionSeverity } from "./security-assurance.js";

export interface FindingIdentity {
  readonly targetId: string;
  readonly lane: ExpansionLane;
  readonly ruleId: string;
  readonly surface: string;
  readonly procedureMajor: number;
}

export interface FindingVersion extends FindingIdentity {
  readonly findingId: string;
  readonly evidenceRefs: readonly string[];
  readonly severity: ExpansionSeverity;
  readonly state: "OPEN" | "RESOLVED" | "REOPENED" | "SUPERSEDED";
  readonly version: number;
  readonly priorFindingId?: string;
  readonly duplicateDeliveries: number;
}

export function stableFindingId(identity: FindingIdentity): string {
  const canonicalIdentity: FindingIdentity = {
    targetId: identity.targetId,
    lane: identity.lane,
    ruleId: identity.ruleId,
    surface: identity.surface,
    procedureMajor: identity.procedureMajor,
  };
  return `afind_${sha256Hex(canonicalJson(canonicalIdentity)).slice(0, 24)}`;
}

export function createFinding(
  identity: FindingIdentity,
  evidenceRefs: readonly string[],
  severity: ExpansionSeverity,
): FindingVersion {
  return {
    ...identity,
    findingId: stableFindingId(identity),
    evidenceRefs: [...new Set(evidenceRefs)].sort(),
    severity,
    state: "OPEN",
    version: 1,
    duplicateDeliveries: 0,
  };
}

export function updateFinding(
  prior: FindingVersion,
  input: {
    readonly identity: FindingIdentity;
    readonly evidenceRefs: readonly string[];
    readonly severity: ExpansionSeverity;
    readonly duplicate?: boolean;
    readonly reopen?: boolean;
  },
): FindingVersion {
  const nextId = stableFindingId(input.identity);
  const procedureChanged = prior.procedureMajor !== input.identity.procedureMajor;
  const materialChanged = nextId !== prior.findingId;
  if (procedureChanged) {
    return {
      ...input.identity,
      findingId: nextId,
      evidenceRefs: [...new Set(input.evidenceRefs)].sort(),
      severity: input.severity,
      state: "SUPERSEDED",
      version: 1,
      priorFindingId: prior.findingId,
      duplicateDeliveries: 0,
    };
  }
  if (materialChanged) {
    return {
      ...input.identity,
      findingId: nextId,
      evidenceRefs: [...new Set(input.evidenceRefs)].sort(),
      severity: input.severity,
      state: "OPEN",
      version: 1,
      priorFindingId: prior.findingId,
      duplicateDeliveries: 0,
    };
  }
  return {
    ...prior,
    evidenceRefs: [...new Set([...prior.evidenceRefs, ...input.evidenceRefs])].sort(),
    severity: input.severity,
    state: input.reopen === true ? "REOPENED" : prior.state,
    version: input.duplicate === true ? prior.version : prior.version + 1,
    duplicateDeliveries: prior.duplicateDeliveries + (input.duplicate === true ? 1 : 0),
  };
}
