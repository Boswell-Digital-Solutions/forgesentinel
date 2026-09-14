import { canonicalJson, sha256Hex } from "../contracts/common.js";

export const MISSION_QUALIFIER_ID = "forgesentinel.mission-qualifier.v0.1";

export type MissionState = "COMPLETED" | "BLOCKED" | "HALTED" | "EXPIRED" | "FAILED" | "PAUSED";
export type TargetState = "admitted" | "unknown" | "conflicted" | "stale";
export type OperationKind = "read" | "write" | "network";

export interface MissionGrant {
  readonly missionId: string;
  readonly authorizationId?: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly revoked?: boolean;
  readonly targets: readonly string[];
  readonly sourceRevision: string;
  readonly procedureId: string;
  readonly caps: {
    readonly wallTimeMs: number;
    readonly evidenceBytes: number;
    readonly toolCalls: number;
    readonly retries: number;
  };
}

export interface InventoryTarget {
  readonly targetId: string;
  readonly state: TargetState;
  readonly revision: string;
  readonly freshUntil: string;
}

export interface MissionOperation {
  readonly operationId: string;
  readonly targetId: string;
  readonly kind: OperationKind;
  readonly at: string;
  readonly elapsedMs: number;
  readonly evidenceBytes: number;
  readonly failureClass?: "transient" | "authority" | "schema" | "integrity" | "scope";
}

export interface MissionInput {
  readonly now: string;
  readonly grant?: MissionGrant;
  readonly inventory: readonly InventoryTarget[];
  readonly operations: readonly MissionOperation[];
  readonly control?: "pause" | "stop" | "kill" | "channel_lost";
  readonly restartOf?: string;
}

export interface CoverageResult {
  readonly requiredTargets: readonly string[];
  readonly inspectedTargets: readonly string[];
  readonly gaps: readonly { targetId: string; reason: string }[];
}

export interface MissionReceipt {
  readonly receiptId: string;
  readonly missionId: string;
  readonly authorizationId: string | null;
  readonly qualifierId: typeof MISSION_QUALIFIER_ID;
  readonly procedureId: string | null;
  readonly sourceRevision: string | null;
  readonly state: MissionState;
  readonly reason: string;
  readonly at: string;
  readonly parentReceiptId?: string;
  readonly usage: {
    readonly elapsedMs: number;
    readonly evidenceBytes: number;
    readonly toolCalls: number;
    readonly retries: number;
  };
  readonly acceptedEffects: 0;
  readonly integrity: { readonly hash: string };
}

export interface MissionResult {
  readonly state: MissionState;
  readonly reason: string;
  readonly coverage: CoverageResult;
  readonly receipts: readonly MissionReceipt[];
  readonly acceptedEffects: 0;
}

function validIso(value: string): boolean {
  return Number.isFinite(Date.parse(value));
}

function receipt(
  input: MissionInput,
  state: MissionState,
  reason: string,
  usage: MissionReceipt["usage"],
  parentReceiptId?: string,
): MissionReceipt {
  const core = {
    missionId: input.grant?.missionId ?? "unassigned",
    authorizationId: input.grant?.authorizationId ?? null,
    qualifierId: MISSION_QUALIFIER_ID as typeof MISSION_QUALIFIER_ID,
    procedureId: input.grant?.procedureId ?? null,
    sourceRevision: input.grant?.sourceRevision ?? null,
    state,
    reason,
    at: input.now,
    usage,
    acceptedEffects: 0 as const,
  };
  const body: Omit<MissionReceipt, "receiptId" | "integrity"> = parentReceiptId === undefined
    ? core
    : { ...core, parentReceiptId };
  const hash = sha256Hex(canonicalJson(body));
  return { ...body, receiptId: `mrcpt_${hash.slice(0, 24)}`, integrity: { hash: `sha256:${hash}` } };
}

function emptyCoverage(input: MissionInput, reason: string): CoverageResult {
  return {
    requiredTargets: [...(input.grant?.targets ?? [])].sort(),
    inspectedTargets: [],
    gaps: [...(input.grant?.targets ?? [])].sort().map((targetId) => ({ targetId, reason })),
  };
}

function finish(
  input: MissionInput,
  state: MissionState,
  reason: string,
  coverage: CoverageResult,
  usage: MissionReceipt["usage"],
  parentReceiptId?: string,
): MissionResult {
  return { state, reason, coverage, receipts: [receipt(input, state, reason, usage, parentReceiptId)], acceptedEffects: 0 };
}

const ZERO_USAGE = { elapsedMs: 0, evidenceBytes: 0, toolCalls: 0, retries: 0 } as const;

export function qualifyMission(input: MissionInput): MissionResult {
  const grant = input.grant;
  if (grant === undefined || grant.authorizationId === undefined || grant.authorizationId.length === 0) {
    return finish(input, "BLOCKED", "missing_authority", emptyCoverage(input, "authority_not_validated"), ZERO_USAGE);
  }
  if (!validIso(input.now) || !validIso(grant.issuedAt) || !validIso(grant.expiresAt)) {
    return finish(input, "BLOCKED", "malformed_time", emptyCoverage(input, "time_invalid"), ZERO_USAGE);
  }
  const now = Date.parse(input.now);
  if (grant.revoked === true) {
    return finish(input, "HALTED", "authorization_revoked", emptyCoverage(input, "authorization_revoked"), ZERO_USAGE);
  }
  if (now < Date.parse(grant.issuedAt)) {
    return finish(input, "BLOCKED", "authorization_not_yet_valid", emptyCoverage(input, "authority_not_validated"), ZERO_USAGE);
  }
  if (now >= Date.parse(grant.expiresAt)) {
    return finish(input, "EXPIRED", "authorization_expired", emptyCoverage(input, "authorization_expired"), ZERO_USAGE);
  }
  if (input.control !== undefined) {
    const state: MissionState = input.control === "pause" ? "PAUSED" : input.control === "channel_lost" ? "FAILED" : "HALTED";
    const result = finish(input, state, `control_${input.control}`, emptyCoverage(input, `control_${input.control}`), ZERO_USAGE);
    if (input.restartOf !== undefined) {
      return finish(input, state, `control_${input.control}`, result.coverage, ZERO_USAGE, input.restartOf);
    }
    return result;
  }

  const inventory = new Map(input.inventory.map((target) => [target.targetId, target]));
  const gaps: { targetId: string; reason: string }[] = [];
  const eligible = new Set<string>();
  for (const targetId of [...grant.targets].sort()) {
    const target = inventory.get(targetId);
    if (target === undefined) gaps.push({ targetId, reason: "unknown_target" });
    else if (target.state !== "admitted") gaps.push({ targetId, reason: `${target.state}_target` });
    else if (!validIso(target.freshUntil) || now >= Date.parse(target.freshUntil)) gaps.push({ targetId, reason: "stale_inventory" });
    else if (target.revision !== grant.sourceRevision) gaps.push({ targetId, reason: "revision_drift" });
    else eligible.add(targetId);
  }

  let elapsedMs = 0;
  let evidenceBytes = 0;
  let toolCalls = 0;
  let retries = 0;
  const inspected = new Set<string>();
  for (const operation of input.operations) {
    if (!grant.targets.includes(operation.targetId)) {
      return finish(input, "BLOCKED", "scope_mismatch", {
        requiredTargets: [...grant.targets].sort(), inspectedTargets: [...inspected].sort(), gaps,
      }, { elapsedMs, evidenceBytes, toolCalls, retries });
    }
    if (!eligible.has(operation.targetId)) continue;
    if (!validIso(operation.at) || Date.parse(operation.at) >= Date.parse(grant.expiresAt)) {
      return finish(input, "EXPIRED", "authorization_expired_mid_stage", {
        requiredTargets: [...grant.targets].sort(), inspectedTargets: [...inspected].sort(), gaps,
      }, { elapsedMs, evidenceBytes, toolCalls, retries });
    }
    if (operation.kind !== "read") {
      return finish(input, "HALTED", `intercepted_${operation.kind}_effect`, {
        requiredTargets: [...grant.targets].sort(), inspectedTargets: [...inspected].sort(), gaps,
      }, { elapsedMs, evidenceBytes, toolCalls, retries });
    }
    const nextElapsed = Math.max(elapsedMs, operation.elapsedMs);
    const nextBytes = evidenceBytes + operation.evidenceBytes;
    const nextCalls = toolCalls + 1;
    if (nextElapsed > grant.caps.wallTimeMs) {
      gaps.push({ targetId: operation.targetId, reason: "wall_time_cap" });
      return finish(input, "HALTED", "wall_time_cap", { requiredTargets: [...grant.targets].sort(), inspectedTargets: [...inspected].sort(), gaps }, { elapsedMs, evidenceBytes, toolCalls, retries });
    }
    if (nextBytes > grant.caps.evidenceBytes) {
      gaps.push({ targetId: operation.targetId, reason: "evidence_byte_cap" });
      return finish(input, "HALTED", "evidence_byte_cap", { requiredTargets: [...grant.targets].sort(), inspectedTargets: [...inspected].sort(), gaps }, { elapsedMs, evidenceBytes, toolCalls, retries });
    }
    if (nextCalls > grant.caps.toolCalls) {
      gaps.push({ targetId: operation.targetId, reason: "tool_call_cap" });
      return finish(input, "HALTED", "tool_call_cap", { requiredTargets: [...grant.targets].sort(), inspectedTargets: [...inspected].sort(), gaps }, { elapsedMs, evidenceBytes, toolCalls, retries });
    }
    elapsedMs = nextElapsed;
    evidenceBytes = nextBytes;
    toolCalls = nextCalls;
    if (operation.failureClass !== undefined) {
      if (operation.failureClass === "transient" && retries < grant.caps.retries) {
        retries += 1;
        continue;
      }
      gaps.push({ targetId: operation.targetId, reason: `${operation.failureClass}_failure` });
      return finish(input, "FAILED", `${operation.failureClass}_failure`, {
        requiredTargets: [...grant.targets].sort(), inspectedTargets: [...inspected].sort(), gaps,
      }, { elapsedMs, evidenceBytes, toolCalls, retries });
    }
    inspected.add(operation.targetId);
  }

  for (const targetId of eligible) {
    if (!inspected.has(targetId)) gaps.push({ targetId, reason: "collector_failure" });
  }
  const coverage: CoverageResult = {
    requiredTargets: [...grant.targets].sort(),
    inspectedTargets: [...inspected].sort(),
    gaps: gaps.sort((a, b) => a.targetId.localeCompare(b.targetId) || a.reason.localeCompare(b.reason)),
  };
  return finish(input, "COMPLETED", gaps.length === 0 ? "mission_complete" : "mission_complete_with_coverage_gaps", coverage, { elapsedMs, evidenceBytes, toolCalls, retries }, input.restartOf);
}

export interface ReplayComparison {
  readonly identical: boolean;
  readonly reason: "identical" | "source_or_procedure_substitution" | "semantic_or_digest_mismatch";
  readonly first: MissionResult;
  readonly second: MissionResult;
}

export function compareReplay(firstInput: MissionInput, secondInput: MissionInput): ReplayComparison {
  const first = qualifyMission(firstInput);
  const second = qualifyMission(secondInput);
  if (
    firstInput.grant?.sourceRevision !== secondInput.grant?.sourceRevision ||
    firstInput.grant?.procedureId !== secondInput.grant?.procedureId
  ) {
    return { identical: false, reason: "source_or_procedure_substitution", first, second };
  }
  const identical = canonicalJson(first) === canonicalJson(second);
  return { identical, reason: identical ? "identical" : "semantic_or_digest_mismatch", first, second };
}
