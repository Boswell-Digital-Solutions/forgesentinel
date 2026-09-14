import { canonicalJson, isRecord, sha256Hex, type ValidationIssue, type ValidationResult } from "../contracts/common.js";

export const FC_ADMISSION_SCHEMA = "forgesentinel.forge-command-adapter.mission.v1";
export const FC_RETURN_SCHEMA = "forgesentinel.forge-command-adapter.return.v1";
export const FC_ADAPTER_ID = "forgesentinel.forge-command-adapter.v0.1";
export const REQUIRED_LANES = ["security", "truthfulness", "accuracy"] as const;

export type AdapterTerminalState = "COMPLETED" | "BLOCKED" | "HALTED" | "EXPIRED" | "FAILED" | "PAUSED";

export interface ForgeCommandMissionAdmission {
  readonly schemaVersion: typeof FC_ADMISSION_SCHEMA;
  readonly missionId: string;
  readonly runId: string;
  readonly intentId: string;
  readonly authorizationId: string;
  readonly issuerId: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly notBefore: string;
  readonly expiresAt: string;
  readonly freshnessDeadline: string;
  readonly target: {
    readonly registryId: string;
    readonly repository: string;
    readonly registryState: "admitted";
    readonly commitSha: string;
    readonly treeSha: string;
  };
  readonly procedure: { readonly id: string; readonly major: 1 };
  readonly lanes: readonly (typeof REQUIRED_LANES)[number][];
  readonly caps: {
    readonly wallTimeMs: number;
    readonly evidenceBytes: number;
    readonly fileCount: number;
    readonly readOps: number;
    readonly retries: number;
  };
  readonly identities: {
    readonly analyzerId: string;
    readonly analyzerStateToken: string;
    readonly verifierId: string;
    readonly verifierStateToken: string;
  };
  readonly redactionPolicyId: string;
  readonly stop: { readonly channelId: string; readonly state: "active" };
}

export interface ForgeCommandObservationReturn {
  readonly schemaVersion: typeof FC_RETURN_SCHEMA;
  readonly adapterId: typeof FC_ADAPTER_ID;
  readonly missionId: string;
  readonly runId: string;
  readonly intentId: string;
  readonly authorizationId: string;
  readonly registryId: string;
  readonly commitSha: string;
  readonly treeSha: string;
  readonly procedureId: string;
  readonly procedureMajor: 1;
  readonly state: AdapterTerminalState;
  readonly reason: string;
  readonly coverage: {
    readonly requiredLanes: readonly string[];
    readonly inspectedLanes: readonly string[];
    readonly gaps: readonly { readonly lane: string; readonly reason: string }[];
  };
  readonly usage: {
    readonly wallTimeMs: number;
    readonly evidenceBytes: number;
    readonly filesOpened: number;
    readonly readOps: number;
    readonly retries: number;
  };
  readonly disagreementCount: number;
  readonly inconclusiveCount: number;
  readonly redactionLeaks: 0;
  readonly acceptedEffects: 0;
  readonly parentReceiptId?: string;
  readonly integrity: { readonly hash: string };
}

const SHA = /^[0-9a-f]{40}$/;
const HASH = /^sha256:[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

function issue(path: string, code: string, message: string): ValidationIssue {
  return { path, code, message };
}

function exact(obj: Record<string, unknown>, allowed: readonly string[], path: string, out: ValidationIssue[]): void {
  for (const key of Object.keys(obj).sort()) {
    if (!allowed.includes(key)) out.push(issue(path ? `${path}.${key}` : key, "unknown_field", "field is not admitted by this contract major"));
  }
}

function record(obj: Record<string, unknown>, key: string, path: string, out: ValidationIssue[]): Record<string, unknown> | undefined {
  if (!isRecord(obj[key])) { out.push(issue(`${path}${key}`, "required_object", "field must be an object")); return undefined; }
  return obj[key];
}

function string(obj: Record<string, unknown>, key: string, path: string, out: ValidationIssue[], pattern: RegExp = ID): string | undefined {
  const value = obj[key];
  if (typeof value !== "string" || !pattern.test(value)) { out.push(issue(`${path}${key}`, "invalid_string", "field is missing or malformed")); return undefined; }
  return value;
}

function timestamp(obj: Record<string, unknown>, key: string, out: ValidationIssue[]): string | undefined {
  const value = obj[key];
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) { out.push(issue(key, "invalid_timestamp", "field must be an ISO timestamp")); return undefined; }
  return value;
}

function integer(obj: Record<string, unknown>, key: string, path: string, min: number, max: number, out: ValidationIssue[]): number | undefined {
  const value = obj[key];
  if (!Number.isInteger(value) || (value as number) < min || (value as number) > max) {
    out.push(issue(`${path}${key}`, "cap_out_of_range", `field must be an integer from ${min} through ${max}`));
    return undefined;
  }
  return value as number;
}

export function validateForgeCommandMissionAdmission(value: unknown, nowIso?: string): ValidationResult {
  const issues: ValidationIssue[] = [];
  if (!isRecord(value)) return { ok: false, issues: [issue("$", "required_object", "admission must be an object")] };
  exact(value, ["schemaVersion","missionId","runId","intentId","authorizationId","issuerId","nonce","issuedAt","notBefore","expiresAt","freshnessDeadline","target","procedure","lanes","caps","identities","redactionPolicyId","stop"], "", issues);
  if (value.schemaVersion !== FC_ADMISSION_SCHEMA) issues.push(issue("schemaVersion", "unknown_major", "only mission.v1 is admitted"));
  for (const key of ["missionId","runId","intentId","authorizationId","issuerId","nonce","redactionPolicyId"]) string(value, key, "", issues);
  const issued = timestamp(value, "issuedAt", issues);
  const notBefore = timestamp(value, "notBefore", issues);
  const expires = timestamp(value, "expiresAt", issues);
  const fresh = timestamp(value, "freshnessDeadline", issues);
  if (issued && notBefore && Date.parse(notBefore) < Date.parse(issued)) issues.push(issue("notBefore", "time_order", "notBefore precedes issuedAt"));
  if (notBefore && expires && Date.parse(expires) <= Date.parse(notBefore)) issues.push(issue("expiresAt", "time_order", "expiry must follow notBefore"));
  if (expires && fresh && Date.parse(fresh) > Date.parse(expires)) issues.push(issue("freshnessDeadline", "time_order", "freshness may not outlive authority"));
  if (nowIso !== undefined) {
    const now = Date.parse(nowIso);
    if (Number.isNaN(now)) issues.push(issue("$now", "invalid_timestamp", "validation time is malformed"));
    else if (notBefore && now < Date.parse(notBefore)) issues.push(issue("notBefore", "not_yet_valid", "authority is not active"));
    else if (expires && now >= Date.parse(expires)) issues.push(issue("expiresAt", "expired", "authority is expired"));
    else if (fresh && now >= Date.parse(fresh)) issues.push(issue("freshnessDeadline", "stale", "mission inputs are stale"));
  }
  const target = record(value, "target", "", issues);
  if (target) {
    exact(target, ["registryId","repository","registryState","commitSha","treeSha"], "target", issues);
    string(target, "registryId", "target.", issues);
    string(target, "repository", "target.", issues, REPOSITORY);
    string(target, "commitSha", "target.", issues, SHA);
    string(target, "treeSha", "target.", issues, SHA);
    if (target.registryState !== "admitted") issues.push(issue("target.registryState", "target_not_admitted", "Registry target must be admitted"));
  }
  const procedure = record(value, "procedure", "", issues);
  if (procedure) {
    exact(procedure, ["id","major"], "procedure", issues);
    string(procedure, "id", "procedure.", issues);
    if (procedure.major !== 1) issues.push(issue("procedure.major", "unknown_major", "only procedure major 1 is admitted"));
  }
  if (!Array.isArray(value.lanes) || value.lanes.length !== 3 || [...value.lanes].sort().join(",") !== [...REQUIRED_LANES].sort().join(",")) {
    issues.push(issue("lanes", "lane_set_mismatch", "exactly security, truthfulness, and accuracy are required"));
  }
  const caps = record(value, "caps", "", issues);
  if (caps) {
    exact(caps, ["wallTimeMs","evidenceBytes","fileCount","readOps","retries"], "caps", issues);
    integer(caps, "wallTimeMs", "caps.", 1, 60_000, issues);
    integer(caps, "evidenceBytes", "caps.", 1, 2_097_152, issues);
    integer(caps, "fileCount", "caps.", 1, 250, issues);
    integer(caps, "readOps", "caps.", 1, 300, issues);
    integer(caps, "retries", "caps.", 0, 1, issues);
  }
  const identities = record(value, "identities", "", issues);
  if (identities) {
    exact(identities, ["analyzerId","analyzerStateToken","verifierId","verifierStateToken"], "identities", issues);
    const analyzer = string(identities, "analyzerId", "identities.", issues);
    const analyzerToken = string(identities, "analyzerStateToken", "identities.", issues);
    const verifier = string(identities, "verifierId", "identities.", issues);
    const verifierToken = string(identities, "verifierStateToken", "identities.", issues);
    if (analyzer && analyzer === verifier) issues.push(issue("identities.verifierId", "independence_violation", "verifier identity equals analyzer identity"));
    if (analyzerToken && analyzerToken === verifierToken) issues.push(issue("identities.verifierStateToken", "independence_violation", "verifier state equals analyzer state"));
  }
  const stop = record(value, "stop", "", issues);
  if (stop) {
    exact(stop, ["channelId","state"], "stop", issues);
    string(stop, "channelId", "stop.", issues);
    if (stop.state !== "active") issues.push(issue("stop.state", "stop_not_active", "stop channel must be active at admission"));
  }
  return { ok: issues.length === 0, issues };
}

export function observationReturnHash(value: Omit<ForgeCommandObservationReturn, "integrity">): string {
  return `sha256:${sha256Hex(canonicalJson(value))}`;
}

export function validateForgeCommandObservationReturn(value: unknown): ValidationResult {
  const issues: ValidationIssue[] = [];
  if (!isRecord(value)) return { ok: false, issues: [issue("$", "required_object", "return must be an object")] };
  exact(value, ["schemaVersion","adapterId","missionId","runId","intentId","authorizationId","registryId","commitSha","treeSha","procedureId","procedureMajor","state","reason","coverage","usage","disagreementCount","inconclusiveCount","redactionLeaks","acceptedEffects","parentReceiptId","integrity"], "", issues);
  if (value.schemaVersion !== FC_RETURN_SCHEMA) issues.push(issue("schemaVersion", "unknown_major", "only return.v1 is admitted"));
  if (value.adapterId !== FC_ADAPTER_ID) issues.push(issue("adapterId", "adapter_mismatch", "return producer is not the admitted adapter"));
  for (const key of ["missionId","runId","intentId","authorizationId","registryId","procedureId","reason"]) string(value, key, "", issues);
  string(value, "commitSha", "", issues, SHA); string(value, "treeSha", "", issues, SHA);
  if (value.procedureMajor !== 1) issues.push(issue("procedureMajor", "unknown_major", "only procedure major 1 is admitted"));
  if (!["COMPLETED","BLOCKED","HALTED","EXPIRED","FAILED","PAUSED"].includes(String(value.state))) issues.push(issue("state", "invalid_state", "terminal/checkpoint state is not admitted"));
  integer(value, "disagreementCount", "", 0, Number.MAX_SAFE_INTEGER, issues);
  integer(value, "inconclusiveCount", "", 0, Number.MAX_SAFE_INTEGER, issues);
  if (value.redactionLeaks !== 0) issues.push(issue("redactionLeaks", "redaction_failure", "any leak blocks the return"));
  if (value.acceptedEffects !== 0) issues.push(issue("acceptedEffects", "effect_violation", "observation return must report zero effects"));
  const coverage = record(value, "coverage", "", issues);
  if (coverage) {
    exact(coverage, ["requiredLanes","inspectedLanes","gaps"], "coverage", issues);
    if (!Array.isArray(coverage.requiredLanes) || !Array.isArray(coverage.inspectedLanes) || !Array.isArray(coverage.gaps)) issues.push(issue("coverage", "malformed_coverage", "coverage arrays are required"));
    if (value.state === "COMPLETED" && Array.isArray(coverage.gaps) && coverage.gaps.length > 0 && value.reason === "healthy") issues.push(issue("reason", "false_health", "coverage gaps cannot produce a healthy claim"));
  }
  const usage = record(value, "usage", "", issues);
  if (usage) {
    exact(usage, ["wallTimeMs","evidenceBytes","filesOpened","readOps","retries"], "usage", issues);
    integer(usage, "wallTimeMs", "usage.", 0, 60_000, issues);
    integer(usage, "evidenceBytes", "usage.", 0, 2_097_152, issues);
    integer(usage, "filesOpened", "usage.", 0, 250, issues);
    integer(usage, "readOps", "usage.", 0, 300, issues);
    integer(usage, "retries", "usage.", 0, 1, issues);
  }
  const integrity = record(value, "integrity", "", issues);
  if (integrity) {
    exact(integrity, ["hash"], "integrity", issues);
    const hash = string(integrity, "hash", "integrity.", issues, HASH);
    const { integrity: _integrity, ...body } = value;
    if (hash && hash !== `sha256:${sha256Hex(canonicalJson(body))}`) issues.push(issue("integrity.hash", "integrity_mismatch", "return digest does not match canonical body"));
  }
  return { ok: issues.length === 0, issues };
}

export function admissionIdentity(value: ForgeCommandMissionAdmission): string {
  return `fcadm_${sha256Hex(canonicalJson(value)).slice(0, 24)}`;
}
