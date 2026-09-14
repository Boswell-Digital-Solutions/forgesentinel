import { constants, openSync, closeSync, fstatSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { sha256Hex } from "../contracts/common.js";
import { validateForgeCommandMissionAdmission, type ForgeCommandMissionAdmission } from "./forge-command-adapter.js";

export const BOUNDED_COLLECTOR_ID = "forgesentinel.bounded-local-collector.v0.1";
export const SAFE_PREFIXES = ["doc/system/", "docs/sentinel/", "src/", "test/", "fixtures/"] as const;

export type CollectorState = "COMPLETED" | "BLOCKED" | "HALTED" | "EXPIRED" | "FAILED";
export type ControlState = "active" | "stopped" | "revoked" | "channel_lost";

export interface RevisionState { readonly commitSha: string; readonly treeSha: string; }
export interface CollectorDependencies {
  readonly now: () => string;
  readonly control: () => ControlState;
  readonly revision: () => RevisionState;
  readonly afterOpen?: (relativePath: string) => void;
}
export interface CollectorManifest { readonly paths: readonly string[]; }
export interface CollectedObservation {
  readonly path: string;
  readonly sizeBytes: number;
  readonly digest: string;
  readonly content: string;
  readonly redaction: "none";
}
export interface CollectionGap { readonly path: string; readonly reason: string; }
export interface CollectionResult {
  readonly collectorId: typeof BOUNDED_COLLECTOR_ID;
  readonly missionId: string;
  readonly runId: string;
  readonly state: CollectorState;
  readonly reason: string;
  readonly observations: readonly CollectedObservation[];
  readonly gaps: readonly CollectionGap[];
  readonly usage: { readonly wallTimeMs: number; readonly evidenceBytes: number; readonly filesOpened: number; readonly readOps: number; readonly retries: number };
  readonly acceptedEffects: 0;
}

const SECRET_PATTERNS: readonly RegExp[] = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
  /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /(?:password|passwd|api[_-]?key|secret|token)\s*[:=]\s*["']?[^\s"']{8,}/i,
];

function result(admission: ForgeCommandMissionAdmission, state: CollectorState, reason: string, observations: CollectedObservation[], gaps: CollectionGap[], usage: CollectionResult["usage"]): CollectionResult {
  return { collectorId: BOUNDED_COLLECTOR_ID, missionId: admission.missionId, runId: admission.runId, state, reason, observations, gaps, usage, acceptedEffects: 0 };
}

function safeRelativePath(value: string): boolean {
  if (!value || isAbsolute(value) || value.includes("\\") || value.includes("\0")) return false;
  const normalized = value.replace(/^\.\//, "");
  if (normalized.split("/").some((part) => part === "" || part === "." || part === "..")) return false;
  return SAFE_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

function controlFailure(control: ControlState): { state: CollectorState; reason: string } | undefined {
  if (control === "stopped" || control === "revoked") return { state: "HALTED", reason: `control_${control}` };
  if (control === "channel_lost") return { state: "FAILED", reason: "control_channel_lost" };
  return undefined;
}

function sameRevision(admission: ForgeCommandMissionAdmission, observed: RevisionState): boolean {
  return observed.commitSha === admission.target.commitSha && observed.treeSha === admission.target.treeSha;
}

function elapsed(start: number, nowIso: string): number {
  return Math.max(0, Date.parse(nowIso) - start);
}

export function collectBoundedLocalText(root: string, admission: ForgeCommandMissionAdmission, manifest: CollectorManifest, dependencies: CollectorDependencies): CollectionResult {
  const initialNow = dependencies.now();
  const admissionValidation = validateForgeCommandMissionAdmission(admission, initialNow);
  const zero = { wallTimeMs: 0, evidenceBytes: 0, filesOpened: 0, readOps: 0, retries: 0 } as const;
  if (!admissionValidation.ok) return result(admission, "BLOCKED", "invalid_admission", [], admissionValidation.issues.map((item) => ({ path: item.path, reason: item.code })), zero);
  if (!isAbsolute(root)) return result(admission, "BLOCKED", "root_not_absolute", [], [{ path: root, reason: "root_not_absolute" }], zero);

  let canonicalRoot: string;
  try { canonicalRoot = realpathSync(root); }
  catch { return result(admission, "BLOCKED", "root_unavailable", [], [{ path: root, reason: "root_unavailable" }], zero); }
  const start = Date.parse(initialNow);
  const observations: CollectedObservation[] = [];
  const gaps: CollectionGap[] = [];
  let evidenceBytes = 0, filesOpened = 0, readOps = 0;
  const usage = (): CollectionResult["usage"] => ({ wallTimeMs: elapsed(start, dependencies.now()), evidenceBytes, filesOpened, readOps, retries: 0 });
  const stop = (state: CollectorState, reason: string, path: string): CollectionResult => result(admission, state, reason, observations, [...gaps, { path, reason }], usage());

  if (!Array.isArray(manifest.paths) || manifest.paths.length === 0) return stop("BLOCKED", "empty_manifest", "$manifest");
  const paths = [...manifest.paths];
  if (new Set(paths).size !== paths.length) return stop("BLOCKED", "duplicate_path", "$manifest");

  for (const declaredPath of paths) {
    const control = controlFailure(dependencies.control());
    if (control) return stop(control.state, control.reason, declaredPath);
    const now = dependencies.now();
    if (Date.parse(now) >= Date.parse(admission.expiresAt)) return stop("EXPIRED", "authorization_expired", declaredPath);
    if (elapsed(start, now) > admission.caps.wallTimeMs) return stop("HALTED", "wall_time_cap", declaredPath);
    if (!sameRevision(admission, dependencies.revision())) return stop("HALTED", "revision_drift", declaredPath);
    if (!safeRelativePath(declaredPath)) return stop("BLOCKED", "unsafe_path", declaredPath);
    const normalized = declaredPath.replace(/^\.\//, "");
    const candidate = resolve(canonicalRoot, normalized);
    const fromRoot = relative(canonicalRoot, candidate);
    if (fromRoot.startsWith(`..${sep}`) || fromRoot === ".." || isAbsolute(fromRoot)) return stop("BLOCKED", "path_escape", declaredPath);
    if (filesOpened + 1 > admission.caps.fileCount || readOps + 1 > admission.caps.readOps) return stop("HALTED", filesOpened + 1 > admission.caps.fileCount ? "file_count_cap" : "read_ops_cap", declaredPath);

    let fd: number | undefined;
    try {
      const beforePath = lstatSync(candidate);
      if (!beforePath.isFile() || beforePath.isSymbolicLink()) return stop("BLOCKED", "unsafe_file_type", declaredPath);
      const resolvedFile = realpathSync(candidate);
      const resolvedRelative = relative(canonicalRoot, resolvedFile);
      if (resolvedRelative.startsWith(`..${sep}`) || resolvedRelative === ".." || isAbsolute(resolvedRelative)) return stop("BLOCKED", "symlink_escape", declaredPath);
      if (evidenceBytes + beforePath.size > admission.caps.evidenceBytes) return stop("HALTED", "evidence_byte_cap", declaredPath);
      fd = openSync(candidate, constants.O_RDONLY | constants.O_NOFOLLOW);
      filesOpened += 1; readOps += 1;
      const before = fstatSync(fd);
      dependencies.afterOpen?.(normalized);
      const bytes = readFileSync(fd);
      const after = fstatSync(fd);
      if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || bytes.length !== after.size) return stop("FAILED", "file_changed_during_read", declaredPath);
      let content: string;
      try { content = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
      catch { return stop("BLOCKED", "malformed_utf8", declaredPath); }
      if (content.includes("\0")) return stop("BLOCKED", "binary_content", declaredPath);
      if (SECRET_PATTERNS.some((pattern) => pattern.test(content))) return stop("BLOCKED", "secret_shaped_content", declaredPath);
      evidenceBytes += bytes.length;
      observations.push({ path: normalized, sizeBytes: bytes.length, digest: `sha256:${sha256Hex(content)}`, content, redaction: "none" });
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      return stop("FAILED", code === "ELOOP" ? "symlink_rejected" : "read_failure", declaredPath);
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
  }

  const finalControl = controlFailure(dependencies.control());
  if (finalControl) return stop(finalControl.state, finalControl.reason, "$finalize");
  if (Date.parse(dependencies.now()) >= Date.parse(admission.expiresAt)) return stop("EXPIRED", "authorization_expired", "$finalize");
  if (!sameRevision(admission, dependencies.revision())) return stop("HALTED", "revision_drift", "$finalize");
  return result(admission, "COMPLETED", "collection_complete", observations, gaps, usage());
}
