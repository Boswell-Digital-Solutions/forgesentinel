import { sha256Hex } from "../contracts/common.js";
import { CLOUD_SECURITY_FINDING_SCHEMA, type CloudSecurityFinding, type CloudSecuritySeverity } from "../contracts/cssa.js";
import type { CloudSecurityOutcome } from "../contracts/cssa_outcome.js";

/**
 * One deterministic detector over the `outcomes` family: repeated `failed`
 * executions for one principal within a window. `outcomes` carry no
 * `principal_id`/`tenant_id` of their own (05 §19) -- the caller must
 * resolve a subject first, via `AuthorizationIndex`, and pass it in;
 * `observe()` never guesses one. Thresholds are explicit constants,
 * matching decisions.ts and authorizations.ts.
 */
export const EXECUTION_FAILURE_BURST_WINDOW_MS = 15 * 60 * 1000;
export const EXECUTION_FAILURE_BURST_THRESHOLD = 3;

export interface ResolvedSubject {
  tenantId: string;
  principalId: string;
}

interface OutcomeRef {
  at: string;
  outcomeId: string;
}

interface SubjectState {
  failures: OutcomeRef[];
  emittedFailureBuckets: string[];
}

/** Durable, JSON-serializable snapshot of every subject's window state. */
export interface OutcomeWatchdogState {
  subjects: Record<string, SubjectState>;
}

export function emptyOutcomeWatchdogState(): OutcomeWatchdogState {
  return { subjects: {} };
}

function subjectKey(tenantId: string, principalId: string): string {
  return `${tenantId}::${principalId}`;
}

function pruneWindow(refs: OutcomeRef[], nowMs: number, windowMs: number): OutcomeRef[] {
  return refs.filter((ref) => nowMs - Date.parse(ref.at) <= windowMs);
}

function severityFor(observed: number, threshold: number): CloudSecuritySeverity {
  if (observed >= threshold * 3) return "S4";
  if (observed >= threshold * 2) return "S3";
  if (observed >= threshold * 1.5) return "S2";
  return "S1";
}

function bucketFor(iso: string, windowMs: number): string {
  return String(Math.floor(Date.parse(iso) / windowMs));
}

function buildFinding(opts: { subject: ResolvedSubject; window: OutcomeRef[]; emittedAt: string; bucket: string }): CloudSecurityFinding {
  const observed = opts.window.length;
  const windowStart = opts.window.reduce((min, ref) => (ref.at < min ? ref.at : min), opts.window[0]!.at);
  const windowEnd = opts.window.reduce((max, ref) => (ref.at > max ? ref.at : max), opts.window[0]!.at);
  const evidenceRefs = opts.window.map((ref) => `dataforge:cssa_outcome:${ref.outcomeId}`);
  const rawFindingId = `wd_execution_failure_burst_${opts.subject.tenantId}_${opts.subject.principalId}_${opts.bucket}`;
  const findingId = `wd_execution_failure_burst_${sha256Hex(rawFindingId).slice(0, 20)}`;
  const expiresAt = new Date(Date.parse(opts.emittedAt) + 24 * 3600 * 1000).toISOString();
  return {
    schema_version: CLOUD_SECURITY_FINDING_SCHEMA,
    finding_id: findingId,
    detector: "execution_failure_burst",
    severity: severityFor(observed, EXECUTION_FAILURE_BURST_THRESHOLD),
    scope: { tenant_id: opts.subject.tenantId, principal_id: opts.subject.principalId },
    window: { from: windowStart, to: windowEnd },
    evidence_refs: evidenceRefs,
    metrics: { observed, baseline: EXECUTION_FAILURE_BURST_THRESHOLD - 1, threshold: EXECUTION_FAILURE_BURST_THRESHOLD },
    reason_codes: ["CSSA_WATCHDOG_EXECUTION_FAILURE_BURST"],
    summary: `${observed} failed executions for principal ${opts.subject.principalId} within ${EXECUTION_FAILURE_BURST_WINDOW_MS / 60000}m (threshold ${EXECUTION_FAILURE_BURST_THRESHOLD}).`,
    emitted_at: opts.emittedAt,
    expires_at: expiresAt,
    finding_hash: `sha256:${sha256Hex(rawFindingId)}`,
  };
}

/**
 * Stateful, durable watchdog over `outcomes` -- same shape and persistence
 * contract as `DecisionWatchdog`/`AuthorizationWatchdog`, except `observe`
 * takes an already-resolved subject rather than reading one off the record.
 */
export class OutcomeWatchdog {
  private state: OutcomeWatchdogState;

  constructor(initialState?: OutcomeWatchdogState) {
    this.state = initialState ?? emptyOutcomeWatchdogState();
  }

  export(): OutcomeWatchdogState {
    return this.state;
  }

  private subject(key: string): SubjectState {
    const existing = this.state.subjects[key];
    if (existing) return existing;
    const created: SubjectState = { failures: [], emittedFailureBuckets: [] };
    this.state.subjects[key] = created;
    return created;
  }

  /**
   * Observe one outcome for an already-resolved subject, returning zero or
   * more newly-crossed findings. Outcomes whose
   * `control_lineage.policy_generated_effect` is true are excluded
   * (ADR-022), same rule as the other two watchdogs.
   */
  observe(outcome: CloudSecurityOutcome, subject: ResolvedSubject, nowIso: string): CloudSecurityFinding[] {
    if (outcome.control_lineage?.policy_generated_effect === true) return [];
    if (outcome.execution_state !== "failed") return [];

    const key = subjectKey(subject.tenantId, subject.principalId);
    const state = this.subject(key);
    const nowMs = Date.parse(nowIso);
    const ref: OutcomeRef = { at: outcome.created_at, outcomeId: outcome.outcome_id };

    state.failures = pruneWindow([...state.failures, ref], nowMs, EXECUTION_FAILURE_BURST_WINDOW_MS);
    if (state.failures.length < EXECUTION_FAILURE_BURST_THRESHOLD) return [];

    const bucket = bucketFor(ref.at, EXECUTION_FAILURE_BURST_WINDOW_MS);
    if (state.emittedFailureBuckets.includes(bucket)) return [];
    state.emittedFailureBuckets.push(bucket);
    return [buildFinding({ subject, window: state.failures, emittedAt: nowIso, bucket })];
  }
}
