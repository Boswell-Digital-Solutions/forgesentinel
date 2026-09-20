import { sha256Hex } from "../contracts/common.js";
import { CLOUD_SECURITY_FINDING_SCHEMA, type CloudSecurityFinding, type CloudSecuritySeverity } from "../contracts/cssa.js";
import type { CloudSecurityDecision } from "../contracts/cssa_decision.js";

/**
 * Two deterministic detectors over Forge-Agents' `decisions` family only
 * (per Charlie's 2026-09-20 ruling: decisions-only first slice, no
 * authorizations/outcomes yet). Thresholds are explicit constants, not
 * baseline-adaptive -- there is no historical baseline model for CSSA
 * decisions yet, so `metrics.baseline` is reported as the detector's fixed
 * threshold minus one, not a learned expectation.
 */
export const DENIAL_STREAK_WINDOW_MS = 15 * 60 * 1000;
export const DENIAL_STREAK_THRESHOLD = 5;

export const QUOTA_EXCEEDED_BURST_WINDOW_MS = 15 * 60 * 1000;
export const QUOTA_EXCEEDED_BURST_THRESHOLD = 3;

const DENIAL_DECISIONS = new Set(["block", "quarantine"]);

interface DecisionRef {
  at: string;
  decisionId: string;
}

interface SubjectState {
  denials: DecisionRef[];
  quotaExceeded: DecisionRef[];
  emittedDenialBuckets: string[];
  emittedQuotaBuckets: string[];
}

/** Durable, JSON-serializable snapshot of every subject's window state. */
export interface DecisionWatchdogState {
  subjects: Record<string, SubjectState>;
}

export function emptyWatchdogState(): DecisionWatchdogState {
  return { subjects: {} };
}

function subjectKey(tenantId: string, principalId: string): string {
  return `${tenantId}::${principalId}`;
}

function pruneWindow(refs: DecisionRef[], nowMs: number, windowMs: number): DecisionRef[] {
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

function buildFinding(opts: {
  detector: string;
  tenantId: string;
  principalId: string;
  window: DecisionRef[];
  threshold: number;
  reasonCode: string;
  summary: string;
  emittedAt: string;
  bucket: string;
}): CloudSecurityFinding {
  const observed = opts.window.length;
  const windowStart = opts.window.reduce((min, ref) => (ref.at < min ? ref.at : min), opts.window[0]!.at);
  const windowEnd = opts.window.reduce((max, ref) => (ref.at > max ? ref.at : max), opts.window[0]!.at);
  const evidenceRefs = opts.window.map((ref) => `dataforge:cssa_decision:${ref.decisionId}`);
  const rawFindingId = `wd_${opts.detector}_${opts.tenantId}_${opts.principalId}_${opts.bucket}`;
  const findingId = `wd_${opts.detector}_${sha256Hex(rawFindingId).slice(0, 20)}`;
  const expiresAt = new Date(Date.parse(opts.emittedAt) + 24 * 3600 * 1000).toISOString();
  return {
    schema_version: CLOUD_SECURITY_FINDING_SCHEMA,
    finding_id: findingId,
    detector: opts.detector,
    severity: severityFor(observed, opts.threshold),
    scope: { tenant_id: opts.tenantId, principal_id: opts.principalId },
    window: { from: windowStart, to: windowEnd },
    evidence_refs: evidenceRefs,
    metrics: { observed, baseline: opts.threshold - 1, threshold: opts.threshold },
    reason_codes: [opts.reasonCode],
    summary: opts.summary,
    emitted_at: opts.emittedAt,
    expires_at: expiresAt,
    finding_hash: `sha256:${sha256Hex(rawFindingId)}`,
  };
}

/**
 * Stateful, durable watchdog: converts a stream of `CloudSecurityDecision`
 * records into `CloudSecurityFinding` records (Forge-Agents §4 shape), one
 * subject-window-bucket at a time. State is plain data (`DecisionWatchdogState`)
 * so the caller owns persistence -- `export()`/`import` let the worker save
 * and reload it across restarts.
 */
export class DecisionWatchdog {
  private state: DecisionWatchdogState;

  constructor(initialState?: DecisionWatchdogState) {
    this.state = initialState ?? emptyWatchdogState();
  }

  export(): DecisionWatchdogState {
    return this.state;
  }

  private subject(key: string): SubjectState {
    const existing = this.state.subjects[key];
    if (existing) return existing;
    const created: SubjectState = { denials: [], quotaExceeded: [], emittedDenialBuckets: [], emittedQuotaBuckets: [] };
    this.state.subjects[key] = created;
    return created;
  }

  /**
   * Observe one decision, returning zero or more newly-crossed findings.
   * Decisions whose `control_lineage.policy_generated_effect` is true are
   * excluded entirely from both windows (ADR-022) -- Sentinel's own past
   * enforcement is never counted as fresh evidence of an anomaly.
   */
  observe(decision: CloudSecurityDecision, nowIso: string): CloudSecurityFinding[] {
    if (decision.control_lineage?.policy_generated_effect === true) return [];

    const key = subjectKey(decision.principal.tenant_id, decision.principal.principal_id);
    const state = this.subject(key);
    const nowMs = Date.parse(nowIso);
    const findings: CloudSecurityFinding[] = [];
    const ref: DecisionRef = { at: decision.occurred_at, decisionId: decision.decision_id };

    if (DENIAL_DECISIONS.has(decision.decision)) {
      state.denials = pruneWindow([...state.denials, ref], nowMs, DENIAL_STREAK_WINDOW_MS);
      if (state.denials.length >= DENIAL_STREAK_THRESHOLD) {
        const bucket = bucketFor(ref.at, DENIAL_STREAK_WINDOW_MS);
        if (!state.emittedDenialBuckets.includes(bucket)) {
          state.emittedDenialBuckets.push(bucket);
          findings.push(
            buildFinding({
              detector: "denial_streak",
              tenantId: decision.principal.tenant_id,
              principalId: decision.principal.principal_id,
              window: state.denials,
              threshold: DENIAL_STREAK_THRESHOLD,
              reasonCode: "CSSA_WATCHDOG_DENIAL_STREAK",
              summary: `${state.denials.length} block/quarantine decisions for principal ${decision.principal.principal_id} within ${DENIAL_STREAK_WINDOW_MS / 60000}m (threshold ${DENIAL_STREAK_THRESHOLD}).`,
              emittedAt: nowIso,
              bucket,
            }),
          );
        }
      }
    }

    if (decision.quota_status === "exceeded") {
      state.quotaExceeded = pruneWindow([...state.quotaExceeded, ref], nowMs, QUOTA_EXCEEDED_BURST_WINDOW_MS);
      if (state.quotaExceeded.length >= QUOTA_EXCEEDED_BURST_THRESHOLD) {
        const bucket = bucketFor(ref.at, QUOTA_EXCEEDED_BURST_WINDOW_MS);
        if (!state.emittedQuotaBuckets.includes(bucket)) {
          state.emittedQuotaBuckets.push(bucket);
          findings.push(
            buildFinding({
              detector: "quota_exceeded_burst",
              tenantId: decision.principal.tenant_id,
              principalId: decision.principal.principal_id,
              window: state.quotaExceeded,
              threshold: QUOTA_EXCEEDED_BURST_THRESHOLD,
              reasonCode: "CSSA_WATCHDOG_QUOTA_EXCEEDED_BURST",
              summary: `${state.quotaExceeded.length} quota-exceeded decisions for principal ${decision.principal.principal_id} within ${QUOTA_EXCEEDED_BURST_WINDOW_MS / 60000}m (threshold ${QUOTA_EXCEEDED_BURST_THRESHOLD}).`,
              emittedAt: nowIso,
              bucket,
            }),
          );
        }
      }
    }

    return findings;
  }
}
