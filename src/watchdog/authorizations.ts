import { sha256Hex } from "../contracts/common.js";
import { CLOUD_SECURITY_FINDING_SCHEMA, type CloudSecurityFinding, type CloudSecuritySeverity } from "../contracts/cssa.js";
import type { CloudSecurityAuthorization } from "../contracts/cssa_authorization.js";

/**
 * One deterministic detector over the `authorizations` family: repeated
 * `approval_pending` authorizations for one principal within a window. This
 * is the one authorization-specific signal not already covered by the
 * decisions watchdog's block/quarantine denial streak (§17's `decision` and
 * §18's `authorization_state` are parallel, mostly-redundant enums for
 * denied/quarantined outcomes -- `approval_pending` has no decisions-side
 * equivalent). Thresholds are explicit constants, matching decisions.ts:
 * there is no historical baseline model for CSSA authorizations yet.
 */
export const APPROVAL_PENDING_BURST_WINDOW_MS = 15 * 60 * 1000;
export const APPROVAL_PENDING_BURST_THRESHOLD = 3;

interface AuthorizationRef {
  at: string;
  authorizationId: string;
}

interface SubjectState {
  approvalPending: AuthorizationRef[];
  emittedApprovalPendingBuckets: string[];
}

/** Durable, JSON-serializable snapshot of every subject's window state. */
export interface AuthorizationWatchdogState {
  subjects: Record<string, SubjectState>;
}

export function emptyAuthorizationWatchdogState(): AuthorizationWatchdogState {
  return { subjects: {} };
}

function subjectKey(tenantId: string, principalId: string): string {
  return `${tenantId}::${principalId}`;
}

function pruneWindow(refs: AuthorizationRef[], nowMs: number, windowMs: number): AuthorizationRef[] {
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
  tenantId: string;
  principalId: string;
  window: AuthorizationRef[];
  emittedAt: string;
  bucket: string;
}): CloudSecurityFinding {
  const observed = opts.window.length;
  const windowStart = opts.window.reduce((min, ref) => (ref.at < min ? ref.at : min), opts.window[0]!.at);
  const windowEnd = opts.window.reduce((max, ref) => (ref.at > max ? ref.at : max), opts.window[0]!.at);
  const evidenceRefs = opts.window.map((ref) => `dataforge:cssa_authorization:${ref.authorizationId}`);
  const rawFindingId = `wd_approval_pending_burst_${opts.tenantId}_${opts.principalId}_${opts.bucket}`;
  const findingId = `wd_approval_pending_burst_${sha256Hex(rawFindingId).slice(0, 20)}`;
  const expiresAt = new Date(Date.parse(opts.emittedAt) + 24 * 3600 * 1000).toISOString();
  return {
    schema_version: CLOUD_SECURITY_FINDING_SCHEMA,
    finding_id: findingId,
    detector: "approval_pending_burst",
    severity: severityFor(observed, APPROVAL_PENDING_BURST_THRESHOLD),
    scope: { tenant_id: opts.tenantId, principal_id: opts.principalId },
    window: { from: windowStart, to: windowEnd },
    evidence_refs: evidenceRefs,
    metrics: { observed, baseline: APPROVAL_PENDING_BURST_THRESHOLD - 1, threshold: APPROVAL_PENDING_BURST_THRESHOLD },
    reason_codes: ["CSSA_WATCHDOG_APPROVAL_PENDING_BURST"],
    summary: `${observed} approval-pending authorizations for principal ${opts.principalId} within ${APPROVAL_PENDING_BURST_WINDOW_MS / 60000}m (threshold ${APPROVAL_PENDING_BURST_THRESHOLD}).`,
    emitted_at: opts.emittedAt,
    expires_at: expiresAt,
    finding_hash: `sha256:${sha256Hex(rawFindingId)}`,
  };
}

/**
 * Stateful, durable watchdog over `authorizations` -- same shape and
 * persistence contract as `DecisionWatchdog` (`decisions.ts`).
 */
export class AuthorizationWatchdog {
  private state: AuthorizationWatchdogState;

  constructor(initialState?: AuthorizationWatchdogState) {
    this.state = initialState ?? emptyAuthorizationWatchdogState();
  }

  export(): AuthorizationWatchdogState {
    return this.state;
  }

  private subject(key: string): SubjectState {
    const existing = this.state.subjects[key];
    if (existing) return existing;
    const created: SubjectState = { approvalPending: [], emittedApprovalPendingBuckets: [] };
    this.state.subjects[key] = created;
    return created;
  }

  /**
   * Observe one authorization, returning zero or more newly-crossed
   * findings. Authorizations whose `control_lineage.policy_generated_effect`
   * is true are excluded (ADR-022) -- same rule as `DecisionWatchdog.observe`.
   */
  observe(authorization: CloudSecurityAuthorization, nowIso: string): CloudSecurityFinding[] {
    if (authorization.control_lineage?.policy_generated_effect === true) return [];
    if (authorization.authorization_state !== "approval_pending") return [];

    const key = subjectKey(authorization.tenant_id, authorization.principal_id);
    const state = this.subject(key);
    const nowMs = Date.parse(nowIso);
    const ref: AuthorizationRef = { at: authorization.created_at, authorizationId: authorization.authorization_id };

    state.approvalPending = pruneWindow([...state.approvalPending, ref], nowMs, APPROVAL_PENDING_BURST_WINDOW_MS);
    if (state.approvalPending.length < APPROVAL_PENDING_BURST_THRESHOLD) return [];

    const bucket = bucketFor(ref.at, APPROVAL_PENDING_BURST_WINDOW_MS);
    if (state.emittedApprovalPendingBuckets.includes(bucket)) return [];
    state.emittedApprovalPendingBuckets.push(bucket);
    return [
      buildFinding({
        tenantId: authorization.tenant_id,
        principalId: authorization.principal_id,
        window: state.approvalPending,
        emittedAt: nowIso,
        bucket,
      }),
    ];
  }
}
