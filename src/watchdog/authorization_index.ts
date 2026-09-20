import type { CloudSecurityAuthorization } from "../contracts/cssa_authorization.js";

/**
 * `outcomes` records carry no `principal_id`/`tenant_id` (Forge-Agents
 * `app/security/contracts.py::CloudActionOutcome`, 05 §19) -- they only tie
 * back to a subject indirectly, through the `authorization_id` of the
 * authorization they resulted from. This index is that join: every observed
 * authorization is recorded here (regardless of its `authorization_state`,
 * since even a denied/quarantined authorization can still produce an
 * outcome), so `OutcomeWatchdog` can resolve a subject before scoring an
 * outcome. Evidence-before-inference (doctrine, CLAUDE.md) applies here too:
 * an outcome whose authorization was never observed resolves to nothing and
 * is never guessed at.
 *
 * Bounded and pruned, not a lifetime cache: an authorization is single-use
 * (05 §18) and its outcome is expected promptly after, so entries older than
 * `maxAgeMs` are dropped -- matching the 24h `expires_at` convention the
 * watchdog findings already use (`decisions.ts`, `authorizations.ts`).
 */
export interface AuthorizationIndexEntry {
  tenantId: string;
  principalId: string;
  seenAtMs: number;
}

export interface AuthorizationIndexState {
  entries: Record<string, AuthorizationIndexEntry>;
}

export function emptyAuthorizationIndexState(): AuthorizationIndexState {
  return { entries: {} };
}

export const AUTHORIZATION_INDEX_MAX_AGE_MS = 24 * 3600 * 1000;

export class AuthorizationIndex {
  private state: AuthorizationIndexState;

  constructor(initialState?: AuthorizationIndexState) {
    this.state = initialState ?? emptyAuthorizationIndexState();
  }

  export(): AuthorizationIndexState {
    return this.state;
  }

  record(authorization: CloudSecurityAuthorization, nowMs: number): void {
    this.state.entries[authorization.authorization_id] = {
      tenantId: authorization.tenant_id,
      principalId: authorization.principal_id,
      seenAtMs: nowMs,
    };
  }

  resolve(authorizationId: string): { tenantId: string; principalId: string } | undefined {
    const entry = this.state.entries[authorizationId];
    if (!entry) return undefined;
    return { tenantId: entry.tenantId, principalId: entry.principalId };
  }

  /** Drop entries older than `AUTHORIZATION_INDEX_MAX_AGE_MS` so this never grows without bound. */
  prune(nowMs: number, maxAgeMs: number = AUTHORIZATION_INDEX_MAX_AGE_MS): void {
    for (const [authorizationId, entry] of Object.entries(this.state.entries)) {
      if (nowMs - entry.seenAtMs > maxAgeMs) delete this.state.entries[authorizationId];
    }
  }
}
