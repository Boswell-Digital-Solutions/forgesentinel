import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { emptyAuthorizationIndexState, type AuthorizationIndexState } from "./authorization_index.js";
import { emptyAuthorizationWatchdogState, type AuthorizationWatchdogState } from "./authorizations.js";
import { emptyWatchdogState, type DecisionWatchdogState } from "./decisions.js";
import { emptyOutcomeWatchdogState, type OutcomeWatchdogState } from "./outcomes.js";

export interface CssaWorkerCursors {
  decisions: string | null;
  authorizations: string | null;
  outcomes: string | null;
}

/**
 * The poller's cursors and every watchdog's window state are saved
 * together, atomically, after every successful poll cycle -- never
 * separately. If they could drift apart (a cursor advanced but its
 * watchdog state not saved, or vice versa), a crash between the two writes
 * would either replay records a watchdog already counted or silently skip
 * ones it never saw. `authorizationIndex` is included for the same reason:
 * it is the join `OutcomeWatchdog` depends on to attribute a subject
 * (`outcomes` records carry none of their own), so it must survive a
 * restart exactly as durably as the watchdogs that read it.
 */
export interface CssaWorkerState {
  cursors: CssaWorkerCursors;
  watchdogs: {
    decisions: DecisionWatchdogState;
    authorizations: AuthorizationWatchdogState;
    outcomes: OutcomeWatchdogState;
  };
  authorizationIndex: AuthorizationIndexState;
}

export function emptyWorkerState(): CssaWorkerState {
  return {
    cursors: { decisions: null, authorizations: null, outcomes: null },
    watchdogs: {
      decisions: emptyWatchdogState(),
      authorizations: emptyAuthorizationWatchdogState(),
      outcomes: emptyOutcomeWatchdogState(),
    },
    authorizationIndex: emptyAuthorizationIndexState(),
  };
}

export class CssaWorkerStateStore {
  constructor(private readonly path: string) {}

  load(): CssaWorkerState {
    if (!existsSync(this.path)) return emptyWorkerState();
    const raw = readFileSync(this.path, "utf8");
    return JSON.parse(raw) as CssaWorkerState;
  }

  /** Write-to-temp-then-rename: a crash mid-write never leaves a truncated state file. */
  save(state: CssaWorkerState): void {
    mkdirSync(dirname(this.path), { recursive: true });
    const tmpPath = `${this.path}.tmp`;
    writeFileSync(tmpPath, JSON.stringify(state), "utf8");
    renameSync(tmpPath, this.path);
  }
}
