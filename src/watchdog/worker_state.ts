import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { emptyWatchdogState, type DecisionWatchdogState } from "./decisions.js";

/**
 * The poller's cursor and the watchdog's window state are saved together,
 * atomically, after every successful poll cycle -- never separately. If
 * they could drift apart (cursor advanced but watchdog state not saved, or
 * vice versa), a crash between the two writes would either replay decisions
 * the watchdog already counted or silently skip ones it never saw.
 */
export interface CssaWorkerState {
  cursor: string | null;
  watchdog: DecisionWatchdogState;
}

export function emptyWorkerState(): CssaWorkerState {
  return { cursor: null, watchdog: emptyWatchdogState() };
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
