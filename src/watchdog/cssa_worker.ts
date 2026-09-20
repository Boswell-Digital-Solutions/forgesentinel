import { cssaFindingToSourceFinding } from "../contracts/cssa.js";
import { validateCloudSecurityDecision, type CloudSecurityDecision } from "../contracts/cssa_decision.js";
import type { Finding } from "../contracts/finding.js";
import type { SentinelRuntime } from "../runtime.js";
import type { DataForgeCssaClient } from "../spine/dataforge_cssa_client.js";
import { DecisionWatchdog } from "./decisions.js";
import { CssaWorkerStateStore } from "./worker_state.js";

export type CssaWorkerLog = (event: Record<string, unknown>) => void;

const DEFAULT_POLL_INTERVAL_MS = 30_000;
const DEFAULT_PAGE_LIMIT = 100;
const MAX_BACKOFF_MULTIPLIER = 8;

export interface CssaWatchWorkerOptions {
  client: DataForgeCssaClient;
  runtime: SentinelRuntime;
  stateStore: CssaWorkerStateStore;
  pollIntervalMs?: number;
  pageLimit?: number;
  log?: CssaWorkerLog;
  clock?: () => string;
  sleep?: (ms: number) => Promise<void>;
}

/** Visible coverage/error state -- what a future health surface would read. */
export interface CssaWatchWorkerStatus {
  cursor: string | null;
  lastPollAt: string | null;
  lastSuccessAt: string | null;
  lastErrorAt: string | null;
  lastError: string | null;
  consecutiveErrors: number;
  totalDecisionsProcessed: number;
  totalDecisionsRejected: number;
  totalFindingsEmitted: number;
}

function defaultClock(): string {
  return new Date().toISOString();
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function defaultLog(event: Record<string, unknown>): void {
  console.log(JSON.stringify({ component: "cssa-watch-worker", ...event }));
}

/**
 * One supervised, persistent, no-inbound worker (2026-09-20 ruling): polls
 * DataForge's `decisions` family, runs each decision through the two
 * deterministic detectors, and feeds any resulting findings to
 * `SentinelRuntime.ingestSourceFindings`. No inbound surface -- it only ever
 * makes outbound calls to DataForge; process supervision (restart on crash)
 * is external, this class just guarantees a single failed poll never kills
 * the loop.
 */
export class CssaWatchWorker {
  private readonly client: DataForgeCssaClient;
  private readonly runtime: SentinelRuntime;
  private readonly stateStore: CssaWorkerStateStore;
  private readonly pollIntervalMs: number;
  private readonly pageLimit: number;
  private readonly log: CssaWorkerLog;
  private readonly clock: () => string;
  private readonly sleep: (ms: number) => Promise<void>;

  private readonly watchdog: DecisionWatchdog;
  private cursor: string | null;
  private readonly status: CssaWatchWorkerStatus;

  constructor(opts: CssaWatchWorkerOptions) {
    this.client = opts.client;
    this.runtime = opts.runtime;
    this.stateStore = opts.stateStore;
    this.pollIntervalMs = opts.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    this.pageLimit = opts.pageLimit ?? DEFAULT_PAGE_LIMIT;
    this.log = opts.log ?? defaultLog;
    this.clock = opts.clock ?? defaultClock;
    this.sleep = opts.sleep ?? defaultSleep;

    const initial = this.stateStore.load();
    this.cursor = initial.cursor;
    this.watchdog = new DecisionWatchdog(initial.watchdog);
    this.status = {
      cursor: initial.cursor,
      lastPollAt: null,
      lastSuccessAt: null,
      lastErrorAt: null,
      lastError: null,
      consecutiveErrors: 0,
      totalDecisionsProcessed: 0,
      totalDecisionsRejected: 0,
      totalFindingsEmitted: 0,
    };
  }

  currentStatus(): CssaWatchWorkerStatus {
    return { ...this.status };
  }

  /** One poll cycle: fetch a page, run detectors, ingest findings, persist state. Never throws. */
  async pollOnce(): Promise<void> {
    const nowIso = this.clock();
    this.status.lastPollAt = nowIso;
    try {
      const page = await this.client.listDecisions(this.cursor, this.pageLimit);
      const findings: Finding[] = [];

      for (const record of page.items) {
        const validation = validateCloudSecurityDecision(record.payload);
        if (!validation.ok) {
          this.status.totalDecisionsRejected += 1;
          this.log({ event: "decision_rejected", record_hash: record.record_hash, issues: validation.issues });
          continue;
        }
        const decision = record.payload as CloudSecurityDecision;
        this.status.totalDecisionsProcessed += 1;
        const cssaFindings = this.watchdog.observe(decision, nowIso);
        for (const cssaFinding of cssaFindings) {
          findings.push(cssaFindingToSourceFinding(cssaFinding, nowIso));
        }
      }

      if (findings.length > 0) {
        this.runtime.ingestSourceFindings(findings, nowIso);
        this.status.totalFindingsEmitted += findings.length;
        this.log({ event: "findings_emitted", count: findings.length, nowIso });
      }

      // Keep-polling-through-nulls: a caught-up page returns next_cursor:
      // null, which is not "the end, forever" -- it just means nothing new
      // exists yet. Only ever advance the cursor forward, never reset it.
      if (page.next_cursor !== null) this.cursor = page.next_cursor;

      this.stateStore.save({ cursor: this.cursor, watchdog: this.watchdog.export() });
      this.status.cursor = this.cursor;
      this.status.lastSuccessAt = nowIso;
      this.status.lastError = null;
      this.status.consecutiveErrors = 0;
      this.log({ event: "poll_cycle_ok", fetched: page.items.length, cursor: this.cursor });
    } catch (error) {
      this.status.lastErrorAt = nowIso;
      this.status.lastError = error instanceof Error ? error.message : String(error);
      this.status.consecutiveErrors += 1;
      this.log({ event: "poll_cycle_error", error: this.status.lastError, consecutiveErrors: this.status.consecutiveErrors });
    }
  }

  /** Runs until `signal` aborts. Backs off (capped) on consecutive errors; never exits on a failed poll. */
  async run(signal?: AbortSignal): Promise<void> {
    while (!signal?.aborted) {
      await this.pollOnce();
      const backoff = Math.min(2 ** this.status.consecutiveErrors, MAX_BACKOFF_MULTIPLIER);
      await this.sleep(this.pollIntervalMs * backoff);
    }
  }
}
