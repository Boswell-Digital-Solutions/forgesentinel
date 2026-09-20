import { cssaFindingToSourceFinding } from "../contracts/cssa.js";
import { validateCloudSecurityAuthorization, type CloudSecurityAuthorization } from "../contracts/cssa_authorization.js";
import { validateCloudSecurityDecision, type CloudSecurityDecision } from "../contracts/cssa_decision.js";
import { validateCloudSecurityOutcome, type CloudSecurityOutcome } from "../contracts/cssa_outcome.js";
import type { Finding } from "../contracts/finding.js";
import type { SentinelRuntime } from "../runtime.js";
import type { DataForgeCssaClient, DataForgeCssaPage } from "../spine/dataforge_cssa_client.js";
import { AuthorizationIndex } from "./authorization_index.js";
import { AuthorizationWatchdog } from "./authorizations.js";
import { DecisionWatchdog } from "./decisions.js";
import { OutcomeWatchdog } from "./outcomes.js";
import { CssaWorkerStateStore, type CssaWorkerCursors } from "./worker_state.js";

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
  cursors: CssaWorkerCursors;
  lastPollAt: string | null;
  lastSuccessAt: string | null;
  lastErrorAt: string | null;
  lastError: string | null;
  consecutiveErrors: number;
  totalDecisionsProcessed: number;
  totalDecisionsRejected: number;
  totalAuthorizationsProcessed: number;
  totalAuthorizationsRejected: number;
  totalOutcomesProcessed: number;
  totalOutcomesRejected: number;
  /** Outcomes whose `authorization_id` was never seen in `authorizations` -- no subject to score against (see `AuthorizationIndex`). */
  totalOutcomesUnattributed: number;
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
 * One supervised, persistent, no-inbound worker: polls all three families
 * DataForge's CSSA ledger exposes (`decisions`, `authorizations`,
 * `outcomes`), runs each through its deterministic detector, and feeds any
 * resulting findings to `SentinelRuntime.ingestSourceFindings`. `outcomes`
 * carry no subject of their own, so every observed authorization is first
 * recorded into `AuthorizationIndex` and every outcome resolved against it
 * before scoring -- an outcome whose authorization was never seen this
 * process (or already pruned) is counted as unattributed and skipped, never
 * guessed at. No inbound surface -- it only ever makes outbound calls to
 * DataForge; process supervision (restart on crash) is external, this class
 * just guarantees a single failed poll never kills the loop.
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

  private readonly decisionWatchdog: DecisionWatchdog;
  private readonly authorizationWatchdog: AuthorizationWatchdog;
  private readonly outcomeWatchdog: OutcomeWatchdog;
  private readonly authorizationIndex: AuthorizationIndex;
  private readonly cursors: CssaWorkerCursors;
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
    this.cursors = { ...initial.cursors };
    this.decisionWatchdog = new DecisionWatchdog(initial.watchdogs.decisions);
    this.authorizationWatchdog = new AuthorizationWatchdog(initial.watchdogs.authorizations);
    this.outcomeWatchdog = new OutcomeWatchdog(initial.watchdogs.outcomes);
    this.authorizationIndex = new AuthorizationIndex(initial.authorizationIndex);
    this.status = {
      cursors: { ...initial.cursors },
      lastPollAt: null,
      lastSuccessAt: null,
      lastErrorAt: null,
      lastError: null,
      consecutiveErrors: 0,
      totalDecisionsProcessed: 0,
      totalDecisionsRejected: 0,
      totalAuthorizationsProcessed: 0,
      totalAuthorizationsRejected: 0,
      totalOutcomesProcessed: 0,
      totalOutcomesRejected: 0,
      totalOutcomesUnattributed: 0,
      totalFindingsEmitted: 0,
    };
  }

  currentStatus(): CssaWatchWorkerStatus {
    return { ...this.status, cursors: { ...this.status.cursors } };
  }

  /** One poll cycle: fetch a page of each family, run detectors, ingest findings, persist state. Never throws. */
  async pollOnce(): Promise<void> {
    const nowIso = this.clock();
    const nowMs = Date.parse(nowIso);
    this.status.lastPollAt = nowIso;
    try {
      const findings: Finding[] = [];

      const decisionsPage = await this.client.listDecisions(this.cursors.decisions, this.pageLimit);
      for (const record of decisionsPage.items) {
        const validation = validateCloudSecurityDecision(record.payload);
        if (!validation.ok) {
          this.status.totalDecisionsRejected += 1;
          this.log({ event: "decision_rejected", record_hash: record.record_hash, issues: validation.issues });
          continue;
        }
        const decision = record.payload as CloudSecurityDecision;
        this.status.totalDecisionsProcessed += 1;
        for (const cssaFinding of this.decisionWatchdog.observe(decision, nowIso)) {
          findings.push(cssaFindingToSourceFinding(cssaFinding, nowIso));
        }
      }
      this.advanceCursor("decisions", decisionsPage);

      const authorizationsPage = await this.client.listAuthorizations(this.cursors.authorizations, this.pageLimit);
      for (const record of authorizationsPage.items) {
        const validation = validateCloudSecurityAuthorization(record.payload);
        if (!validation.ok) {
          this.status.totalAuthorizationsRejected += 1;
          this.log({ event: "authorization_rejected", record_hash: record.record_hash, issues: validation.issues });
          continue;
        }
        const authorization = record.payload as CloudSecurityAuthorization;
        this.status.totalAuthorizationsProcessed += 1;
        this.authorizationIndex.record(authorization, nowMs);
        for (const cssaFinding of this.authorizationWatchdog.observe(authorization, nowIso)) {
          findings.push(cssaFindingToSourceFinding(cssaFinding, nowIso));
        }
      }
      this.advanceCursor("authorizations", authorizationsPage);

      const outcomesPage = await this.client.listOutcomes(this.cursors.outcomes, this.pageLimit);
      for (const record of outcomesPage.items) {
        const validation = validateCloudSecurityOutcome(record.payload);
        if (!validation.ok) {
          this.status.totalOutcomesRejected += 1;
          this.log({ event: "outcome_rejected", record_hash: record.record_hash, issues: validation.issues });
          continue;
        }
        const outcome = record.payload as CloudSecurityOutcome;
        this.status.totalOutcomesProcessed += 1;
        const subject = this.authorizationIndex.resolve(outcome.authorization_id);
        if (!subject) {
          this.status.totalOutcomesUnattributed += 1;
          this.log({ event: "outcome_unattributed", outcome_id: outcome.outcome_id, authorization_id: outcome.authorization_id });
          continue;
        }
        for (const cssaFinding of this.outcomeWatchdog.observe(outcome, subject, nowIso)) {
          findings.push(cssaFindingToSourceFinding(cssaFinding, nowIso));
        }
      }
      this.advanceCursor("outcomes", outcomesPage);
      this.authorizationIndex.prune(nowMs);

      if (findings.length > 0) {
        this.runtime.ingestSourceFindings(findings, nowIso);
        this.status.totalFindingsEmitted += findings.length;
        this.log({ event: "findings_emitted", count: findings.length, nowIso });
      }

      this.stateStore.save({
        cursors: { ...this.cursors },
        watchdogs: {
          decisions: this.decisionWatchdog.export(),
          authorizations: this.authorizationWatchdog.export(),
          outcomes: this.outcomeWatchdog.export(),
        },
        authorizationIndex: this.authorizationIndex.export(),
      });
      this.status.cursors = { ...this.cursors };
      this.status.lastSuccessAt = nowIso;
      this.status.lastError = null;
      this.status.consecutiveErrors = 0;
      this.log({
        event: "poll_cycle_ok",
        fetched: decisionsPage.items.length + authorizationsPage.items.length + outcomesPage.items.length,
        cursors: this.cursors,
      });
    } catch (error) {
      this.status.lastErrorAt = nowIso;
      this.status.lastError = error instanceof Error ? error.message : String(error);
      this.status.consecutiveErrors += 1;
      this.log({ event: "poll_cycle_error", error: this.status.lastError, consecutiveErrors: this.status.consecutiveErrors });
    }
  }

  // Keep-polling-through-nulls: a caught-up page returns next_cursor: null,
  // which is not "the end, forever" -- it just means nothing new exists yet
  // for that family. Only ever advance a cursor forward, never reset it.
  private advanceCursor(family: keyof CssaWorkerCursors, page: DataForgeCssaPage): void {
    if (page.next_cursor !== null) this.cursors[family] = page.next_cursor;
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
