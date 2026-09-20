import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  APPROVAL_PENDING_BURST_THRESHOLD,
  CLOUD_SECURITY_AUTHORIZATION_SCHEMA,
  CLOUD_SECURITY_DECISION_SCHEMA,
  CLOUD_SECURITY_OUTCOME_SCHEMA,
  DENIAL_STREAK_THRESHOLD,
  EXECUTION_FAILURE_BURST_THRESHOLD,
  CssaWatchWorker,
  CssaWorkerStateStore,
  DataForgeCssaClient,
  SentinelRuntime,
  type CloudSecurityAuthorization,
  type CloudSecurityDecision,
  type CloudSecurityOutcome,
  type DataForgeCssaPage,
  type FetchLike,
} from "../src/index.js";

const TENANT = "ten_demo";
const PRINCIPAL = "usr_watched";
const BASE = "2026-09-20T12:00:00.000Z";

function minutesAfter(baseIso: string, minutes: number): string {
  return new Date(Date.parse(baseIso) + minutes * 60_000).toISOString();
}

function decisionAt(iso: string, id: string, overrides: Partial<CloudSecurityDecision> = {}): CloudSecurityDecision {
  return {
    schema_version: CLOUD_SECURITY_DECISION_SCHEMA,
    decision_id: id,
    attempt_id: `att_${id}`,
    correlation_id: `cor_${id}`,
    occurred_at: iso,
    principal: { principal_id: PRINCIPAL, tenant_id: TENANT },
    decision: "block",
    quota_status: "not_applicable",
    reason_codes: [],
    ...overrides,
  };
}

function authorizationAt(iso: string, id: string, overrides: Partial<CloudSecurityAuthorization> = {}): CloudSecurityAuthorization {
  return {
    schema_version: CLOUD_SECURITY_AUTHORIZATION_SCHEMA,
    authorization_id: id,
    attempt_id: `att_${id}`,
    correlation_id: `cor_${id}`,
    created_at: iso,
    principal_id: PRINCIPAL,
    tenant_id: TENANT,
    authorization_state: "approval_pending",
    ...overrides,
  };
}

function outcomeAt(iso: string, id: string, authorizationId: string, overrides: Partial<CloudSecurityOutcome> = {}): CloudSecurityOutcome {
  return {
    schema_version: CLOUD_SECURITY_OUTCOME_SCHEMA,
    outcome_id: id,
    attempt_id: `att_${id}`,
    authorization_id: authorizationId,
    correlation_id: `cor_${id}`,
    created_at: iso,
    execution_state: "failed",
    ...overrides,
  };
}

type Family = "decisions" | "authorizations" | "outcomes";
type FamilyPages = Partial<Record<Family, Record<string, DataForgeCssaPage>>>;

/**
 * A scripted fetch, one page-set per family: a family left out of
 * `familyPages` entirely defaults to an empty page for every cursor (most
 * tests only care about one family); a family that IS specified stays as
 * strict as the original single-family mock -- an unscripted cursor throws.
 */
function mockFetch(familyPages: FamilyPages): { fetch: FetchLike; calls: string[] } {
  const calls: string[] = [];
  const emptyPage: DataForgeCssaPage = { items: [], count: 0, next_cursor: null };
  const fetchImpl: FetchLike = async (url: string) => {
    calls.push(url);
    const parsed = new URL(url);
    const family = parsed.pathname.split("/").pop() as Family;
    const cursorParam = parsed.searchParams.get("cursor") ?? "start";
    const pages = familyPages[family];
    let page: DataForgeCssaPage;
    if (!pages) {
      page = emptyPage;
    } else {
      const scripted = pages[cursorParam];
      if (!scripted) throw new Error(`mockFetch: no page scripted for ${family} cursor "${cursorParam}"`);
      page = scripted;
    }
    return {
      ok: true,
      status: 200,
      json: async () => page,
      text: async () => JSON.stringify(page),
    };
  };
  return { fetch: fetchImpl, calls };
}

function withTempDir<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-cssa-worker-"));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("end to end: decisions become findings in the ledger and promote to a lone-signal incident", () =>
  withTempDir(async (dir) => {
    const items = Array.from({ length: DENIAL_STREAK_THRESHOLD }, (_, i) => ({
      payload: decisionAt(minutesAfter(BASE, i), `dec_${i}`),
      record_hash: `sha256:${i}`,
    }));
    const { fetch } = mockFetch({ decisions: { start: { items, count: items.length, next_cursor: null } } });
    const runtime = new SentinelRuntime("test");
    const worker = new CssaWatchWorker({
      client: new DataForgeCssaClient({ baseUrl: "http://dataforge.invalid", bearerToken: "test-token", fetchImpl: fetch }),
      runtime,
      stateStore: new CssaWorkerStateStore(join(dir, "state.json")),
      log: () => {},
      clock: () => minutesAfter(BASE, DENIAL_STREAK_THRESHOLD),
    });

    await worker.pollOnce();

    const status = worker.currentStatus();
    assert.equal(status.lastError, null);
    assert.equal(status.totalDecisionsProcessed, DENIAL_STREAK_THRESHOLD);
    assert.equal(status.totalFindingsEmitted, 1);

    const findingRecords = runtime.ledger.all().filter((r) => r.kind === "finding");
    assert.equal(findingRecords.length, 1, "the finding reached the evidence ledger");
    const incidentRecords = runtime.ledger.all().filter((r) => r.kind === "incident");
    assert.equal(
      incidentRecords.length,
      1,
      "cssa.denial_streak is now wired into promoteSingles() -- a lone finding still promotes, capped confidence",
    );
    const incident = incidentRecords[0]!.body as { incident_type: string; risk: { confidence: number } };
    assert.equal(incident.incident_type, "cssa.denial_streak_watch");
    assert.ok(incident.risk.confidence <= 0.7, "a single decisions-only signal caps confidence");
  }));

test("end to end: an approval-pending burst in authorizations promotes to a lone-signal incident", () =>
  withTempDir(async (dir) => {
    const items = Array.from({ length: APPROVAL_PENDING_BURST_THRESHOLD }, (_, i) => ({
      payload: authorizationAt(minutesAfter(BASE, i), `auth_${i}`),
      record_hash: `sha256:${i}`,
    }));
    const { fetch } = mockFetch({ authorizations: { start: { items, count: items.length, next_cursor: null } } });
    const runtime = new SentinelRuntime("test");
    const worker = new CssaWatchWorker({
      client: new DataForgeCssaClient({ baseUrl: "http://dataforge.invalid", bearerToken: "t", fetchImpl: fetch }),
      runtime,
      stateStore: new CssaWorkerStateStore(join(dir, "state.json")),
      log: () => {},
      clock: () => minutesAfter(BASE, APPROVAL_PENDING_BURST_THRESHOLD),
    });

    await worker.pollOnce();

    const status = worker.currentStatus();
    assert.equal(status.lastError, null);
    assert.equal(status.totalAuthorizationsProcessed, APPROVAL_PENDING_BURST_THRESHOLD);
    assert.equal(status.totalFindingsEmitted, 1);

    const incidentRecords = runtime.ledger.all().filter((r) => r.kind === "incident");
    assert.equal(incidentRecords.length, 1);
    const incident = incidentRecords[0]!.body as { incident_type: string };
    assert.equal(incident.incident_type, "cssa.approval_pending_watch");
  }));

test("end to end: an outcome resolves its subject through a previously observed authorization, and a failure burst promotes", () =>
  withTempDir(async (dir) => {
    const authItems = [{ payload: authorizationAt(BASE, "auth_0", { authorization_state: "issued" }), record_hash: "sha256:auth0" }];
    const outcomeItems = Array.from({ length: EXECUTION_FAILURE_BURST_THRESHOLD }, (_, i) => ({
      payload: outcomeAt(minutesAfter(BASE, i), `out_${i}`, "auth_0"),
      record_hash: `sha256:out${i}`,
    }));
    const { fetch } = mockFetch({
      authorizations: { start: { items: authItems, count: authItems.length, next_cursor: null } },
      outcomes: { start: { items: outcomeItems, count: outcomeItems.length, next_cursor: null } },
    });
    const runtime = new SentinelRuntime("test");
    const worker = new CssaWatchWorker({
      client: new DataForgeCssaClient({ baseUrl: "http://dataforge.invalid", bearerToken: "t", fetchImpl: fetch }),
      runtime,
      stateStore: new CssaWorkerStateStore(join(dir, "state.json")),
      log: () => {},
      clock: () => minutesAfter(BASE, EXECUTION_FAILURE_BURST_THRESHOLD),
    });

    await worker.pollOnce();

    const status = worker.currentStatus();
    assert.equal(status.lastError, null);
    assert.equal(status.totalOutcomesProcessed, EXECUTION_FAILURE_BURST_THRESHOLD);
    assert.equal(status.totalOutcomesUnattributed, 0, "the authorization was observed in the same cycle, so every outcome resolves");
    assert.equal(status.totalFindingsEmitted, 1);

    const incidentRecords = runtime.ledger.all().filter((r) => r.kind === "incident");
    assert.equal(incidentRecords.length, 1);
    const incident = incidentRecords[0]!.body as { incident_type: string; subject: { tenant_id: string } };
    assert.equal(incident.incident_type, "cssa.execution_failure_watch");
    assert.equal(incident.subject.tenant_id, TENANT, "subject was correctly resolved from the authorization, not guessed");
  }));

test("an outcome whose authorization was never observed is counted unattributed, not guessed at", () =>
  withTempDir(async (dir) => {
    const outcomeItems = [{ payload: outcomeAt(BASE, "out_orphan", "auth_never_seen"), record_hash: "sha256:orphan" }];
    const { fetch } = mockFetch({ outcomes: { start: { items: outcomeItems, count: outcomeItems.length, next_cursor: null } } });
    const events: Record<string, unknown>[] = [];
    const worker = new CssaWatchWorker({
      client: new DataForgeCssaClient({ baseUrl: "http://dataforge.invalid", bearerToken: "t", fetchImpl: fetch }),
      runtime: new SentinelRuntime("test"),
      stateStore: new CssaWorkerStateStore(join(dir, "state.json")),
      log: (event) => events.push(event),
      clock: () => BASE,
    });

    await worker.pollOnce();

    const status = worker.currentStatus();
    assert.equal(status.totalOutcomesProcessed, 1);
    assert.equal(status.totalOutcomesUnattributed, 1);
    assert.equal(status.totalFindingsEmitted, 0);
    assert.ok(events.some((e) => e["event"] === "outcome_unattributed"));
  }));

test("cursors resume across a restart, independently per family", () =>
  withTempDir(async (dir) => {
    const statePath = join(dir, "state.json");
    const firstPage = { items: [{ payload: decisionAt(BASE, "dec_0"), record_hash: "sha256:0" }], count: 1, next_cursor: "cursor_1" };
    const secondPage = { items: [{ payload: decisionAt(minutesAfter(BASE, 1), "dec_1"), record_hash: "sha256:1" }], count: 1, next_cursor: null };

    const { fetch: fetch1 } = mockFetch({ decisions: { start: firstPage } });
    const worker1 = new CssaWatchWorker({
      client: new DataForgeCssaClient({ baseUrl: "http://dataforge.invalid", bearerToken: "t", fetchImpl: fetch1 }),
      runtime: new SentinelRuntime("test"),
      stateStore: new CssaWorkerStateStore(statePath),
      log: () => {},
      clock: () => BASE,
    });
    await worker1.pollOnce();
    assert.equal(worker1.currentStatus().cursors.decisions, "cursor_1");
    assert.equal(worker1.currentStatus().cursors.authorizations, null, "an untouched family's cursor stays null");

    // A brand-new worker, same state file -- simulates a process restart.
    const { fetch: fetch2, calls } = mockFetch({ decisions: { cursor_1: secondPage } });
    const worker2 = new CssaWatchWorker({
      client: new DataForgeCssaClient({ baseUrl: "http://dataforge.invalid", bearerToken: "t", fetchImpl: fetch2 }),
      runtime: new SentinelRuntime("test"),
      stateStore: new CssaWorkerStateStore(statePath),
      log: () => {},
      clock: () => minutesAfter(BASE, 1),
    });
    await worker2.pollOnce();
    assert.ok(calls[0]!.includes("cursor=cursor_1"), "resumed from the persisted cursor, not the start");
    assert.equal(worker2.currentStatus().totalDecisionsProcessed, 1);
  }));

test("a caught-up page (next_cursor: null) does not reset the cursor -- polling continues from where it was", () =>
  withTempDir(async (dir) => {
    const page = { items: [{ payload: decisionAt(BASE, "dec_0"), record_hash: "sha256:0" }], count: 1, next_cursor: null };
    const { fetch } = mockFetch({ decisions: { start: page } });
    const worker = new CssaWatchWorker({
      client: new DataForgeCssaClient({ baseUrl: "http://dataforge.invalid", bearerToken: "t", fetchImpl: fetch }),
      runtime: new SentinelRuntime("test"),
      stateStore: new CssaWorkerStateStore(join(dir, "state.json")),
      log: () => {},
      clock: () => BASE,
    });
    await worker.pollOnce();
    assert.equal(worker.currentStatus().cursors.decisions, null, "no next_cursor was ever issued, so there is nothing to advance to");
    assert.equal(worker.currentStatus().lastError, null, "a null next_cursor is a normal caught-up state, not an error");
  }));

test("a malformed decision is rejected and logged, not fatal to the poll cycle", () =>
  withTempDir(async (dir) => {
    const items = [
      { payload: { schema_version: CLOUD_SECURITY_DECISION_SCHEMA, decision_id: "dec_bad" }, record_hash: "sha256:bad" },
      { payload: decisionAt(BASE, "dec_good"), record_hash: "sha256:good" },
    ];
    const { fetch } = mockFetch({ decisions: { start: { items, count: items.length, next_cursor: null } } });
    const events: Record<string, unknown>[] = [];
    const worker = new CssaWatchWorker({
      client: new DataForgeCssaClient({ baseUrl: "http://dataforge.invalid", bearerToken: "t", fetchImpl: fetch }),
      runtime: new SentinelRuntime("test"),
      stateStore: new CssaWorkerStateStore(join(dir, "state.json")),
      log: (event) => events.push(event),
      clock: () => BASE,
    });
    await worker.pollOnce();
    const status = worker.currentStatus();
    assert.equal(status.lastError, null, "a malformed record does not fail the whole cycle");
    assert.equal(status.totalDecisionsRejected, 1);
    assert.equal(status.totalDecisionsProcessed, 1);
    assert.ok(events.some((e) => e["event"] === "decision_rejected"));
  }));

test("a DataForge fetch failure is caught, logged, and reflected in status -- never thrown out of pollOnce", () =>
  withTempDir(async (dir) => {
    const failingFetch: FetchLike = async () => ({ ok: false, status: 503, json: async () => ({}), text: async () => "unavailable" });
    const worker = new CssaWatchWorker({
      client: new DataForgeCssaClient({ baseUrl: "http://dataforge.invalid", bearerToken: "t", fetchImpl: failingFetch }),
      runtime: new SentinelRuntime("test"),
      stateStore: new CssaWorkerStateStore(join(dir, "state.json")),
      log: () => {},
      clock: () => BASE,
    });
    await assert.doesNotReject(worker.pollOnce());
    const status = worker.currentStatus();
    assert.equal(status.consecutiveErrors, 1);
    assert.match(status.lastError ?? "", /503/);
  }));
