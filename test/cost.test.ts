import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildEvent,
  validateFinding,
  type ReplayLine,
  type ShadowReport,
} from "../src/index.js";
import { byService, productionRuntime, testProducers } from "./support/producers.js";

/**
 * Wave 2 (Sentinel-Cost) completion: cache collapse, billing/usage divergence,
 * and quota bypass. All shadow / recommend-only; replay is deterministic.
 */

const DAY = 24 * 3600 * 1000;
const BASE = Date.parse("2026-05-20T12:00:00.000Z");
const RECOMMEND_ONLY = new Set(["RECOMMEND_ONLY", "REQUEST_OPERATOR"]);
const PRODUCERS = testProducers("production");
const producers = byService(PRODUCERS);
const TENANT = { tenant_id: "ten_cost", account_id: "acct_cost_1" };

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

function run(lines: ReplayLine[]): ShadowReport {
  return productionRuntime(PRODUCERS).runShadow(lines);
}

function cacheUsage(id: string, occurredAt: string, hits: number, misses: number): ReplayLine {
  return buildEvent(producers["usage-metering"]!, {
    event_id: id,
    event_type: "usage.tokens.recorded",
    occurred_at: occurredAt,
    tenant: TENANT,
    actor: { actor_type: "service", actor_id: "neuroforge-gateway" },
    subject: { subject_type: "account", subject_id: TENANT.account_id },
    correlation: { trace_id: `trc_${id}` },
    // total_tokens stays flat so only the cache ratio moves (no usage spike).
    payload: { total_tokens: 100000, route_class: "general_cloud", cache_hits: hits, cache_misses: misses },
  });
}

function costEvent(id: string, occurredAt: string, type: "usage.cost.estimated" | "usage.cost.finalized", cents: number): ReplayLine {
  return buildEvent(producers["usage-metering"]!, {
    event_id: id,
    event_type: type,
    occurred_at: occurredAt,
    tenant: TENANT,
    actor: { actor_type: "service", actor_id: "usage-metering" },
    subject: { subject_type: "account", subject_id: TENANT.account_id },
    correlation: { trace_id: `trc_${id}` },
    payload: { cost_cents: cents },
  });
}

function quotaEvent(id: string, occurredAt: string): ReplayLine {
  return buildEvent(producers["usage-metering"]!, {
    event_id: id,
    event_type: "usage.quota.exceeded",
    occurred_at: occurredAt,
    tenant: TENANT,
    actor: { actor_type: "service", actor_id: "usage-metering" },
    subject: { subject_type: "account", subject_id: TENANT.account_id },
    correlation: { trace_id: `trc_${id}` },
    payload: { quota_type: "tokens" },
  });
}

/** 20 prior days of a healthy ~90% cache hit ratio (with light variance). */
function cacheHistory(): ReplayLine[] {
  const lines: ReplayLine[] = [];
  for (let day = 0; day < 20; day++) {
    lines.push(cacheUsage(`evt_cache_hist_${String(day).padStart(2, "0")}`, iso(BASE + day * DAY), 900 + (day % 7) * 5, 100 + (day % 5) * 3));
  }
  return lines;
}

test("cache collapse: a sharp hit-ratio drop raises one RECOMMEND_ONLY finding", () => {
  const lines = [...cacheHistory(), cacheUsage("evt_cache_collapse", iso(BASE + 20 * DAY), 100, 900)];
  const report = run(lines);

  const cache = report.findings.filter((finding) => finding.finding_type === "cost.cache_collapse");
  assert.equal(cache.length, 1, "exactly one cache-collapse finding");
  assert.equal(validateFinding(cache[0]!).ok, true, JSON.stringify(validateFinding(cache[0]!).issues));
  assert.equal(cache[0]!.recommendation.action_class, "RECOMMEND_ONLY");
  assert.ok(cache[0]!.baseline && cache[0]!.baseline.observed < cache[0]!.baseline.expected, "observed ratio is below baseline");
  // Flat tokens + cold-start usage baseline (20 < 21 samples) => nothing else fires.
  assert.equal(report.findings.length, 1, "no usage/retry/billing/quota noise");
});

test("a stable cache ratio does not fire", () => {
  const lines = [...cacheHistory(), cacheUsage("evt_cache_stable", iso(BASE + 20 * DAY), 905, 95)];
  const report = run(lines);
  assert.equal(report.findings.filter((finding) => finding.finding_type === "cost.cache_collapse").length, 0);
});

test("billing/usage divergence raises a REQUEST_OPERATOR reconciliation finding", () => {
  const at = iso(BASE + 20 * DAY);
  const report = run([
    costEvent("evt_cost_est", at, "usage.cost.estimated", 10000),
    costEvent("evt_cost_fin", at, "usage.cost.finalized", 20000),
  ]);
  const billing = report.findings.filter((finding) => finding.finding_type === "cost.billing_divergence");
  assert.equal(billing.length, 1);
  assert.equal(validateFinding(billing[0]!).ok, true, JSON.stringify(validateFinding(billing[0]!).issues));
  assert.equal(billing[0]!.recommendation.action_class, "REQUEST_OPERATOR");
  assert.equal(billing[0]!.recommendation.playbook, "PB-COST-RECONCILE-01");
  assert.equal(billing[0]!.explanation.expected, 10000);
  assert.equal(billing[0]!.explanation.observed, 20000);
});

test("matched billing within tolerance does not fire", () => {
  const at = iso(BASE + 20 * DAY);
  const report = run([
    costEvent("evt_cost_est2", at, "usage.cost.estimated", 10000),
    costEvent("evt_cost_fin2", at, "usage.cost.finalized", 10500),
  ]);
  assert.equal(report.findings.length, 0, "5% divergence is within tolerance");
});

test("quota bypass: repeated breaches raise a finding that can feed correlation", () => {
  const at = BASE + 20 * DAY;
  const report = run([
    quotaEvent("evt_q1", iso(at)),
    quotaEvent("evt_q2", iso(at + 60_000)),
    quotaEvent("evt_q3", iso(at + 120_000)),
  ]);
  const quota = report.findings.filter((finding) => finding.finding_type === "cost.quota_bypass");
  assert.equal(quota.length, 1);
  assert.equal(validateFinding(quota[0]!).ok, true, JSON.stringify(validateFinding(quota[0]!).issues));
  assert.equal(quota[0]!.recommendation.action_class, "REQUEST_OPERATOR");
  assert.equal(quota[0]!.correlation_hints.account_id, TENANT.account_id);
});

test("two quota breaches stay below the threshold (no fire)", () => {
  const at = BASE + 20 * DAY;
  const report = run([quotaEvent("evt_q1b", iso(at)), quotaEvent("evt_q2b", iso(at + 60_000))]);
  assert.equal(report.findings.length, 0);
});

test("Wave 2 cost detectors stay shadow / recommend-only (no enforcement, no policy effect)", () => {
  const at = iso(BASE + 20 * DAY);
  const report = run([...cacheHistory(), cacheUsage("evt_cache_c2", at, 100, 900)]);
  assert.ok(report.findings.length >= 1);
  for (const finding of report.findings) {
    assert.ok(
      RECOMMEND_ONLY.has(finding.recommendation.action_class),
      `${finding.finding_type} must be recommend-only, got ${finding.recommendation.action_class}`,
    );
    assert.equal(finding.policy_generated_effect, false);
  }
});

test("cost detectors are deterministic across runs (Wave 2 exit gate)", () => {
  const lines = [...cacheHistory(), cacheUsage("evt_cache_det", iso(BASE + 20 * DAY), 100, 900)];
  const first = run(lines);
  const second = run(lines);
  assert.deepEqual(
    second.findings.map((finding) => [finding.finding_type, finding.risk]),
    first.findings.map((finding) => [finding.finding_type, finding.risk]),
  );
});
