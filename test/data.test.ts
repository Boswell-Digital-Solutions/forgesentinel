import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SentinelRuntime,
  buildEvent,
  standardProducers,
  validateFinding,
  DATA_FORBIDDEN_ACTIONS,
  type ReplayLine,
  type ShadowReport,
} from "../src/index.js";

/**
 * Wave 8 (Sentinel-Data): egress anomaly, cross-tenant access attempt, and
 * redaction failure. Shadow / recommend-only — the node never deletes evidence
 * or exports unredacted content.
 */

const RECOMMEND_CLASSES = new Set(["RECOMMEND_ONLY", "REQUEST_OPERATOR"]);
const producers = Object.fromEntries(standardProducers("production").map((producer) => [producer.service, producer]));
const agents = producers["forgeagents"]!;
const TENANT = { tenant_id: "ten_data", account_id: "acct_data_1" };
const BASE = Date.parse("2026-06-09T12:00:00.000Z");

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

function run(lines: ReplayLine[]): ShadowReport {
  return new SentinelRuntime("production").runShadow(lines);
}

function dataEvent(id: string, occurredAt: string, eventType: string, payload: Record<string, unknown>): ReplayLine {
  return buildEvent(agents, {
    event_id: `evt_${id}`,
    event_type: eventType,
    occurred_at: occurredAt,
    tenant: TENANT,
    actor: { actor_type: "agent", actor_id: "agt_exporter" },
    subject: { subject_type: "object", subject_id: `obj_${id}` },
    correlation: { trace_id: `trc_${id}` },
    payload,
  });
}

const exported = (id: string, at: string) => dataEvent(id, at, "data.object.exported", { object_path_hash: "sha256:abc", destination: "external" });
const crossTenantDenied = (id: string, at: string) => dataEvent(id, at, "data.cross_tenant.denied", { target_tenant: "ten_other" });
const redactionFailed = (id: string, at: string) => dataEvent(id, at, "data.redaction.failed", { reason: "pattern_unmatched" });

test("egress anomaly: an export spike in one hour raises a REQUEST_OPERATOR finding", () => {
  const lines = Array.from({ length: 20 }, (_, index) => exported(`exp_${index}`, iso(BASE + index * 2 * 60_000)));
  const report = run(lines);
  const egress = report.findings.filter((finding) => finding.finding_type === "data.egress_anomaly");
  assert.equal(egress.length, 1);
  assert.equal(validateFinding(egress[0]!).ok, true, JSON.stringify(validateFinding(egress[0]!).issues));
  assert.equal(egress[0]!.recommendation.action_class, "REQUEST_OPERATOR");
  assert.equal(egress[0]!.recommendation.playbook, "PB-DATA-EGRESS-01");
  assert.equal(
    egress[0]!.correlation_hints.destination,
    "external",
    "carries the triggering export's destination so a downstream data_exfiltration incident can recommend an exact-destination block",
  );
});

test("a handful of exports does not fire", () => {
  const lines = Array.from({ length: 5 }, (_, index) => exported(`few_${index}`, iso(BASE + index * 2 * 60_000)));
  const report = run(lines);
  assert.equal(report.findings.filter((finding) => finding.finding_type === "data.egress_anomaly").length, 0);
});

test("a denied cross-tenant access surfaces a REQUEST_OPERATOR finding", () => {
  const report = run([crossTenantDenied("ct_1", iso(BASE))]);
  const crossTenant = report.findings.filter((finding) => finding.finding_type === "data.cross_tenant_access");
  assert.equal(crossTenant.length, 1);
  assert.equal(validateFinding(crossTenant[0]!).ok, true, JSON.stringify(validateFinding(crossTenant[0]!).issues));
  assert.equal(crossTenant[0]!.recommendation.action_class, "REQUEST_OPERATOR");
  assert.equal(crossTenant[0]!.recommendation.playbook, "PB-DATA-CROSSTENANT-01");
});

test("a redaction failure surfaces a REQUEST_OPERATOR finding", () => {
  const report = run([redactionFailed("rf_1", iso(BASE))]);
  const redaction = report.findings.filter((finding) => finding.finding_type === "data.redaction_failure");
  assert.equal(redaction.length, 1);
  assert.equal(validateFinding(redaction[0]!).ok, true, JSON.stringify(validateFinding(redaction[0]!).issues));
  assert.equal(redaction[0]!.recommendation.action_class, "REQUEST_OPERATOR");
  assert.equal(redaction[0]!.recommendation.playbook, "PB-DATA-REDACTION-01");
});

test("Sentinel-Data stays shadow / recommend-only and never deletes evidence", () => {
  const report = run([
    crossTenantDenied("rc_ct", iso(BASE)),
    redactionFailed("rc_rf", iso(BASE + 60_000)),
    ...Array.from({ length: 20 }, (_, index) => exported(`rc_exp_${index}`, iso(BASE + 2 * 60_000 + index * 60_000))),
  ]);
  assert.ok(report.findings.length >= 3);
  const forbidden = new Set<string>(DATA_FORBIDDEN_ACTIONS);
  assert.ok(forbidden.has("data.evidence.delete") && forbidden.has("data.object.export_unredacted"));
  for (const finding of report.findings) {
    assert.ok(
      RECOMMEND_CLASSES.has(finding.recommendation.action_class),
      `${finding.finding_type} must be recommend-only, got ${finding.recommendation.action_class}`,
    );
    assert.equal(finding.policy_generated_effect, false);
  }
});

test("data detectors are deterministic across runs (Wave 8 exit gate)", () => {
  const lines = Array.from({ length: 20 }, (_, index) => exported(`det_${index}`, iso(BASE + index * 2 * 60_000)));
  const first = run(lines);
  const second = run(lines);
  assert.deepEqual(
    second.findings.map((finding) => [finding.finding_type, finding.risk]),
    first.findings.map((finding) => [finding.finding_type, finding.risk]),
  );
});
