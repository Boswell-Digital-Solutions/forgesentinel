import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildEvent,
  validateFinding,
  LICENSE_FORBIDDEN_ACTIONS,
  type ReplayLine,
  type ShadowReport,
} from "../src/index.js";
import { byService, productionRuntime, testProducers } from "./support/producers.js";

/**
 * Wave 7 (Sentinel-License): entitlement rejection, device-activation abuse,
 * and Stripe/entitlement divergence. Shadow / recommend-only — the node never
 * permanently revokes a license or mutates billing truth.
 */

const RECOMMEND_CLASSES = new Set(["RECOMMEND_ONLY", "REQUEST_OPERATOR"]);
const PRODUCERS = testProducers("production");
const producers = byService(PRODUCERS);
const billing = producers["billing-service"]!;
const TENANT = { tenant_id: "ten_lic", account_id: "acct_lic_1" };
const BASE = Date.parse("2026-06-09T12:00:00.000Z");

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

function run(lines: ReplayLine[]): ShadowReport {
  return productionRuntime(PRODUCERS).runShadow(lines);
}

function licenseEvent(id: string, occurredAt: string, eventType: string, subjectType: string, payload: Record<string, unknown>): ReplayLine {
  return buildEvent(billing, {
    event_id: `evt_${id}`,
    event_type: eventType,
    occurred_at: occurredAt,
    tenant: TENANT,
    actor: { actor_type: "service", actor_id: "license-validator" },
    subject: { subject_type: subjectType, subject_id: `${subjectType}_${id}` },
    correlation: { trace_id: `trc_${id}` },
    payload,
  });
}

const entitlementRejected = (id: string, at: string) => licenseEvent(id, at, "license.entitlement.rejected", "entitlement", { reason: "signature_invalid" });
const deviceActivated = (id: string, at: string) => licenseEvent(id, at, "license.device.activated", "device", { device_id: `dev_${id}` });
const featureAllowed = (id: string, at: string) => licenseEvent(id, at, "license.feature.allowed", "feature", { feature: "export" });
const subscriptionChanged = (id: string, at: string, status: string) => licenseEvent(id, at, "billing.subscription.changed", "subscription", { status });

test("a rejected entitlement (e.g. invalid signature) surfaces a REQUEST_OPERATOR finding", () => {
  const report = run([entitlementRejected("rej_1", iso(BASE))]);
  const rejected = report.findings.filter((finding) => finding.finding_type === "license.entitlement_rejected");
  assert.equal(rejected.length, 1);
  assert.equal(validateFinding(rejected[0]!).ok, true, JSON.stringify(validateFinding(rejected[0]!).issues));
  assert.equal(rejected[0]!.recommendation.action_class, "REQUEST_OPERATOR");
});

test("device-activation abuse: many activations in a day raise a RECOMMEND_ONLY finding", () => {
  const lines = Array.from({ length: 5 }, (_, index) => deviceActivated(`act_${index}`, iso(BASE + index * 4 * 60_000)));
  const report = run(lines);
  const abuse = report.findings.filter((finding) => finding.finding_type === "license.activation_abuse");
  assert.equal(abuse.length, 1);
  assert.equal(validateFinding(abuse[0]!).ok, true, JSON.stringify(validateFinding(abuse[0]!).issues));
  assert.equal(abuse[0]!.recommendation.action_class, "RECOMMEND_ONLY");
});

test("Stripe/entitlement divergence: a feature granted while the subscription is canceled fires", () => {
  const report = run([
    subscriptionChanged("sub_c", iso(BASE), "canceled"),
    featureAllowed("feat_x", iso(BASE + 5 * 60_000)),
  ]);
  const divergence = report.findings.filter((finding) => finding.finding_type === "license.stripe_divergence");
  assert.equal(divergence.length, 1);
  assert.equal(validateFinding(divergence[0]!).ok, true, JSON.stringify(validateFinding(divergence[0]!).issues));
  assert.equal(divergence[0]!.recommendation.action_class, "REQUEST_OPERATOR");
  assert.equal(divergence[0]!.recommendation.playbook, "PB-LICENSE-RECONCILE-01");
});

test("an active subscription granting a feature is not divergence", () => {
  const report = run([
    subscriptionChanged("sub_a", iso(BASE), "active"),
    featureAllowed("feat_y", iso(BASE + 5 * 60_000)),
  ]);
  assert.equal(report.findings.filter((finding) => finding.finding_type === "license.stripe_divergence").length, 0);
});

test("Sentinel-License stays shadow / recommend-only and cannot permanently revoke", () => {
  const report = run([
    entitlementRejected("rc_rej", iso(BASE)),
    ...Array.from({ length: 5 }, (_, index) => deviceActivated(`rc_act_${index}`, iso(BASE + index * 4 * 60_000))),
  ]);
  assert.ok(report.findings.length >= 2);
  const forbidden = new Set<string>(LICENSE_FORBIDDEN_ACTIONS);
  assert.ok(forbidden.has("license.permanent_revoke") && forbidden.has("billing.subscription.cancel"));
  for (const finding of report.findings) {
    assert.ok(
      RECOMMEND_CLASSES.has(finding.recommendation.action_class),
      `${finding.finding_type} must be recommend-only, got ${finding.recommendation.action_class}`,
    );
    assert.equal(finding.policy_generated_effect, false);
  }
});

test("license detectors are deterministic across runs (Wave 7 exit gate)", () => {
  const lines = [subscriptionChanged("sub_d", iso(BASE), "past_due"), featureAllowed("feat_d", iso(BASE + 5 * 60_000)), entitlementRejected("rej_d", iso(BASE + 6 * 60_000))];
  const first = run(lines);
  const second = run(lines);
  assert.deepEqual(
    second.findings.map((finding) => [finding.finding_type, finding.risk]),
    first.findings.map((finding) => [finding.finding_type, finding.risk]),
  );
});
