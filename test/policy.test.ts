import { test } from "node:test";
import assert from "node:assert/strict";
import { PolicyService, ACCOUNT_COMPROMISE_POLICY, GLOBAL_ALWAYS_DENY, type Incident } from "../src/index.js";

const NOW = "2026-06-09T17:05:00.000Z";

function incident(overrides: Partial<Incident> = {}): Incident {
  return {
    incident_id: "inc_t1",
    title: "Possible account compromise",
    incident_type: "compound.account_compromise",
    status: "open",
    priority: "high",
    origin: ["sentinel-cost", "sentinel-cloud"],
    subject: { tenant_id: "ten_a", account_id: "acct_1" },
    risk: { likelihood: 0.9, impact: 0.85, confidence: 0.85, evidence_quality: 0.95 },
    briefing: { issue: "i", where: "w", recommended_fix: "f", why_now: "y" },
    finding_ids: ["fnd_1"],
    evidence_ids: ["evd_1"],
    independent_signal_count: 4,
    signals: ["cost.usage_change_extreme", "cloud.new_api_key", "cloud.new_region", "cloud.login_failure_burst"],
    required_authority: ["identity_service", "forge_command_operator"],
    recommended_actions: [
      { action_type: "identity.api_key.pause", target_id: "key_1", scope: "single_key", reversible: true, approval: "single_operator" },
    ],
    conflicts: [],
    missing_telemetry: [],
    version: 1,
    created_at: NOW,
    updated_at: NOW,
    status_history: [{ status: "open", at: NOW }],
    ...overrides,
  };
}

function service(): PolicyService {
  const policy = new PolicyService();
  policy.register(ACCOUNT_COMPROMISE_POLICY);
  return policy;
}

test("matching compound incident yields REQUEST_OPERATOR with bounded reversible actions", () => {
  const decision = service().evaluate(incident(), { environment: "production" }, NOW);
  assert.equal(decision.result, "REQUEST_OPERATOR");
  assert.equal(decision.policy_version, "3.1.0");
  const pause = decision.allowed_actions.find((action) => action.action_type === "identity.api_key.pause");
  assert.ok(pause);
  assert.equal(pause.scope, "single_key");
  assert.equal(pause.requires_approval, "single_operator");
  const mfa = decision.allowed_actions.find((action) => action.action_type === "identity.mfa.require");
  assert.ok(mfa);
  assert.equal(mfa.requires_approval, "policy_allowed");
});

test("thresholds are conjunctive: low confidence blocks the rule", () => {
  const decision = service().evaluate(incident({ risk: { likelihood: 0.9, impact: 0.85, confidence: 0.5, evidence_quality: 0.95 } }), { environment: "production" }, NOW);
  assert.equal(decision.result, "RECOMMEND_ONLY");
  assert.equal(decision.allowed_actions.length, 0);
});

test("insufficient independent signals block the rule", () => {
  const decision = service().evaluate(incident({ independent_signal_count: 2 }), { environment: "production" }, NOW);
  assert.equal(decision.result, "RECOMMEND_ONLY");
});

test("missing required signal blocks the rule", () => {
  const decision = service().evaluate(incident({ signals: ["cost.usage_change_extreme", "cloud.login_failure_burst", "cloud.new_device"] }), { environment: "production" }, NOW);
  assert.equal(decision.result, "RECOMMEND_ONLY");
});

test("unmatched incident type is recommend-only", () => {
  const decision = service().evaluate(incident({ incident_type: "cost.usage_runaway" }), { environment: "production" }, NOW);
  assert.equal(decision.policy_id, "none_matched");
  assert.equal(decision.result, "RECOMMEND_ONLY");
});

test("always-deny actions are denied with an explicit reason even if recommended", () => {
  const bad = incident({
    recommended_actions: [
      { action_type: "license.permanent_revoke", target_id: "lic_1", scope: "account", reversible: false, approval: "single_operator" },
      { action_type: "source_code.direct_patch", target_id: "repo_1", scope: "repo", reversible: false, approval: "single_operator" },
    ],
  });
  const decision = service().evaluate(bad, { environment: "production" }, NOW);
  const denied = decision.denied_actions.map((action) => action.action_type);
  assert.ok(denied.includes("license.permanent_revoke"));
  assert.ok(denied.includes("source_code.direct_patch"));
  const reason = decision.denied_actions.find((action) => action.action_type === "license.permanent_revoke")!.reason;
  assert.match(reason, /irreversible commercial revocation/);
});

test("global always-deny covers Sentinel-forbidden authority even without a matching policy", () => {
  assert.ok(GLOBAL_ALWAYS_DENY["customer_data.delete"]);
  assert.ok(GLOBAL_ALWAYS_DENY["billing.subscription.cancel"]);
  const decision = service().evaluate(
    incident({
      incident_type: "cost.usage_runaway",
      recommended_actions: [{ action_type: "billing.subscription.cancel", target_id: "sub_1", scope: "account", reversible: false, approval: "single_operator" }],
    }),
    { environment: "production" },
    NOW,
  );
  assert.equal(decision.result, "RECOMMEND_ONLY");
  assert.equal(decision.denied_actions[0]?.action_type, "billing.subscription.cancel");
});

test("cooldown denies repeat actions inside the hold period (06 hysteresis)", () => {
  const policy = service();
  const first = policy.evaluate(incident(), { environment: "production" }, NOW);
  assert.ok(first.allowed_actions.some((action) => action.action_type === "identity.api_key.pause"));
  // Keyed on the exact target ("key_1", from the incident's recommended
  // action) so it matches what recordExecutedAction is called with at real
  // execution time (presented.target) — not the coarser account id.
  policy.recordExecutedAction("identity.api_key.pause", "key_1", NOW);
  const second = policy.evaluate(incident(), { environment: "production" }, "2026-06-09T17:08:00.000Z");
  assert.ok(second.denied_actions.some((action) => action.action_type === "identity.api_key.pause" && action.reason.includes("cooldown")));
  const later = policy.evaluate(incident(), { environment: "production" }, "2026-06-09T17:20:00.000Z");
  assert.ok(later.allowed_actions.some((action) => action.action_type === "identity.api_key.pause"), "allowed again after cooldown");
});

test("cooldown is keyed per exact target, not the whole account (06 hysteresis)", () => {
  const policy = service();
  policy.recordExecutedAction("identity.api_key.pause", "key_1", NOW);
  // A second, unrelated key on the same account must not inherit key_1's
  // cooldown — otherwise one action anywhere on an account would silently
  // block every future bounded action of that type on the account.
  const otherKey = incident({
    recommended_actions: [{ action_type: "identity.api_key.pause", target_id: "key_2", scope: "single_key", reversible: true, approval: "single_operator" }],
  });
  const decision = policy.evaluate(otherKey, { environment: "production" }, "2026-06-09T17:08:00.000Z");
  assert.ok(decision.allowed_actions.some((action) => action.action_type === "identity.api_key.pause"), "a different target is not blocked by another target's cooldown");
});

test("emergency rule requires its own strict conditions", () => {
  const exfiltration = incident({ risk: { likelihood: 0.9, impact: 0.95, confidence: 0.9, evidence_quality: 0.96 } });
  const without = service().evaluate(exfiltration, { environment: "production" }, NOW);
  assert.ok(!without.allowed_actions.some((action) => action.action_type === "identity.session.revoke"));
  const withFlag = service().evaluate(exfiltration, { environment: "production", active_data_exfiltration: true }, NOW);
  assert.ok(withFlag.allowed_actions.some((action) => action.action_type === "identity.session.revoke"));
  assert.equal(withFlag.result, "ALLOW_EMERGENCY_CONTAINMENT");
});
