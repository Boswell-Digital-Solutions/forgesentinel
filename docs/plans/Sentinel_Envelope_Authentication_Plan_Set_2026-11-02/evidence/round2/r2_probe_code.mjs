// Probes against the built code at 3cae2dd (worktree wt/dist). Run from round2-work.
import { randomBytes } from "node:crypto";
const D = "./wt/dist/src";
const { ProducerRegistry } = await import(`${D}/spine/producers.js`);
const { EventGateway } = await import(`${D}/spine/gateway.js`);
const { EvidenceLedger } = await import(`${D}/spine/ledger.js`);
const { buildEvent } = await import(`${D}/spine/build.js`);
const { validateEventEnvelope } = await import(`${D}/contracts/envelope.js`);
const { hashPayload } = await import(`${D}/contracts/common.js`);

const secret = () => randomBytes(32).toString("base64url") + "Aa1!";
const usage = { service: "usage-metering", environment: "production", key_id: "key_usage_01", secret: secret(), signature_required: false, allowed_event_prefixes: ["usage."], tenant_scope: "required" };
const fresh = () => { const r = new ProducerRegistry("production"); r.register(usage); const l = new EvidenceLedger(); return { g: new EventGateway(r, l), l }; };
const base = () => buildEvent(usage, { event_id: "evt_probe_1", event_type: "usage.tokens.recorded", occurred_at: "2026-11-04T09:00:00.000Z",
  tenant: { tenant_id: "ten_demo", account_id: "acct_2041" }, actor: { actor_type: "service", actor_id: "svc" }, subject: { subject_type: "account", subject_id: "acct_2041" },
  payload: { total_tokens: 1 } });

// P1: KI-008 still open in fact (tenant transplant with original credential).
{ const { g } = fresh(); const { event, credential } = base(); const moved = structuredClone(event); moved.tenant.tenant_id = "ten_other";
  console.log("P1 KI-008 tenant transplant today:", g.ingest(moved, credential).status); }

// P2: KI-006 still open in fact: __proto__ key in payload keeps the hash.
{ const p = JSON.parse('{"total_tokens":1,"__proto__":{"admin":true}}'); console.log("P2 KI-006 __proto__ payload same hash:", hashPayload(p) === hashPayload({ total_tokens: 1 })); }

// P3: contract-failure reason text carries unbounded attacker text (envelope.ts:148), to ledger and caller.
{ const { g, l } = fresh(); const { event, credential } = base(); const bad = structuredClone(event); bad.event_type = "x".repeat(100000) + "\u0000\u001b[31m";
  const r = g.ingest(bad, credential); const rec = l.all().at(-1);
  const msgLen = Math.max(...r.reasons.map((x) => x.message.length));
  console.log("P3 unknown_event_type: status", r.status, "caller message length", msgLen, "ledger reason message length", Math.max(...rec.rejection_reasons.map((x) => x.message.length)),
    "contains NUL/ESC:", rec.rejection_reasons.some((x) => x.message.includes("\u0000\u001b")), "record tenant_id:", rec.tenant_id); }

// P4: what a pre-authentication rejection record holds today (keys), vs the five-element ceiling.
{ const { g, l } = fresh(); const { event, credential } = base(); const bad = structuredClone(event); bad.payload.total_tokens = 2;
  g.ingest(bad, credential); const rec = l.all().at(-1);
  console.log("P4 payload_hash_mismatch record keys:", Object.keys(rec).join(","), "| body is whole envelope:", rec.body === bad || JSON.stringify(rec.body) === JSON.stringify(bad)); }

// P5: unknown and prototype-named keys at top level and inside bound objects pass and are stored (S2 not implemented).
{ const { g, l } = fresh(); const { event, credential } = base();
  const txt = JSON.stringify(event).replace('"tenant":{', '"tenant":{"__proto__":{"tenant_id":"ten_victim"},"constructor":1,').replace('{"event_id"', '{"__proto__":{"resource":{"resource_type":"x","resource_id":"y"}},"toString":"z","event_id"');
  const parsed = JSON.parse(txt);
  console.log("P5 own keys survive JSON.parse:", Object.hasOwn(parsed, "__proto__"), Object.hasOwn(parsed.tenant, "__proto__"), "| parsed.resource:", parsed.resource, "| status:", g.ingest(parsed, credential).status);
  const copied = Object.assign({}, parsed); const tcopy = Object.assign({}, parsed.tenant);
  console.log("P5b Object.assign copy: copied.resource =", JSON.stringify(copied.resource), "own?", Object.hasOwn(copied, "resource"), "| tcopy.tenant_id =", tcopy.tenant_id);
  const allow = { tenant_id: true, account_id: true };
  console.log("P5c a naive object-literal allowlist: '__proto__' in allow =", "__proto__" in allow, "| 'constructor' in allow =", "constructor" in allow, "| allow['toString'] truthy =", !!allow["toString"]); }

// P6: example B from 01 against today's validator.
{ const payload = { plan_from: "team", plan_to: "business", seats: 12 };
  const B = { event_id: "evt_example_billing", event_type: "billing.subscription.changed", schema_version: "1.0.0", occurred_at: "2026-11-04T09:00:00.000Z", observed_at: "2026-11-04T09:00:01.000Z",
    producer: { service: "billing-service", instance_id: "billing-service-01", version: "1.4.0", environment: "production" }, tenant: { tenant_id: "ten_demo", account_id: "acct_2041" },
    actor: { actor_type: "operator", actor_id: "op_charlie" }, subject: { subject_type: "subscription", subject_id: "sub_7781" },
    resource: { resource_type: "subscription", resource_id: "sub_7781", classification: "confidential" }, correlation: { trace_id: "trc_evt_example_billing", run_id: "run_42" },
    location: { execution_lane: "cloud", region: "us-east-1" }, payload,
    data_policy: { content_included: false, sensitivity: "confidential", retention_class: "security_365d", cloud_allowed: true },
    integrity: { payload_hash: hashPayload(payload), idempotency_key: "evt_example_billing", signature_key_id: "key_billing_01", signature: "0123456789abcdef".repeat(4) },
    control_lineage: { control_origin: "sentinel_policy", policy_generated_effect: true, sentinel_incident_id: "inc_0091", policy_decision_id: "pd_0117", control_id: "ctl_cloud_route_hold", sentinel_finding_ids: ["fnd_0301", "fnd_0302"] } };
  console.log("P6 example B validates today:", validateEventEnvelope(B).ok, "| hashPayload matches 01:", hashPayload(payload) === "sha256:39de473dec94c28e7c2376880a524c31572d13096ea06ea64e8fa1de6060adfe"); }

// P7: the gateway receives a parsed value, never bytes: two different received texts, one parsed value.
{ const a = '{"x":1,"x":2}', b = '{"x":2}', c = '{"x":2.0}', d = '{"x":2e0}';
  console.log("P7 four different texts, hashPayload of parsed:", new Set([a, b, c, d].map((t) => hashPayload(JSON.parse(t)))).size, "distinct value(s)"); }

// P8: KI-017 colon shift still authenticates (ruling 6 not implemented).
{ const r = new ProducerRegistry("production"); const reg = { ...usage, key_id: "a:b" }; r.register(reg);
  const { createHmac } = await import("node:crypto"); const ph = "sha256:" + "0".repeat(64); const tok = createHmac("sha256", reg.secret).update(ph).digest("hex");
  console.log("P8 KI-017 shifted labels authenticate:", !!r.authenticate({ service: "usage-metering:a", key_id: "b", token: tok }, ph)); }
