// Disposable derivation script: design evidence for the regeneration of 01 (owner ruling on
// KI-SENTINEL-20261104-001, 2026-11-04). It is not shipped, nothing in src/ imports it, and it is not
// wired into the gateway. It uses the Node standard library only, so a reviewer can reproduce its
// output without this repository's code.
//
//   node derive_01_regeneration.mjs [path/to/event.usage_tokens_recorded.json]
//
// It prints: a positive control (the old 41-record layout must reproduce the 1479-byte example that
// review round 1 verified), the regenerated field table, and the worked examples with their record
// counts, byte counts and SHA-256 digests. The digests are of the authenticated bytes, not HMACs:
// S1's golden vector carries the HMACs over a published test key.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const US = "\x1f"; // unit separator
const RS = "\x1e"; // record separator
const FORMAT = "forgesentinel.event_auth.v1";

// ---------- the encoder, exactly as 01 specifies a record ----------

function utf8(s) {
  // Refuse a lone surrogate: Node would replace it with U+FFFD and two strings would collide.
  if (/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(s)) {
    throw new Error("unpaired surrogate");
  }
  return Buffer.from(s, "utf8");
}

function record(name, tag, valueBytes) {
  return Buffer.concat([
    utf8(name), Buffer.from(US), Buffer.from(tag), Buffer.from(US),
    Buffer.from(String(valueBytes.length)), Buffer.from(US), valueBytes, Buffer.from(RS),
  ]);
}

const get = (obj, path) => path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);

/** A leaf record: `s`, `b` or the absent tag. A wrong type is refused, never coerced. */
function leaf(name, value, kind) {
  if (value === undefined) return record(name, "-", Buffer.alloc(0));
  if (value === null) throw new Error(`null in bound field ${name}`);
  if (kind === "s") {
    if (typeof value !== "string") throw new Error(`wrong type for ${name}`);
    return record(name, "s", utf8(value));
  }
  if (kind === "b") {
    if (typeof value !== "boolean") throw new Error(`wrong type for ${name}`);
    return record(name, "b", Buffer.from(value ? "true" : "false"));
  }
  throw new Error(`unknown kind ${kind}`);
}

const STR = (path) => ({ name: path, build: (e) => leaf(path, get(e, path), "s") });
const BOOL = (path) => ({ name: path, build: (e) => leaf(path, get(e, path), "b") });

/** A presence record for an optional parent (R1-B): tag `b`, `true` when the object is present. */
const PRESENCE = (parent) => ({
  name: parent,
  presence: true,
  build: (e) => {
    const v = e[parent];
    if (v !== undefined && (v === null || typeof v !== "object" || Array.isArray(v))) {
      throw new Error(`bound object ${parent} is not an object`);
    }
    return record(parent, "b", Buffer.from(v !== undefined ? "true" : "false"));
  },
});

/** The finding-id array: a count record (tag `c`), then one `s` record for each element. */
const FINDINGS = {
  name: "control_lineage.sentinel_finding_ids.count",
  build: (e) => {
    const ids = get(e, "control_lineage.sentinel_finding_ids");
    const countName = "control_lineage.sentinel_finding_ids.count";
    if (ids === undefined) return record(countName, "-", Buffer.alloc(0));
    if (!Array.isArray(ids)) throw new Error("sentinel_finding_ids is not an array");
    const parts = [record(countName, "c", Buffer.from(String(ids.length)))];
    ids.forEach((id, i) => {
      if (typeof id !== "string") throw new Error("finding id is not a string");
      parts.push(record(`control_lineage.sentinel_finding_ids.${i}`, "s", utf8(id)));
    });
    return Buffer.concat(parts);
  },
};

// ---------- the two layouts ----------

const CONTEXT_RECORDS = [
  { name: "auth_format", build: () => record("auth_format", "s", utf8(FORMAT)) },
  { name: "context", build: (_e, ctx) => record("context", "s", utf8(ctx.context)) },
  { name: "key_id", build: (_e, ctx) => record("key_id", "s", utf8(ctx.keyId)) },
];

const EVENT_HEAD = [
  "producer.service", "producer.instance_id", "producer.version", "producer.environment",
  "event_id", "event_type", "schema_version", "occurred_at", "observed_at",
].map(STR);

/** The 41-record layout of 01 as review round 1 verified it. Used only as the positive control. */
const OLD_LAYOUT = [
  ...CONTEXT_RECORDS,
  ...EVENT_HEAD,
  STR("tenant.tenant_id"), STR("tenant.account_id"),
  STR("actor.actor_type"), STR("actor.actor_id"), STR("actor.session_id"), STR("actor.api_key_fingerprint"),
  STR("subject.subject_type"), STR("subject.subject_id"),
  STR("resource.resource_type"), STR("resource.resource_id"), STR("resource.classification"),
  STR("correlation.trace_id"), STR("correlation.run_id"), STR("correlation.parent_event_id"),
  STR("location.execution_lane"), STR("location.region"), STR("location.country"),
  BOOL("data_policy.content_included"), STR("data_policy.sensitivity"),
  STR("data_policy.retention_class"), BOOL("data_policy.cloud_allowed"),
  STR("integrity.payload_hash"), STR("integrity.idempotency_key"),
  STR("control_lineage.control_origin"), BOOL("control_lineage.policy_generated_effect"),
  STR("control_lineage.sentinel_incident_id"), STR("control_lineage.policy_decision_id"),
  STR("control_lineage.control_id"),
  FINDINGS,
];

/**
 * In the `signature` context the record for integrity.signature is always the absent form: a value
 * cannot be an input to the bytes that produce it. The record keeps one layout for both contexts,
 * and record 2 binds the context, so the constant cannot be confused with an absent signature.
 */
const SIGNATURE_FIELD = {
  name: "integrity.signature",
  build: (e, ctx) =>
    ctx.context === "signature"
      ? record("integrity.signature", "-", Buffer.alloc(0))
      : leaf("integrity.signature", get(e, "integrity.signature"), "s"),
};

/** The regenerated layout: R1-B's three presence records and R1-A's two signature fields. */
const NEW_LAYOUT = [
  ...CONTEXT_RECORDS,
  ...EVENT_HEAD,
  PRESENCE("tenant"), STR("tenant.tenant_id"), STR("tenant.account_id"),
  STR("actor.actor_type"), STR("actor.actor_id"), STR("actor.session_id"), STR("actor.api_key_fingerprint"),
  STR("subject.subject_type"), STR("subject.subject_id"),
  PRESENCE("resource"), STR("resource.resource_type"), STR("resource.resource_id"), STR("resource.classification"),
  STR("correlation.trace_id"), STR("correlation.run_id"), STR("correlation.parent_event_id"),
  STR("location.execution_lane"), STR("location.region"), STR("location.country"),
  BOOL("data_policy.content_included"), STR("data_policy.sensitivity"),
  STR("data_policy.retention_class"), BOOL("data_policy.cloud_allowed"),
  STR("integrity.payload_hash"), STR("integrity.idempotency_key"),
  STR("integrity.signature_key_id"), SIGNATURE_FIELD,
  PRESENCE("control_lineage"),
  STR("control_lineage.control_origin"), BOOL("control_lineage.policy_generated_effect"),
  STR("control_lineage.sentinel_incident_id"), STR("control_lineage.policy_decision_id"),
  STR("control_lineage.control_id"),
  FINDINGS,
];

function encode(layout, event, ctx) {
  const parts = layout.map((r) => r.build(event, ctx));
  const bytes = Buffer.concat(parts);
  const records = bytes.toString("latin1").split(RS).length - 1;
  return { bytes, records, sha256: createHash("sha256").update(bytes).digest("hex") };
}

const escaped = (bytes) =>
  bytes.toString("utf8").split(RS).filter(Boolean).map((r) => r.replaceAll(US, "\\x1f") + "\\x1e").join("\n");

// ---------- the payload digest, as the golden event computes it ----------

/** Sorted-key compact JSON for an integer-and-string payload, then SHA-256. Checked against the golden digest. */
function payloadDigest(payload) {
  const canon = (v) =>
    Array.isArray(v) ? `[${v.map(canon).join(",")}]`
    : v && typeof v === "object" ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(",")}}`
    : JSON.stringify(v);
  return "sha256:" + createHash("sha256").update(canon(payload)).digest("hex");
}

// ---------- the events ----------

const here = dirname(fileURLToPath(import.meta.url));
const goldenPath = process.argv[2] ?? join(here, "../../../../fixtures/golden/event.usage_tokens_recorded.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf8"));

/**
 * Example B is CONSTRUCTED for this design: no committed fixture holds an event of a
 * signature-required family. It exercises every new record: all three parents present, a finding-id
 * array of two, and both signature fields. Its integrity.signature is an illustrative value of the
 * approved syntax (64 lowercase hex), not an HMAC: S1's golden vector carries real HMACs.
 */
const billingPayload = { plan_from: "team", plan_to: "business", seats: 12 };
const billing = {
  event_id: "evt_example_billing",
  event_type: "billing.subscription.changed",
  schema_version: "1.0.0",
  occurred_at: "2026-11-04T09:00:00.000Z",
  observed_at: "2026-11-04T09:00:01.000Z",
  producer: { service: "billing-service", instance_id: "billing-service-01", version: "1.4.0", environment: "production" },
  tenant: { tenant_id: "ten_demo", account_id: "acct_2041" },
  actor: { actor_type: "operator", actor_id: "op_charlie" },
  subject: { subject_type: "subscription", subject_id: "sub_7781" },
  resource: { resource_type: "subscription", resource_id: "sub_7781", classification: "confidential" },
  correlation: { trace_id: "trc_evt_example_billing", run_id: "run_42" },
  location: { execution_lane: "cloud", region: "us-east-1" },
  payload: billingPayload,
  data_policy: { content_included: false, sensitivity: "confidential", retention_class: "security_365d", cloud_allowed: true },
  integrity: {
    payload_hash: payloadDigest(billingPayload),
    idempotency_key: "evt_example_billing",
    signature_key_id: "key_billing_sig_01",
    signature: "0123456789abcdef".repeat(4),
  },
  control_lineage: {
    control_origin: "sentinel_policy",
    policy_generated_effect: true,
    sentinel_incident_id: "inc_0091",
    sentinel_finding_ids: ["fnd_0301", "fnd_0302"],
    policy_decision_id: "pd_0117",
    control_id: "ctl_cloud_route_hold",
  },
};

// ---------- output ----------

const out = [];
const say = (s = "") => out.push(s);

const digestOk = payloadDigest(golden.payload) === golden.integrity.payload_hash;
say(`payload digest method reproduces the golden digest: ${digestOk}`);

const control = encode(OLD_LAYOUT, golden, { context: "credential", keyId: "key_usage_01" });
say(`POSITIVE CONTROL old layout on the golden event: ${control.records} records, ${control.bytes.length} bytes` +
    ` (round 1 verified 41 records and 1479 bytes): ${control.records === 41 && control.bytes.length === 1479 ? "PASS" : "FAIL"}`);
if (!(control.records === 41 && control.bytes.length === 1479) || !digestOk) {
  console.log(out.join("\n"));
  console.error("The control failed, so nothing below can be trusted.");
  process.exit(1);
}

say();
say(`NEW LAYOUT: ${NEW_LAYOUT.length} fixed records, plus one record for each finding id`);
say("| # | Field name | Kind |");
NEW_LAYOUT.forEach((r, i) => say(`| ${i + 1} | ${r.name} | ${r.presence ? "presence" : r === FINDINGS ? "count, then elements" : "field"} |`));

const show = (label, event, ctx) => {
  const r = encode(NEW_LAYOUT, event, ctx);
  say();
  say(`EXAMPLE ${label}: context=${ctx.context} key_id=${ctx.keyId}: ${r.records} records, ${r.bytes.length} bytes, sha256 ${r.sha256}`);
  say(escaped(r.bytes));
  return r;
};

show("A (committed golden event)", golden, { context: "credential", keyId: "key_usage_01" });
const sig = show("B1 (constructed, signature input)", billing, { context: "signature", keyId: billing.integrity.signature_key_id });
const cred = show("B2 (constructed, credential input)", billing, { context: "credential", keyId: "key_billing_cred_01" });

// The signature input must not depend on the signature value: change it and the B1 bytes must not move.
const altered = structuredClone(billing);
altered.integrity.signature = "f".repeat(64);
const sig2 = encode(NEW_LAYOUT, altered, { context: "signature", keyId: billing.integrity.signature_key_id });
const cred2 = encode(NEW_LAYOUT, altered, { context: "credential", keyId: "key_billing_cred_01" });
say();
say(`CHECK the signature input is independent of integrity.signature: ${sig.sha256 === sig2.sha256 ? "PASS" : "FAIL"}`);
say(`CHECK the credential input binds integrity.signature: ${cred.sha256 !== cred2.sha256 ? "PASS" : "FAIL"}`);

// F3: integrity.signature_key_id was unbound in the credential context. It must now be bound there.
const rekeyed = structuredClone(billing); rekeyed.integrity.signature_key_id = "key_attacker";
const rk = encode(NEW_LAYOUT, rekeyed, { context: "credential", keyId: "key_billing_cred_01" });
const rkOld = encode(OLD_LAYOUT, rekeyed, { context: "credential", keyId: "key_billing_cred_01" });
const baseOld = encode(OLD_LAYOUT, billing, { context: "credential", keyId: "key_billing_cred_01" });
say(`CHECK F3 (old layout): a changed signature_key_id leaves the credential input unchanged: ${rkOld.sha256 === baseOld.sha256 ? "yes, as round 1 found" : "no"}`);
say(`CHECK F3 (new layout): a changed signature_key_id changes the credential input: ${rk.sha256 !== cred.sha256 ? "PASS" : "FAIL"}`);

// R1-B: an absent parent and a present empty parent must now encode differently.
const absent = structuredClone(golden); delete absent.resource;
const empty = structuredClone(golden); empty.resource = {};
const a = encode(NEW_LAYOUT, absent, { context: "credential", keyId: "key_usage_01" });
const b = encode(NEW_LAYOUT, empty, { context: "credential", keyId: "key_usage_01" });
const oa = encode(OLD_LAYOUT, absent, { context: "credential", keyId: "key_usage_01" });
const ob = encode(OLD_LAYOUT, empty, { context: "credential", keyId: "key_usage_01" });
say(`CHECK F2 (old layout): absent and empty resource collide: ${oa.sha256 === ob.sha256 ? "yes, as round 1 found" : "no"}`);
say(`CHECK F2 (new layout): absent and empty resource differ: ${a.sha256 !== b.sha256 ? "PASS" : "FAIL"}`);

// Tenant transplant (KI-SENTINEL-20261102-008): another tenant id must change both inputs.
const moved = structuredClone(billing); moved.tenant.tenant_id = "ten_victim";
const ms = encode(NEW_LAYOUT, moved, { context: "signature", keyId: billing.integrity.signature_key_id });
const mc = encode(NEW_LAYOUT, moved, { context: "credential", keyId: "key_billing_cred_01" });
say(`CHECK a tenant transplant changes the signature input: ${ms.sha256 !== sig.sha256 ? "PASS" : "FAIL"}`);
say(`CHECK a tenant transplant changes the credential input: ${mc.sha256 !== cred.sha256 ? "PASS" : "FAIL"}`);

console.log(out.join("\n"));
