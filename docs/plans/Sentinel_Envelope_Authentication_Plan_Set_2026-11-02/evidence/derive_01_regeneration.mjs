// Disposable derivation script: design evidence for the regeneration of 01 (owner ruling on
// KI-SENTINEL-20261104-001, 2026-11-04). It is not shipped, nothing in src/ imports it, and it is not
// wired into the gateway. It uses the Node standard library only, so a reviewer can reproduce its
// output without this repository's code.
//
// Run it from the plan-set directory:
//
//   node evidence/derive_01_regeneration.mjs [path/to/event.usage_tokens_recorded.json]
//
// It prints: a positive control (the old 41-record layout must reproduce the 1479-byte example that
// review round 1 verified), the regenerated field table, the worked examples with their record
// counts, byte counts and SHA-256 digests, and the checks that each rule of 01 holds. The digests are
// of the authenticated bytes, not HMACs: S1's golden vector carries the HMACs over a published test
// key.
//
// Revised after the four-lane retest of de52ad3 (2026-11-04): records are counted as they are built,
// not by splitting on 0x1E; the listing is built from the records; the encoder refuses a missing
// required field or object, a hole in the finding-id array, and a signature-context key id that is
// not integrity.signature_key_id; example B uses one key id, as a registration has one.

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
  return Buffer.from(s, "utf8"); // no Unicode normalization: the bytes are the string's own
}

/** One record: <name> 0x1F <tag> 0x1F <length> 0x1F <value> 0x1E. An absent record keeps all three 0x1F. */
function record(name, tag, valueBytes) {
  return Buffer.concat([
    utf8(name), Buffer.from(US), Buffer.from(tag), Buffer.from(US),
    Buffer.from(String(valueBytes.length)), Buffer.from(US), valueBytes, Buffer.from(RS),
  ]);
}

const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * The failure rules for required fields and objects. Always on in 01's format. The checks switch it
 * off only to show what the encoding did before the rule existed (`encode(..., { strict: false })`).
 */
let enforceRequired = true;

/** Walk a dotted path. A parent that is present must be a plain object; otherwise the event is refused. */
function get(obj, path) {
  const keys = path.split(".");
  let o = obj;
  for (let i = 0; i < keys.length; i++) {
    if (o === undefined) return undefined;
    if (i > 0 && !isPlainObject(o)) {
      if (!enforceRequired) return undefined; // the behaviour before the rule: a non-object parent read as absent
      throw new Error(`bound object ${keys.slice(0, i).join(".")} is not an object`);
    }
    o = o[keys[i]];
  }
  return o;
}

/**
 * A leaf record: `s`, `b` or the absent tag. A wrong type is refused, never coerced. A required leaf
 * may be absent only when its optional parent is absent; otherwise its absence is refused.
 */
function leaf(name, value, kind, required, event) {
  if (value === undefined) {
    const parent = name.includes(".") ? name.slice(0, name.lastIndexOf(".")) : undefined;
    const parentAbsent = parent !== undefined && get(event, parent) === undefined;
    if (required && enforceRequired && !parentAbsent) throw new Error(`required field ${name} is absent`);
    return record(name, "-", Buffer.alloc(0));
  }
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

// `required` follows src/contracts/envelope.ts. For a field of an optional parent it applies when the parent is present.
const STR = (path, required) => ({ name: path, build: (e) => [leaf(path, get(e, path), "s", required, e)] });
const BOOL = (path, required) => ({ name: path, build: (e) => [leaf(path, get(e, path), "b", required, e)] });
const REQ = true, OPT = false;

/** A presence record for an optional parent (R1-B): tag `b`, `true` when the object is present. */
const PRESENCE = (parent) => ({
  name: parent,
  presence: true,
  build: (e) => {
    const v = e[parent];
    if (v !== undefined && !isPlainObject(v)) throw new Error(`bound object ${parent} is not an object`);
    return [record(parent, "b", Buffer.from(v !== undefined ? "true" : "false"))];
  },
});

/** The finding-id array: a count record (tag `c`), then one `s` record for each index 0 to length-1. */
const FINDINGS = {
  name: "control_lineage.sentinel_finding_ids.count",
  build: (e) => {
    const ids = get(e, "control_lineage.sentinel_finding_ids");
    const countName = "control_lineage.sentinel_finding_ids.count";
    if (ids === undefined) return [record(countName, "-", Buffer.alloc(0))];
    if (!Array.isArray(ids)) throw new Error("sentinel_finding_ids is not an array");
    const parts = [record(countName, "c", Buffer.from(String(ids.length)))];
    for (let i = 0; i < ids.length; i++) {
      if (!(i in ids)) throw new Error(`sentinel_finding_ids has a hole at ${i}`);
      if (typeof ids[i] !== "string") throw new Error("finding id is not a string");
      // The element name is the index in plain decimal, with no leading zero.
      parts.push(record(`control_lineage.sentinel_finding_ids.${i}`, "s", utf8(ids[i])));
    }
    return parts;
  },
};

// ---------- the two layouts ----------

const CONTEXT_RECORDS = [
  { name: "auth_format", build: () => [record("auth_format", "s", utf8(FORMAT))] },
  { name: "context", build: (_e, ctx) => [record("context", "s", utf8(ctx.context))] },
  { name: "key_id", build: (_e, ctx) => [record("key_id", "s", utf8(ctx.keyId))] },
];

const HEAD = ["producer.service", "producer.instance_id", "producer.version", "producer.environment",
  "event_id", "event_type", "schema_version", "occurred_at", "observed_at"];

/** The 41-record layout of 01 as review round 1 verified it, with its permissive leaves. Positive control only. */
const PERMISSIVE = (path, kind) => ({
  name: path,
  build: (e) => {
    const keys = path.split(".");
    let o = e;
    for (const k of keys) o = o == null ? undefined : o[k];
    return [o === undefined ? record(path, "-", Buffer.alloc(0)) : record(path, kind, kind === "b" ? Buffer.from(o ? "true" : "false") : utf8(o))];
  },
});
const OLD_LAYOUT = [
  ...CONTEXT_RECORDS,
  ...HEAD.map((p) => PERMISSIVE(p, "s")),
  ...["tenant.tenant_id", "tenant.account_id", "actor.actor_type", "actor.actor_id", "actor.session_id",
    "actor.api_key_fingerprint", "subject.subject_type", "subject.subject_id", "resource.resource_type",
    "resource.resource_id", "resource.classification", "correlation.trace_id", "correlation.run_id",
    "correlation.parent_event_id", "location.execution_lane", "location.region", "location.country"].map((p) => PERMISSIVE(p, "s")),
  PERMISSIVE("data_policy.content_included", "b"), PERMISSIVE("data_policy.sensitivity", "s"),
  PERMISSIVE("data_policy.retention_class", "s"), PERMISSIVE("data_policy.cloud_allowed", "b"),
  PERMISSIVE("integrity.payload_hash", "s"), PERMISSIVE("integrity.idempotency_key", "s"),
  PERMISSIVE("control_lineage.control_origin", "s"), PERMISSIVE("control_lineage.policy_generated_effect", "b"),
  PERMISSIVE("control_lineage.sentinel_incident_id", "s"), PERMISSIVE("control_lineage.policy_decision_id", "s"),
  PERMISSIVE("control_lineage.control_id", "s"),
  { name: FINDINGS.name, build: (e) => {
      const ids = e.control_lineage?.sentinel_finding_ids;
      const n = "control_lineage.sentinel_finding_ids.count";
      if (ids === undefined) return [record(n, "-", Buffer.alloc(0))];
      return [record(n, "c", Buffer.from(String(ids.length))), ...ids.map((id, i) => record(`control_lineage.sentinel_finding_ids.${i}`, "s", utf8(id)))];
    } },
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
      ? [record("integrity.signature", "-", Buffer.alloc(0))]
      : [leaf("integrity.signature", get(e, "integrity.signature"), "s", OPT, e)],
};

/** The regenerated layout: R1-B's three presence records and R1-A's two signature fields. */
const NEW_LAYOUT = [
  ...CONTEXT_RECORDS,
  ...HEAD.map((p) => STR(p, REQ)),
  PRESENCE("tenant"), STR("tenant.tenant_id", REQ), STR("tenant.account_id", OPT),
  STR("actor.actor_type", REQ), STR("actor.actor_id", REQ), STR("actor.session_id", OPT), STR("actor.api_key_fingerprint", OPT),
  STR("subject.subject_type", REQ), STR("subject.subject_id", REQ),
  PRESENCE("resource"), STR("resource.resource_type", REQ), STR("resource.resource_id", REQ), STR("resource.classification", OPT),
  STR("correlation.trace_id", REQ), STR("correlation.run_id", OPT), STR("correlation.parent_event_id", OPT),
  STR("location.execution_lane", REQ), STR("location.region", OPT), STR("location.country", OPT),
  BOOL("data_policy.content_included", REQ), STR("data_policy.sensitivity", REQ),
  STR("data_policy.retention_class", REQ), BOOL("data_policy.cloud_allowed", REQ),
  STR("integrity.payload_hash", REQ), STR("integrity.idempotency_key", REQ),
  STR("integrity.signature_key_id", OPT), SIGNATURE_FIELD,
  PRESENCE("control_lineage"),
  STR("control_lineage.control_origin", REQ), BOOL("control_lineage.policy_generated_effect", REQ),
  STR("control_lineage.sentinel_incident_id", OPT), STR("control_lineage.policy_decision_id", OPT),
  STR("control_lineage.control_id", OPT),
  FINDINGS,
];

/** The seven required objects of the contract. Each must be a plain object; an absent one is refused. */
const REQUIRED_OBJECTS = ["producer", "actor", "subject", "correlation", "location", "data_policy", "integrity"];

function encode(layout, event, ctx, { strict = true } = {}) {
  const previous = enforceRequired;
  enforceRequired = strict;
  try {
    return encodeChecked(layout, event, ctx, strict);
  } finally {
    enforceRequired = previous;
  }
}

function encodeChecked(layout, event, ctx, strict) {
  if (strict) {
    for (const o of REQUIRED_OBJECTS) {
      if (!isPlainObject(event[o])) throw new Error(`required object ${o} is absent or not an object`);
    }
    // The signature context binds the event's signature key id as record 3, so the two must be one value.
    if (ctx.context === "signature" && event.integrity.signature_key_id !== ctx.keyId) {
      throw new Error("signature context key id is not integrity.signature_key_id");
    }
  }
  const recs = layout.flatMap((r) => r.build(event, ctx));
  const bytes = Buffer.concat(recs);
  return { recs, bytes, records: recs.length, sha256: createHash("sha256").update(bytes).digest("hex") };
}

/** The listing, one record per line, built from the records themselves: every 0x1F and 0x1E is escaped. */
const escaped = (recs) =>
  recs.map((r) => r.toString("utf8").replaceAll(US, "\\x1f").replaceAll(RS, "\\x1e")).join("\n");

// ---------- the payload digest ----------

/**
 * Sorted-key compact JSON for an integer-and-string payload, then SHA-256. This is NOT src's
 * hashPayload: it reproduces the golden digest for a benign payload, and it does not reproduce
 * hashPayload's KI-SENTINEL-20261102-006 defects (`__proto__`, `-0`, non-finite numbers).
 */
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
 * array of two, and both signature fields. One key id, as a producer registration has one: the
 * credential's key id, integrity.signature_key_id and the registration's key id are all
 * `key_billing_01`. Its integrity.signature is an illustrative value of the approved syntax (64
 * lowercase hex), not an HMAC: S1's golden vector carries real HMACs.
 */
const KEY_B = "key_billing_01";
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
    signature_key_id: KEY_B,
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
const refused = (fn) => { try { fn(); return false; } catch { return true; } };
const passIf = (ok) => (ok ? "PASS" : "FAIL");

const digestOk = payloadDigest(golden.payload) === golden.integrity.payload_hash;
say(`payload digest method reproduces the golden digest (benign payload only): ${digestOk}`);

const control = encode(OLD_LAYOUT, golden, { context: "credential", keyId: "key_usage_01" }, { strict: false });
const controlOk = control.records === 41 && control.bytes.length === 1479;
say(`POSITIVE CONTROL old layout on the golden event: ${control.records} records, ${control.bytes.length} bytes, sha256 ${control.sha256}` +
    ` (round 1 verified 41 records and 1479 bytes): ${passIf(controlOk)}`);
if (!controlOk || !digestOk) {
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
  say(escaped(r.recs));
  return r;
};

show("A (committed golden event)", golden, { context: "credential", keyId: "key_usage_01" });
const sig = show("B1 (constructed, signature input)", billing, { context: "signature", keyId: KEY_B });
const cred = show("B2 (constructed, credential input)", billing, { context: "credential", keyId: KEY_B });

say();
// The signature input must not depend on the signature value: change it and the B1 bytes must not move.
const altered = structuredClone(billing); altered.integrity.signature = "f".repeat(64);
say(`CHECK the signature input is independent of integrity.signature: ${passIf(encode(NEW_LAYOUT, altered, { context: "signature", keyId: KEY_B }).sha256 === sig.sha256)}`);
say(`CHECK the credential input binds integrity.signature: ${passIf(encode(NEW_LAYOUT, altered, { context: "credential", keyId: KEY_B }).sha256 !== cred.sha256)}`);

// F3: integrity.signature_key_id was unbound in the credential context.
const rekeyed = structuredClone(billing); rekeyed.integrity.signature_key_id = "key_attacker";
const oldBase = encode(OLD_LAYOUT, billing, { context: "credential", keyId: KEY_B }, { strict: false });
const oldRekey = encode(OLD_LAYOUT, rekeyed, { context: "credential", keyId: KEY_B }, { strict: false });
say(`CHECK F3 (old layout): a changed signature_key_id leaves the credential input unchanged: ${oldRekey.sha256 === oldBase.sha256 ? "yes, as round 1 found" : "no"}`);
say(`CHECK F3 (new layout): a changed signature_key_id changes the credential input: ${passIf(encode(NEW_LAYOUT, rekeyed, { context: "credential", keyId: KEY_B }).sha256 !== cred.sha256)}`);

// R1-B: an absent optional parent and a present empty one must encode differently.
const absent = structuredClone(golden); delete absent.resource;
const empty = structuredClone(golden); empty.resource = {};
const ctxA = { context: "credential", keyId: "key_usage_01" };
say(`CHECK F2 (old layout): absent and empty resource collide: ${encode(OLD_LAYOUT, absent, ctxA, { strict: false }).sha256 === encode(OLD_LAYOUT, empty, ctxA, { strict: false }).sha256 ? "yes, as round 1 found" : "no"}`);
say(`CHECK F2 (new layout, presence record alone, without the failure rule): absent and empty resource differ: ${passIf(encode(NEW_LAYOUT, absent, ctxA, { strict: false }).sha256 !== encode(NEW_LAYOUT, empty, ctxA, { strict: false }).sha256)}`);
say(`CHECK F2 (new layout, with the failure rule): an empty resource is refused, because a present resource needs resource_type and resource_id: ${passIf(refused(() => encode(NEW_LAYOUT, empty, ctxA)))}`);

// A required object: absent, empty, null and an array collided before the failure rule. Each must now be refused.
const actorVariants = { absent: (e) => { delete e.actor; }, empty: (e) => { e.actor = {}; }, null: (e) => { e.actor = null; }, array: (e) => { e.actor = []; } };
const permissiveHashes = new Set(Object.values(actorVariants).map((f) => { const e = structuredClone(golden); f(e); return encode(NEW_LAYOUT, e, ctxA, { strict: false, }).sha256; }));
const allRefused = Object.values(actorVariants).every((f) => refused(() => { const e = structuredClone(golden); f(e); encode(NEW_LAYOUT, e, ctxA); }));
say(`CHECK required object (without the failure rule): actor absent, {}, null and [] give ${permissiveHashes.size} distinct encoding(s)`);
say(`CHECK required object (with the failure rule): all four are refused: ${passIf(allRefused)}`);
const noActorId = structuredClone(golden); delete noActorId.actor.actor_id;
say(`CHECK a missing required field is refused: ${passIf(refused(() => encode(NEW_LAYOUT, noActorId, ctxA)))}`);

// The signature-context key id rule.
say(`CHECK a signature context whose key id differs from integrity.signature_key_id is refused: ${passIf(refused(() => encode(NEW_LAYOUT, billing, { context: "signature", keyId: "key_other" })))}`);
const noSigKey = structuredClone(billing); delete noSigKey.integrity.signature_key_id;
say(`CHECK a signature context with no integrity.signature_key_id is refused: ${passIf(refused(() => encode(NEW_LAYOUT, noSigKey, { context: "signature", keyId: KEY_B })))}`);

// The finding-id array: a hole is refused, and an empty array is the count 0 with no element records.
const holed = structuredClone(billing); holed.control_lineage.sentinel_finding_ids = [, "fnd_0302"];
say(`CHECK a hole in sentinel_finding_ids is refused: ${passIf(refused(() => encode(NEW_LAYOUT, holed, { context: "credential", keyId: KEY_B })))}`);
const noIds = structuredClone(billing); noIds.control_lineage.sentinel_finding_ids = [];
const noIdsEnc = encode(NEW_LAYOUT, noIds, { context: "credential", keyId: KEY_B });
say(`CHECK an empty sentinel_finding_ids is the count 0 with no element records: ${passIf(noIdsEnc.records === 46 && noIdsEnc.bytes.includes(Buffer.from(`control_lineage.sentinel_finding_ids.count${US}c${US}1${US}0${RS}`)))}`);

// A value that contains the separators: the record count must still be the number of records built.
const sepValue = structuredClone(golden); sepValue.actor.actor_id = `a${RS}b${US}c`;
say(`CHECK a value containing 0x1E and 0x1F still counts 46 records: ${passIf(encode(NEW_LAYOUT, sepValue, ctxA).records === 46)}`);

// Tenant transplant (KI-SENTINEL-20261102-008): another tenant id must change both inputs.
const moved = structuredClone(billing); moved.tenant.tenant_id = "ten_victim";
say(`CHECK a tenant transplant changes the signature input: ${passIf(encode(NEW_LAYOUT, moved, { context: "signature", keyId: KEY_B }).sha256 !== sig.sha256)}`);
say(`CHECK a tenant transplant changes the credential input: ${passIf(encode(NEW_LAYOUT, moved, { context: "credential", keyId: KEY_B }).sha256 !== cred.sha256)}`);

say();
say("Example B payload (record 36 is its digest): " + JSON.stringify(billingPayload));

console.log(out.join("\n"));
