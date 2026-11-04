// Round 2 reviewer's independent encoder, written from the text of 01 at 3cae2dd only.
// It does not import or read evidence/derive_01_regeneration.mjs.
import { createHash, createHmac, hkdfSync } from "node:crypto";

const US = 0x1f, RS = 0x1e;
export const FORMAT = "forgesentinel.event_auth.v1";

// [name, kind, tag, required] in table order. kind: ctx | field | presence | count
const OPT_PARENTS = new Set(["tenant", "resource", "control_lineage"]);
const REQ_OBJECTS = ["producer", "actor", "subject", "correlation", "location", "data_policy", "integrity"];
export const TABLE = [
  ["auth_format", "ctx"], ["context", "ctx"], ["key_id", "ctx"],
  ["producer.service", "field", "s", true], ["producer.instance_id", "field", "s", true],
  ["producer.version", "field", "s", true], ["producer.environment", "field", "s", true],
  ["event_id", "field", "s", true], ["event_type", "field", "s", true], ["schema_version", "field", "s", true],
  ["occurred_at", "field", "s", true], ["observed_at", "field", "s", true],
  ["tenant", "presence"], ["tenant.tenant_id", "field", "s", true], ["tenant.account_id", "field", "s", false],
  ["actor.actor_type", "field", "s", true], ["actor.actor_id", "field", "s", true],
  ["actor.session_id", "field", "s", false], ["actor.api_key_fingerprint", "field", "s", false],
  ["subject.subject_type", "field", "s", true], ["subject.subject_id", "field", "s", true],
  ["resource", "presence"], ["resource.resource_type", "field", "s", true], ["resource.resource_id", "field", "s", true],
  ["resource.classification", "field", "s", false],
  ["correlation.trace_id", "field", "s", true], ["correlation.run_id", "field", "s", false],
  ["correlation.parent_event_id", "field", "s", false],
  ["location.execution_lane", "field", "s", true], ["location.region", "field", "s", false], ["location.country", "field", "s", false],
  ["data_policy.content_included", "field", "b", true], ["data_policy.sensitivity", "field", "s", true],
  ["data_policy.retention_class", "field", "s", true], ["data_policy.cloud_allowed", "field", "b", true],
  ["integrity.payload_hash", "field", "s", true], ["integrity.idempotency_key", "field", "s", true],
  ["integrity.signature_key_id", "field", "s", false], ["integrity.signature", "field", "s", false],
  ["control_lineage", "presence"], ["control_lineage.control_origin", "field", "s", true],
  ["control_lineage.policy_generated_effect", "field", "b", true],
  ["control_lineage.sentinel_incident_id", "field", "s", false], ["control_lineage.policy_decision_id", "field", "s", false],
  ["control_lineage.control_id", "field", "s", false],
  ["control_lineage.sentinel_finding_ids.count", "count"],
];

export class Refused extends Error {}
const isPlain = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const hasLone = (s) => /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(s);

function rec(name, tag, valueBytes) {
  return Buffer.concat([Buffer.from(name, "ascii"), Buffer.from([US]), Buffer.from(tag, "ascii"), Buffer.from([US]),
    Buffer.from(String(valueBytes.length), "ascii"), Buffer.from([US]), valueBytes, Buffer.from([RS])]);
}
const absent = (name) => rec(name, "-", Buffer.alloc(0));
function str(name, v) {
  if (typeof v !== "string") throw new Refused(`${name}: not a string`);
  if (hasLone(v)) throw new Refused(`${name}: lone surrogate`);
  return rec(name, "s", Buffer.from(v, "utf8"));
}

export function encode(context, keyId, ev) {
  if (!isPlain(ev)) throw new Refused("envelope not an object");
  for (const o of REQ_OBJECTS) if (!isPlain(ev[o])) throw new Refused(`${o}: required object absent or not an object`);
  for (const o of OPT_PARENTS) if (ev[o] !== undefined && !isPlain(ev[o])) throw new Refused(`${o}: not an object`);
  if (context === "signature") {
    if (ev.integrity.signature_key_id === undefined || keyId !== ev.integrity.signature_key_id) throw new Refused("signature key id rule");
  }
  const out = [];
  for (const [name, kind, tag, required] of TABLE) {
    if (kind === "ctx") {
      if (name === "auth_format") out.push(str(name, FORMAT));
      else if (name === "context") out.push(str(name, context));
      else out.push(str(name, keyId));
      continue;
    }
    if (kind === "presence") { out.push(rec(name, "b", Buffer.from(ev[name] !== undefined ? "true" : "false"))); continue; }
    if (kind === "count") {
      const lin = ev.control_lineage;
      const ids = lin === undefined ? undefined : lin.sentinel_finding_ids;
      if (ids === undefined) { out.push(absent(name)); continue; }
      if (ids === null || !Array.isArray(ids)) throw new Refused("sentinel_finding_ids not an array");
      out.push(rec(name, "c", Buffer.from(String(ids.length), "ascii")));
      for (let i = 0; i < ids.length; i++) {
        if (!(i in ids)) throw new Refused("hole");
        out.push(str(`control_lineage.sentinel_finding_ids.${i}`, ids[i]));
      }
      continue;
    }
    const parts = name.split(".");
    let v;
    if (parts.length === 1) v = ev[name];
    else {
      const parent = ev[parts[0]];
      if (parent === undefined) { out.push(absent(name)); continue; } // only optional parents can be undefined here
      v = parent[parts[1]];
    }
    if (context === "signature" && name === "integrity.signature") { out.push(absent(name)); continue; }
    if (v === undefined) {
      if (required) throw new Refused(`${name}: required field absent`);
      out.push(absent(name)); continue;
    }
    if (v === null) throw new Refused(`${name}: null`);
    if (tag === "s") out.push(str(name, v));
    else if (tag === "b") {
      if (typeof v !== "boolean") throw new Refused(`${name}: not a boolean`);
      out.push(rec(name, "b", Buffer.from(String(v))));
    }
  }
  return Buffer.concat(out);
}

// Decoder: strict parse under the fixed schedule. Returns a projection; throws on any deviation.
export function decode(buf) {
  let p = 0;
  const readUntil = (b) => { const i = buf.indexOf(b, p); if (i < 0) throw new Error("trunc"); const s = buf.subarray(p, i); p = i + 1; return s; };
  const readRecord = (expectName) => {
    const name = readUntil(US).toString("ascii");
    if (name !== expectName) throw new Error(`name ${name} != ${expectName}`);
    const tag = readUntil(US).toString("ascii");
    if (!["s", "b", "c", "-"].includes(tag)) throw new Error("tag");
    const lenTxt = readUntil(US).toString("ascii");
    if (!/^(0|[1-9][0-9]*)$/.test(lenTxt)) throw new Error("len");
    const len = Number(lenTxt);
    if (p + len >= buf.length + 1) throw new Error("trunc v");
    const val = buf.subarray(p, p + len); p += len;
    if (buf[p] !== RS) throw new Error("no RS"); p++;
    if (tag === "-" && len !== 0) throw new Error("absent nonzero");
    return { tag, val };
  };
  const proj = {};
  for (const [name, kind] of TABLE) {
    const r = readRecord(name);
    if (kind === "count") {
      if (r.tag === "-") { proj[name] = undefined; continue; }
      if (r.tag !== "c") throw new Error("count tag");
      const n = Number(r.val.toString("ascii"));
      const ids = [];
      for (let i = 0; i < n; i++) { const e = readRecord(`control_lineage.sentinel_finding_ids.${i}`); if (e.tag !== "s") throw new Error("el"); ids.push(e.val.toString("utf8")); }
      proj["control_lineage.sentinel_finding_ids"] = ids;
      continue;
    }
    proj[name] = r.tag === "-" ? undefined : r.tag === "b" ? r.val.toString() === "true" : r.val.toString("utf8");
  }
  if (p !== buf.length) throw new Error("trailing bytes");
  return proj;
}

// Projection taken directly from the envelope, from the contract's field list (independent of TABLE order).
export function project(context, keyId, ev) {
  const p = { auth_format: FORMAT, context, key_id: keyId };
  for (const [name, kind] of TABLE) {
    if (kind === "ctx") continue;
    if (kind === "presence") { p[name] = ev[name] !== undefined; continue; }
    if (kind === "count") {
      const ids = ev.control_lineage?.sentinel_finding_ids;
      p["control_lineage.sentinel_finding_ids.count"] = ids === undefined ? undefined : undefined;
      if (ids !== undefined) { delete p["control_lineage.sentinel_finding_ids.count"]; p["control_lineage.sentinel_finding_ids"] = [...ids]; }
      continue;
    }
    const [a, b] = name.split(".");
    let v = b === undefined ? ev[a] : ev[a]?.[b];
    if (context === "signature" && name === "integrity.signature") v = undefined;
    p[name] = v;
  }
  return p;
}

export const sha = (b) => createHash("sha256").update(b).digest("hex");
export function deriveKey(secret, usage, keyId) {
  return Buffer.from(hkdfSync("sha256", Buffer.from(secret, "utf8"), Buffer.from(FORMAT, "ascii"), Buffer.from(`${usage}|${keyId}`, "utf8"), 32));
}
export const hmac = (k, b) => createHmac("sha256", k).update(b).digest("hex");
