// Seeded fuzz: injectivity (bytes -> projection map), decoder round trip, cross-context separation.
import { encode, decode, project, Refused, TABLE } from "./r2_encoder.mjs";

let seed = 20261104 >>> 0;
const rnd = () => { seed = (seed + 0x6d2b79f5) >>> 0; let t = seed; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const pick = (a) => a[Math.floor(rnd() * a.length)];
const ATOMS = ["", "a", "ab", "\x1f", "\x1e", "\x1f\x1e", "a\x1fs\x1f1\x1fb\x1e", "é", "é", "😀", "0", "true", "false", "-", "tenant.tenant_id\x1fs\x1f1\x1fx\x1e"];
const s = () => (rnd() < 0.7 ? pick(ATOMS) : pick(ATOMS) + pick(ATOMS));
const opt = (f) => (rnd() < 0.4 ? undefined : f());
const strip = (o) => { for (const k of Object.keys(o)) if (o[k] === undefined) delete o[k]; return o; };

function gen() {
  const e = strip({
    event_id: s(), event_type: s(), schema_version: s(), occurred_at: s(), observed_at: s(),
    producer: strip({ service: s(), instance_id: s(), version: s(), environment: s() }),
    tenant: opt(() => strip({ tenant_id: s(), account_id: opt(s) })),
    actor: strip({ actor_type: s(), actor_id: s(), session_id: opt(s), api_key_fingerprint: opt(s) }),
    subject: strip({ subject_type: s(), subject_id: s() }),
    resource: opt(() => strip({ resource_type: s(), resource_id: s(), classification: opt(s) })),
    correlation: strip({ trace_id: s(), run_id: opt(s), parent_event_id: opt(s) }),
    location: strip({ execution_lane: s(), region: opt(s), country: opt(s) }),
    payload: {},
    data_policy: { content_included: rnd() < 0.5, sensitivity: s(), retention_class: s(), cloud_allowed: rnd() < 0.5 },
    integrity: strip({ payload_hash: s(), idempotency_key: s(), signature_key_id: opt(s), signature: opt(s) }),
    control_lineage: opt(() => strip({ control_origin: s(), policy_generated_effect: rnd() < 0.5, sentinel_incident_id: opt(s),
      policy_decision_id: opt(s), control_id: opt(s), sentinel_finding_ids: opt(() => Array.from({ length: Math.floor(rnd() * 4) }, s)) })),
  });
  return e;
}

const N = Number(process.argv[2] ?? 50000);
const seen = new Map();
let encoded = 0, refused = 0, collisions = 0, rtFail = 0, crossCtx = 0;
const byCtx = { credential: new Set(), signature: new Set() };
const canon = (o) => JSON.stringify(Object.keys(o).sort().map((k) => [k, o[k] === undefined ? "<absent>" : o[k]]));
for (let i = 0; i < N; i++) {
  const e = gen();
  for (const ctx of ["credential", "signature"]) {
    const key = ctx === "signature" ? e.integrity.signature_key_id ?? s() : s();
    let b;
    try { b = encode(ctx, key, e); } catch (err) { if (err instanceof Refused) { refused++; continue; } throw err; }
    encoded++;
    const hex = b.toString("hex");
    const p = canon(project(ctx, key, e));
    const prev = seen.get(hex);
    if (prev !== undefined && prev !== p) { collisions++; if (collisions < 3) console.log("COLLISION", prev, p); }
    seen.set(hex, p);
    byCtx[ctx].add(hex);
    try { if (canon(decode(b)) !== p) { rtFail++; if (rtFail < 3) console.log("RT", canon(decode(b)), p); } } catch (err) { rtFail++; if (rtFail < 3) console.log("RT throw", err.message); }
  }
}
for (const h of byCtx.credential) if (byCtx.signature.has(h)) crossCtx++;
console.log(JSON.stringify({ envelopes: N, encoded, refused, distinctByteStrings: seen.size, collisions, roundTripFailures: rtFail, crossContextEqual: crossCtx }));
