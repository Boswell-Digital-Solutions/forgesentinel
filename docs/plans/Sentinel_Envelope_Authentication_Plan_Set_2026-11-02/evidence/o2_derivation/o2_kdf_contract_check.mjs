// Disposable design evidence for the O-2 derivation contract proposed in 09 (owner ruling on O-2,
// 2026-11-04: audience binding through key derivation, conditionally). It is not shipped, nothing in
// src/ imports it, and it implements nothing in the gateway. Node standard library only.
//
// Run it from the plan-set directory:
//
//   node evidence/o2_derivation/o2_kdf_contract_check.mjs
//
// It shows, for the proposed contract: RFC 5869 A.1, determinism, context and audience separation,
// cross-audience rejection, the injectivity of the info encoding, the fail-closed refusals, two known-answer
// values, that the frozen v1 vectors are unchanged, and that each deliberately broken derivation (a mutant)
// is caught.

import { hkdfSync, createHmac, createHash, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const US = "\x1f", RS = "\x1e";
const AUTH_FORMAT = "forgesentinel.event_auth.v1";
const KDF_LABEL = "forgesentinel.event_auth.v1.kdf";

// ---------- the proposed contract ----------

/** The canonical audience identifier: ASCII, lowercase, `aud:` then one to eight dotted labels. */
const AUDIENCE_GRAMMAR = /^aud:[a-z][a-z0-9-]{0,62}(\.[a-z][a-z0-9-]{0,62}){0,7}$/;
function assertAudience(a) {
  if (typeof a !== "string" || a.length > 255 || !AUDIENCE_GRAMMAR.test(a)) throw new Error("audience_invalid");
}
const CONTEXTS = new Set(["credential", "signature"]);
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

/** One record of 01's grammar: <name> 0x1F s 0x1F <length> 0x1F <value> 0x1E. Length-prefixed, so injective. */
function rec(name, value) {
  if (LONE_SURROGATE.test(value)) throw new Error("unpaired surrogate"); // unreachable from deriveAuthKey: each input is checked first
  const v = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${name}${US}s${US}${v.length}${US}`), v, Buffer.from(RS)]);
}

/** info = the label record, then context, audience and key id records, each length-prefixed. */
function kdfInfo(context, audience, keyId) {
  return Buffer.concat([rec("kdf", KDF_LABEL), rec("context", context), rec("audience", audience), rec("key_id", keyId)]);
}

/** deriveAuthKey(secret, context, audience, registrationKeyId). No default, no fallback, four arguments. */
function deriveAuthKey(secret, context, audience, keyId, impl = {}) {
  if (!(secret instanceof Uint8Array) || secret.length === 0) throw new Error("secret_invalid");
  if (!CONTEXTS.has(context)) throw new Error("context_invalid");
  (impl.assertAudience ?? assertAudience)(audience);
  if (typeof keyId !== "string" || keyId.length === 0 || LONE_SURROGATE.test(keyId)) throw new Error("key_id_invalid");
  const info = (impl.kdfInfo ?? kdfInfo)(context, audience, keyId);
  return Buffer.from(hkdfSync("sha256", secret, Buffer.from(AUTH_FORMAT, "ascii"), info, 32));
}
const mac = (key, bytes) => createHmac("sha256", key).update(bytes).digest();

// ---------- the reviewed v1 encoder, for the frozen vectors ----------

const derivePath = join(here, "../derive_01_regeneration.mjs");
const src = readFileSync(derivePath, "utf8").replace(/\/\/ ---------- the events ----------[\s\S]*$/, "") + "\nexport { encode, NEW_LAYOUT };";
const v1 = await import("data:text/javascript," + encodeURIComponent(src));
const golden = JSON.parse(readFileSync(join(here, "../../../../../fixtures/golden/event.usage_tokens_recorded.json"), "utf8"));
const authA = v1.encode(v1.NEW_LAYOUT, golden, { context: "credential", keyId: "key_usage_01" });

// ---------- checks ----------

let fails = 0;
const check = (name, ok) => { if (!ok) fails++; console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); };
const throws = (f, code) => { try { f(); return false; } catch (e) { return code ? e.message === code : true; } };
const SECRET = Buffer.from("test-secret-usage-metering-o2-evidence", "utf8"); // a published test value
const AUD_A = "aud:forgesentinel.gateway.test";
const AUD_B = "aud:forgesentinel.gateway.other";

// RFC 5869 test case A.1: the HKDF primitive itself.
{
  const ikm = Buffer.alloc(22, 0x0b);
  const salt = Buffer.from("000102030405060708090a0b0c", "hex");
  const info = Buffer.from("f0f1f2f3f4f5f6f7f8f9", "hex");
  const okm = Buffer.from(hkdfSync("sha256", ikm, salt, info, 42)).toString("hex");
  check("RFC 5869 A.1 reproduces", okm === "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
}

const kCA = deriveAuthKey(SECRET, "credential", AUD_A, "key_usage_01");
check("determinism: the same inputs give the same key", kCA.equals(deriveAuthKey(SECRET, "credential", AUD_A, "key_usage_01")));
check("context separation: credential and signature keys differ", !kCA.equals(deriveAuthKey(SECRET, "signature", AUD_A, "key_usage_01")));
const kCB = deriveAuthKey(SECRET, "credential", AUD_B, "key_usage_01");
check("audience separation: two audiences give two keys under one root secret", !kCA.equals(kCB));
const macA = mac(kCA, authA.bytes), macB = mac(kCB, authA.bytes);
check("cross-audience rejection: a MAC made for audience A does not verify as audience B", !timingSafeEqual(macA, macB));
check("key-id separation: two key ids give two keys", !kCA.equals(deriveAuthKey(SECRET, "credential", AUD_A, "key_usage_02")));

// The info encoding is injective: field boundaries cannot move.
const pairs = [
  [["credential", "aud:x", "y1"], ["credential", "aud:xy", "1"]],
  [["credential", "aud:a.b", "c"], ["credential", "aud:a", "b.c"]],
];
check("info injectivity: boundary-shifted inputs give different info and different keys",
  pairs.every(([p, q]) => !kdfInfo(...p).equals(kdfInfo(...q)) &&
    !deriveAuthKey(SECRET, ...p).equals(deriveAuthKey(SECRET, ...q))));

// Fail closed: every bad audience is refused, and nothing falls back to an unscoped key.
const bad = [undefined, null, "", " aud:x", "aud:x ", "AUD:x", "aud:X", "aud:", "aud:x.", "aud:.x", "aud:1x",
  "aud:x..y", "aud:é", "ten_demo", "aud:x|y", "aud:" + "a".repeat(64), 42, ["aud:x"]];
check(`fail-closed: ${bad.length} malformed, missing or tenant-shaped audiences are refused with audience_invalid`,
  bad.every((a) => throws(() => deriveAuthKey(SECRET, "credential", a, "key_usage_01"), "audience_invalid")));
check("fail-closed: the three-argument (unscoped) call is refused, not defaulted",
  throws(() => deriveAuthKey(SECRET, "credential", "key_usage_01")));
check("fail-closed: an unknown context is refused", throws(() => deriveAuthKey(SECRET, "verify", AUD_A, "k"), "context_invalid"));
check("fail-closed: an empty secret and an empty key id are refused",
  throws(() => deriveAuthKey(Buffer.alloc(0), "credential", AUD_A, "k"), "secret_invalid") &&
  throws(() => deriveAuthKey(SECRET, "credential", AUD_A, ""), "key_id_invalid"));

check("fail-closed: a key id with a lone high or low surrogate is refused with key_id_invalid (09, section 3.3)",
  ["k\ud800", "\udc00k", "a\ud800b"].every((k) => throws(() => deriveAuthKey(SECRET, "credential", AUD_A, k), "key_id_invalid")) &&
  !throws(() => deriveAuthKey(SECRET, "credential", AUD_A, "k\ud83d\ude00")));

// Known answers: the derivation's output, pinned. Two independent implementations agree on these values
// (this script on Node's hkdfSync, and an HKDF written by hand in Python from 09, section 3.2, alone).
// SECRET is the published test value above. These are test keys, never operational keys.
const KNOWN = [
  ["credential", AUD_A, "key_usage_01", "1bc9486c41bcd69ce064d2cf12f6dab0cd9508450aae095b4c124b56f54e3673"],
  ["signature", AUD_B, "key_billing_01", "e1180424aa87b0161e843136647b8772a40d60ffed8105e4be4ad3e7d31fc8b5"],
];
for (const [c, a, k, hex] of KNOWN)
  check(`known answer: ${c} / ${a} / ${k}`, deriveAuthKey(SECRET, c, a, k).toString("hex") === hex);

// Frozen-vector integrity: the derivation is not an input to the authenticated bytes.
const frozen = {
  A: ["ecb0d8f47b26861ecb4c6413a70571a891e83019744318ff74da2015d37cf998", 1597],
};
check("frozen v1 vector A is unchanged: 1597 bytes, the same SHA-256 (the derivation does not touch AUTH bytes)",
  authA.bytes.length === frozen.A[1] && createHash("sha256").update(authA.bytes).digest("hex") === frozen.A[0]);
const oldInfoKey = Buffer.from(hkdfSync("sha256", SECRET, Buffer.from(AUTH_FORMAT, "ascii"), Buffer.from("credential|key_usage_01"), 32));
check("compatibility, stated: a key under the earlier info (usage|key_id) differs, so any MAC value changes — and no MAC vector is committed",
  !oldInfoKey.equals(kCA));

// Mutants: each deliberately broken derivation must be caught by one of the checks above.
const mutants = {
  "audience left out of info": { kdfInfo: (c, a, k) => Buffer.concat([rec("kdf", KDF_LABEL), rec("context", c), rec("key_id", k)]) },
  "fields joined with no length prefix": { kdfInfo: (c, a, k) => Buffer.from(c + a + k) },
  "malformed audience falls back to an unscoped key": { assertAudience: () => {}, kdfInfo: (c, a, k) => (AUDIENCE_GRAMMAR.test(String(a)) ? kdfInfo(c, a, k) : Buffer.from(`${c}|${k}`)) },
  "audience case-folded instead of refused": { assertAudience: (a) => assertAudience(String(a).toLowerCase()) },
  "any string accepted as an audience": { assertAudience: () => {} },
};
const catches = {
  "audience left out of info": (m) => deriveAuthKey(SECRET, "credential", AUD_A, "k", m).equals(deriveAuthKey(SECRET, "credential", AUD_B, "k", m)),
  "fields joined with no length prefix": (m) => pairs.some(([p, q]) => deriveAuthKey(SECRET, ...p, m).equals(deriveAuthKey(SECRET, ...q, m))),
  "malformed audience falls back to an unscoped key": (m) => !throws(() => deriveAuthKey(SECRET, "credential", "ten_demo", "k", m)),
  "audience case-folded instead of refused": (m) => !throws(() => deriveAuthKey(SECRET, "credential", "AUD:x", "k", m)),
  "any string accepted as an audience": (m) => !throws(() => deriveAuthKey(SECRET, "credential", "ten_demo", "k", m)),
};
for (const [name, m] of Object.entries(mutants)) check(`mutant caught: ${name}`, catches[name](m) === true);

console.log(fails === 0 ? "ALL PASS" : `${fails} FAILED`);
process.exit(fails ? 1 : 0);
