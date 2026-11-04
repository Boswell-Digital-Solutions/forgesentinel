// Evidence for the S1 preconditions of the owner disposition on review round 2 (2026-11-04).
// Run from committed sources only, in this layout (the same one review round 2 used):
//
//   W=$(mktemp -d)
//   git archive 3cae2dd560ba20e69b6249f21cb2174db13e8f4d | (mkdir -p "$W/round2-frozen" && tar -x -C "$W/round2-frozen")
//   cp -r <plan set>/evidence/round2 "$W/round2-work"
//   cp <plan set>/evidence/s1_preconditions/*.mjs "$W"
//   cd "$W" && node r2f4_proph02_check.mjs
//
// The corrected PROP-H02 (R2-F4): the expected field set comes from the contract, not from the encoder.
import { readFileSync } from "node:fs";
const src = readFileSync("./round2-frozen/src/contracts/envelope.ts", "utf8");
// Parse the declared fields of EventEnvelope and its member interfaces (the 51 the plan set counts).
const iface = {}; let cur = null;
for (const line of src.split("\n")) {
  const m = line.match(/^export interface (\w+)/); if (m) { cur = m[1]; iface[cur] = []; continue; }
  if (cur && /^}/.test(line)) { cur = null; continue; }
  const f = cur && line.match(/^\s+(\w+)(\??):\s*(.+?);/); if (f) iface[cur].push({ name: f[1], opt: f[2] === "?", type: f[3] });
}
const objects = { producer: "EventProducer", actor: "EventActor", subject: "EventSubject", resource: "EventResource", correlation: "EventCorrelation", location: "EventLocation", data_policy: "EventDataPolicy", integrity: "EventIntegrity", control_lineage: "ControlLineage" };
const leaves = [], parents = [];
for (const f of iface.EventEnvelope) {
  if (f.name === "payload") continue;                        // bound through the digest, R-5's one exclusion
  if (f.name === "tenant") { parents.push("tenant"); leaves.push("tenant.tenant_id", "tenant.account_id"); continue; }
  if (objects[f.name]) { if (f.opt) parents.push(f.name); for (const g of iface[objects[f.name]]) leaves.push(`${f.name}.${g.name}`); continue; }
  leaves.push(f.name);
}
const fail = [];
const ok = (n, c) => { console.log(`${c ? "PASS" : "FAIL"}  ${n}`); if (!c) fail.push(n); };
ok(`the contract declares 40 leaves and 3 optional parents (found ${leaves.length} and ${parents.length})`, leaves.length === 40 && parents.length === 3);

// The decoded field names, from an independent encoder's decode of example A.
const run = async (mutate) => {
  const enc = await import(`./round2-work/r2_encoder.mjs?${mutate ? "mutant" : "clean"}`);
  if (mutate) enc.TABLE.splice(enc.TABLE.findIndex((r) => r[0] === "location.country"), 1);
  const g = JSON.parse(readFileSync("./round2-frozen/fixtures/golden/event.usage_tokens_recorded.json", "utf8"));
  const decoded = new Set(Object.keys(enc.decode(enc.encode("credential", "key_usage_01", g))).map((k) => k.replace(/\.count$/, "")));
  const missing = [...leaves, ...parents].filter((n) => !decoded.has(n));
  return missing;
};
const clean = await run(false);
ok(`clean encoder: every declared leaf and parent is in the decoded projection (missing: ${clean.join(", ") || "none"})`, clean.length === 0);
const mutant = await run(true);
ok(`R2-F4 mutant (location.country dropped): the corrected property FAILS it (missing: ${mutant.join(", ") || "none"})`, mutant.length === 1 && mutant[0] === "location.country");
console.log(fail.length ? `${fail.length} FAILED` : "ALL PASS"); process.exit(fail.length ? 1 : 0);
