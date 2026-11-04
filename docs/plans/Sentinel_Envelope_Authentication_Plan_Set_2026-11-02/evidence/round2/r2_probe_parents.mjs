import { readFileSync } from "node:fs";
import { encode, Refused, TABLE } from "./r2_encoder.mjs";
const g = JSON.parse(readFileSync("../round2-frozen/fixtures/golden/event.usage_tokens_recorded.json", "utf8"));
const sys = { ...structuredClone(g), event_type: "sentinel.finding.created" };
for (const [label, e] of [["resource: {}", { ...structuredClone(g), resource: {} }], ["tenant: {} (system-scoped type)", (() => { const x = structuredClone(sys); x.tenant = {}; return x; })()],
  ["control_lineage: {}", { ...structuredClone(g), control_lineage: {} }]]) {
  try { encode("credential", "k", e); console.log(label, "-> encoded (bytes exist)"); } catch (err) { console.log(label, "-> REFUSED by encoder:", err.message); }
}
// Presence records carry no extra information once the failure rules hold: drop them and re-check distinctness.
const strip = (b) => b.toString("latin1").split("\x1e").filter((r) => !/^(tenant|resource|control_lineage)\x1fb\x1f/.test(r)).join("\x1e");
const pairs = [[structuredClone(g), (() => { const x = structuredClone(g); x.resource = { resource_type: "a", resource_id: "b" }; return x; })()],
  [(() => { const x = structuredClone(sys); delete x.tenant; return x; })(), (() => { const x = structuredClone(sys); x.tenant = { tenant_id: "" }; return x; })()]];
for (const [a, b] of pairs) console.log("absent parent vs minimal present parent, presence records removed: differ =", strip(encode("credential", "k", a)) !== strip(encode("credential", "k", b)));
