// Evidence for the S1 preconditions of the owner disposition on review round 2 (2026-11-04).
// Run from committed sources only, in this layout (the same one review round 2 used):
//
//   W=$(mktemp -d)
//   git archive 3cae2dd560ba20e69b6249f21cb2174db13e8f4d | (mkdir -p "$W/round2-frozen" && tar -x -C "$W/round2-frozen")
//   cp -r <plan set>/evidence/round2 "$W/round2-work"
//   cp <plan set>/evidence/s1_preconditions/*.mjs "$W"
//   cd "$W" && node r2f3_matrix_check.mjs round2-frozen/docs/plans/Sentinel_Envelope_Authentication_Plan_Set_2026-11-02/evidence/derive_01_regeneration.mjs
//
// The corrected 04 cases (R2-F3), checked against two independent encoders.
import { readFileSync } from "node:fs";
import * as rv from "./round2-work/r2_encoder.mjs";
const planSrc = readFileSync(process.argv[2], "utf8").replace(/\/\/ ---------- the events ----------[\s\S]*$/, "") + "\nexport { encode as planEncode, NEW_LAYOUT };";
const plan = await import("data:text/javascript," + encodeURIComponent(planSrc));
const golden = JSON.parse(readFileSync("./round2-frozen/fixtures/golden/event.usage_tokens_recorded.json", "utf8"));
const encoders = {
  plan: (ev) => plan.planEncode(plan.NEW_LAYOUT, ev, { context: "credential", keyId: "key_usage_01" }).bytes,
  reviewer: (ev) => rv.encode("credential", "key_usage_01", ev),
};
const refused = (f) => { try { f(); return false; } catch { return true; } };
const minimal = { tenant: { tenant_id: "ten_x" }, resource: { resource_type: "r", resource_id: "r1" }, control_lineage: { control_origin: "operator", policy_generated_effect: false } };
let fail = 0;
const check = (name, ok) => { if (!ok) fail++; console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); };
for (const [enc, f] of Object.entries(encoders)) {
  for (const parent of ["tenant", "resource", "control_lineage"]) {
    const absent = structuredClone(golden); delete absent[parent];
    const empty = structuredClone(golden); empty[parent] = {};
    const min = structuredClone(golden); min[parent] = structuredClone(minimal[parent]);
    check(`[${enc}] ADV-H10 ${parent}: the absent form encodes`, !refused(() => f(absent)));
    check(`[${enc}] ADV-H10/NEG-L04 ${parent}: the present empty form is refused`, refused(() => f(empty)));
    const a = f(absent), m = f(min);
    check(`[${enc}] ADV-H10 ${parent}: absent and minimal present give different bytes`, !a.equals(m));
    check(`[${enc}] ADV-H10 ${parent}: the presence record is false against true`,
      a.includes(Buffer.from(`${parent}\x1fb\x1f5\x1ffalse\x1e`)) && m.includes(Buffer.from(`${parent}\x1fb\x1f4\x1ftrue\x1e`)));
  }
  const noField = structuredClone(golden); delete noField.actor.actor_id;
  const noObj = structuredClone(golden); delete noObj.subject;
  check(`[${enc}] PROP-H01: an absent required field is a refusal case`, refused(() => f(noField)));
  check(`[${enc}] PROP-H01: an absent required object is a refusal case`, refused(() => f(noObj)));
}
console.log(fail === 0 ? "ALL PASS" : `${fail} FAILED`);
process.exit(fail ? 1 : 0);
