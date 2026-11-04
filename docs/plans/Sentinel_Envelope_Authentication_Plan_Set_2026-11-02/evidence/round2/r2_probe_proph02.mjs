// Mutant: drop location.country from the schedule. A round trip built on the same schedule still passes.
import * as enc from "./r2_encoder.mjs";
import { readFileSync } from "node:fs";
const g = JSON.parse(readFileSync("../round2-frozen/fixtures/golden/event.usage_tokens_recorded.json", "utf8"));
const i = enc.TABLE.findIndex((r) => r[0] === "location.country");
enc.TABLE.splice(i, 1);
const a = structuredClone(g), b = structuredClone(g); b.location.country = "XX";
const rt = (e) => { const d = enc.decode(enc.encode("credential", "k", e)); const p = enc.project("credential", "k", e); return JSON.stringify(Object.entries(d).sort()) === JSON.stringify(Object.entries(p).sort()); };
console.log("mutant round trip passes for a:", rt(a), "and b:", rt(b));
console.log("mutant: a and b give identical bytes:", enc.encode("credential", "k", a).equals(enc.encode("credential", "k", b)));
