const { validateEventEnvelope } = await import("./wt/dist/src/contracts/envelope.js");
import { readFileSync } from "node:fs";
const g = JSON.parse(readFileSync("../round2-frozen/fixtures/golden/event.usage_tokens_recorded.json", "utf8"));
const big = "Z".repeat(50000) + "\u0000";
for (const [label, mut] of [
  ["actor.actor_type (invalid_enum)", (e) => (e.actor.actor_type = big)],
  ["schema_version (invalid_semver)", (e) => (e.schema_version = big)],
  ["data_policy.sensitivity (invalid_enum)", (e) => (e.data_policy.sensitivity = big)],
  ["event_type (unknown_event_type)", (e) => (e.event_type = big)],
]) {
  const e = structuredClone(g); mut(e);
  const r = validateEventEnvelope(e);
  console.log(label, "->", r.issues.map((i) => `${i.code}: message ${i.message.length} chars, NUL ${i.message.includes("\u0000")}`).join("; "));
}
