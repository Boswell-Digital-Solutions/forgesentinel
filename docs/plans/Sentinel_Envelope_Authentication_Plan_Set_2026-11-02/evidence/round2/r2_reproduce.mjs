// Reproduce 01's worked examples with the reviewer's own encoder, then attack it.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { encode, decode, project, sha, Refused, deriveKey, hmac, TABLE } from "./r2_encoder.mjs";

const FROZEN = process.argv[2] ?? "../round2-frozen";
const golden = JSON.parse(readFileSync(`${FROZEN}/fixtures/golden/event.usage_tokens_recorded.json`, "utf8"));
const count = (b) => b.filter((x) => x === 0x1e).length;
const show = (label, b) => console.log(`${label}: ${count(b)} records, ${b.length} bytes, sha256 ${sha(b)}`);

show("A credential key_usage_01", encode("credential", "key_usage_01", golden));

// Example B, built from the values listed in 01 (lines 776-901).
const payloadB = { plan_from: "team", plan_to: "business", seats: 12 };
const canon = (v) => JSON.stringify(v, Object.keys(v).sort());
const B = {
  event_id: "evt_example_billing", event_type: "billing.subscription.changed", schema_version: "1.0.0",
  occurred_at: "2026-11-04T09:00:00.000Z", observed_at: "2026-11-04T09:00:01.000Z",
  producer: { service: "billing-service", instance_id: "billing-service-01", version: "1.4.0", environment: "production" },
  tenant: { tenant_id: "ten_demo", account_id: "acct_2041" },
  actor: { actor_type: "operator", actor_id: "op_charlie" },
  subject: { subject_type: "subscription", subject_id: "sub_7781" },
  resource: { resource_type: "subscription", resource_id: "sub_7781", classification: "confidential" },
  correlation: { trace_id: "trc_evt_example_billing", run_id: "run_42" },
  location: { execution_lane: "cloud", region: "us-east-1" },
  payload: payloadB,
  data_policy: { content_included: false, sensitivity: "confidential", retention_class: "security_365d", cloud_allowed: true },
  integrity: {
    payload_hash: "sha256:" + createHash("sha256").update(canon(payloadB)).digest("hex"),
    idempotency_key: "evt_example_billing", signature_key_id: "key_billing_01",
    signature: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  },
  control_lineage: { control_origin: "sentinel_policy", policy_generated_effect: true, sentinel_incident_id: "inc_0091",
    policy_decision_id: "pd_0117", control_id: "ctl_cloud_route_hold", sentinel_finding_ids: ["fnd_0301", "fnd_0302"] },
};
if (!import.meta.url.includes("quiet")) console.log("B payload_hash", B.integrity.payload_hash);
show("B1 signature key_billing_01", encode("signature", "key_billing_01", B));
show("B2 credential key_billing_01", encode("credential", "key_billing_01", B));

// Decoder round trip on the three examples.
for (const [c, k, e] of [["credential", "key_usage_01", golden], ["signature", "key_billing_01", B], ["credential", "key_billing_01", B]]) {
  const d = decode(encode(c, k, e));
  const p = project(c, k, e);
  const ok = JSON.stringify(d, Object.keys(d).sort()) === JSON.stringify(p, Object.keys(d).sort()) && Object.keys(d).length === Object.keys(p).length;
  console.log(`round trip ${c}/${k}: ${ok ? "PASS" : "FAIL"}`);
}
export { B, golden };
