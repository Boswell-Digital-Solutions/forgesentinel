import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EventGateway,
  EvidenceLedger,
  ProducerRegistry,
  buildEvent,
  producerToken,
  standardProducers,
  type ProducerRegistration,
} from "../src/index.js";

function setup(): { gateway: EventGateway; ledger: EvidenceLedger; producers: Record<string, ProducerRegistration> } {
  const registry = new ProducerRegistry();
  const producers: Record<string, ProducerRegistration> = {};
  for (const producer of standardProducers("production")) {
    registry.register(producer);
    producers[producer.service] = producer;
  }
  const ledger = new EvidenceLedger();
  return { gateway: new EventGateway(registry, ledger), ledger, producers };
}

function usageLine(producers: Record<string, ProducerRegistration>, id = "evt_t1") {
  return buildEvent(producers["usage-metering"]!, {
    event_id: id,
    event_type: "usage.tokens.recorded",
    occurred_at: "2026-06-09T12:00:00.000Z",
    tenant: { tenant_id: "ten_demo", account_id: "acct_1" },
    actor: { actor_type: "service", actor_id: "neuroforge-gateway" },
    subject: { subject_type: "account", subject_id: "acct_1" },
    correlation: { trace_id: "trc_t1" },
    payload: { total_tokens: 1000, route_class: "general_cloud" },
  });
}

test("valid event from registered producer is accepted with ingestion metadata", () => {
  const { gateway, producers } = setup();
  const { event, credential } = usageLine(producers);
  const result = gateway.ingest(event, credential);
  assert.equal(result.status, "accepted");
  assert.ok(result.record);
  assert.equal(result.record.validation, "accepted");
  assert.equal(result.record.tenant_id, "ten_demo");
  assert.ok(result.record.ingested_at);
});

test("unregistered producer is rejected and rejection is recorded (explicit rejection)", () => {
  const { gateway, ledger, producers } = setup();
  const { event } = usageLine(producers);
  const result = gateway.ingest(event, { service: "rogue-service", key_id: "key_rogue", token: "deadbeef" });
  assert.equal(result.status, "rejected");
  assert.ok(result.reasons.some((reason) => reason.code === "producer_auth_failed"));
  const rejections = ledger.all().filter((record) => record.kind === "rejection");
  assert.equal(rejections.length, 1);
});

test("wrong producer token fails authentication", () => {
  const { gateway, producers } = setup();
  const { event } = usageLine(producers);
  const result = gateway.ingest(event, { service: "usage-metering", key_id: "key_usage_01", token: "0".repeat(64) });
  assert.equal(result.status, "rejected");
  assert.ok(result.reasons.some((reason) => reason.code === "producer_auth_failed"));
});

test("producer cannot emit event types outside its registration", () => {
  const { gateway, producers } = setup();
  const usage = producers["usage-metering"]!;
  const { event } = buildEvent(usage, {
    event_id: "evt_t2",
    event_type: "identity.login.failed",
    occurred_at: "2026-06-09T12:00:00.000Z",
    tenant: { tenant_id: "ten_demo" },
    actor: { actor_type: "user", actor_id: "usr_1" },
    subject: { subject_type: "account", subject_id: "acct_1" },
    correlation: { trace_id: "trc_t2" },
    payload: {},
  });
  const result = gateway.ingest(event, { service: usage.service, key_id: usage.key_id, token: producerToken(usage.secret, event.integrity.payload_hash) });
  assert.equal(result.status, "rejected");
  assert.ok(result.reasons.some((reason) => reason.code === "event_type_not_allowed"));
});

test("environment boundary is enforced", () => {
  const { gateway, producers } = setup();
  const { event, credential } = usageLine(producers);
  (event.producer as { environment: string }).environment = "staging";
  const result = gateway.ingest(event, credential);
  assert.equal(result.status, "rejected");
  assert.ok(result.reasons.some((reason) => reason.code === "environment_boundary"));
});

test("payload tampering is detected via payload hash", () => {
  const { gateway, producers } = setup();
  const { event, credential } = usageLine(producers);
  event.payload["total_tokens"] = 999999999;
  const result = gateway.ingest(event, credential);
  assert.equal(result.status, "rejected");
  assert.ok(result.reasons.some((reason) => reason.code === "payload_hash_mismatch"));
});

test("high-value billing events require a valid signature", () => {
  const { gateway, producers } = setup();
  const billing = producers["billing-service"]!;
  const { event, credential } = buildEvent(billing, {
    event_id: "evt_stripe_1",
    event_type: "billing.stripe.webhook_verified",
    occurred_at: "2026-06-09T12:00:00.000Z",
    tenant: { tenant_id: "ten_demo", account_id: "acct_1" },
    actor: { actor_type: "service", actor_id: "stripe-webhook-handler" },
    subject: { subject_type: "subscription", subject_id: "sub_1" },
    correlation: { trace_id: "trc_stripe" },
    payload: { stripe_event_id: "evt_stripe_native_1", type: "invoice.paid" },
  });
  assert.ok(event.integrity.signature, "billing events are signed by the builder");
  const tampered = { ...event, integrity: { ...event.integrity, signature: "0".repeat(64) } };
  const bad = gateway.ingest(tampered, credential);
  assert.equal(bad.status, "rejected");
  assert.ok(bad.reasons.some((reason) => reason.code === "signature_invalid"));
  const good = gateway.ingest(event, credential);
  assert.equal(good.status, "accepted");
});

test("replayed Stripe webhook is idempotent: duplicate has no second effect (12 core scenario)", () => {
  const { gateway, ledger, producers } = setup();
  const billing = producers["billing-service"]!;
  const { event, credential } = buildEvent(billing, {
    event_id: "evt_stripe_2",
    event_type: "billing.stripe.webhook_verified",
    occurred_at: "2026-06-09T12:00:00.000Z",
    tenant: { tenant_id: "ten_demo", account_id: "acct_1" },
    actor: { actor_type: "service", actor_id: "stripe-webhook-handler" },
    subject: { subject_type: "subscription", subject_id: "sub_1" },
    correlation: { trace_id: "trc_stripe2" },
    payload: { stripe_event_id: "evt_stripe_native_2", type: "invoice.paid" },
  });
  assert.equal(gateway.ingest(event, credential).status, "accepted");
  const replayed = gateway.ingest(event, credential);
  assert.equal(replayed.status, "duplicate");
  assert.equal(ledger.events().length, 1);
});

test("distinct events are never collapsed even with similar content", () => {
  const { gateway, producers } = setup();
  const first = usageLine(producers, "evt_d1");
  const second = usageLine(producers, "evt_d2");
  assert.equal(gateway.ingest(first.event, first.credential).status, "accepted");
  assert.equal(gateway.ingest(second.event, second.credential).status, "accepted");
});

test("tenant-scoped producer must carry tenant", () => {
  const { gateway, producers } = setup();
  const identity = producers["identity-service"]!;
  const { event, credential } = buildEvent(identity, {
    event_id: "evt_t3",
    event_type: "identity.login.failed",
    occurred_at: "2026-06-09T12:00:00.000Z",
    actor: { actor_type: "user", actor_id: "usr_1" },
    subject: { subject_type: "account", subject_id: "acct_1" },
    correlation: { trace_id: "trc_t3" },
    payload: {},
  });
  const result = gateway.ingest(event, credential);
  assert.equal(result.status, "rejected");
  assert.ok(result.reasons.some((reason) => reason.code === "tenant_required"));
});

test("dedupe key includes tenant: identical event_id/subject/payload from two tenants never collapse (2026-09-19 finding)", () => {
  const { gateway, ledger, producers } = setup();
  const usage = producers["usage-metering"]!;
  const shared = {
    event_id: "evt_shared_1",
    event_type: "usage.tokens.recorded",
    occurred_at: "2026-06-09T12:00:00.000Z",
    actor: { actor_type: "service" as const, actor_id: "neuroforge-gateway" },
    subject: { subject_type: "account" as const, subject_id: "acct_1" },
    correlation: { trace_id: "trc_shared" },
    payload: { total_tokens: 1000, route_class: "general_cloud" },
  };
  const tenantA = buildEvent(usage, { ...shared, tenant: { tenant_id: "ten_a" } });
  const tenantB = buildEvent(usage, { ...shared, tenant: { tenant_id: "ten_b" } });
  const resultA = gateway.ingest(tenantA.event, tenantA.credential);
  const resultB = gateway.ingest(tenantB.event, tenantB.credential);
  assert.equal(resultA.status, "accepted");
  assert.equal(resultB.status, "accepted", "a same-hour collision from a different tenant must not read back as the other tenant's record");
  assert.notEqual(resultA.dedupe_key, resultB.dedupe_key);
  assert.equal(ledger.events().length, 2);
});

test("non-canonical ad hoc event types are rejected", () => {
  const { gateway, producers } = setup();
  const usage = producers["usage-metering"]!;
  const { event, credential } = buildEvent(usage, {
    event_id: "evt_t4",
    event_type: "usage.something_adhoc",
    occurred_at: "2026-06-09T12:00:00.000Z",
    tenant: { tenant_id: "ten_demo" },
    actor: { actor_type: "service", actor_id: "svc" },
    subject: { subject_type: "account", subject_id: "acct_1" },
    correlation: { trace_id: "trc_t4" },
    payload: {},
  });
  const result = gateway.ingest(event, credential);
  assert.equal(result.status, "rejected");
  assert.ok(result.reasons.some((reason) => reason.code === "unknown_event_type"));
});
