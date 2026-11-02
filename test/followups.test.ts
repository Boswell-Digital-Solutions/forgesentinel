import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MAX_EVENT_PREFIXES,
  ProducerRegistrationError,
  ProducerRegistry,
  SentinelRuntime,
  buildEvent,
  replayInto,
  type ProducerCredential,
  type ProducerRegistration,
  type ReplayLine,
} from "../src/index.js";
import { byService, testProducers } from "./support/producers.js";

/**
 * KI-SENTINEL-20261102-001: the prefix-list length is bounded before the copy.
 * KI-SENTINEL-20261030-006 item 1: tokens and signatures are lowercase hex only.
 * KI-SENTINEL-20261030-006 item 2: a malformed credential or replay line is a
 * rejection of that event, not an exception.
 */

const TENANT = { tenant_id: "ten_demo", account_id: "acct_1" };
let counter = 0;

function line(producer: ProducerRegistration, eventType: string, payload: Record<string, unknown>): ReplayLine {
  counter += 1;
  return buildEvent(producer, {
    event_id: `evt_followup_${counter}`,
    event_type: eventType,
    occurred_at: "2026-06-09T12:00:00.000Z",
    tenant: TENANT,
    actor: { actor_type: "service", actor_id: producer.service },
    subject: { subject_type: "account", subject_id: TENANT.account_id },
    correlation: { trace_id: `trc_followup_${counter}` },
    payload,
  });
}

function setup(): { runtime: SentinelRuntime; producers: Record<string, ProducerRegistration> } {
  const configured = testProducers("production");
  return { runtime: new SentinelRuntime("production", { producers: configured }), producers: byService(configured) };
}

const usage = (producer: ProducerRegistration) => line(producer, "usage.tokens.recorded", { total_tokens: 10, route_class: "general_cloud" });
const billing = (producer: ProducerRegistration) => line(producer, "billing.subscription.changed", { plan: "pro" });

// KI-SENTINEL-20261102-001 ----------------------------------------------------

test("a prefix list longer than the bound is refused before any element is read", () => {
  const registry = new ProducerRegistry("production");
  const base = testProducers("production")[1]!;
  for (const length of [MAX_EVENT_PREFIXES + 1, 5_000_000, 2 ** 32 - 1]) {
    const sparse: string[] = [];
    sparse.length = length;
    const started = Date.now();
    assert.throws(() => registry.register({ ...base, key_id: `key_sparse_${length}`, allowed_event_prefixes: sparse }), ProducerRegistrationError);
    assert.ok(Date.now() - started < 1000, `length ${length} is refused quickly`);
  }
  let indexReads = 0;
  const huge = new Proxy(["usage."], {
    get(target, property, receiver) {
      if (property === "length") return 2 ** 32 - 1;
      if (typeof property === "string" && /^\d+$/.test(property)) indexReads += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  assert.throws(() => registry.register({ ...base, key_id: "key_proxy_huge", allowed_event_prefixes: huge }), ProducerRegistrationError);
  assert.equal(indexReads, 0, "no element is read when the length is over the bound");
});

test("a prefix list at the bound is accepted", () => {
  const registry = new ProducerRegistry("production");
  const prefixes = Array.from({ length: MAX_EVENT_PREFIXES }, (_, index) => `usage.p${index}.`);
  assert.doesNotThrow(() => registry.register({ ...testProducers("production")[1]!, allowed_event_prefixes: prefixes }));
});

// KI-SENTINEL-20261030-006 item 1 --------------------------------------------

test("an upper-case producer token is rejected; the lower-case token is accepted", () => {
  const { runtime, producers } = setup();
  const genuine = usage(producers["usage-metering"]!);
  const upper = { ...genuine.credential, token: genuine.credential.token.toUpperCase() };
  const result = runtime.gateway.ingest(genuine.event, upper);
  assert.equal(result.status, "rejected");
  assert.ok(result.reasons.some((reason) => reason.code === "producer_auth_failed"));
  assert.equal(runtime.gateway.ingest(genuine.event, genuine.credential).status, "accepted", "positive control");
});

test("an upper-case producer signature is rejected; the lower-case signature is accepted", () => {
  const { runtime, producers } = setup();
  const genuine = billing(producers["billing-service"]!);
  assert.ok(genuine.event.integrity.signature, "the billing event carries a signature");
  const upperEvent = { ...genuine.event, integrity: { ...genuine.event.integrity, signature: genuine.event.integrity.signature!.toUpperCase() } };
  const result = runtime.gateway.ingest(upperEvent, genuine.credential);
  assert.equal(result.status, "rejected");
  assert.ok(result.reasons.some((reason) => reason.code === "signature_invalid"));
  assert.equal(runtime.gateway.ingest(genuine.event, genuine.credential).status, "accepted", "positive control");
});

// KI-SENTINEL-20261030-006 item 2 --------------------------------------------

test("a missing or malformed credential is rejected, not thrown", () => {
  const { runtime, producers } = setup();
  const genuine = usage(producers["usage-metering"]!);
  const malformed: unknown[] = [null, undefined, {}, "token", { service: "usage-metering", key_id: "key_usage_01" }, { ...genuine.credential, token: 7 }, { ...genuine.credential, service: null }];
  for (const credential of malformed) {
    const result = runtime.gateway.ingest(genuine.event, credential as ProducerCredential);
    assert.equal(result.status, "rejected", JSON.stringify(credential));
    assert.ok(result.reasons.some((reason) => reason.code === "producer_credential_malformed"), JSON.stringify(credential));
  }
  assert.equal(runtime.gateway.ingest(genuine.event, genuine.credential).status, "accepted", "positive control");
});

test("a malformed replay line is rejected and the replay continues", () => {
  const { runtime, producers } = setup();
  const before = usage(producers["usage-metering"]!);
  const after = usage(producers["usage-metering"]!);
  const noCredential = { event: usage(producers["usage-metering"]!).event } as ReplayLine;
  const lines = [before, null, noCredential, after] as unknown as ReplayLine[];
  const summary = replayInto(runtime.gateway, lines);
  assert.equal(summary.total, 4);
  assert.equal(summary.accepted, 2, "the lines around the malformed ones are still ingested");
  assert.equal(summary.rejected, 2);
  assert.equal(summary.results[0]!.status, "accepted");
  assert.equal(summary.results[3]!.status, "accepted");
  assert.ok(summary.results[2]!.reasons.some((reason) => reason.code === "producer_credential_malformed"));
});
