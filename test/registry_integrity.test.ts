import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EventGateway,
  EvidenceLedger,
  ProducerRegistrationError,
  ProducerRegistry,
  SentinelRuntime,
  buildEvent,
  type ProducerRegistration,
  type ReplayLine,
} from "../src/index.js";
import { byService, fixtureProducers, testProducers } from "./support/producers.js";

/**
 * KI-SENTINEL-20261030-004: the gateway's producer registry cannot be
 * replaced or shadowed. KI-SENTINEL-20261030-005: a producer cannot emit an
 * event outside its assigned prefixes, and an empty or malformed prefix is
 * refused at registration. Each refusal is checked through the gateway.
 *
 * These guard against accidental change in the same process. They are not a
 * boundary against hostile code that runs in the same process.
 */

const TENANT = { tenant_id: "ten_demo", account_id: "acct_1" };

function line(producer: ProducerRegistration, id: string, eventType: string, payload: Record<string, unknown>): ReplayLine {
  return buildEvent(producer, {
    event_id: id,
    event_type: eventType,
    occurred_at: "2026-06-09T12:00:00.000Z",
    tenant: TENANT,
    actor: { actor_type: "service", actor_id: producer.service },
    subject: { subject_type: "account", subject_id: TENANT.account_id },
    correlation: { trace_id: `trc_${id}` },
    payload,
  });
}

function usage(producer: ProducerRegistration, id: string): ReplayLine {
  return line(producer, id, "usage.tokens.recorded", { total_tokens: 10, route_class: "general_cloud" });
}

function setup(): { runtime: SentinelRuntime; producers: Record<string, ProducerRegistration>; published: Record<string, ProducerRegistration> } {
  const configured = testProducers("production");
  return {
    runtime: new SentinelRuntime("production", { producers: configured }),
    producers: byService(configured),
    published: byService(fixtureProducers("production")),
  };
}

function status(gateway: EventGateway, replay: ReplayLine): string {
  return gateway.ingest(replay.event, replay.credential).status;
}

function codes(gateway: EventGateway, replay: ReplayLine): string[] {
  return gateway.ingest(replay.event, replay.credential).reasons.map((reason) => reason.code);
}

/** A registry that accepts any credential with an empty secret and any event type. */
function lookalike(): unknown {
  return {
    environment: "production",
    authenticate: (credential: { service: string; key_id: string }) => ({ service: credential.service, environment: "production", key_id: credential.key_id, secret: "", signature_required: false, allowed_event_prefixes: [""], tenant_scope: "required" }),
    allowsEventType: () => true,
    register: () => undefined,
    get: () => undefined,
  };
}

// KI-004: the registry cannot be replaced -----------------------------------

test("replacing the gateway's registry from outside has no effect", () => {
  const { runtime, producers, published } = setup();
  const gateway = runtime.gateway as unknown as Record<string, unknown>;
  assert.equal(gateway["registry"], undefined, "the registry is not a reachable property");
  gateway["registry"] = lookalike();
  assert.equal(status(runtime.gateway, usage(published["usage-metering"]!, "evt_swap_forged")), "rejected");
  assert.equal(status(runtime.gateway, usage(producers["usage-metering"]!, "evt_swap_genuine")), "accepted", "positive control");
});

test("replacing the runtime's registry does not change the gateway's registry", () => {
  const { runtime, producers, published } = setup();
  (runtime as unknown as Record<string, unknown>)["registry"] = new ProducerRegistry("production");
  assert.equal(status(runtime.gateway, usage(published["usage-metering"]!, "evt_runtime_swap_forged")), "rejected");
  assert.equal(status(runtime.gateway, usage(producers["usage-metering"]!, "evt_runtime_swap_genuine")), "accepted", "the gateway keeps its own registry");
});

test("the gateway refuses a look-alike registry object", () => {
  assert.throws(() => new EventGateway(lookalike() as ProducerRegistry, new EvidenceLedger()), TypeError);
  assert.throws(() => new EventGateway(null as unknown as ProducerRegistry, new EvidenceLedger()), TypeError);
});

test("the gateway refuses a ProducerRegistry subclass that overrides authentication", () => {
  class PermissiveRegistry extends ProducerRegistry {
    override authenticate(): ProducerRegistration | undefined {
      return byService(fixtureProducers("production"))["usage-metering"];
    }
  }
  assert.throws(() => new EventGateway(new PermissiveRegistry("production"), new EvidenceLedger()), TypeError);
});

test("a registry method cannot be shadowed on the instance", () => {
  const { runtime, published } = setup();
  const registry = runtime.registry as unknown as Record<string, unknown>;
  assert.ok(Object.isFrozen(runtime.registry));
  assert.throws(() => {
    registry["authenticate"] = () => published["usage-metering"];
  }, TypeError);
  assert.throws(() => {
    registry["allowsEventType"] = () => true;
  }, TypeError);
  assert.equal(status(runtime.gateway, usage(published["usage-metering"]!, "evt_shadow_forged")), "rejected");
});

// KI-005: prefixes are well formed and enforced -----------------------------

test("registration refuses an empty prefix list, an empty prefix and malformed prefixes", () => {
  const registry = new ProducerRegistry("production");
  const base = testProducers("production")[1]!;
  for (const allowed of [[], [""], ["usage"], ["Usage."], ["usage.."], [".usage."], ["usage.*"], [" usage."]]) {
    assert.throws(() => registry.register({ ...base, allowed_event_prefixes: allowed }), ProducerRegistrationError, JSON.stringify(allowed));
  }
  assert.throws(() => registry.register({ ...base, allowed_event_prefixes: undefined as unknown as string[] }), ProducerRegistrationError);
  assert.throws(() => registry.register({ ...base, allowed_event_prefixes: [7] as unknown as string[] }), ProducerRegistrationError);
});

test("a runtime refuses a producer registered with an empty prefix", () => {
  const producers = testProducers("production");
  producers[1] = { ...producers[1]!, allowed_event_prefixes: [""] };
  assert.throws(() => new SentinelRuntime("production", { producers }), ProducerRegistrationError);
});

test("a producer cannot emit an event outside its assigned prefixes", () => {
  const { runtime, producers } = setup();
  const usageProducer = producers["usage-metering"]!;
  const billing = line(usageProducer, "evt_usage_as_billing", "billing.subscription.changed", { plan: "pro" });
  assert.ok(codes(runtime.gateway, billing).includes("event_type_not_allowed"));
  const identity = line(producers["cssa"]!, "evt_cssa_as_identity", "identity.login.failed", { reason: "bad_password" });
  assert.ok(codes(runtime.gateway, identity).includes("event_type_not_allowed"));
  assert.equal(status(runtime.gateway, usage(usageProducer, "evt_usage_in_scope")), "accepted", "positive control");
});

test("the standard producer profiles pass the prefix rule", () => {
  const registry = new ProducerRegistry("production");
  for (const producer of testProducers("production")) assert.doesNotThrow(() => registry.register(producer));
});
