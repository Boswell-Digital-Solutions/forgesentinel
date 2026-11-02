import { test } from "node:test";
import assert from "node:assert/strict";
import { runInNewContext } from "node:vm";
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
  assert.throws(() => {
    gateway["registry"] = lookalike();
  }, TypeError, "the gateway is frozen");
  assert.equal(status(runtime.gateway, usage(published["usage-metering"]!, "evt_swap_forged")), "rejected");
  assert.equal(status(runtime.gateway, usage(producers["usage-metering"]!, "evt_swap_genuine")), "accepted", "positive control");
});

test("replacing the runtime's registry does not change the gateway's registry", () => {
  const { runtime, producers, published } = setup();
  assert.throws(() => {
    (runtime as unknown as Record<string, unknown>)["registry"] = new ProducerRegistry("production");
  }, TypeError, "the runtime is frozen");
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

// Independent review of PR #24 (round 1) -------------------------------------

test("the gateway refuses objects that only borrow ProducerRegistry.prototype", () => {
  const ledger = new EvidenceLedger();
  const permissive = { authenticate: { value: () => byService(fixtureProducers("production"))["usage-metering"] }, allowsEventType: { value: () => true } };
  const created = Object.create(ProducerRegistry.prototype, permissive);
  class Fake {}
  const constructed = Reflect.construct(Fake, [], ProducerRegistry);
  const proxied = new Proxy(new ProducerRegistry("production"), {});
  const trapped = new Proxy({}, { getPrototypeOf: () => ProducerRegistry.prototype });
  const foreign = runInNewContext("Object.create(proto)", { proto: ProducerRegistry.prototype });
  for (const [name, candidate] of Object.entries({ created, constructed, proxied, trapped, foreign })) {
    assert.equal(Object.getPrototypeOf(candidate), ProducerRegistry.prototype, `${name} borrows the prototype`);
    assert.throws(() => new EventGateway(candidate as ProducerRegistry, ledger), TypeError, name);
  }
});

test("a runtime's gateway, registry and ledger cannot be replaced", () => {
  const { runtime, producers, published } = setup();
  assert.ok(Object.isFrozen(runtime));
  const fields = runtime as unknown as Record<string, unknown>;
  assert.throws(() => {
    fields["gateway"] = Object.create(EventGateway.prototype);
  }, TypeError);
  assert.throws(() => {
    fields["registry"] = new ProducerRegistry("production");
  }, TypeError);
  assert.throws(() => {
    fields["ledger"] = new EvidenceLedger();
  }, TypeError);
  assert.equal(status(runtime.gateway, usage(published["usage-metering"]!, "evt_frozen_runtime_forged")), "rejected");
  assert.equal(status(runtime.gateway, usage(producers["usage-metering"]!, "evt_frozen_runtime_genuine")), "accepted", "positive control");
});

test("the gateway's dedupe map and ledger are not reachable", () => {
  const { runtime, producers } = setup();
  const gateway = runtime.gateway as unknown as Record<string, unknown>;
  assert.ok(Object.isFrozen(runtime.gateway));
  assert.equal(gateway["seen"], undefined);
  assert.equal(gateway["ledger"], undefined);
  const first = usage(producers["usage-metering"]!, "evt_dedupe_once");
  assert.equal(status(runtime.gateway, first), "accepted");
  assert.throws(() => {
    gateway["seen"] = new Map();
  }, TypeError);
  assert.equal(status(runtime.gateway, first), "duplicate", "de-duplication still holds");
});

test("a producer registered after construction with an empty prefix is refused, and the gateway still enforces scope", () => {
  const { runtime, producers } = setup();
  const rogue = { ...testProducers("production")[1]!, key_id: "key_usage_rogue", allowed_event_prefixes: [""] };
  assert.throws(() => runtime.registry.register(rogue), ProducerRegistrationError);
  const billing = line({ ...rogue, allowed_event_prefixes: ["usage."] }, "evt_rogue_billing", "billing.subscription.changed", { plan: "pro" });
  assert.ok(codes(runtime.gateway, billing).includes("producer_auth_failed"), "the refused key was never registered");
  const inScope = line(producers["usage-metering"]!, "evt_usage_billing_after_refusal", "billing.subscription.changed", { plan: "pro" });
  assert.ok(codes(runtime.gateway, inScope).includes("event_type_not_allowed"));
});

test("a prefix list is read once: a getter or iterator cannot change it after the check", () => {
  const registry = new ProducerRegistry("production");
  const base = testProducers("production")[1]!;
  let reads = 0;
  const viaGetter = { ...base, key_id: "key_usage_getter" } as ProducerRegistration;
  Object.defineProperty(viaGetter, "allowed_event_prefixes", { get: () => (reads++ === 0 ? ["usage."] : [""]), enumerable: true });
  registry.register(viaGetter);
  assert.deepEqual(registry.get(base.service, "key_usage_getter")!.allowed_event_prefixes, ["usage."]);
  assert.equal(reads, 1);

  const tricky = ["usage."];
  (tricky as unknown as { [Symbol.iterator]: () => Iterator<string> })[Symbol.iterator] = function* () {
    yield "";
  };
  registry.register({ ...testProducers("production")[1]!, key_id: "key_usage_iterator", allowed_event_prefixes: tricky });
  const stored = registry.get(base.service, "key_usage_iterator")!;
  assert.deepEqual([...stored.allowed_event_prefixes], ["usage."]);
  assert.equal(registry.allowsEventType(stored, "billing.subscription.changed"), false);
});

test("a prefix list cannot be swapped through an Array subclass or Symbol.species", () => {
  const registry = new ProducerRegistry("production");
  class Evil extends Array<string> {
    override *[Symbol.iterator](): ArrayIterator<string> {
      yield "usage.";
    }
  }
  const subclassed = Evil.from([""]) as unknown as string[];
  assert.throws(() => registry.register({ ...testProducers("production")[1]!, key_id: "key_usage_subclass", allowed_event_prefixes: subclassed }), ProducerRegistrationError);

  const species = ["usage."] as string[] & { constructor: unknown };
  species.constructor = { [Symbol.species]: function () { return { some: () => true, length: 1, 0: "usage." }; } };
  registry.register({ ...testProducers("production")[1]!, key_id: "key_usage_species", allowed_event_prefixes: species });
  const stored = registry.get("usage-metering", "key_usage_species")!;
  assert.ok(Array.isArray(stored.allowed_event_prefixes));
  assert.equal(Object.getPrototypeOf(stored.allowed_event_prefixes), Array.prototype);
  assert.ok(Object.isFrozen(stored.allowed_event_prefixes));
  assert.equal(registry.allowsEventType(stored, "billing.subscription.changed"), false);
  assert.equal(registry.allowsEventType(stored, "usage.tokens.recorded"), true);
});
