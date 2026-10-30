import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  MIN_PRODUCER_SECRET_BYTES,
  PRODUCER_SECRETS_FILE_ENV,
  PRODUCER_SECRETS_SCHEMA,
  ProducerRegistry,
  ProducerSecretsError,
  STANDARD_PRODUCER_PROFILES,
  SentinelRuntime,
  buildEvent,
  loadProducerRegistrations,
  loadReplayFile,
  producerToken,
  type Environment,
  type ProducerRegistration,
  type ReplayLine,
} from "../src/index.js";
import { byService, fixtureProducers, resign, testProducers } from "./support/producers.js";

/**
 * KI-SENTINEL-20261030-002: producer secrets come from protected
 * configuration. Production and staging refuse published or weak secrets,
 * and a forged producer event is rejected.
 */

const POSIX = "linux" as const;

function secretsDocument(environment: Environment, producers: readonly ProducerRegistration[]): Record<string, unknown> {
  return {
    schema: PRODUCER_SECRETS_SCHEMA,
    environment,
    producers: Object.fromEntries(producers.map((producer) => [producer.service, { key_id: producer.key_id, secret: producer.secret }])),
  };
}

function writeSecrets(document: unknown, mode = 0o600): string {
  const path = join(mkdtempSync(join(tmpdir(), "sentinel-secrets-")), "producers.json");
  writeFileSync(path, typeof document === "string" ? document : JSON.stringify(document));
  chmodSync(path, mode);
  return path;
}

function load(environment: Environment, path: string | undefined, platform: NodeJS.Platform = process.platform): ProducerRegistration[] {
  return loadProducerRegistrations(environment, { env: { [PRODUCER_SECRETS_FILE_ENV]: path }, platform });
}

function usageLine(producer: ProducerRegistration, id: string): ReplayLine {
  return buildEvent(producer, {
    event_id: id,
    event_type: "usage.tokens.recorded",
    occurred_at: "2026-06-09T12:00:00.000Z",
    tenant: { tenant_id: "ten_demo", account_id: "acct_1" },
    actor: { actor_type: "service", actor_id: "neuroforge-gateway" },
    subject: { subject_type: "account", subject_id: "acct_1" },
    correlation: { trace_id: `trc_${id}` },
    payload: { total_tokens: 100, route_class: "general_cloud" },
  });
}

function billingLine(producer: ProducerRegistration, id: string): ReplayLine {
  return buildEvent(producer, {
    event_id: id,
    event_type: "billing.subscription.changed",
    occurred_at: "2026-06-09T12:00:00.000Z",
    tenant: { tenant_id: "ten_demo", account_id: "acct_1" },
    actor: { actor_type: "service", actor_id: "billing" },
    subject: { subject_type: "account", subject_id: "acct_1" },
    correlation: { trace_id: `trc_${id}` },
    payload: { plan: "pro" },
  });
}

// Runtime refusal ------------------------------------------------------------

for (const environment of ["production", "staging"] as const) {
  test(`${environment} runtime refuses the published fixture secrets`, () => {
    assert.throws(() => new SentinelRuntime(environment, { producers: fixtureProducers(environment) }), ProducerSecretsError);
  });

  test(`${environment} runtime refuses a secret shorter than ${MIN_PRODUCER_SECRET_BYTES} bytes`, () => {
    const producers = testProducers(environment).map((producer, index) => (index === 0 ? { ...producer, secret: "x".repeat(MIN_PRODUCER_SECRET_BYTES - 1) } : producer));
    assert.throws(() => new SentinelRuntime(environment, { producers }), /shorter than/);
  });

  test(`${environment} runtime refuses one secret shared by two producers`, () => {
    const producers = testProducers(environment);
    producers[1] = { ...producers[1]!, secret: producers[0]!.secret };
    assert.throws(() => new SentinelRuntime(environment, { producers }), /shares its secret/);
  });

  test(`${environment} runtime refuses a missing secret`, () => {
    const producers = testProducers(environment).map((producer, index) => (index === 0 ? { ...producer, secret: "" } : producer));
    assert.throws(() => new SentinelRuntime(environment, { producers }), /has no secret/);
  });
}

test("runtime refuses a producer registered for another environment", () => {
  assert.throws(() => new SentinelRuntime("production", { producers: testProducers("staging") }), /registered for "staging"/);
});

test("test and development runtimes accept the fixture secrets", () => {
  assert.doesNotThrow(() => new SentinelRuntime("test", { producers: fixtureProducers("test") }));
  assert.doesNotThrow(() => new SentinelRuntime("development", { producers: fixtureProducers("development") }));
});

test("production runtime accepts strong random secrets", () => {
  assert.doesNotThrow(() => new SentinelRuntime("production", { producers: testProducers("production") }));
});

test("a refusal message never contains the secret value", () => {
  const producers = fixtureProducers("production");
  try {
    new SentinelRuntime("production", { producers });
    assert.fail("expected a refusal");
  } catch (error) {
    assert.ok(error instanceof ProducerSecretsError);
    for (const producer of producers) assert.ok(!error.message.includes(producer.secret));
  }
});

// Loader ---------------------------------------------------------------------

test("loader refuses when the secrets file variable is not set", () => {
  assert.throws(() => load("production", undefined), /is not set/);
  assert.throws(() => load("test", undefined), /is not set/);
});

test("loader refuses an unreadable file", () => {
  assert.throws(() => load("production", join(tmpdir(), "no-such-sentinel-secrets.json")), /cannot open/);
});

test("loader refuses malformed JSON and a wrong schema", () => {
  assert.throws(() => load("production", writeSecrets("{not json")), /not valid JSON/);
  const document = secretsDocument("production", testProducers("production"));
  assert.throws(() => load("production", writeSecrets({ ...document, schema: "other.v1" })), /schema/);
});

test("loader refuses a file for another environment", () => {
  const path = writeSecrets(secretsDocument("staging", testProducers("staging")));
  assert.throws(() => load("production", path), /is for "staging"/);
});

test("loader refuses a missing producer and an unknown producer", () => {
  const producers = testProducers("production");
  const missing = secretsDocument("production", producers.slice(1));
  assert.throws(() => load("production", writeSecrets(missing)), new RegExp(`no entry for producer "${producers[0]!.service}"`));
  const unknown = secretsDocument("production", producers) as { producers: Record<string, unknown> };
  unknown.producers["rogue-service"] = { key_id: "k", secret: "s".repeat(64) };
  assert.throws(() => load("production", writeSecrets(unknown)), /unknown producer "rogue-service"/);
});

test("loader refuses the published fixture secrets in production and staging", () => {
  for (const environment of ["production", "staging"] as const) {
    const path = writeSecrets(secretsDocument(environment, fixtureProducers(environment)));
    assert.throws(() => load(environment, path), /published test secret/);
  }
});

test("loader refuses a file that group or others can read (POSIX)", () => {
  const path = writeSecrets(secretsDocument("production", testProducers("production")), 0o644);
  if (process.platform === "win32") {
    // chmod cannot set group/other bits on Windows; check the decision on a reported POSIX mode instead.
    assert.doesNotThrow(() => load("production", path, "win32"));
    return;
  }
  assert.throws(() => load("production", path, POSIX), /must not be readable or writable by group or others/);
});

test("loader returns the standard profiles with the configured secrets", () => {
  const producers = testProducers("production");
  const loaded = load("production", writeSecrets(secretsDocument("production", producers)));
  assert.deepEqual(loaded.map((producer) => producer.service), STANDARD_PRODUCER_PROFILES.map((profile) => profile.service));
  const expected = byService(producers);
  for (const producer of loaded) {
    assert.equal(producer.environment, "production");
    assert.equal(producer.secret, expected[producer.service]!.secret);
    assert.equal(producer.key_id, expected[producer.service]!.key_id);
  }
});

// Forged producer events -----------------------------------------------------

test("a production gateway rejects an event signed with the published secret", () => {
  const configured = load("production", writeSecrets(secretsDocument("production", testProducers("production"))));
  const runtime = new SentinelRuntime("production", { producers: configured });
  const forged = usageLine(byService(fixtureProducers("production"))["usage-metering"]!, "evt_forged_usage");
  const result = runtime.gateway.ingest(forged.event, forged.credential);
  assert.equal(result.status, "rejected");
  assert.ok(result.reasons.some((reason) => reason.code === "producer_auth_failed"));
});

test("a production gateway rejects a billing event with a forged signature but a valid token", () => {
  const configured = load("production", writeSecrets(secretsDocument("production", testProducers("production"))));
  const runtime = new SentinelRuntime("production", { producers: configured });
  const real = byService(configured)["billing-service"]!;
  const forged = billingLine(byService(fixtureProducers("production"))["billing-service"]!, "evt_forged_billing");
  // The attacker also holds a valid producer token, but signs with the published secret.
  const token = producerToken(real.secret, forged.event.integrity.payload_hash);
  const result = runtime.gateway.ingest(forged.event, { service: real.service, key_id: real.key_id, token });
  assert.equal(result.status, "rejected");
  assert.ok(result.reasons.some((reason) => reason.code === "signature_invalid"));
});

test("a production gateway accepts an event signed with the configured secret (positive control)", () => {
  const configured = load("production", writeSecrets(secretsDocument("production", testProducers("production"))));
  const runtime = new SentinelRuntime("production", { producers: configured });
  const genuine = usageLine(byService(configured)["usage-metering"]!, "evt_genuine_usage");
  assert.equal(runtime.gateway.ingest(genuine.event, genuine.credential).status, "accepted");
});

test("a runtime with no producers rejects every event", () => {
  const runtime = new SentinelRuntime("production", { producers: [] });
  const line = usageLine(byService(testProducers("production"))["usage-metering"]!, "evt_no_producers");
  const result = runtime.gateway.ingest(line.event, line.credential);
  assert.equal(result.status, "rejected");
  assert.ok(result.reasons.some((reason) => reason.code === "producer_auth_failed"));
});

// Committed fixtures ---------------------------------------------------------

test("the committed replay fixtures are signed with the test-only fixture secrets", () => {
  const fixtures = byService(fixtureProducers("production"));
  for (const name of ["compound_account_compromise.jsonl", "usage_spike_only.jsonl", "agent_drift.jsonl"]) {
    for (const line of loadReplayFile(join(process.cwd(), "fixtures", "replay", name))) {
      const producer = fixtures[line.credential.service]!;
      assert.equal(line.credential.key_id, producer.key_id, `${name}: key id`);
      assert.equal(line.credential.token, producerToken(producer.secret, line.event.integrity.payload_hash), `${name}: token`);
    }
  }
});

// Review findings (independent review of PR #21) ------------------------------

function withSecret(environment: Environment, index: number, secret: string): ProducerRegistration[] {
  return testProducers(environment).map((producer, i) => (i === index ? { ...producer, secret } : producer));
}

test("every environment refuses a NUL-padded secret, which HMAC treats as the empty key", () => {
  assert.equal(producerToken("", "h"), producerToken("\u0000".repeat(32), "h"));
  for (const environment of ["production", "staging", "test", "development", "local"] as const) {
    assert.throws(() => new SentinelRuntime(environment, { producers: withSecret(environment, 0, "\u0000".repeat(40)) }), /control character/);
  }
});

test("production refuses whitespace, non-ASCII and low-variety secrets", () => {
  assert.throws(() => new SentinelRuntime("production", { producers: withSecret("production", 0, " ".repeat(40)) }), /printable ASCII/);
  assert.throws(() => new SentinelRuntime("production", { producers: withSecret("production", 0, "\u{1F511}".repeat(10)) }), /printable ASCII/);
  assert.throws(() => new SentinelRuntime("production", { producers: withSecret("production", 0, "a".repeat(31) + "b") }), /distinct characters/);
});

test("a registration added after construction is checked too", () => {
  const runtime = new SentinelRuntime("production", { producers: testProducers("production") });
  const published = fixtureProducers("production")[1]!;
  assert.throws(() => runtime.registry.register(published), /already registered/);
  assert.throws(() => runtime.registry.register({ ...published, key_id: "key_usage_99" }), /published test secret/);
  const line = usageLine(published, "evt_post_construction");
  assert.equal(runtime.gateway.ingest(line.event, line.credential).status, "rejected");
});

test("a bare registry refuses an empty secret and a mismatched environment", () => {
  const registry = new ProducerRegistry("production");
  const producer = testProducers("production")[0]!;
  assert.throws(() => registry.register({ ...producer, secret: "" }), /has no secret/);
  assert.throws(() => registry.register(testProducers("staging")[0]!), /registered for "staging"/);
});

test("loader refuses unknown fields and a key_id shared by two producers", () => {
  const producers = testProducers("production");
  const document = secretsDocument("production", producers) as { producers: Record<string, Record<string, unknown>> };
  assert.throws(() => load("production", writeSecrets({ ...document, extra: true })), /unknown field "extra"/);
  const entryField = structuredClone(document);
  entryField.producers[producers[0]!.service]!["signature_required"] = false;
  assert.throws(() => load("production", writeSecrets(entryField)), /unknown field "signature_required"/);
  const sharedKey = structuredClone(document);
  sharedKey.producers[producers[1]!.service]!["key_id"] = producers[0]!.key_id;
  assert.throws(() => load("production", writeSecrets(sharedKey)), /used by more than one producer/);
});

test("loader refuses a path that is not a regular file", () => {
  assert.throws(() => load("production", tmpdir()), ProducerSecretsError);
});

test("loader refuses a symlink to the secrets file (POSIX)", { skip: process.platform === "win32" ? "symlinks need extra privilege on Windows" : false }, () => {
  const target = writeSecrets(secretsDocument("production", testProducers("production")));
  const link = `${target}.link`;
  symlinkSync(target, link);
  assert.throws(() => load("production", link, POSIX), /symlink is refused/);
});

test("resign re-signs a signature-required event so it authenticates with the new secret only", () => {
  const producers = testProducers("production");
  const signed = billingLine(byService(fixtureProducers("production"))["billing-service"]!, "evt_resign_billing");
  assert.ok(signed.event.integrity.signature, "the fixture billing event carries a signature");
  const runtime = new SentinelRuntime("production", { producers });
  assert.equal(runtime.gateway.ingest(signed.event, signed.credential).status, "rejected");
  const [resigned] = resign([signed], producers);
  assert.notEqual(resigned!.event.integrity.signature, signed.event.integrity.signature);
  assert.equal(resigned!.event.integrity.payload_hash, signed.event.integrity.payload_hash);
  assert.equal(runtime.gateway.ingest(resigned!.event, resigned!.credential).status, "accepted");
});

test("changing a registration object after it is registered has no effect", () => {
  const producers = testProducers("production");
  const runtime = new SentinelRuntime("production", { producers });
  const published = fixtureProducers("production")[1]!;
  producers[1]!.secret = published.secret;
  producers[1]!.allowed_event_prefixes.push("billing.");
  const forged = usageLine(published, "evt_mutated_registration");
  assert.equal(runtime.gateway.ingest(forged.event, forged.credential).status, "rejected");
  const stored = runtime.registry.get(producers[1]!.service, producers[1]!.key_id)!;
  assert.ok(Object.isFrozen(stored));
  assert.notEqual(stored.secret, published.secret);
  assert.deepEqual(stored.allowed_event_prefixes, ["usage."]);
});
