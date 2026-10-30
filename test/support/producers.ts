import { randomBytes } from "node:crypto";
import {
  STANDARD_PRODUCER_PROFILES,
  SentinelRuntime,
  producerToken,
  type Environment,
  type ProducerRegistration,
  type ReplayLine,
} from "../../src/index.js";

/**
 * Test-only producer registrations. Nothing under src/ imports this module.
 *
 * `testProducers` makes fresh random secrets on each call, so a test can
 * build a production runtime without a fixed secret.
 *
 * `fixtureProducers` holds the fixed secrets that signed the committed
 * fixtures under fixtures/. They are public (KI-SENTINEL-20261030-002), so a
 * production or staging runtime refuses them. Use them only to regenerate
 * fixtures or in a test or development runtime.
 */
const FIXTURE_SECRETS: Readonly<Record<string, { key_id: string; secret: string }>> = {
  "identity-service": { key_id: "key_identity_01", secret: "test-secret-identity" },
  "usage-metering": { key_id: "key_usage_01", secret: "test-secret-usage" },
  neuroforge: { key_id: "key_neuroforge_01", secret: "test-secret-neuroforge" },
  "billing-service": { key_id: "key_billing_01", secret: "test-secret-billing" },
  cssa: { key_id: "key_cssa_01", secret: "test-secret-cssa" },
  forgeagents: { key_id: "key_agents_01", secret: "test-secret-agents" },
};

export function fixtureProducers(environment: Environment): ProducerRegistration[] {
  return STANDARD_PRODUCER_PROFILES.map((profile) => {
    const fixed = FIXTURE_SECRETS[profile.service];
    if (!fixed) throw new Error(`no fixture secret for producer "${profile.service}"`);
    return { ...profile, allowed_event_prefixes: [...profile.allowed_event_prefixes], environment, ...fixed };
  });
}

export function testProducers(environment: Environment): ProducerRegistration[] {
  return fixtureProducers(environment).map((producer) => ({ ...producer, secret: randomBytes(32).toString("hex") }));
}

export function byService(producers: readonly ProducerRegistration[]): Record<string, ProducerRegistration> {
  return Object.fromEntries(producers.map((producer) => [producer.service, producer]));
}

/**
 * Re-sign replay lines with `producers`. The committed fixtures carry
 * credentials made with the fixture secrets; a test that replays them through
 * a runtime with other secrets re-signs them first. The event content does
 * not change, so the payload hash and the dedupe key stay the same.
 */
export function resign(lines: readonly ReplayLine[], producers: readonly ProducerRegistration[]): ReplayLine[] {
  const map = byService(producers);
  return lines.map((line) => {
    const producer = map[line.credential.service];
    if (!producer) throw new Error(`no test producer for "${line.credential.service}"`);
    const hash = line.event.integrity.payload_hash;
    const token = producerToken(producer.secret, hash);
    const integrity = line.event.integrity.signature === undefined
      ? line.event.integrity
      : { ...line.event.integrity, signature: token, signature_key_id: producer.key_id };
    return {
      event: { ...line.event, integrity },
      credential: { service: producer.service, key_id: producer.key_id, token },
    };
  });
}

/** A production runtime with fresh random producer secrets. */
export function productionRuntime(producers: readonly ProducerRegistration[] = testProducers("production")): SentinelRuntime {
  return new SentinelRuntime("production", { producers });
}
