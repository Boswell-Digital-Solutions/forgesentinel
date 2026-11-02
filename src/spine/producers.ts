import { createHmac, timingSafeEqual } from "node:crypto";
import type { Environment } from "../contracts/envelope.js";
import { ProducerSecretsError, assertProducerSecretsAllowed } from "./producer_secrets.js";

/**
 * Producer registration (02, SNT-010). Producers authenticate to the
 * gateway and are bound to an environment, an event-type allowlist, and a
 * tenant-scope rule. MVP authentication is HMAC-SHA256 over the payload
 * hash with a per-producer key (ADR-026 records the planned move to
 * ed25519 producer signatures).
 */
export interface ProducerRegistration {
  service: string;
  environment: Environment;
  key_id: string;
  secret: string;
  signature_required: boolean;
  allowed_event_prefixes: string[];
  tenant_scope: "required" | "system";
}

export interface ProducerCredential {
  service: string;
  key_id: string;
  token: string;
}

export function producerToken(secret: string, payloadHash: string): string {
  return createHmac("sha256", secret).update(payloadHash, "utf8").digest("hex");
}

/** A registration that the registry refuses for a reason other than its secret. */
export class ProducerRegistrationError extends Error {
  override readonly name = "ProducerRegistrationError";
}

/**
 * An event prefix is one or more lowercase dotted segments and ends in ".".
 * An empty prefix would match every event type (KI-SENTINEL-20261030-005).
 */
const EVENT_PREFIX_PATTERN = /^[a-z0-9_]+(\.[a-z0-9_]+)*\.$/;

export class ProducerRegistry {
  readonly #producers = new Map<string, Readonly<ProducerRegistration>>();

  /**
   * Every registration is checked against `environment` when it is added, not
   * only at construction (KI-SENTINEL-20261030-002). A registry is bound to
   * one environment. A key that is already registered cannot be replaced.
   * The registry checks and keeps a frozen copy, so a caller cannot change a
   * registration after the check. The instance is frozen, so a caller cannot
   * shadow a method with an own property (KI-SENTINEL-20261030-004). These
   * guard against accidental change in the same process. They are not a
   * boundary against hostile code that runs in the same process.
   */
  constructor(readonly environment: Environment) {
    Object.freeze(this);
  }

  /**
   * True only for an object made by this class's constructor. A private-field
   * check is false for an Object.create look-alike, a Proxy, and an object
   * from another realm, even when its prototype is ProducerRegistry.prototype.
   */
  static isRegistry(value: unknown): value is ProducerRegistry {
    return typeof value === "object" && value !== null && #producers in value;
  }

  register(registration: ProducerRegistration): void {
    // Read each field once into a copy, then check and freeze that copy, so a
    // getter or iterator cannot return one value to the check and another to
    // the store.
    // Copy element by element into a new plain array. slice() or spread would
    // honour Symbol.species or a subclass iterator, so the stored list could
    // differ from the list that was checked.
    const rawPrefixes: unknown = registration.allowed_event_prefixes;
    const prefixes: unknown[] = [];
    if (Array.isArray(rawPrefixes)) {
      const length = rawPrefixes.length;
      for (let index = 0; index < length; index++) prefixes.push(rawPrefixes[index]);
    }
    const copy: Readonly<ProducerRegistration> = Object.freeze({
      service: registration.service,
      environment: registration.environment,
      key_id: registration.key_id,
      secret: registration.secret,
      signature_required: registration.signature_required,
      allowed_event_prefixes: Object.freeze(prefixes) as string[],
      tenant_scope: registration.tenant_scope,
    });
    if (copy.allowed_event_prefixes.length === 0) {
      throw new ProducerRegistrationError(`producer "${copy.service}" has no allowed event prefixes`);
    }
    for (let index = 0; index < copy.allowed_event_prefixes.length; index++) {
      const prefix: unknown = copy.allowed_event_prefixes[index];
      if (typeof prefix !== "string" || !EVENT_PREFIX_PATTERN.test(prefix)) {
        throw new ProducerRegistrationError(`producer "${copy.service}" has a malformed event prefix ${JSON.stringify(prefix)}; a prefix is lowercase dotted segments that end in "."`);
      }
    }
    const key = `${copy.service}:${copy.key_id}`;
    if (this.#producers.has(key)) {
      throw new ProducerSecretsError(`producer "${copy.service}" key "${copy.key_id}" is already registered`);
    }
    assertProducerSecretsAllowed(this.environment, [...this.#producers.values(), copy]);
    this.#producers.set(key, copy);
  }

  get(service: string, keyId: string): Readonly<ProducerRegistration> | undefined {
    return this.#producers.get(`${service}:${keyId}`);
  }

  authenticate(credential: ProducerCredential, payloadHash: string): ProducerRegistration | undefined {
    const registration = this.get(credential.service, credential.key_id);
    if (!registration) return undefined;
    const expected = producerToken(registration.secret, payloadHash);
    const a = Buffer.from(expected, "hex");
    const b = Buffer.from(credential.token.length === expected.length ? credential.token : "0".repeat(expected.length), "hex");
    if (a.length !== b.length || !timingSafeEqual(a, b)) return undefined;
    return registration;
  }

  allowsEventType(registration: ProducerRegistration, eventType: string): boolean {
    return registration.allowed_event_prefixes.some((prefix) => eventType === prefix || eventType.startsWith(prefix));
  }
}
