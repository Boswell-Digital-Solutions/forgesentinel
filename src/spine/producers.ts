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

export class ProducerRegistry {
  readonly #producers = new Map<string, Readonly<ProducerRegistration>>();

  /**
   * Every registration is checked against `environment` when it is added, not
   * only at construction (KI-SENTINEL-20261030-002). A registry is bound to
   * one environment. A key that is already registered cannot be replaced.
   * The registry checks and keeps a frozen copy, so a caller cannot change a
   * registration after the check.
   */
  constructor(readonly environment: Environment) {}

  register(registration: ProducerRegistration): void {
    const copy: Readonly<ProducerRegistration> = Object.freeze({
      service: registration.service,
      environment: registration.environment,
      key_id: registration.key_id,
      secret: registration.secret,
      signature_required: registration.signature_required,
      allowed_event_prefixes: Object.freeze([...registration.allowed_event_prefixes]) as string[],
      tenant_scope: registration.tenant_scope,
    });
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
