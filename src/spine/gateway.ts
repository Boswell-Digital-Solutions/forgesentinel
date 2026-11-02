import { createHmac, timingSafeEqual } from "node:crypto";
import { hashPayload, sha256Hex, type ValidationIssue } from "../contracts/common.js";
import { validateEventEnvelope, type EventEnvelope } from "../contracts/envelope.js";
import { lookupEventType } from "../contracts/families.js";
import { HMAC_HEX_PATTERN, ProducerRegistry, isWellFormedCredential, type ProducerCredential } from "./producers.js";
import { EvidenceLedger, type LedgerRecord } from "./ledger.js";

export const GATEWAY_VERSION = "1.0.0";

export interface IngestResult {
  status: "accepted" | "duplicate" | "rejected";
  event_id?: string;
  dedupe_key?: string;
  reasons: ValidationIssue[];
  record?: LedgerRecord;
}

/**
 * Idempotency key per 04: producer, tenant, native event ID, event type,
 * subject, time bucket, and payload hash. Distinct security events are never
 * collapsed because their text looks similar. Tenant is included even though
 * producers register once per service, not per tenant (finding 2026-09-19):
 * without it, a same-hour event-id/subject/payload-hash collision from two
 * different tenants behind one producer would return the *other* tenant's
 * ledger record as a "duplicate".
 */
export function dedupeKey(event: EventEnvelope): string {
  const bucket = Math.floor(Date.parse(event.occurred_at) / (60 * 60 * 1000));
  return sha256Hex(
    [
      event.producer.service,
      event.tenant?.tenant_id ?? "",
      event.event_id,
      event.event_type,
      `${event.subject.subject_type}:${event.subject.subject_id}`,
      String(bucket),
      event.integrity.payload_hash,
    ].join("|"),
  );
}

/**
 * Sentinel Event Gateway (02, SNT-010): authenticates the producer,
 * verifies integrity, validates the contract, enforces tenant/environment
 * boundaries and idempotency, and records explicit rejections. The gateway
 * does not compute risk.
 */
export class EventGateway {
  readonly #seen = new Map<string, number>();
  readonly #registry: ProducerRegistry;
  readonly #ledger: EvidenceLedger;

  /**
   * The registry, the ledger and the dedupe map are held in true private
   * fields, and the instance is frozen. Only an object that the
   * ProducerRegistry constructor made, and not a subclass, is accepted as the
   * registry: an Object.create look-alike, a Proxy, an object from another
   * realm and a subclass instance are refused (KI-SENTINEL-20261030-004). This
   * guards against accidental replacement in the same process. It is not a
   * boundary against hostile code that runs in the same process.
   */
  constructor(registry: ProducerRegistry, ledger: EvidenceLedger) {
    if (!ProducerRegistry.isRegistry(registry) || Object.getPrototypeOf(registry) !== ProducerRegistry.prototype) {
      throw new TypeError("EventGateway needs a ProducerRegistry instance");
    }
    this.#registry = registry;
    this.#ledger = ledger;
    Object.freeze(this);
  }

  ingest(rawEvent: unknown, credential: ProducerCredential): IngestResult {
    const reasons: ValidationIssue[] = [];

    const contract = validateEventEnvelope(rawEvent);
    if (!contract.ok) {
      return this.reject(rawEvent, contract.issues, undefined);
    }
    const event = rawEvent as EventEnvelope;

    const expectedHash = hashPayload(event.payload);
    if (event.integrity.payload_hash !== expectedHash) {
      reasons.push({ path: "integrity.payload_hash", code: "payload_hash_mismatch", message: "payload hash does not match canonical payload" });
      return this.reject(event, reasons, event.tenant?.tenant_id);
    }

    // A missing or malformed credential is a rejection of this event, not an
    // exception that stops a whole replay (KI-SENTINEL-20261030-006 item 2).
    if (!isWellFormedCredential(credential)) {
      reasons.push({ path: "credential", code: "producer_credential_malformed", message: "producer credential must have string service, key_id and token" });
      return this.reject(event, reasons, event.tenant?.tenant_id);
    }
    const producer = this.#registry.authenticate(credential, event.integrity.payload_hash);
    if (!producer) {
      reasons.push({ path: "producer", code: "producer_auth_failed", message: `producer "${credential.service}" failed authentication for key "${credential.key_id}"` });
      return this.reject(event, reasons, event.tenant?.tenant_id);
    }
    if (producer.service !== event.producer.service) {
      reasons.push({ path: "producer.service", code: "producer_identity_mismatch", message: "authenticated producer does not match envelope producer" });
      return this.reject(event, reasons, event.tenant?.tenant_id);
    }
    if (producer.environment !== event.producer.environment) {
      reasons.push({ path: "producer.environment", code: "environment_boundary", message: `producer is registered for "${producer.environment}" but emitted a "${event.producer.environment}" event` });
      return this.reject(event, reasons, event.tenant?.tenant_id);
    }
    if (!this.#registry.allowsEventType(producer, event.event_type)) {
      reasons.push({ path: "event_type", code: "event_type_not_allowed", message: `producer "${producer.service}" is not registered to emit "${event.event_type}"` });
      return this.reject(event, reasons, event.tenant?.tenant_id);
    }
    if (producer.tenant_scope === "required" && !event.tenant?.tenant_id) {
      reasons.push({ path: "tenant", code: "tenant_required", message: "producer is tenant-scoped but event carries no tenant" });
      return this.reject(event, reasons, undefined);
    }

    const familyEntry = lookupEventType(event.event_type);
    const signatureRequired = producer.signature_required || familyEntry?.signature_required === true;
    if (signatureRequired) {
      if (!event.integrity.signature || !event.integrity.signature_key_id) {
        reasons.push({ path: "integrity.signature", code: "signature_required", message: `high-value event type "${event.event_type}" requires a producer signature` });
        return this.reject(event, reasons, event.tenant?.tenant_id);
      }
      // Only 64 lowercase hex characters are a signature, as for the token.
      const wellFormed = typeof event.integrity.signature === "string" && HMAC_HEX_PATTERN.test(event.integrity.signature);
      const expected = Buffer.from(createHmac("sha256", producer.secret).update(event.integrity.payload_hash, "utf8").digest("hex"), "hex");
      const presented = Buffer.from(wellFormed ? event.integrity.signature : "0".repeat(64), "hex");
      if (!wellFormed || expected.length !== presented.length || !timingSafeEqual(expected, presented) || event.integrity.signature_key_id !== producer.key_id) {
        reasons.push({ path: "integrity.signature", code: "signature_invalid", message: "producer signature verification failed" });
        return this.reject(event, reasons, event.tenant?.tenant_id);
      }
    }

    const key = dedupeKey(event);
    const existingSeq = this.#seen.get(key);
    if (existingSeq !== undefined) {
      return { status: "duplicate", event_id: event.event_id, dedupe_key: key, reasons: [], record: this.#ledger.bySeq(existingSeq) as LedgerRecord };
    }

    const record = this.#ledger.append({
      kind: "event",
      gateway_version: GATEWAY_VERSION,
      validation: "accepted",
      transformation_version: "ingest.1.0.0",
      ...(event.tenant?.tenant_id !== undefined ? { tenant_id: event.tenant.tenant_id } : {}),
      body: event,
    });
    this.#seen.set(key, record.ledger_seq);
    return { status: "accepted", event_id: event.event_id, dedupe_key: key, reasons: [], record };
  }

  private reject(rawEvent: unknown, reasons: ValidationIssue[], tenantId: string | undefined): IngestResult {
    const record = this.#ledger.append({
      kind: "rejection",
      gateway_version: GATEWAY_VERSION,
      validation: "rejected",
      rejection_reasons: reasons,
      transformation_version: "ingest.1.0.0",
      ...(tenantId !== undefined ? { tenant_id: tenantId } : {}),
      // A missing event is recorded as null: JSON has no undefined, and the
      // ledger hashes the body (KI-SENTINEL-20261030-006 item 2).
      body: rawEvent === undefined ? null : rawEvent,
    });
    const eventId =
      typeof rawEvent === "object" && rawEvent !== null && typeof (rawEvent as Record<string, unknown>)["event_id"] === "string"
        ? ((rawEvent as Record<string, unknown>)["event_id"] as string)
        : undefined;
    return { status: "rejected", ...(eventId !== undefined ? { event_id: eventId } : {}), reasons, record };
  }
}
