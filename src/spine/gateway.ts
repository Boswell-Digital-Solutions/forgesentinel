import { createHmac, timingSafeEqual } from "node:crypto";
import { canonicalJson, hashPayload, sha256Hex, type ValidationIssue } from "../contracts/common.js";
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

/** The reserved key that marks a wrapped rejection body. */
export const MALFORMED_INPUT_KEY = "malformed_input";

/**
 * The body a rejection record stores for `rawEvent`.
 *
 * - An object or array that JSON can serialize, and that has no own
 *   `malformed_input` key, is stored as it is.
 * - Every other input is wrapped as `{ malformed_input, input_type }`. This
 *   includes an object that itself has the reserved key, so an input with
 *   that key can no longer collide with a wrapped primitive
 *   (KI-SENTINEL-20261102-004).
 * - `malformed_input` holds a JSON-safe form of the input: the value for a
 *   string, boolean or finite number; the text for -0, NaN and Infinity; a
 *   decimal string for a BigInt; the description for a Symbol; the object for
 *   a serializable object with the reserved key; otherwise null. `input_type`
 *   records what the input was, so a function, a Symbol or an unserializable
 *   object is not lost as `{}` (KI-SENTINEL-20261102-005).
 *
 * This is not a one-to-one encoding of every input. Inputs that canonical
 * JSON writes alike still give the same body: for example a nested -0 and 0,
 * a nested out-of-range number and null, a `__proto__` key that the canonical
 * form drops, or (from a library caller) a Date, Map, Set and `{}`, two
 * functions, or two unserializable objects. See KI-SENTINEL-20261102-006.
 *
 * The ledger hashes the body, and its integrity check verifies only an object
 * or array body, so every rejection stays verifiable.
 */
export function rejectionBody(rawEvent: unknown): unknown {
  const serializable = (value: unknown): boolean => {
    try {
      canonicalJson(value);
      return true;
    } catch {
      return false;
    }
  };
  if (typeof rawEvent === "object" && rawEvent !== null) {
    const hasReservedKey = Object.prototype.hasOwnProperty.call(rawEvent, MALFORMED_INPUT_KEY);
    if (!serializable(rawEvent)) return { [MALFORMED_INPUT_KEY]: null, input_type: "unserializable" };
    if (!hasReservedKey) return rawEvent;
    return { [MALFORMED_INPUT_KEY]: rawEvent, input_type: Array.isArray(rawEvent) ? "array" : "object" };
  }
  switch (typeof rawEvent) {
    case "undefined":
      return { [MALFORMED_INPUT_KEY]: null, input_type: "undefined" };
    case "string":
    case "boolean":
      return { [MALFORMED_INPUT_KEY]: rawEvent, input_type: typeof rawEvent };
    case "number":
      // JSON writes NaN and Infinity as null and -0 as 0; record the text so they stay distinct.
      if (Object.is(rawEvent, -0)) return { [MALFORMED_INPUT_KEY]: "-0", input_type: "number" };
      return { [MALFORMED_INPUT_KEY]: Number.isFinite(rawEvent) ? rawEvent : String(rawEvent), input_type: "number" };
    case "bigint":
      return { [MALFORMED_INPUT_KEY]: rawEvent.toString(), input_type: "bigint" };
    case "symbol":
      return { [MALFORMED_INPUT_KEY]: rawEvent.description ?? null, input_type: "symbol" };
    case "function":
      return { [MALFORMED_INPUT_KEY]: null, input_type: "function" };
    default:
      return { [MALFORMED_INPUT_KEY]: null, input_type: rawEvent === null ? "null" : typeof rawEvent };
  }
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
      body: rejectionBody(rawEvent),
    });
    const eventId =
      typeof rawEvent === "object" && rawEvent !== null && typeof (rawEvent as Record<string, unknown>)["event_id"] === "string"
        ? ((rawEvent as Record<string, unknown>)["event_id"] as string)
        : undefined;
    return { status: "rejected", ...(eventId !== undefined ? { event_id: eventId } : {}), reasons, record };
  }
}
