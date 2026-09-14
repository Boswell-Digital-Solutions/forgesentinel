import { createHmac, timingSafeEqual } from "node:crypto";
import { hashPayload, sha256Hex, type ValidationIssue } from "../contracts/common.js";
import { validateEventEnvelope, type EventEnvelope } from "../contracts/envelope.js";
import { lookupEventType } from "../contracts/families.js";
import { ProducerRegistry, type ProducerCredential } from "./producers.js";
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
 * Idempotency key per 04: producer, native event ID, event type, subject,
 * time bucket, and payload hash. Distinct security events are never
 * collapsed because their text looks similar.
 */
export function dedupeKey(event: EventEnvelope): string {
  const bucket = Math.floor(Date.parse(event.occurred_at) / (60 * 60 * 1000));
  return sha256Hex(
    [
      event.producer.service,
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
  private readonly seen = new Map<string, number>();

  constructor(
    private readonly registry: ProducerRegistry,
    private readonly ledger: EvidenceLedger,
  ) {}

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

    const producer = this.registry.authenticate(credential, event.integrity.payload_hash);
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
    if (!this.registry.allowsEventType(producer, event.event_type)) {
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
      const expected = createHmac("sha256", producer.secret).update(event.integrity.payload_hash, "utf8").digest("hex");
      const a = Buffer.from(expected, "hex");
      const b = Buffer.from(event.integrity.signature.length === expected.length ? event.integrity.signature : "0".repeat(expected.length), "hex");
      if (a.length !== b.length || !timingSafeEqual(a, b) || event.integrity.signature_key_id !== producer.key_id) {
        reasons.push({ path: "integrity.signature", code: "signature_invalid", message: "producer signature verification failed" });
        return this.reject(event, reasons, event.tenant?.tenant_id);
      }
    }

    const key = dedupeKey(event);
    const existingSeq = this.seen.get(key);
    if (existingSeq !== undefined) {
      return { status: "duplicate", event_id: event.event_id, dedupe_key: key, reasons: [], record: this.ledger.bySeq(existingSeq) as LedgerRecord };
    }

    const record = this.ledger.append({
      kind: "event",
      gateway_version: GATEWAY_VERSION,
      validation: "accepted",
      transformation_version: "ingest.1.0.0",
      ...(event.tenant?.tenant_id !== undefined ? { tenant_id: event.tenant.tenant_id } : {}),
      body: event,
    });
    this.seen.set(key, record.ledger_seq);
    return { status: "accepted", event_id: event.event_id, dedupe_key: key, reasons: [], record };
  }

  private reject(rawEvent: unknown, reasons: ValidationIssue[], tenantId: string | undefined): IngestResult {
    const record = this.ledger.append({
      kind: "rejection",
      gateway_version: GATEWAY_VERSION,
      validation: "rejected",
      rejection_reasons: reasons,
      transformation_version: "ingest.1.0.0",
      ...(tenantId !== undefined ? { tenant_id: tenantId } : {}),
      body: rawEvent,
    });
    const eventId =
      typeof rawEvent === "object" && rawEvent !== null && typeof (rawEvent as Record<string, unknown>)["event_id"] === "string"
        ? ((rawEvent as Record<string, unknown>)["event_id"] as string)
        : undefined;
    return { status: "rejected", ...(eventId !== undefined ? { event_id: eventId } : {}), reasons, record };
  }
}
