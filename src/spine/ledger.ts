import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { canonicalJson, hashPayload, isRecord } from "../contracts/common.js";
import type { EventEnvelope } from "../contracts/envelope.js";
import type { ValidationIssue } from "../contracts/common.js";

export type LedgerRecordKind = "event" | "rejection" | "evidence" | "finding" | "incident" | "policy_decision" | "receipt" | "feedback_label";

/**
 * Append-oriented evidence ledger record (02, SNT-020). Originals are
 * immutable; corrections append with a supersedes link, never erase.
 */
export interface LedgerRecord {
  ledger_seq: number;
  kind: LedgerRecordKind;
  ingested_at: string;
  gateway_version: string;
  validation: "accepted" | "rejected";
  rejection_reasons?: ValidationIssue[];
  source_hash: string;
  transformation_version: string;
  tenant_id?: string;
  supersedes?: number;
  body: unknown;
}

export interface LedgerAccessContext {
  principal: string;
  tenant_id?: string;
  role: "tenant" | "system" | "auditor";
}

export class CrossTenantAccessDenied extends Error {
  constructor(readonly requestedTenant: string, readonly context: LedgerAccessContext) {
    super(`cross-tenant access denied: principal "${context.principal}" (tenant ${context.tenant_id ?? "none"}) requested tenant "${requestedTenant}"`);
  }
}

export class EvidenceLedger {
  private readonly records: LedgerRecord[] = [];
  private readonly bySeqIndex = new Map<number, LedgerRecord>();
  private seq = 0;
  readonly denials: { at: string; requested_tenant: string; principal: string }[] = [];

  constructor(private readonly walPath?: string) {
    if (walPath) {
      // Create the WAL directory once, up front, rather than on every
      // append — the path never changes for the lifetime of this ledger.
      mkdirSync(dirname(walPath), { recursive: true });
      if (existsSync(walPath)) this.loadWal(walPath);
    }
  }

  private loadWal(path: string): void {
    const lines = readFileSync(path, "utf8").split("\n").filter((line) => line.trim().length > 0);
    for (const line of lines) {
      const record = JSON.parse(line) as LedgerRecord;
      this.records.push(record);
      this.bySeqIndex.set(record.ledger_seq, record);
      this.seq = Math.max(this.seq, record.ledger_seq);
    }
  }

  private persist(record: LedgerRecord): void {
    if (!this.walPath) return;
    appendFileSync(this.walPath, `${JSON.stringify(record)}\n`, "utf8");
  }

  append(input: Omit<LedgerRecord, "ledger_seq" | "ingested_at" | "source_hash"> & { ingested_at?: string }): LedgerRecord {
    const record: LedgerRecord = {
      ...input,
      ledger_seq: ++this.seq,
      ingested_at: input.ingested_at ?? new Date().toISOString(),
      source_hash: hashPayload(input.body),
    };
    this.records.push(record);
    this.bySeqIndex.set(record.ledger_seq, record);
    this.persist(record);
    return record;
  }

  appendCorrection(originalSeq: number, correctedBody: unknown, transformationVersion: string): LedgerRecord {
    const original = this.bySeq(originalSeq);
    if (!original) throw new Error(`cannot correct unknown ledger record ${originalSeq}`);
    return this.append({
      kind: original.kind,
      gateway_version: original.gateway_version,
      validation: original.validation,
      transformation_version: transformationVersion,
      ...(original.tenant_id !== undefined ? { tenant_id: original.tenant_id } : {}),
      supersedes: originalSeq,
      body: correctedBody,
    });
  }

  bySeq(seq: number): LedgerRecord | undefined {
    return this.bySeqIndex.get(seq);
  }

  all(): readonly LedgerRecord[] {
    return this.records;
  }

  events(): EventEnvelope[] {
    return this.records.filter((record) => record.kind === "event" && record.validation === "accepted").map((record) => record.body as EventEnvelope);
  }

  /** Tenant isolation: tenant-scoped principals only read their own tenant. */
  queryByTenant(tenantId: string, context: LedgerAccessContext, kind?: LedgerRecordKind): LedgerRecord[] {
    if (context.role === "tenant" && context.tenant_id !== tenantId) {
      this.denials.push({ at: new Date().toISOString(), requested_tenant: tenantId, principal: context.principal });
      this.append({
        kind: "event",
        gateway_version: "ledger",
        validation: "accepted",
        transformation_version: "1.0.0",
        tenant_id: tenantId,
        body: {
          event_type: "data.cross_tenant.denied",
          denied_principal: context.principal,
          principal_tenant: context.tenant_id ?? null,
          requested_tenant: tenantId,
        },
      });
      throw new CrossTenantAccessDenied(tenantId, context);
    }
    return this.records.filter((record) => record.tenant_id === tenantId && (kind === undefined || record.kind === kind));
  }

  /**
   * Cloud projection field policy (10): cloud telemetry receives metadata,
   * hashes, and approved fields — never payload content that is not cloud
   * eligible. Local detail stays in DataForge Local.
   */
  cloudProjection(record: LedgerRecord): Record<string, unknown> | null {
    if (record.kind !== "event") {
      return { ledger_seq: record.ledger_seq, kind: record.kind, source_hash: record.source_hash, tenant_id: record.tenant_id ?? null, body: record.body };
    }
    const event = record.body as EventEnvelope;
    const policy = event.data_policy;
    const base: Record<string, unknown> = {
      ledger_seq: record.ledger_seq,
      event_id: event.event_id,
      event_type: event.event_type,
      occurred_at: event.occurred_at,
      observed_at: event.observed_at,
      producer: event.producer,
      tenant: event.tenant ?? null,
      subject: event.subject,
      location: event.location,
      payload_hash: event.integrity.payload_hash,
      sensitivity: policy.sensitivity,
      retention_class: policy.retention_class,
    };
    if (!policy.cloud_allowed) return null;
    const contentForbidden = policy.content_included && (policy.sensitivity === "restricted" || policy.sensitivity === "regulated" || policy.sensitivity === "confidential");
    if (!contentForbidden) {
      base["payload"] = event.payload;
    } else {
      base["payload_omitted"] = "content_excluded_by_field_policy";
    }
    return base;
  }

  cloudProjectionContains(record: LedgerRecord, needle: string): boolean {
    const projection = this.cloudProjection(record);
    return projection !== null && canonicalJson(projection).includes(needle);
  }

  /** Deterministic replay support: serialize accepted events as JSONL. */
  exportEventsJsonl(): string {
    return this.events().map((event) => JSON.stringify(event)).join("\n");
  }

  integrityCheck(): { seq: number; ok: boolean }[] {
    return this.records.map((record) => ({
      seq: record.ledger_seq,
      ok: isRecord(record.body) || Array.isArray(record.body) ? hashPayload(record.body) === record.source_hash : false,
    }));
  }
}
