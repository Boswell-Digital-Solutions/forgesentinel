import type { EventEnvelope } from "../contracts/envelope.js";
import type { EvidenceRecord } from "../contracts/evidence.js";
import type { Finding } from "../contracts/finding.js";

/**
 * Versioned feature definitions (02, SNT-030, 13 examples). A feature value
 * is derived evidence: it references its source events and carries an
 * evidence root so transformations of the same stream are never counted as
 * independent corroboration.
 */
export interface FeatureDefinition {
  feature_id: string;
  version: string;
  source_events: string[];
  scope: string[];
  window: { type: "rolling"; duration_ms: number; lateness_allowance_ms: number };
  aggregation: { operation: "sum" | "count" | "mean"; field?: string };
  privacy: { stores_content: false; cloud_allowed: boolean; retention_class: string };
}

interface FeatureSample {
  occurred_at_ms: number;
  value: number;
  event_id: string;
}

export interface FeatureWindowValue {
  feature: string;
  scope_key: string;
  window: { start: string; end: string };
  value: number;
  sample_count: number;
  event_ids: string[];
  evidence_root: string;
}

function valueAtPath(event: EventEnvelope, path: string): unknown {
  const parts = path.split(".");
  let current: unknown = event;
  for (const part of parts) {
    if (typeof current !== "object" || current === null) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

export function scopeValue(event: EventEnvelope, field: string): string | undefined {
  switch (field) {
    case "tenant_id":
      return event.tenant?.tenant_id;
    case "account_id":
      return event.tenant?.account_id;
    case "actor_id":
      return event.actor.actor_id;
    default: {
      const fromPayload = event.payload[field];
      return typeof fromPayload === "string" ? fromPayload : undefined;
    }
  }
}

export function scopeKeyOf(def: FeatureDefinition, event: EventEnvelope): string | undefined {
  const parts: string[] = [];
  for (const field of def.scope) {
    const value = scopeValue(event, field);
    // Unknown values stay explicit (04): an event missing a scope field is
    // excluded from that feature rather than guessed into a bucket.
    if (value === undefined) return undefined;
    parts.push(`${field}=${value}`);
  }
  return parts.join("|");
}

export class FeatureService {
  readonly version = "1.0.0";
  private readonly definitions = new Map<string, FeatureDefinition>();
  private readonly samples = new Map<string, FeatureSample[]>();

  register(def: FeatureDefinition): void {
    this.definitions.set(`${def.feature_id}@${def.version}`, def);
  }

  definition(featureRef: string): FeatureDefinition {
    const def = this.definitions.get(featureRef);
    if (!def) throw new Error(`unknown feature definition "${featureRef}"`);
    return def;
  }

  observe(event: EventEnvelope): void {
    for (const def of this.definitions.values()) {
      if (!def.source_events.includes(event.event_type)) continue;
      const scopeKey = scopeKeyOf(def, event);
      if (scopeKey === undefined) continue;
      let value: number;
      if (def.aggregation.operation === "count") {
        value = 1;
      } else {
        const raw = valueAtPath(event, def.aggregation.field ?? "");
        if (typeof raw === "boolean") {
          value = raw ? 1 : 0;
        } else if (typeof raw === "number") {
          value = raw;
        } else {
          continue;
        }
      }
      const key = `${def.feature_id}@${def.version}::${scopeKey}`;
      const list = this.samples.get(key) ?? [];
      list.push({ occurred_at_ms: Date.parse(event.occurred_at), value, event_id: event.event_id });
      this.samples.set(key, list);
    }
  }

  evaluateWindow(featureRef: string, scopeKey: string, endIso: string): FeatureWindowValue {
    const def = this.definition(featureRef);
    const endMs = Date.parse(endIso);
    const startMs = endMs - def.window.duration_ms;
    const list = (this.samples.get(`${featureRef}::${scopeKey}`) ?? []).filter(
      (sample) => sample.occurred_at_ms > startMs && sample.occurred_at_ms <= endMs,
    );
    const sum = list.reduce((total, sample) => total + sample.value, 0);
    const value = def.aggregation.operation === "count" ? list.length : def.aggregation.operation === "mean" ? (list.length > 0 ? sum / list.length : 0) : sum;
    return {
      feature: featureRef,
      scope_key: scopeKey,
      window: { start: new Date(startMs).toISOString(), end: new Date(endMs).toISOString() },
      value,
      sample_count: list.length,
      event_ids: list.map((sample) => sample.event_id),
      evidence_root: `feature:${featureRef}:${scopeKey}`,
    };
  }

  /** Non-overlapping windows preceding `endIso`, oldest first, for baseline seeding. */
  history(featureRef: string, scopeKey: string, endIso: string, windows: number): FeatureWindowValue[] {
    const def = this.definition(featureRef);
    const result: FeatureWindowValue[] = [];
    for (let index = windows; index >= 1; index--) {
      const windowEnd = Date.parse(endIso) - index * def.window.duration_ms;
      result.push(this.evaluateWindow(featureRef, scopeKey, new Date(windowEnd).toISOString()));
    }
    return result;
  }

  scopeKeys(featureRef: string): string[] {
    const prefix = `${featureRef}::`;
    return [...this.samples.keys()].filter((key) => key.startsWith(prefix)).map((key) => key.slice(prefix.length));
  }
}

let evidenceCounter = 0;

export function featureEvidence(
  window: FeatureWindowValue,
  unit: string,
  scope: Record<string, string>,
  policyGenerated: boolean,
): EvidenceRecord {
  evidenceCounter += 1;
  return {
    evidence_id: `evd_${String(evidenceCounter).padStart(6, "0")}`,
    source_event_ids: window.event_ids.length > 0 ? window.event_ids : ["evt_none"],
    evidence_type: "derived_feature",
    feature_definition: window.feature,
    value: window.value,
    unit,
    scope,
    window: window.window,
    quality: {
      score: window.event_ids.length > 0 ? 0.96 : 0.5,
      completeness: 1.0,
      freshness: 0.98,
      integrity: 1.0,
      source_reliability: 0.9,
    },
    created_by: { component: "sentinel-feature-service", version: "1.0.0" },
    source_event_root: window.evidence_root,
    policy_generated_effect: policyGenerated,
  };
}

export interface ThresholdBurstSpec {
  events: EventEnvelope[];
  learnCutoff: number;
  /** Event type counted toward the threshold. */
  eventType: string;
  featureRef: string;
  threshold: number;
  /** Grouping field — must match the feature definition's own `scope`. */
  groupField: "account_id" | "actor_id";
  unit: string;
  nextFindingId: () => string;
  node: { name: string; version: string };
  findingType: string;
  actionClass: Finding["recommendation"]["action_class"];
  playbook?: string;
  likelihood: (count: number) => number;
  impact: number;
  confidence: number;
  summarize: (count: number) => string;
  subject: (tenantId: string, groupId: string) => Finding["subject"];
  correlationHints: (tenantId: string, groupId: string, lastEvent: EventEnvelope) => Finding["correlation_hints"];
}

/**
 * Shared shape behind every "N qualifying events for one subject within a
 * rolling window" detector (agent patch/denial bursts, cloud login-failure
 * bursts, license activation abuse, data egress anomaly): filter by event
 * type and learn cutoff, group by tenant+subject, evaluate the feature
 * window for the most recent event in each group, and emit one finding per
 * group that crosses `threshold`. Only the per-node specifics (finding
 * shape, likelihood curve, grouping field) vary between callers.
 */
export function thresholdBurst(features: FeatureService, spec: ThresholdBurstSpec): { findings: Finding[]; evidence: EvidenceRecord[] } {
  const findings: Finding[] = [];
  const evidence: EvidenceRecord[] = [];
  const relevant = spec.events.filter(
    (event) => event.event_type === spec.eventType && Date.parse(event.occurred_at) >= spec.learnCutoff && event.tenant?.tenant_id,
  );
  const byGroup = new Map<string, EventEnvelope[]>();
  for (const event of relevant) {
    const tenantId = event.tenant!.tenant_id;
    const groupId = scopeValue(event, spec.groupField) ?? tenantId;
    const key = `${tenantId}|${groupId}`;
    const group = byGroup.get(key);
    if (group) group.push(event);
    else byGroup.set(key, [event]);
  }
  for (const [key, groupEvents] of byGroup) {
    const last = groupEvents[groupEvents.length - 1];
    if (!last) continue;
    const [tenantId, groupId] = key.split("|") as [string, string];
    const scopeKey = `tenant_id=${tenantId}|${spec.groupField}=${groupId}`;
    const window = features.evaluateWindow(spec.featureRef, scopeKey, last.occurred_at);
    if (window.value < spec.threshold) continue;
    const record = featureEvidence(window, spec.unit, { tenant_id: tenantId, account_id: last.tenant?.account_id ?? tenantId }, false);
    evidence.push(record);
    findings.push({
      finding_id: spec.nextFindingId(),
      finding_type: spec.findingType,
      node: spec.node,
      subject: spec.subject(tenantId, groupId),
      tenant_id: tenantId,
      window: window.window,
      risk: { likelihood: spec.likelihood(window.value), impact: spec.impact, confidence: spec.confidence, evidence_quality: record.quality.score },
      evidence_ids: [record.evidence_id],
      source_event_roots: [record.source_event_root],
      explanation: {
        summary: spec.summarize(window.value),
        top_factors: [{ factor: spec.findingType, contribution: 1 }],
        uncertainties: ["A large but legitimate burst of activity can resemble abuse; verify before acting."],
        observed: window.value,
        expected: 0,
      },
      recommendation: { action_class: spec.actionClass, ...(spec.playbook !== undefined ? { playbook: spec.playbook } : {}) },
      expires_at: new Date(Date.parse(last.occurred_at) + 24 * 3600 * 1000).toISOString(),
      correlation_hints: spec.correlationHints(tenantId, groupId, last),
      policy_generated_effect: last.control_lineage?.policy_generated_effect === true,
    });
  }
  return { findings, evidence };
}

export function eventEvidence(event: EventEnvelope, scope: Record<string, string>): EvidenceRecord {
  evidenceCounter += 1;
  return {
    evidence_id: `evd_${String(evidenceCounter).padStart(6, "0")}`,
    source_event_ids: [event.event_id],
    evidence_type: "validated_event",
    scope,
    quality: { score: 0.95, completeness: 1.0, freshness: 1.0, integrity: 1.0, source_reliability: 0.9 },
    created_by: { component: "sentinel-feature-service", version: "1.0.0" },
    // Copies of one source attempt (e.g. CSSA decision/authorization/outcome
    // sharing a run) collapse to one root; otherwise the event is its own root.
    source_event_root: event.correlation.run_id ? `run:${event.correlation.run_id}` : event.event_id,
    policy_generated_effect: event.control_lineage?.policy_generated_effect === true,
  };
}
