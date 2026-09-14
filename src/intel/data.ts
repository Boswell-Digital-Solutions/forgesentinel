import { clamp01 } from "../contracts/common.js";
import type { EventEnvelope } from "../contracts/envelope.js";
import type { EvidenceRecord } from "../contracts/evidence.js";
import type { Finding } from "../contracts/finding.js";
import { eventEvidence, FeatureService, thresholdBurst } from "./features.js";
import type { NodeOutput } from "./cost.js";

export const EXPORTS_PER_HOUR = "data.exports_per_hour@1.0.0";

/**
 * Actions Sentinel-Data may never recommend (03/10): it surfaces governance
 * findings and recommends scoped quarantine/block through the owning authority,
 * but never deletes evidence or exports unredacted content itself.
 */
export const DATA_FORBIDDEN_ACTIONS = [
  "data.evidence.delete",
  "data.object.export_unredacted",
  "data.object.delete",
  "usage.evidence.delete",
] as const;

export interface DataNodeConfig {
  egress_burst_count: number;
}

export const DEFAULT_DATA_CONFIG: DataNodeConfig = {
  egress_burst_count: 20,
};

interface DirectSpec {
  findingType: string;
  summary: string;
  factor: string;
  uncertainty: string;
  playbook: string;
  likelihood: number;
  impact: number;
  confidence: number;
}

/**
 * Sentinel-Data (03, SNT-150). Shadow mode. Cloud field policy and cross-tenant
 * denial are enforced at the ledger (Wave 1); this node is the intelligence
 * layer that surfaces egress anomalies, cross-tenant attempts, and redaction
 * failures and recommends scoped containment — it never deletes or exfiltrates.
 */
export class SentinelDataNode {
  readonly name = "sentinel-data";
  readonly version = "1.0.0";
  readonly shadow = true;
  private findingCounter = 0;

  constructor(
    private readonly features: FeatureService,
    private readonly config: DataNodeConfig = DEFAULT_DATA_CONFIG,
  ) {}

  private nextFindingId(): string {
    this.findingCounter += 1;
    return `fnd_data_${String(this.findingCounter).padStart(5, "0")}`;
  }

  process(events: EventEnvelope[], noveltyLearnedBefore: string): NodeOutput {
    const findings: Finding[] = [];
    const evidence: EvidenceRecord[] = [];
    const learnCutoff = Date.parse(noveltyLearnedBefore);
    const sorted = [...events].sort((a, b) => Date.parse(a.occurred_at) - Date.parse(b.occurred_at));

    for (const event of sorted) {
      if (Date.parse(event.occurred_at) < learnCutoff) continue;
      const tenantId = event.tenant?.tenant_id;
      if (!tenantId) continue;
      const accountId = event.tenant?.account_id ?? tenantId;

      if (event.event_type === "data.cross_tenant.denied") {
        const record = eventEvidence(event, { tenant_id: tenantId, account_id: accountId });
        evidence.push(record);
        findings.push(this.directFinding(event, record, tenantId, accountId, {
          findingType: "data.cross_tenant_access",
          summary: `A cross-tenant data access was denied for actor "${event.actor.actor_id}" — a tenant-isolation boundary was tested.`,
          factor: "tenant_isolation_violation",
          uncertainty: "Could be a misrouted request or a probing attempt; verify the actor and the target tenant.",
          playbook: "PB-DATA-CROSSTENANT-01",
          likelihood: 0.6,
          impact: 0.6,
          confidence: 0.8,
        }));
      }

      if (event.event_type === "data.redaction.failed") {
        const record = eventEvidence(event, { tenant_id: tenantId, account_id: accountId });
        evidence.push(record);
        findings.push(this.directFinding(event, record, tenantId, accountId, {
          findingType: "data.redaction_failure",
          summary: "Redaction failed for a data object where redaction is required; the transfer should be blocked.",
          factor: "redaction_failure",
          uncertainty: "A transient redactor error can cause a benign failure; the safe default is to block the transfer.",
          playbook: "PB-DATA-REDACTION-01",
          likelihood: 0.55,
          impact: 0.6,
          confidence: 0.8,
        }));
      }
    }

    const egress = this.egressAnomaly(sorted, learnCutoff);
    findings.push(...egress.findings);
    evidence.push(...egress.evidence);

    return { findings, evidence };
  }

  private egressAnomaly(events: EventEnvelope[], learnCutoff: number): NodeOutput {
    return thresholdBurst(this.features, {
      events,
      learnCutoff,
      eventType: "data.object.exported",
      featureRef: EXPORTS_PER_HOUR,
      threshold: this.config.egress_burst_count,
      groupField: "account_id",
      unit: "exports/hour",
      nextFindingId: () => this.nextFindingId(),
      node: { name: this.name, version: this.version },
      findingType: "data.egress_anomaly",
      actionClass: "REQUEST_OPERATOR",
      playbook: "PB-DATA-EGRESS-01",
      likelihood: (count) => clamp01(0.4 + 0.02 * count),
      impact: 0.6,
      confidence: 0.65,
      summarize: (count) => `${count} data exports in one hour for this account — an egress spike that may indicate exfiltration.`,
      subject: (_tenantId, accountId) => ({ type: "account", id: accountId }),
      // Surfaces the triggering export's destination so a downstream
      // data_exfiltration compound incident can recommend an
      // exact-destination block (DATA_EXFILTRATION_POLICY) instead of an
      // action with no target to bind to.
      correlationHints: (_tenantId, accountId, last) => ({
        account_id: accountId,
        ...(typeof last.payload["destination"] === "string" ? { destination: last.payload["destination"] } : {}),
      }),
    });
  }

  private directFinding(event: EventEnvelope, record: EvidenceRecord, tenantId: string, accountId: string, spec: DirectSpec): Finding {
    return {
      finding_id: this.nextFindingId(),
      finding_type: spec.findingType,
      node: { name: this.name, version: this.version },
      subject: { type: "account", id: accountId },
      tenant_id: tenantId,
      window: { start: event.occurred_at, end: event.occurred_at },
      risk: { likelihood: spec.likelihood, impact: spec.impact, confidence: spec.confidence, evidence_quality: record.quality.score },
      evidence_ids: [record.evidence_id],
      source_event_roots: [record.source_event_root],
      explanation: {
        summary: spec.summary,
        top_factors: [{ factor: spec.factor, contribution: 1 }],
        uncertainties: [spec.uncertainty],
      },
      recommendation: { action_class: "REQUEST_OPERATOR", playbook: spec.playbook },
      expires_at: new Date(Date.parse(event.occurred_at) + 24 * 3600 * 1000).toISOString(),
      correlation_hints: { account_id: accountId, actor_id: event.actor.actor_id },
      policy_generated_effect: event.control_lineage?.policy_generated_effect === true,
    };
  }
}
