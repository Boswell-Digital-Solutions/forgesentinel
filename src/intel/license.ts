import type { EventEnvelope } from "../contracts/envelope.js";
import type { EvidenceRecord } from "../contracts/evidence.js";
import type { Finding } from "../contracts/finding.js";
import { clamp01 } from "../contracts/common.js";
import { eventEvidence, FeatureService, thresholdBurst } from "./features.js";
import type { NodeOutput } from "./cost.js";

export const DEVICE_ACTIVATIONS_PER_DAY = "license.device_activations_per_day@1.0.0";

/**
 * Actions Sentinel-License may never recommend (03): it protects entitlements
 * and surfaces commercial divergence, but never permanently revokes a license,
 * cancels a subscription, or mutates Stripe/billing truth.
 */
export const LICENSE_FORBIDDEN_ACTIONS = [
  "license.permanent_revoke",
  "billing.subscription.cancel",
  "billing.stripe.customer.modify",
  "usage.evidence.delete",
] as const;

/** Stripe subscription states that mean the paid entitlement should not be active. */
const INACTIVE_SUB_STATUS = new Set(["canceled", "cancelled", "unpaid", "past_due", "incomplete_expired"]);

export interface LicenseNodeConfig {
  activation_abuse_count: number;
}

export const DEFAULT_LICENSE_CONFIG: LicenseNodeConfig = {
  activation_abuse_count: 5,
};

/**
 * Sentinel-License (03, SNT-140). Shadow mode: protects signed entitlements,
 * device authorization, trials, and commercial policy. It surfaces rejections
 * and divergence and recommends revalidation/reconciliation — it never
 * permanently revokes a license or mutates billing truth.
 */
export class SentinelLicenseNode {
  readonly name = "sentinel-license";
  readonly version = "1.0.0";
  readonly shadow = true;
  private findingCounter = 0;

  constructor(
    private readonly features: FeatureService,
    private readonly config: LicenseNodeConfig = DEFAULT_LICENSE_CONFIG,
  ) {}

  private nextFindingId(): string {
    this.findingCounter += 1;
    return `fnd_license_${String(this.findingCounter).padStart(5, "0")}`;
  }

  process(events: EventEnvelope[], noveltyLearnedBefore: string): NodeOutput {
    const findings: Finding[] = [];
    const evidence: EvidenceRecord[] = [];
    const learnCutoff = Date.parse(noveltyLearnedBefore);
    const sorted = [...events].sort((a, b) => Date.parse(a.occurred_at) - Date.parse(b.occurred_at));
    const subStatus = new Map<string, string>();

    for (const event of sorted) {
      const tenantId = event.tenant?.tenant_id;
      if (!tenantId) continue;
      const accountId = event.tenant?.account_id ?? tenantId;
      const accountKey = `${tenantId}/${accountId}`;

      // Track the latest Stripe subscription status (learning + post) so a later
      // entitlement grant can be compared against the most recent billing truth.
      if (event.event_type === "billing.subscription.changed") {
        const status = typeof event.payload["status"] === "string" ? (event.payload["status"] as string) : undefined;
        if (status) subStatus.set(accountKey, status);
        continue;
      }

      if (Date.parse(event.occurred_at) < learnCutoff) continue;

      if (event.event_type === "license.entitlement.rejected") {
        const record = eventEvidence(event, { tenant_id: tenantId, account_id: accountId });
        evidence.push(record);
        findings.push(this.rejectedFinding(event, record, tenantId, accountId));
      }

      if (event.event_type === "license.feature.allowed" || event.event_type === "license.entitlement.validated") {
        const status = subStatus.get(accountKey);
        if (status && INACTIVE_SUB_STATUS.has(status)) {
          const record = eventEvidence(event, { tenant_id: tenantId, account_id: accountId });
          evidence.push(record);
          findings.push(this.divergenceFinding(event, record, tenantId, accountId, status));
        }
      }
    }

    const activation = this.activationAbuse(sorted, learnCutoff);
    findings.push(...activation.findings);
    evidence.push(...activation.evidence);

    return { findings, evidence };
  }

  private activationAbuse(events: EventEnvelope[], learnCutoff: number): NodeOutput {
    return thresholdBurst(this.features, {
      events,
      learnCutoff,
      eventType: "license.device.activated",
      featureRef: DEVICE_ACTIVATIONS_PER_DAY,
      threshold: this.config.activation_abuse_count,
      groupField: "account_id",
      unit: "activations/day",
      nextFindingId: () => this.nextFindingId(),
      node: { name: this.name, version: this.version },
      findingType: "license.activation_abuse",
      actionClass: "RECOMMEND_ONLY",
      playbook: "PB-LICENSE-ACTIVATION-01",
      likelihood: (count) => clamp01(0.35 + 0.05 * count),
      impact: 0.45,
      confidence: 0.65,
      summarize: (count) => `${count} device activations in 24h for this account — possible license sharing or trial abuse.`,
      subject: (_tenantId, accountId) => ({ type: "account", id: accountId }),
      correlationHints: (_tenantId, accountId) => ({ account_id: accountId }),
    });
  }

  private rejectedFinding(event: EventEnvelope, record: EvidenceRecord, tenantId: string, accountId: string): Finding {
    const reason = typeof event.payload["reason"] === "string" ? (event.payload["reason"] as string) : undefined;
    return {
      finding_id: this.nextFindingId(),
      finding_type: "license.entitlement_rejected",
      node: { name: this.name, version: this.version },
      subject: { type: "account", id: accountId },
      tenant_id: tenantId,
      window: { start: event.occurred_at, end: event.occurred_at },
      risk: { likelihood: 0.5, impact: 0.55, confidence: 0.8, evidence_quality: record.quality.score },
      evidence_ids: [record.evidence_id],
      source_event_roots: [record.source_event_root],
      explanation: {
        summary: `Entitlement validation was rejected${reason ? ` (${reason})` : ""}; the signed entitlement failed closed.`,
        top_factors: [{ factor: "entitlement_rejected", contribution: 1 }],
        uncertainties: ["A clock skew, key rotation, or offline cache can cause a benign rejection."],
      },
      recommendation: { action_class: "REQUEST_OPERATOR", playbook: "PB-LICENSE-REJECT-01" },
      expires_at: new Date(Date.parse(event.occurred_at) + 24 * 3600 * 1000).toISOString(),
      correlation_hints: { account_id: accountId },
      policy_generated_effect: event.control_lineage?.policy_generated_effect === true,
    };
  }

  private divergenceFinding(event: EventEnvelope, record: EvidenceRecord, tenantId: string, accountId: string, status: string): Finding {
    return {
      finding_id: this.nextFindingId(),
      finding_type: "license.stripe_divergence",
      node: { name: this.name, version: this.version },
      subject: { type: "account", id: accountId },
      tenant_id: tenantId,
      window: { start: event.occurred_at, end: event.occurred_at },
      risk: { likelihood: 0.55, impact: 0.55, confidence: 0.75, evidence_quality: record.quality.score },
      evidence_ids: [record.evidence_id],
      source_event_roots: [record.source_event_root],
      explanation: {
        summary: `Entitlement granted a feature while the Stripe subscription is "${status}" — the cached entitlement may have outlived the subscription.`,
        top_factors: [{ factor: "stripe_entitlement_divergence", contribution: 1 }],
        uncertainties: ["A billing webhook delay or grace period can produce a transient divergence."],
      },
      recommendation: { action_class: "REQUEST_OPERATOR", playbook: "PB-LICENSE-RECONCILE-01" },
      expires_at: new Date(Date.parse(event.occurred_at) + 24 * 3600 * 1000).toISOString(),
      correlation_hints: { account_id: accountId },
      policy_generated_effect: event.control_lineage?.policy_generated_effect === true,
    };
  }
}
