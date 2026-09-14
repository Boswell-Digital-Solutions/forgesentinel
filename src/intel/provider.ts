import { clamp01 } from "../contracts/common.js";
import type { EventEnvelope } from "../contracts/envelope.js";
import type { EvidenceRecord } from "../contracts/evidence.js";
import type { Finding } from "../contracts/finding.js";
import { fingerprintMaterialChange, type ModelFingerprint, type TrustVector } from "../contracts/trust.js";
import { eventEvidence } from "./features.js";
import type { NodeOutput } from "./cost.js";

/**
 * Sentinel-Provider (03, SNT-130, 08). Shadow mode. Model aliases are not
 * identities (ADR-006): when an alias's fingerprint changes materially, the
 * new fingerprint enters provisional state and inherits none of the old
 * route's task trust. Trust stays scoped per fingerprint + task category +
 * route class (ADR-005); NeuroForge keeps routing authority (ADR-014).
 */
export class SentinelProviderNode {
  readonly name = "sentinel-provider";
  readonly version = "1.0.0";
  readonly shadow = true;

  private readonly byAlias = new Map<string, ModelFingerprint>();
  private readonly trust = new Map<string, TrustVector>();
  private findingCounter = 0;

  private aliasKey(fingerprint: ModelFingerprint): string {
    return `${fingerprint.provider}::${fingerprint.declared_model_name}`;
  }

  private trustKey(fingerprintId: string, taskCategory: string, routeClass: string): string {
    return `${fingerprintId}::${taskCategory}::${routeClass}`;
  }

  knownFingerprint(provider: string, declaredModelName: string): ModelFingerprint | undefined {
    return this.byAlias.get(`${provider}::${declaredModelName}`);
  }

  setTrust(vector: TrustVector): void {
    this.trust.set(this.trustKey(vector.fingerprint_id, vector.task_category, vector.route_class), vector);
  }

  trustFor(fingerprintId: string, taskCategory: string, routeClass: string): TrustVector | undefined {
    return this.trust.get(this.trustKey(fingerprintId, taskCategory, routeClass));
  }

  /**
   * Sensitive categories require a verified fingerprint in normal state
   * with demonstrated security/contract behavior (08 security-sensitive
   * rules). Provisional or reduced trust is never eligible.
   */
  sensitiveEligible(fingerprintId: string, taskCategory: string, routeClass: string): boolean {
    const vector = this.trustFor(fingerprintId, taskCategory, routeClass);
    if (!vector) return false;
    return (
      vector.state === "normal" &&
      vector.dimensions.security_compliance >= 0.9 &&
      vector.dimensions.contract_validity >= 0.95 &&
      vector.dimensions.tool_policy_compliance >= 0.95 &&
      vector.dimensions.evidence_quality >= 0.8
    );
  }

  /**
   * Registers an observed fingerprint for an alias. A material change emits
   * a fingerprint-change finding and resets inherited trust: every trust
   * vector of the old fingerprint gets a provisional successor with task
   * performance zeroed and only infrastructure observations carried.
   */
  observe(fingerprint: ModelFingerprint, event?: EventEnvelope): NodeOutput {
    const key = this.aliasKey(fingerprint);
    const previous = this.byAlias.get(key);
    this.byAlias.set(key, fingerprint);

    if (!previous || previous.fingerprint_id === fingerprint.fingerprint_id) {
      return { findings: [], evidence: [] };
    }
    const changed = fingerprintMaterialChange(previous, fingerprint);
    if (changed.length === 0) {
      return { findings: [], evidence: [] };
    }

    const resetCount = this.resetInheritedTrust(previous.fingerprint_id, fingerprint);
    const evidence: EvidenceRecord[] = [];
    let evidenceIds = [`evd_provider_${fingerprint.fingerprint_id}`];
    let roots = [`fingerprint:${fingerprint.fingerprint_id}`];
    let tenantId = "ten_platform";
    if (event) {
      const record = eventEvidence(event, { provider: fingerprint.provider, declared_model_name: fingerprint.declared_model_name });
      evidence.push(record);
      evidenceIds = [record.evidence_id];
      roots = [record.source_event_root];
      tenantId = event.tenant?.tenant_id ?? tenantId;
    }

    this.findingCounter += 1;
    const finding: Finding = {
      finding_id: `fnd_provider_${String(this.findingCounter).padStart(5, "0")}`,
      finding_type: "provider.fingerprint_changed",
      node: { name: this.name, version: this.version },
      subject: { type: "model_route", id: `${fingerprint.provider}/${fingerprint.declared_model_name}` },
      tenant_id: tenantId,
      window: { start: fingerprint.first_seen_at, end: fingerprint.first_seen_at },
      risk: {
        likelihood: clamp01(0.4 + 0.1 * changed.length),
        impact: 0.7,
        // The change itself is deterministic; only its consequences are
        // uncertain.
        confidence: 0.95,
        evidence_quality: 0.95,
      },
      evidence_ids: evidenceIds,
      source_event_roots: roots,
      explanation: {
        summary: `Alias "${fingerprint.declared_model_name}" at ${fingerprint.provider} changed materially (${changed.join(", ")}). Inherited trust was reset on ${resetCount} scoped vector(s); the new snapshot is provisional.`,
        top_factors: changed.map((field) => ({ factor: `changed:${field}`, contribution: 1 / changed.length })),
        uncertainties: ["The new snapshot may be equivalent or better; evaluation is required before trust returns."],
      },
      recommendation: { action_class: "REQUEST_OPERATOR", playbook: "PB-PROVIDER-CHANGE-01" },
      expires_at: new Date(Date.parse(fingerprint.first_seen_at) + 7 * 24 * 3600 * 1000).toISOString(),
      correlation_hints: { provider: fingerprint.provider, model_fingerprint: fingerprint.fingerprint_id },
      policy_generated_effect: false,
    };
    return { findings: [finding], evidence };
  }

  private resetInheritedTrust(oldFingerprintId: string, next: ModelFingerprint): number {
    let resets = 0;
    for (const vector of [...this.trust.values()]) {
      if (vector.fingerprint_id !== oldFingerprintId) continue;
      resets += 1;
      // Historical identity is retained: the old vector stays, marked reduced.
      this.setTrust({ ...vector, state: "reduced" });
      this.setTrust({
        ...vector,
        fingerprint_id: next.fingerprint_id,
        model_snapshot: next.snapshot,
        state: "provisional",
        window: "no_eligible_runs_yet",
        dimensions: {
          ...vector.dimensions,
          // Task performance is earned per fingerprint, never inherited.
          task_success: 0,
          evaluation_quality: 0,
          security_compliance: 0,
          contract_validity: 0,
          tool_policy_compliance: 0,
          evidence_quality: 0,
        },
      });
    }
    return resets;
  }

  /** Consumes neuroforge.model_fingerprint.changed events from the ledger. */
  process(events: EventEnvelope[]): NodeOutput {
    const findings: Finding[] = [];
    const evidence: EvidenceRecord[] = [];
    for (const event of events) {
      if (event.event_type !== "neuroforge.model_fingerprint.changed") continue;
      const previous = event.payload["previous"] as ModelFingerprint | undefined;
      const current = event.payload["current"] as ModelFingerprint | undefined;
      if (!previous || !current) continue;
      this.observe(previous);
      const output = this.observe(current, event);
      findings.push(...output.findings);
      evidence.push(...output.evidence);
    }
    return { findings, evidence };
  }
}
