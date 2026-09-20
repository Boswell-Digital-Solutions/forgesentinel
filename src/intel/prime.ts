import { canonicalJson, clamp01 } from "../contracts/common.js";
import type { Finding } from "../contracts/finding.js";
import type { Incident, IncidentPriority, IncidentStatus, RecommendedAction } from "../contracts/incident.js";

/** Deterministic correlation rule (13 example), versioned like any detector. */
export interface CorrelationRule {
  correlation_id: string;
  version: string;
  /** Field name the correlated subject is stored under in the incident. */
  subject_field: "account_id" | "agent_fingerprint";
  window_ms: number;
  supporting: { finding_type: string; weight: number }[];
  independence: { minimum_groups: number };
  emit: { incident_type: string; playbook: string; title: string; required_authority: string[] };
}

export const ACCOUNT_COMPROMISE_COMPOUND: CorrelationRule = {
  correlation_id: "prime.account_compromise_compound",
  version: "1.0.0",
  subject_field: "account_id",
  window_ms: 2 * 3600 * 1000,
  supporting: [
    { finding_type: "cloud.new_api_key", weight: 0.25 },
    { finding_type: "cloud.new_region", weight: 0.2 },
    { finding_type: "cloud.new_device", weight: 0.15 },
    { finding_type: "cost.usage_change_extreme", weight: 0.3 },
    { finding_type: "cloud.login_failure_burst", weight: 0.25 },
  ],
  independence: { minimum_groups: 3 },
  emit: {
    incident_type: "compound.account_compromise",
    playbook: "PB-ACCOUNT-COMPROMISE-01",
    title: "Possible account compromise with rapid usage growth",
    required_authority: ["identity_service", "forge_command_operator"],
  },
};

export const DATA_EXFILTRATION_COMPOUND: CorrelationRule = {
  correlation_id: "prime.data_exfiltration_compound",
  version: "1.0.0",
  subject_field: "account_id",
  window_ms: 2 * 3600 * 1000,
  // finding_type values matched to SentinelDataNode's actual output
  // (src/intel/data.ts): no per-destination novelty or volume-based
  // bulk-export detector exists yet, so egress_anomaly stands in for scale.
  supporting: [
    { finding_type: "data.egress_anomaly", weight: 0.35 },
    { finding_type: "data.redaction_failure", weight: 0.3 },
    { finding_type: "data.cross_tenant_access", weight: 0.35 },
  ],
  independence: { minimum_groups: 2 },
  emit: {
    incident_type: "compound.data_exfiltration",
    playbook: "PB-DATA-EXFIL-01",
    title: "Possible data exfiltration: bulk movement with boundary pressure",
    required_authority: ["dataforge", "forge_command_operator"],
  },
};

export const AGENT_DRIFT_COMPOUND: CorrelationRule = {
  correlation_id: "prime.agent_drift_compound",
  version: "1.0.0",
  // SentinelAgentNode (src/intel/agent.ts) scopes findings by actor_id, not a
  // separate fingerprint identity; subject_field falls back to finding.subject.id
  // when no matching correlation_hints entry exists, so this still groups
  // correctly per agent.
  subject_field: "agent_fingerprint",
  window_ms: 2 * 3600 * 1000,
  // finding_type values matched to SentinelAgentNode's actual output: no loop
  // detector exists yet, and the denial-burst type is agent.denied_action_burst.
  supporting: [
    { finding_type: "agent.boundary_violation", weight: 0.4 },
    { finding_type: "agent.patch_burst", weight: 0.3 },
    { finding_type: "agent.denied_action_burst", weight: 0.3 },
  ],
  independence: { minimum_groups: 2 },
  emit: {
    incident_type: "compound.agent_drift",
    playbook: "PB-AGENT-DRIFT-01",
    title: "Agent drift: boundary pressure with abnormal activity",
    required_authority: ["yellowjacket", "forge_command_operator"],
  },
};

export interface ApprovedChangeWindow {
  tenant_id: string;
  /** Same subject shape a CorrelationRule keys on, so a window applies to any rule type — account-scoped or agent-fingerprint-scoped. */
  subject_field: "account_id" | "agent_fingerprint";
  subject_id: string;
  start: string;
  end: string;
  reason: string;
  approved_by: string;
}

/** One finding_type promoted to a standalone, confidence-capped incident when it never joins a compound rule (see `promoteSingles`). */
interface SingletonPromotionRule {
  finding_type: string;
  incident_type: string;
  title: string;
  required_authority: string[];
  missing_telemetry: string;
  briefing: (finding: Finding) => Incident["briefing"];
}

const SINGLETON_PROMOTIONS: SingletonPromotionRule[] = [
  {
    finding_type: "cost.usage_change_extreme",
    incident_type: "cost.usage_runaway",
    title: "Unusual usage growth on one account",
    required_authority: ["forge_command_operator"],
    missing_telemetry: "identity telemetry did not corroborate; treat as cost-only signal",
    briefing: (finding) => ({
      issue: finding.explanation.summary,
      where: `Account ${finding.subject.id} (tenant ${finding.tenant_id}).`,
      recommended_fix: "Monitor and request workload context from the account owner. No suspension is justified by usage alone.",
      why_now: "A single independent signal crossed the extreme-change threshold.",
    }),
  },
  // The CSSA watchdog finding_types (src/watchdog/decisions.ts,
  // authorizations.ts, outcomes.ts): shadow-only, all four detectors report
  // a single node's own boundary observation with nothing else to
  // corroborate it yet, so these stay a lone-signal watch, not a compound
  // CorrelationRule, until a second independent CSSA-sourced signal exists
  // to correlate against.
  {
    finding_type: "cssa.denial_streak",
    incident_type: "cssa.denial_streak_watch",
    title: "Repeated policy denials for one principal",
    required_authority: ["forge_command_operator"],
    missing_telemetry: "no corroborating signal from another node; treat as a decisions-only signal",
    briefing: (finding) => ({
      issue: finding.explanation.summary,
      where: `Principal ${finding.subject.id} (tenant ${finding.tenant_id}).`,
      recommended_fix: "Review the denied attempts with the principal's owning team. A single decisions-only signal does not justify containment by itself.",
      why_now: "A single independent signal crossed the denial-streak threshold.",
    }),
  },
  {
    finding_type: "cssa.quota_exceeded_burst",
    incident_type: "cssa.quota_exceeded_watch",
    title: "Repeated quota-exceeded decisions for one principal",
    required_authority: ["forge_command_operator"],
    missing_telemetry: "no corroborating signal from another node; treat as a decisions-only signal",
    briefing: (finding) => ({
      issue: finding.explanation.summary,
      where: `Principal ${finding.subject.id} (tenant ${finding.tenant_id}).`,
      recommended_fix: "Review usage against the principal's quota with the owning team. A single decisions-only signal does not justify containment by itself.",
      why_now: "A single independent signal crossed the quota-exceeded-burst threshold.",
    }),
  },
  {
    finding_type: "cssa.approval_pending_burst",
    incident_type: "cssa.approval_pending_watch",
    title: "Repeated approval-pending authorizations for one principal",
    required_authority: ["forge_command_operator"],
    missing_telemetry: "no corroborating signal from another node; treat as an authorizations-only signal",
    briefing: (finding) => ({
      issue: finding.explanation.summary,
      where: `Principal ${finding.subject.id} (tenant ${finding.tenant_id}).`,
      recommended_fix: "Review the pending approval queue with the principal's owning team. A single authorizations-only signal does not justify containment by itself.",
      why_now: "A single independent signal crossed the approval-pending-burst threshold.",
    }),
  },
  {
    finding_type: "cssa.execution_failure_burst",
    incident_type: "cssa.execution_failure_watch",
    title: "Repeated execution failures for one principal",
    required_authority: ["forge_command_operator"],
    missing_telemetry: "no corroborating signal from another node; treat as an outcomes-only signal",
    briefing: (finding) => ({
      issue: finding.explanation.summary,
      where: `Principal ${finding.subject.id} (tenant ${finding.tenant_id}).`,
      recommended_fix: "Review the failing executions with the principal's owning team. A single outcomes-only signal does not justify containment by itself.",
      why_now: "A single independent signal crossed the execution-failure-burst threshold.",
    }),
  },
];

/**
 * Sentinel Prime (03, SNT-200) — deterministic correlation MVP (ADR-018).
 * Prime correlates findings into incidents, tracks evidence independence,
 * preserves conflicts, and manages lifecycle. It executes nothing.
 */
export class SentinelPrime {
  readonly name = "sentinel-prime";
  readonly version = "1.0.0";

  private readonly findings: Finding[] = [];
  private readonly incidents = new Map<string, Incident>();
  private readonly changeWindows: ApprovedChangeWindow[] = [];
  private incidentCounter = 0;

  constructor(private readonly rules: CorrelationRule[] = [ACCOUNT_COMPROMISE_COMPOUND]) {}

  submitFindings(findings: Finding[]): void {
    this.findings.push(...findings);
  }

  registerChangeWindow(window: ApprovedChangeWindow): void {
    this.changeWindows.push(window);
  }

  allIncidents(): Incident[] {
    return [...this.incidents.values()];
  }

  /**
   * Independence accounting (03 anti-patterns, ADR-022): findings sharing an
   * evidence root collapse into one group, and groups whose findings are all
   * policy-generated effects are excluded — enforcement working is not fresh
   * proof the hypothesis was right.
   */
  private independenceGroups(findings: Finding[]): Map<string, Finding[]> {
    const groups = new Map<string, Finding[]>();
    for (const finding of findings) {
      for (const root of finding.source_event_roots) {
        const group = groups.get(root);
        if (group) group.push(finding);
        else groups.set(root, [finding]);
      }
    }
    for (const [root, members] of [...groups.entries()]) {
      if (members.every((finding) => finding.policy_generated_effect)) groups.delete(root);
    }
    return groups;
  }

  correlate(nowIso: string): Incident[] {
    const produced: Incident[] = [];
    for (const rule of this.rules) {
      produced.push(...this.applyRule(rule, nowIso));
    }
    produced.push(...this.promoteSingles(nowIso));
    return produced;
  }

  private applyRule(rule: CorrelationRule, nowIso: string): Incident[] {
    const produced: Incident[] = [];
    const supportingTypes = new Map(rule.supporting.map((entry) => [entry.finding_type, entry.weight]));
    const bySubject = new Map<string, Finding[]>();
    for (const finding of this.findings) {
      if (!supportingTypes.has(finding.finding_type)) continue;
      const subjectId = finding.correlation_hints[rule.subject_field] ?? finding.subject.id;
      const key = `${finding.tenant_id}/${subjectId}`;
      const group = bySubject.get(key);
      if (group) group.push(finding);
      else bySubject.set(key, [finding]);
    }

    for (const [subjectKey, candidates] of bySubject) {
      const windowEnd = Math.max(...candidates.map((finding) => Date.parse(finding.window.end)));
      const windowStart = windowEnd - rule.window_ms;
      const inWindow = candidates.filter((finding) => Date.parse(finding.window.end) >= windowStart);
      const groups = this.independenceGroups(inWindow);
      if (groups.size < rule.independence.minimum_groups) continue;

      const [tenantId, subjectId] = subjectKey.split("/") as [string, string];
      const incident = this.formIncident(rule, tenantId, subjectId, inWindow, groups, nowIso);
      const existing = this.findOpenDuplicate(incident);
      if (existing) {
        this.mergeIncident(existing, incident, nowIso);
      } else {
        this.incidents.set(incident.incident_id, incident);
        produced.push(incident);
      }
    }
    return produced;
  }

  private formIncident(
    rule: CorrelationRule,
    tenantId: string,
    subjectId: string,
    findings: Finding[],
    groups: Map<string, Finding[]>,
    nowIso: string,
  ): Incident {
    // Risk composition (05): noisy-OR over the strongest finding per
    // independent group, then evidence-quality adjustment. Impact, confidence,
    // and evidence quality remain separate dimensions (ADR-010).
    let survival = 1;
    let evidenceQualitySum = 0;
    for (const members of groups.values()) {
      const strongest = Math.max(...members.map((finding) => finding.risk.likelihood));
      survival *= 1 - strongest;
      evidenceQualitySum += Math.max(...members.map((finding) => finding.risk.evidence_quality));
    }
    const evidenceQuality = clamp01(evidenceQualitySum / groups.size);
    let likelihood = clamp01((1 - survival) * (0.9 + 0.1 * evidenceQuality));
    const impact = clamp01(Math.max(...findings.map((finding) => finding.risk.impact)) + 0.05 * (groups.size - 1));
    let confidence = clamp01(0.5 + 0.1 * groups.size);

    const conflicts: string[] = [];
    // Applies uniformly to any rule's subject shape (account- or
    // agent-fingerprint-scoped) — a change window is only ever meaningful
    // for the exact subject it was approved for.
    const overlapping = this.changeWindows.find(
      (window) =>
        window.tenant_id === tenantId &&
        window.subject_field === rule.subject_field &&
        window.subject_id === subjectId &&
        findings.some((finding) => Date.parse(finding.window.end) >= Date.parse(window.start) && Date.parse(finding.window.start) <= Date.parse(window.end)),
    );
    if (overlapping) {
      // Conflict preservation (03): the approved change window lowers risk but
      // stays visible — evidence is never deleted to make the story cleaner.
      conflicts.push(`approved_change_window:${overlapping.reason} (approved by ${overlapping.approved_by})`);
      likelihood = clamp01(likelihood * 0.4);
      confidence = clamp01(confidence * 0.7);
    }

    const policyEffectCount = findings.filter((finding) => finding.policy_generated_effect).length;
    if (policyEffectCount > 0) {
      conflicts.push(`${policyEffectCount} supporting finding(s) are policy-generated effects and were excluded from independence`);
    }

    const signals = [...new Set(findings.map((finding) => finding.finding_type))];
    const risk = { likelihood, impact, confidence, evidence_quality: evidenceQuality };
    const recommendedActions: RecommendedAction[] = [];
    let briefing: Incident["briefing"];

    switch (rule.emit.incident_type) {
      case "compound.data_exfiltration": {
        const destination = findings.map((finding) => finding.correlation_hints.destination).find((value) => value !== undefined);
        if (!overlapping) {
          if (destination) {
            recommendedActions.push({ action_type: "data.export_destination.block", target_id: destination, scope: "single_destination", reversible: true, approval: "single_operator" });
          }
          recommendedActions.push({ action_type: "data.redaction.require", target_id: subjectId, scope: "account_exports", reversible: true, approval: "policy_allowed" });
        }
        briefing = {
          issue: `Account ${subjectId} shows correlated data-movement signals: ${signals.join(", ")}.`,
          where: `Data exports for account ${subjectId} (tenant ${tenantId}).`,
          recommended_fix: overlapping
            ? "No containment recommended: activity overlaps an approved change window. Review and annotate."
            : destination
              ? `Temporarily block only destination "${destination}", require redaction on this account's exports, and preserve evidence without copying raw content.`
              : "Require redaction on this account's exports and preserve evidence without copying raw content.",
          why_now: `Independent weak signals (${groups.size} independent evidence groups) now form a correlated exfiltration pattern.`,
        };
        break;
      }
      case "compound.agent_drift": {
        const boundary = findings.find((finding) => finding.finding_type === "agent.boundary_violation");
        const runId = boundary?.correlation_hints.run_id;
        if (!overlapping) {
          if (runId) {
            recommendedActions.push({ action_type: "yellowjacket.run.stop", target_id: runId, scope: "single_run", reversible: false, approval: "policy_allowed" });
          }
          recommendedActions.push({ action_type: "yellowjacket.agent_version.quarantine", target_id: subjectId, scope: "single_agent_version", reversible: true, approval: "single_operator" });
        }
        briefing = {
          issue: `Agent version ${subjectId} shows correlated drift signals: ${signals.join(", ")}.`,
          where: `Agent version ${subjectId} (tenant ${tenantId}).`,
          recommended_fix: overlapping
            ? "No containment recommended: activity overlaps an approved change window. Review and annotate."
            : "Stop the active run through YellowJacket and quarantine exactly this agent version pending sandbox replay and SMITH review. Sentinel does not patch code.",
          why_now: `Independent weak signals (${groups.size} independent evidence groups) now form a correlated drift pattern.`,
        };
        break;
      }
      case "compound.account_compromise": {
        const keyFingerprint = findings.map((finding) => finding.correlation_hints.api_key_fingerprint).find((value) => value !== undefined);
        if (!overlapping) {
          if (keyFingerprint) {
            recommendedActions.push({ action_type: "identity.api_key.pause", target_id: keyFingerprint, scope: "single_key", reversible: true, approval: "single_operator" });
          }
          recommendedActions.push({ action_type: "identity.mfa.require", target_id: subjectId, scope: "account", reversible: true, approval: "policy_allowed" });
        }
        const cost = findings.find((finding) => finding.finding_type === "cost.usage_change_extreme");
        const ratioText = cost?.baseline && Number.isFinite(cost.baseline.change_ratio) ? `${cost.baseline.change_ratio.toFixed(0)}x` : "sharply";
        briefing = {
          issue: `Token usage increased ${ratioText} together with: ${signals.join(", ")}.`,
          where: `Cloud access for account ${subjectId} (tenant ${tenantId}).`,
          recommended_fix: overlapping
            ? "No containment recommended: activity overlaps an approved change window. Review and annotate."
            : "Pause only the new key, require MFA, and review the last 24 hours.",
          why_now: `Independent weak signals (${groups.size} independent evidence groups) now form a correlated compromise pattern.`,
        };
        break;
      }
      default:
        // Unrecognized incident_type (e.g. a new CorrelationRule registered
        // without a matching case here): recommend nothing rather than
        // silently reusing another incident type's actions and briefing.
        briefing = {
          issue: `Correlated signals for ${subjectId}: ${signals.join(", ")}.`,
          where: `Tenant ${tenantId}.`,
          recommended_fix: `No recommendation logic is registered for incident type "${rule.emit.incident_type}"; route to an operator for manual review.`,
          why_now: `Independent weak signals (${groups.size} independent evidence groups) now form a correlated pattern.`,
        };
    }

    this.incidentCounter += 1;
    return {
      incident_id: `inc_${String(this.incidentCounter).padStart(4, "0")}`,
      title: rule.emit.title,
      incident_type: rule.emit.incident_type,
      status: "open",
      priority: priorityOf(risk),
      origin: [...new Set(findings.map((finding) => finding.node.name))],
      subject: { tenant_id: tenantId, [rule.subject_field]: subjectId },
      risk,
      briefing,
      finding_ids: findings.map((finding) => finding.finding_id),
      evidence_ids: [...new Set(findings.flatMap((finding) => finding.evidence_ids))],
      independent_signal_count: groups.size,
      signals,
      required_authority: rule.emit.required_authority,
      recommended_actions: recommendedActions,
      playbook: rule.emit.playbook,
      conflicts,
      missing_telemetry: [],
      version: 1,
      created_at: nowIso,
      updated_at: nowIso,
      status_history: [{ status: "open", at: nowIso }],
    };
  }

  /**
   * Deterministic single-finding promotion: a strong finding of a registered
   * type becomes a monitor-priority incident on its own, but a single source
   * caps confidence — one signal alone never reaches suspension thresholds
   * (12 core scenarios). Extend `SINGLETON_PROMOTIONS` to wire a new
   * finding_type in rather than adding a second near-identical loop.
   */
  private promoteSingles(nowIso: string): Incident[] {
    const produced: Incident[] = [];
    const covered = new Set<string>();
    for (const incident of this.incidents.values()) {
      for (const findingId of incident.finding_ids) covered.add(findingId);
    }
    const rulesByFindingType = new Map(SINGLETON_PROMOTIONS.map((rule) => [rule.finding_type, rule]));
    for (const finding of this.findings) {
      const rule = rulesByFindingType.get(finding.finding_type);
      if (!rule) continue;
      if (finding.policy_generated_effect) continue;
      if (covered.has(finding.finding_id)) continue;
      const risk = {
        likelihood: finding.risk.likelihood,
        impact: finding.risk.impact,
        confidence: Math.min(finding.risk.confidence, 0.7),
        evidence_quality: finding.risk.evidence_quality,
      };
      this.incidentCounter += 1;
      const incident: Incident = {
        incident_id: `inc_${String(this.incidentCounter).padStart(4, "0")}`,
        title: rule.title,
        incident_type: rule.incident_type,
        status: "open",
        priority: priorityOf(risk) === "critical" ? "high" : priorityOf(risk),
        origin: [finding.node.name],
        subject: { tenant_id: finding.tenant_id, account_id: finding.subject.id },
        risk,
        briefing: rule.briefing(finding),
        finding_ids: [finding.finding_id],
        evidence_ids: finding.evidence_ids,
        independent_signal_count: 1,
        signals: [finding.finding_type],
        required_authority: rule.required_authority,
        recommended_actions: [],
        conflicts: [],
        missing_telemetry: [rule.missing_telemetry],
        version: 1,
        created_at: nowIso,
        updated_at: nowIso,
        status_history: [{ status: "open", at: nowIso }],
      };
      this.incidents.set(incident.incident_id, incident);
      produced.push(incident);
    }
    return produced;
  }

  private findOpenDuplicate(incident: Incident): Incident | undefined {
    return [...this.incidents.values()].find(
      (existing) =>
        existing.incident_type === incident.incident_type &&
        canonicalJson(existing.subject) === canonicalJson(incident.subject) &&
        !["resolved", "dismissed"].includes(existing.status),
    );
  }

  /** Duplicate merge preserves every finding and evidence reference (03). */
  private mergeIncident(existing: Incident, incoming: Incident, nowIso: string): void {
    existing.finding_ids = [...new Set([...existing.finding_ids, ...incoming.finding_ids])];
    existing.evidence_ids = [...new Set([...existing.evidence_ids, ...incoming.evidence_ids])];
    existing.signals = [...new Set([...existing.signals, ...incoming.signals])];
    existing.conflicts = [...new Set([...existing.conflicts, ...incoming.conflicts])];
    existing.independent_signal_count = Math.max(existing.independent_signal_count, incoming.independent_signal_count);
    existing.risk = incoming.risk;
    existing.priority = incoming.priority;
    existing.version += 1;
    existing.updated_at = nowIso;
  }

  transition(incidentId: string, status: IncidentStatus, actor: string, reason?: string): Incident {
    const incident = this.incidents.get(incidentId);
    if (!incident) throw new Error(`unknown incident ${incidentId}`);
    if (status === "dismissed" && !reason) throw new Error("dismissal requires a reason (09 lifecycle)");
    if (status === "reopened") incident.reopened_from = `${incident.incident_id}@v${incident.version}`;
    incident.status = status;
    incident.version += 1;
    incident.updated_at = new Date().toISOString();
    incident.status_history.push({ status, at: incident.updated_at, actor, ...(reason !== undefined ? { reason } : {}) });
    return incident;
  }
}

export function priorityOf(risk: { likelihood: number; impact: number; confidence: number }): IncidentPriority {
  if (risk.likelihood >= 0.8 && risk.impact >= 0.8 && risk.confidence >= 0.8) return "critical";
  if (risk.likelihood >= 0.7 && risk.impact >= 0.7) return "high";
  if (risk.likelihood >= 0.5 || risk.impact >= 0.7) return "medium";
  return "low";
}
