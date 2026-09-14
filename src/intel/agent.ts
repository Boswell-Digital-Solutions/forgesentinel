import { clamp01 } from "../contracts/common.js";
import type { EventEnvelope } from "../contracts/envelope.js";
import type { EvidenceRecord } from "../contracts/evidence.js";
import type { Finding } from "../contracts/finding.js";
import { eventEvidence, FeatureService, thresholdBurst } from "./features.js";
import type { NodeOutput } from "./cost.js";

export const PATCHES_PER_HOUR = "agent.patches_per_hour@1.0.0";
export const DENIALS_PER_15M = "agent.denials_per_15m@1.0.0";

/**
 * Actions Sentinel-Agent may never recommend (03): it observes and recommends
 * bounded responses, but never applies or promotes a patch or mutates code.
 * Remediation routes through Centipede -> Forge_Command -> SMITH -> YellowJacket.
 */
export const AGENT_FORBIDDEN_ACTIONS = [
  "agent.patch.apply",
  "agent.patch.promote",
  "code.mutate",
  "release.promote",
] as const;

export interface AgentNodeConfig {
  patch_burst_count: number;
  denial_burst_count: number;
}

export const DEFAULT_AGENT_CONFIG: AgentNodeConfig = {
  patch_burst_count: 10,
  denial_burst_count: 5,
};

/**
 * Sentinel-Agent (03, SNT-120). Shadow mode: detects unsafe, looping, or
 * compromised agent behavior and recommends bounded responses (stop a run via
 * YellowJacket, move the exact agent version to shadow, request SMITH review).
 * It holds no authority credentials and never patches or promotes code.
 */
export class SentinelAgentNode {
  readonly name = "sentinel-agent";
  readonly version = "1.0.0";
  readonly shadow = true;
  private findingCounter = 0;

  constructor(
    private readonly features: FeatureService,
    private readonly config: AgentNodeConfig = DEFAULT_AGENT_CONFIG,
  ) {}

  private nextFindingId(): string {
    this.findingCounter += 1;
    return `fnd_agent_${String(this.findingCounter).padStart(5, "0")}`;
  }

  /**
   * Processes agent events in time order. Events older than
   * `noveltyLearnedBefore` only train feature windows; later events can emit.
   */
  process(events: EventEnvelope[], noveltyLearnedBefore: string): NodeOutput {
    const findings: Finding[] = [];
    const evidence: EvidenceRecord[] = [];
    const learnCutoff = Date.parse(noveltyLearnedBefore);
    const sorted = [...events].sort((a, b) => Date.parse(a.occurred_at) - Date.parse(b.occurred_at));

    // Repository/permission boundary violations: one finding per post-cutoff event.
    for (const event of sorted) {
      if (event.event_type !== "agent.boundary.violated") continue;
      if (Date.parse(event.occurred_at) < learnCutoff) continue;
      const tenantId = event.tenant?.tenant_id;
      if (!tenantId) continue;
      const accountId = event.tenant?.account_id ?? tenantId;
      const record = eventEvidence(event, { tenant_id: tenantId, account_id: accountId });
      evidence.push(record);
      findings.push(this.boundaryFinding(event, record, tenantId, accountId));
    }

    const patchBurst = thresholdBurst(this.features, {
      events: sorted,
      learnCutoff,
      eventType: "agent.patch.applied",
      featureRef: PATCHES_PER_HOUR,
      threshold: this.config.patch_burst_count,
      groupField: "actor_id",
      unit: "patches/hour",
      nextFindingId: () => this.nextFindingId(),
      node: { name: this.name, version: this.version },
      findingType: "agent.patch_burst",
      actionClass: "REQUEST_OPERATOR",
      playbook: "PB-AGENT-PATCHBURST-01",
      likelihood: (count) => clamp01(0.4 + 0.04 * count),
      impact: 0.55,
      confidence: 0.7,
      summarize: (count) => `${count} patches applied by this agent within an hour — far above a normal task.`,
      subject: (_tenantId, actorId) => ({ type: "agent", id: actorId }),
      correlationHints: (tenantId, actorId, last) => ({ account_id: last.tenant?.account_id ?? tenantId, actor_id: actorId }),
    });
    findings.push(...patchBurst.findings);
    evidence.push(...patchBurst.evidence);

    const denialBurst = thresholdBurst(this.features, {
      events: sorted,
      learnCutoff,
      eventType: "agent.permission.denied",
      featureRef: DENIALS_PER_15M,
      threshold: this.config.denial_burst_count,
      groupField: "actor_id",
      unit: "denials/15m",
      nextFindingId: () => this.nextFindingId(),
      node: { name: this.name, version: this.version },
      findingType: "agent.denied_action_burst",
      actionClass: "RECOMMEND_ONLY",
      playbook: "PB-AGENT-DENIED-01",
      likelihood: (count) => clamp01(0.4 + 0.04 * count),
      impact: 0.55,
      confidence: 0.7,
      summarize: (count) => `${count} denied permission attempts by this agent within 15 minutes.`,
      subject: (_tenantId, actorId) => ({ type: "agent", id: actorId }),
      correlationHints: (tenantId, actorId, last) => ({ account_id: last.tenant?.account_id ?? tenantId, actor_id: actorId }),
    });
    findings.push(...denialBurst.findings);
    evidence.push(...denialBurst.evidence);

    return { findings, evidence };
  }

  private boundaryFinding(event: EventEnvelope, record: EvidenceRecord, tenantId: string, accountId: string): Finding {
    const actorId = event.actor.actor_id;
    const boundary = typeof event.payload["boundary"] === "string" ? (event.payload["boundary"] as string) : undefined;
    return {
      finding_id: this.nextFindingId(),
      finding_type: "agent.boundary_violation",
      node: { name: this.name, version: this.version },
      subject: { type: "agent", id: actorId },
      tenant_id: tenantId,
      window: { start: event.occurred_at, end: event.occurred_at },
      risk: { likelihood: 0.6, impact: 0.6, confidence: 0.75, evidence_quality: record.quality.score },
      evidence_ids: [record.evidence_id],
      source_event_roots: [record.source_event_root],
      explanation: {
        summary: `Agent "${actorId}" crossed a repository/permission boundary${boundary ? ` (${boundary})` : ""}.`,
        top_factors: [{ factor: "repository_boundary_violation", contribution: 1 }],
        uncertainties: ["A misconfigured boundary or an approved exception can produce a benign violation event."],
      },
      recommendation: { action_class: "REQUEST_OPERATOR", playbook: "PB-AGENT-BOUNDARY-01" },
      expires_at: new Date(Date.parse(event.occurred_at) + 24 * 3600 * 1000).toISOString(),
      correlation_hints: { account_id: accountId, actor_id: actorId, ...(event.correlation?.run_id !== undefined ? { run_id: event.correlation.run_id } : {}) },
      policy_generated_effect: event.control_lineage?.policy_generated_effect === true,
    };
  }
}
