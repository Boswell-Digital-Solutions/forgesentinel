import { clamp01 } from "../contracts/common.js";
import type { EventEnvelope } from "../contracts/envelope.js";
import type { EvidenceRecord } from "../contracts/evidence.js";
import type { Finding } from "../contracts/finding.js";
import { eventEvidence, featureEvidence, FeatureService } from "./features.js";
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

    const patchBurst = this.burst(sorted, learnCutoff, {
      eventType: "agent.patch.applied",
      featureRef: PATCHES_PER_HOUR,
      threshold: this.config.patch_burst_count,
      findingType: "agent.patch_burst",
      actionClass: "REQUEST_OPERATOR",
      playbook: "PB-AGENT-PATCHBURST-01",
      unit: "patches/hour",
      summarize: (count) => `${count} patches applied by this agent within an hour — far above a normal task.`,
    });
    findings.push(...patchBurst.findings);
    evidence.push(...patchBurst.evidence);

    const denialBurst = this.burst(sorted, learnCutoff, {
      eventType: "agent.permission.denied",
      featureRef: DENIALS_PER_15M,
      threshold: this.config.denial_burst_count,
      findingType: "agent.denied_action_burst",
      actionClass: "RECOMMEND_ONLY",
      playbook: "PB-AGENT-DENIED-01",
      unit: "denials/15m",
      summarize: (count) => `${count} denied permission attempts by this agent within 15 minutes.`,
    });
    findings.push(...denialBurst.findings);
    evidence.push(...denialBurst.evidence);

    return { findings, evidence };
  }

  private burst(
    events: EventEnvelope[],
    learnCutoff: number,
    spec: {
      eventType: string;
      featureRef: string;
      threshold: number;
      findingType: string;
      actionClass: "REQUEST_OPERATOR" | "RECOMMEND_ONLY";
      playbook: string;
      unit: string;
      summarize: (count: number) => string;
    },
  ): NodeOutput {
    const findings: Finding[] = [];
    const evidence: EvidenceRecord[] = [];
    const relevant = events.filter((event) => event.event_type === spec.eventType && Date.parse(event.occurred_at) >= learnCutoff && event.tenant?.tenant_id);
    const byAgent = new Map<string, EventEnvelope[]>();
    for (const event of relevant) {
      const key = `${event.tenant?.tenant_id}|${event.actor.actor_id}`;
      byAgent.set(key, [...(byAgent.get(key) ?? []), event]);
    }
    for (const [agentKey, agentEvents] of byAgent) {
      const last = agentEvents[agentEvents.length - 1];
      if (!last) continue;
      const [tenantId, actorId] = agentKey.split("|") as [string, string];
      const accountId = last.tenant?.account_id ?? tenantId;
      const scopeKey = `tenant_id=${tenantId}|actor_id=${actorId}`;
      const window = this.features.evaluateWindow(spec.featureRef, scopeKey, last.occurred_at);
      if (window.value < spec.threshold) continue;
      const record = featureEvidence(window, spec.unit, { tenant_id: tenantId, account_id: accountId }, false);
      evidence.push(record);
      findings.push({
        finding_id: this.nextFindingId(),
        finding_type: spec.findingType,
        node: { name: this.name, version: this.version },
        subject: { type: "agent", id: actorId },
        tenant_id: tenantId,
        window: window.window,
        risk: { likelihood: clamp01(0.4 + 0.04 * window.value), impact: 0.55, confidence: 0.7, evidence_quality: record.quality.score },
        evidence_ids: [record.evidence_id],
        source_event_roots: [record.source_event_root],
        explanation: {
          summary: spec.summarize(window.value),
          top_factors: [{ factor: spec.findingType, contribution: 1 }],
          uncertainties: ["A large but legitimate task (e.g. a wide refactor) can resemble a burst; verify the run."],
          observed: window.value,
          expected: 0,
        },
        recommendation: { action_class: spec.actionClass, playbook: spec.playbook },
        expires_at: new Date(Date.parse(last.occurred_at) + 24 * 3600 * 1000).toISOString(),
        correlation_hints: { account_id: accountId, actor_id: actorId },
        policy_generated_effect: last.control_lineage?.policy_generated_effect === true,
      });
    }
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
