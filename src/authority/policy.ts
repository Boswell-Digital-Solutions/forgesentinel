import type { Incident } from "../contracts/incident.js";
import type { AllowedAction, ApprovalLevel, DeniedAction, PolicyDecision, PolicyDefinition, PolicyResult, PolicyRuleCondition } from "../contracts/policy.js";

/**
 * Actions Sentinel can never authorize regardless of policy content
 * (01 doctrine, 06 always_deny). These are enforced even when an individual
 * policy definition forgets to list them.
 */
export const GLOBAL_ALWAYS_DENY: Record<string, string> = {
  "license.permanent_revoke": "Sentinel cannot authorize irreversible commercial revocation.",
  "customer_data.delete": "Sentinel cannot authorize customer data deletion.",
  "source_code.direct_patch": "Code mutation routes through SMITH governance, never Sentinel (ADR-007).",
  "agent.patch.apply": "Sentinel cannot apply or promote patches; repair routes through SMITH (ADR-007).",
  "agent.patch.promote": "Sentinel cannot apply or promote patches; repair routes through SMITH (ADR-007).",
  "smith.proposal.approve": "Mutation approval belongs to SMITH governance, not Sentinel.",
  "billing.subscription.cancel": "Billing truth belongs to the Stripe-verified billing service (ADR-013).",
  "account.terminate": "Permanent customer action requires the authorized business owner.",
};

/** sentinel_account_compromise v3.1.0 — transcribed from 06 example policy. */
export const ACCOUNT_COMPROMISE_POLICY: PolicyDefinition = {
  policy_id: "sentinel_account_compromise",
  version: "3.1.0",
  match: { incident_type: "compound.account_compromise", environment: "production" },
  rules: [
    {
      when: {
        likelihood_gte: 0.8,
        confidence_gte: 0.75,
        evidence_quality_gte: 0.85,
        independent_signal_count_gte: 3,
        includes_signal: ["cloud.new_api_key", "cloud.new_region"],
      },
      allow: [
        { action: "identity.api_key.pause", scope: "single_key", approval: "single_operator", reversible: true, expires_in_seconds: 900 },
        { action: "identity.mfa.require", scope: "account", approval: "policy_allowed", reversible: true, expires_in_seconds: 900 },
      ],
    },
    {
      when: { impact_gte: 0.9, active_data_exfiltration: true, evidence_quality_gte: 0.95 },
      allow: [{ action: "identity.session.revoke", scope: "affected_sessions", approval: "emergency_policy", reversible: false, expires_in_seconds: 300 }],
    },
  ],
  always_deny: ["license.permanent_revoke", "customer_data.delete", "source_code.direct_patch"],
  cooldown_seconds: 600,
};

/** sentinel_agent_drift v1.0.0 — Wave 5 playbook PB-AGENT-DRIFT-01 (03, 12). */
export const AGENT_DRIFT_POLICY: PolicyDefinition = {
  policy_id: "sentinel_agent_drift",
  version: "1.0.0",
  match: { incident_type: "compound.agent_drift", environment: "production" },
  rules: [
    {
      when: {
        likelihood_gte: 0.7,
        confidence_gte: 0.7,
        evidence_quality_gte: 0.8,
        independent_signal_count_gte: 2,
        includes_signal: ["agent.boundary_violation"],
      },
      allow: [
        // Stopping one run is a Class 2 guard: narrow, pre-approved.
        { action: "yellowjacket.run.stop", scope: "single_run", approval: "policy_allowed", reversible: false, expires_in_seconds: 300 },
        // Quarantining an exact version is Class 3: operator approved.
        { action: "yellowjacket.agent_version.quarantine", scope: "single_agent_version", approval: "single_operator", reversible: true, expires_in_seconds: 900 },
      ],
    },
  ],
  always_deny: ["agent.patch.apply", "agent.patch.promote", "source_code.direct_patch", "smith.proposal.approve"],
  cooldown_seconds: 600,
};

/** sentinel_data_exfiltration v1.0.0 — Wave 8 playbook PB-DATA-EXFIL-01 (03, 10). */
export const DATA_EXFILTRATION_POLICY: PolicyDefinition = {
  policy_id: "sentinel_data_exfiltration",
  version: "1.0.0",
  match: { incident_type: "compound.data_exfiltration", environment: "production" },
  rules: [
    {
      // Lower likelihood gate than identity containment: the allowed actions
      // are a reversible single-destination block behind operator approval
      // and a redaction requirement — smallest scope, lowest blast radius.
      when: {
        likelihood_gte: 0.65,
        confidence_gte: 0.65,
        evidence_quality_gte: 0.8,
        independent_signal_count_gte: 2,
      },
      allow: [
        { action: "data.export_destination.block", scope: "single_destination", approval: "single_operator", reversible: true, expires_in_seconds: 900 },
        { action: "data.redaction.require", scope: "account_exports", approval: "policy_allowed", reversible: true, expires_in_seconds: 900 },
      ],
    },
  ],
  always_deny: ["customer_data.delete", "license.permanent_revoke", "source_code.direct_patch"],
  cooldown_seconds: 600,
};

export interface PolicyContext {
  environment: string;
  active_data_exfiltration?: boolean;
}

function conditionMatches(condition: PolicyRuleCondition, incident: Incident, context: PolicyContext): boolean {
  if (condition.likelihood_gte !== undefined && incident.risk.likelihood < condition.likelihood_gte) return false;
  if (condition.impact_gte !== undefined && incident.risk.impact < condition.impact_gte) return false;
  if (condition.confidence_gte !== undefined && incident.risk.confidence < condition.confidence_gte) return false;
  if (condition.evidence_quality_gte !== undefined && incident.risk.evidence_quality < condition.evidence_quality_gte) return false;
  if (condition.independent_signal_count_gte !== undefined && incident.independent_signal_count < condition.independent_signal_count_gte) return false;
  if (condition.includes_signal && !condition.includes_signal.every((signal) => incident.signals.includes(signal))) return false;
  if (condition.active_data_exfiltration !== undefined && (context.active_data_exfiltration ?? false) !== condition.active_data_exfiltration) return false;
  return true;
}

/**
 * Policy Decision Point (02, SNT-210). Deterministic, versioned, and owned
 * outside node code. Sentinel models may propose policy text but cannot
 * deploy it (ADR-017).
 */
export class PolicyService {
  private readonly policies: PolicyDefinition[] = [];
  private readonly decisions: PolicyDecision[] = [];
  private readonly lastActionAt = new Map<string, number>();
  private decisionCounter = 0;

  register(policy: PolicyDefinition): void {
    this.policies.push(policy);
  }

  allDecisions(): readonly PolicyDecision[] {
    return this.decisions;
  }

  recordExecutedAction(actionType: string, targetId: string, atIso: string): void {
    this.lastActionAt.set(`${actionType}:${targetId}`, Date.parse(atIso));
  }

  evaluate(incident: Incident, context: PolicyContext, nowIso: string): PolicyDecision {
    this.decisionCounter += 1;
    const decisionId = `pdec_${String(this.decisionCounter).padStart(4, "0")}`;
    const policy = this.policies.find(
      (candidate) => candidate.match.incident_type === incident.incident_type && candidate.match.environment === context.environment,
    );

    const denied: DeniedAction[] = [];
    for (const action of incident.recommended_actions) {
      const globalReason = GLOBAL_ALWAYS_DENY[action.action_type];
      const policyDenied = policy?.always_deny.includes(action.action_type);
      if (globalReason || policyDenied) {
        denied.push({ action_type: action.action_type, reason: globalReason ?? "denied by policy always_deny list" });
      }
    }

    if (!policy) {
      return this.record({
        policy_decision_id: decisionId,
        incident_id: incident.incident_id,
        policy_id: "none_matched",
        policy_version: "0.0.0",
        result: "RECOMMEND_ONLY",
        allowed_actions: [],
        denied_actions: denied,
        evaluated_at: nowIso,
      });
    }

    const allowed: AllowedAction[] = [];
    for (const rule of policy.rules) {
      if (!conditionMatches(rule.when, incident, context)) continue;
      for (const entry of rule.allow) {
        if (GLOBAL_ALWAYS_DENY[entry.action] || policy.always_deny.includes(entry.action)) continue;
        const cooldownKey = `${entry.action}:${incident.subject["account_id"] ?? incident.subject.tenant_id}`;
        const lastAt = this.lastActionAt.get(cooldownKey);
        if (lastAt !== undefined && Date.parse(nowIso) - lastAt < policy.cooldown_seconds * 1000) {
          denied.push({ action_type: entry.action, reason: `cooldown: action executed less than ${policy.cooldown_seconds}s ago (06 hysteresis)` });
          continue;
        }
        allowed.push({
          action_type: entry.action,
          scope: entry.scope,
          expires_in_seconds: entry.expires_in_seconds ?? 900,
          requires_approval: entry.approval,
          reversible: entry.reversible,
        });
      }
    }

    return this.record({
      policy_decision_id: decisionId,
      incident_id: incident.incident_id,
      policy_id: policy.policy_id,
      policy_version: policy.version,
      result: resultFor(allowed),
      allowed_actions: allowed,
      denied_actions: denied,
      evaluated_at: nowIso,
    });
  }

  private record(decision: PolicyDecision): PolicyDecision {
    this.decisions.push(decision);
    return decision;
  }
}

function resultFor(allowed: AllowedAction[]): PolicyResult {
  if (allowed.length === 0) return "RECOMMEND_ONLY";
  const levels = new Set<ApprovalLevel>(allowed.map((action) => action.requires_approval));
  if (levels.has("emergency_policy")) return "ALLOW_EMERGENCY_CONTAINMENT";
  if ([...levels].some((level) => level !== "policy_allowed" && level !== "emergency_policy")) return "REQUEST_OPERATOR";
  return "ALLOW_BOUNDED_ACTION";
}
