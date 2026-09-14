import type { CapabilityToken } from "../contracts/capability.js";
import type { ActionReceipt } from "../contracts/receipt.js";
import type { CapabilityService } from "./capability.js";
import type { ReceiptService } from "./receipts.js";

/**
 * YellowJacket authority adapter (02 authority adapters): runtime/tool
 * admission and emergency stop. Sentinel recommends; YellowJacket executes
 * the exact capability-approved action. Quarantine targets one exact agent
 * version (fingerprint), other versions are untouched, and the re-enable
 * path is a receipted rollback (Wave 5 exit gate).
 */
export class YellowJacketAuthority {
  readonly audience = "yellowjacket";
  private readonly runs = new Map<string, "running" | "stopped">();
  private readonly agentVersions = new Map<string, "active" | "quarantined">();

  constructor(
    private readonly capabilities: CapabilityService,
    private readonly receipts: ReceiptService,
  ) {}

  registerRun(runId: string): void {
    this.runs.set(runId, "running");
  }

  registerAgentVersion(fingerprint: string): void {
    this.agentVersions.set(fingerprint, "active");
  }

  runState(runId: string): "running" | "stopped" | undefined {
    return this.runs.get(runId);
  }

  agentVersionState(fingerprint: string): "active" | "quarantined" | undefined {
    return this.agentVersions.get(fingerprint);
  }

  execute(token: CapabilityToken, presented: { action: string; target: string; scope: string }, nowIso: string): ActionReceipt {
    const validation = this.capabilities.validate(token, { audience: this.audience, ...presented }, nowIso);
    const decision = {
      decision_id: token.claims.policy_decision_id,
      policy_id: "sentinel_agent_drift",
      policy_version: "1.0.0",
      result: "ALLOW_BOUNDED_ACTION",
      approver: { type: "operator", id: "via_capability" },
    };

    if (!validation.ok) {
      return this.receipts.create(
        {
          receipt_type: "sentinel.action",
          incident_id: token.claims.incident_id,
          decision,
          action: {
            requested: presented.action,
            executed: null,
            target_id: presented.target,
            scope: presented.scope,
            result: "rejected",
            failure_reason: validation.issues.map((issue) => `${issue.code}: ${issue.message}`).join("; "),
          },
          rollback: { supported: false },
          control_lineage: { policy_decision_id: token.claims.policy_decision_id },
        },
        nowIso,
      );
    }

    const before: Record<string, unknown> = {};
    const after: Record<string, unknown> = {};
    let result: "success" | "failure" = "success";
    let rollbackAction: string | undefined;

    switch (presented.action) {
      case "yellowjacket.run.stop": {
        const state = this.runs.get(presented.target);
        if (state === undefined) {
          result = "failure";
        } else {
          before["run_state"] = state;
          this.runs.set(presented.target, "stopped");
          after["run_state"] = "stopped";
        }
        break;
      }
      case "yellowjacket.agent_version.quarantine": {
        const state = this.agentVersions.get(presented.target);
        if (state === undefined) {
          result = "failure";
        } else {
          before["agent_version_state"] = state;
          this.agentVersions.set(presented.target, "quarantined");
          after["agent_version_state"] = "quarantined";
          rollbackAction = "yellowjacket.agent_version.reenable";
        }
        break;
      }
      default:
        result = "failure";
    }

    return this.receipts.create(
      {
        receipt_type: "sentinel.action",
        incident_id: token.claims.incident_id,
        decision,
        action: {
          requested: presented.action,
          executed: result === "success" ? presented.action : null,
          target_id: presented.target,
          scope: presented.scope,
          result,
          ...(result === "failure" ? { failure_reason: "target unknown or action unsupported by this authority" } : {}),
        },
        before_state: before,
        after_state: after,
        rollback: rollbackAction ? { supported: true, action_type: rollbackAction } : { supported: false },
        control_lineage: { policy_decision_id: token.claims.policy_decision_id },
      },
      nowIso,
    );
  }

  /** Re-enable path: receipted rollback of a quarantine. */
  rollback(original: ActionReceipt, nowIso: string): ActionReceipt {
    if (!original.rollback.supported || original.rollback.action_type !== "yellowjacket.agent_version.reenable") {
      throw new Error(`receipt ${original.receipt_id} does not support rollback`);
    }
    const target = original.action.target_id;
    const before: Record<string, unknown> = {};
    const after: Record<string, unknown> = {};
    let result: "success" | "failure" = "success";
    const state = this.agentVersions.get(target);
    if (state === undefined) {
      result = "failure";
    } else {
      before["agent_version_state"] = state;
      this.agentVersions.set(target, "active");
      after["agent_version_state"] = "active";
    }
    return this.receipts.create(
      {
        receipt_type: "sentinel.rollback",
        incident_id: original.incident_id,
        decision: original.decision,
        action: {
          requested: "yellowjacket.agent_version.reenable",
          executed: result === "success" ? "yellowjacket.agent_version.reenable" : null,
          target_id: target,
          scope: original.action.scope,
          result: result === "success" ? "rolled_back" : "failure",
        },
        before_state: before,
        after_state: after,
        rollback: { supported: false, rollback_of: original.receipt_id },
        ...(original.control_lineage !== undefined ? { control_lineage: original.control_lineage } : {}),
      },
      nowIso,
    );
  }
}
