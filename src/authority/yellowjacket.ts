import { CapabilityValidatedAuthority, type PresentedAction } from "./authority-base.js";

/**
 * YellowJacket authority adapter (02 authority adapters): runtime/tool
 * admission and emergency stop. Sentinel recommends; YellowJacket executes
 * the exact capability-approved action. Quarantine targets one exact agent
 * version (fingerprint), other versions are untouched, and the re-enable
 * path is a receipted rollback (Wave 5 exit gate).
 */
export class YellowJacketAuthority extends CapabilityValidatedAuthority {
  readonly audience = "yellowjacket";
  private readonly runs = new Map<string, "running" | "stopped">();
  private readonly agentVersions = new Map<string, "active" | "quarantined">();

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

  protected applyAction(presented: PresentedAction) {
    const before: Record<string, unknown> = {};
    const after: Record<string, unknown> = {};
    let result: "success" | "failure" = "success";
    let rollback_action: string | undefined;

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
          rollback_action = "yellowjacket.agent_version.reenable";
        }
        break;
      }
      default:
        result = "failure";
    }

    return { result, before, after, rollback_action };
  }

  /** Re-enable path: applies a validated rollback of a quarantine (capability-checked by the base class). */
  protected applyRollback(action: string, target: string) {
    const before: Record<string, unknown> = {};
    const after: Record<string, unknown> = {};
    let result: "success" | "failure" = "success";

    if (action === "yellowjacket.agent_version.reenable") {
      const state = this.agentVersions.get(target);
      if (state === undefined) {
        result = "failure";
      } else {
        before["agent_version_state"] = state;
        this.agentVersions.set(target, "active");
        after["agent_version_state"] = "active";
      }
    } else {
      result = "failure";
    }

    return { result, before, after };
  }
}
