import type { ActionReceipt } from "../contracts/receipt.js";
import { CapabilityValidatedAuthority, type PresentedAction } from "./authority-base.js";

/**
 * Identity authority adapter (02 authority adapters). The identity service —
 * not Sentinel — owns key/session/MFA state. It executes only the exact
 * approved action presented with a valid capability, and every attempt
 * (success, rejection, rollback) yields a receipt.
 */
export class IdentityAuthority extends CapabilityValidatedAuthority {
  readonly audience = "identity-service";
  private readonly keyStates = new Map<string, "active" | "paused">();
  private readonly mfaRequired = new Set<string>();

  registerKey(keyFingerprint: string): void {
    this.keyStates.set(keyFingerprint, "active");
  }

  keyState(keyFingerprint: string): "active" | "paused" | undefined {
    return this.keyStates.get(keyFingerprint);
  }

  mfaIsRequired(accountId: string): boolean {
    return this.mfaRequired.has(accountId);
  }

  protected applyAction(presented: PresentedAction) {
    const before: Record<string, unknown> = {};
    const after: Record<string, unknown> = {};
    let result: "success" | "failure" = "success";
    let rollback_action: string | undefined;

    switch (presented.action) {
      case "identity.api_key.pause": {
        const state = this.keyStates.get(presented.target);
        if (state === undefined) {
          result = "failure";
        } else {
          before["key_state"] = state;
          this.keyStates.set(presented.target, "paused");
          after["key_state"] = "paused";
          rollback_action = "identity.api_key.resume";
        }
        break;
      }
      case "identity.api_key.resume": {
        const state = this.keyStates.get(presented.target);
        if (state === undefined) {
          result = "failure";
        } else {
          before["key_state"] = state;
          this.keyStates.set(presented.target, "active");
          after["key_state"] = "active";
        }
        break;
      }
      case "identity.mfa.require": {
        before["mfa_required"] = this.mfaRequired.has(presented.target);
        this.mfaRequired.add(presented.target);
        after["mfa_required"] = true;
        rollback_action = "identity.mfa.release";
        break;
      }
      default:
        result = "failure";
    }

    return { result, before, after, rollback_action };
  }

  /** Rollback is itself a receipted action referencing what it reverses. */
  rollback(original: ActionReceipt, nowIso: string): ActionReceipt {
    if (!original.rollback.supported || !original.rollback.action_type) {
      throw new Error(`receipt ${original.receipt_id} does not support rollback`);
    }
    const action = original.rollback.action_type;
    const target = original.action.target_id;
    const before: Record<string, unknown> = {};
    const after: Record<string, unknown> = {};
    let result: "success" | "failure" = "success";

    if (action === "identity.api_key.resume") {
      const state = this.keyStates.get(target);
      if (state === undefined) {
        result = "failure";
      } else {
        before["key_state"] = state;
        this.keyStates.set(target, "active");
        after["key_state"] = "active";
      }
    } else if (action === "identity.mfa.release") {
      before["mfa_required"] = this.mfaRequired.has(target);
      this.mfaRequired.delete(target);
      after["mfa_required"] = false;
    } else {
      result = "failure";
    }

    return this.receipts.create(
      {
        receipt_type: "sentinel.rollback",
        incident_id: original.incident_id,
        decision: original.decision,
        action: {
          requested: action,
          executed: result === "success" ? action : null,
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
