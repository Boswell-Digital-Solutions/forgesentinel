import type { CapabilityToken } from "../contracts/capability.js";
import type { ActionReceipt } from "../contracts/receipt.js";
import type { CapabilityService } from "./capability.js";
import type { PolicyService } from "./policy.js";
import type { ReceiptService } from "./receipts.js";

export interface PresentedAction {
  action: string;
  target: string;
  scope: string;
}

interface AppliedAction {
  result: "success" | "failure";
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  rollback_action: string | undefined;
}

interface AppliedRollback {
  result: "success" | "failure";
  before: Record<string, unknown>;
  after: Record<string, unknown>;
}

/**
 * Shared skeleton for capability-validated authority adapters (02): validate
 * the presented action against its capability, apply exactly the approved
 * state transition, and receipt every attempt — success, rejection, or
 * rollback. Concrete authorities (identity, YellowJacket, ...) supply only
 * their own state and the `applyAction`/`applyRollback` transitions; this
 * base class owns the parts that must never drift between them: receipt
 * shape, and recording every successful action with PolicyService so cooldown
 * hysteresis (06) has something real to check against.
 */
export abstract class CapabilityValidatedAuthority {
  abstract readonly audience: string;

  constructor(
    protected readonly capabilities: CapabilityService,
    protected readonly receipts: ReceiptService,
    protected readonly policy: PolicyService,
  ) {}

  /** Applies the presented action's state transition; never receipts directly. */
  protected abstract applyAction(presented: PresentedAction): AppliedAction;

  /** Applies a rollback's state transition once its capability has validated; never receipts directly. */
  protected abstract applyRollback(action: string, target: string): AppliedRollback;

  private decisionFor(token: CapabilityToken): ActionReceipt["decision"] {
    return {
      decision_id: token.claims.policy_decision_id,
      policy_id: token.claims.policy_id,
      policy_version: token.claims.policy_version,
      result: "ALLOW_BOUNDED_ACTION",
      approver: { type: token.claims.approver_type, id: token.claims.approver_id },
    };
  }

  execute(token: CapabilityToken, presented: PresentedAction, nowIso: string): ActionReceipt {
    const validation = this.capabilities.validate(token, { audience: this.audience, ...presented }, nowIso);
    const decision = this.decisionFor(token);

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

    const { result, before, after, rollback_action } = this.applyAction(presented);
    if (result === "success") {
      // Cooldown hysteresis (06) keys off this call; nothing else records it.
      this.policy.recordExecutedAction(presented.action, presented.target, nowIso);
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
        rollback: rollback_action ? { supported: true, action_type: rollback_action } : { supported: false },
        control_lineage: { policy_decision_id: token.claims.policy_decision_id },
      },
      nowIso,
    );
  }

  /**
   * Rollback is itself a capability-validated action (finding 2026-09-19:
   * the original receipt is caller-supplied and TypeScript types don't exist
   * at runtime, so it must never be trusted on its own — a fresh capability,
   * scoped to the receipt's own declared rollback action/target, is required
   * exactly as `execute()` requires one for the forward action).
   */
  rollback(token: CapabilityToken, original: ActionReceipt, nowIso: string): ActionReceipt {
    if (!original.rollback.supported || !original.rollback.action_type) {
      throw new Error(`receipt ${original.receipt_id} does not support rollback`);
    }
    const action = original.rollback.action_type;
    const target = original.action.target_id;
    const presented: PresentedAction = { action, target, scope: original.action.scope };
    const validation = this.capabilities.validate(token, { audience: this.audience, ...presented }, nowIso);

    if (!validation.ok) {
      return this.receipts.create(
        {
          receipt_type: "sentinel.rollback",
          incident_id: original.incident_id,
          decision: original.decision,
          action: {
            requested: action,
            executed: null,
            target_id: target,
            scope: original.action.scope,
            result: "rejected",
            failure_reason: validation.issues.map((issue) => `${issue.code}: ${issue.message}`).join("; "),
          },
          rollback: { supported: false, rollback_of: original.receipt_id },
          ...(original.control_lineage !== undefined ? { control_lineage: original.control_lineage } : {}),
        },
        nowIso,
      );
    }

    const { result, before, after } = this.applyRollback(action, target);
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
