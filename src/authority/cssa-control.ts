import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { canonicalJson, type ValidationIssue } from "../contracts/common.js";
import {
  CONTROL_DIRECTIVE_SCHEMA,
  DIRECTIVE_ACTION_ALLOWLIST,
  validateControlDirectiveShape,
  type CloudSecurityControlDirective,
  type ControlDirectiveTarget,
} from "../contracts/cssa.js";
import type { ControlLineage } from "../contracts/envelope.js";
import type { ActionReceipt } from "../contracts/receipt.js";
import type { PolicyDecision } from "../contracts/policy.js";
import type { ApprovalRecord } from "./capability.js";
import { GLOBAL_ALWAYS_DENY } from "./policy.js";
import type { ReceiptService } from "./receipts.js";

function directiveSignature(directive: CloudSecurityControlDirective, key: string): string {
  const unsigned = { ...directive, integrity: { ...directive.integrity, signature: "" } };
  return createHmac("sha256", key).update(canonicalJson(unsigned), "utf8").digest("hex");
}

/**
 * Control-directive issuer owned by Forge_Command policy (06, 07 §8). A
 * directive exists only downstream of a policy decision plus the required
 * approval; Sentinel nodes cannot reach this signer.
 */
export class ControlDirectiveIssuer {
  readonly issuer = "forge-command-policy";

  constructor(private readonly signingKey: string, private readonly keyId: string = "key_fc_policy_01") {}

  issue(
    decision: PolicyDecision,
    action: string,
    target: ControlDirectiveTarget,
    approval: ApprovalRecord,
    reasonCodes: string[],
    nowIso: string,
    ttlSeconds = 900,
  ): CloudSecurityControlDirective {
    const allowlisted = DIRECTIVE_ACTION_ALLOWLIST[action];
    if (!allowlisted) throw new Error(`action "${action}" is not an allowlisted CSSA control`);
    const directive: CloudSecurityControlDirective = {
      schema_version: CONTROL_DIRECTIVE_SCHEMA,
      control_id: `ctl_${randomUUID().replaceAll("-", "")}`,
      incident_id: decision.incident_id,
      policy_decision_id: decision.policy_decision_id,
      issuer: this.issuer,
      issued_at: nowIso,
      expires_at: new Date(Date.parse(nowIso) + ttlSeconds * 1000).toISOString(),
      action,
      target,
      scope: allowlisted.max_scope,
      max_uses: 1,
      approval: { level: approval.level, approval_id: `apr_${approval.approver_id}_${Date.parse(nowIso)}` },
      rollback: { required: true, action: allowlisted.rollback_action },
      reason_codes: reasonCodes,
      integrity: { algorithm: "hmac-sha256", key_id: this.keyId, signature: "" },
    };
    directive.integrity.signature = directiveSignature(directive, this.signingKey);
    return directive;
  }
}

export interface DirectiveSubmission {
  accepted: boolean;
  issues: ValidationIssue[];
  receipt?: ActionReceipt;
  /** Lineage CSSA stamps onto every record the control affects (ADR-022). */
  lineage?: ControlLineage;
}

/**
 * CSSA-side control registry and validator (07 §9). CSSA consumes only
 * authenticated policy artifacts: a raw incident, finding, or anomaly score
 * submitted here is rejected as non-authoritative (ADR-021).
 */
export class CssaControlRegistry {
  private readonly trustedIssuers = new Map<string, string>();
  private readonly applied = new Map<string, { directive: CloudSecurityControlDirective; uses: number; rolled_back: boolean }>();

  constructor(private readonly receipts: ReceiptService) {}

  trustIssuer(issuer: string, keyId: string, key: string): void {
    this.trustedIssuers.set(`${issuer}:${keyId}`, key);
  }

  /** ADR-021: incidents do not grant cloud authority — ever. */
  submitRawIncident(_incident: unknown): DirectiveSubmission {
    return {
      accepted: false,
      issues: [
        {
          path: "",
          code: "non_authoritative_artifact",
          message: "raw Sentinel incidents are not CSSA authorization artifacts; submit a signed control directive (ADR-021)",
        },
      ],
    };
  }

  submitDirective(directive: CloudSecurityControlDirective, nowIso: string): DirectiveSubmission {
    const issues: ValidationIssue[] = [];
    const shape = validateControlDirectiveShape(directive);
    issues.push(...shape.issues);
    if (issues.length > 0) return this.rejected(directive, issues, nowIso);

    // GLOBAL_ALWAYS_DENY (06) is Sentinel's non-negotiable floor and must
    // hold on every authority path, not only PolicyService.evaluate() — a
    // future scoped CSSA control accidentally allowlisting a forbidden
    // action must not bypass it.
    const globalDenyReason = GLOBAL_ALWAYS_DENY[directive.action];
    if (globalDenyReason) {
      issues.push({ path: "action", code: "globally_denied", message: globalDenyReason });
      return this.rejected(directive, issues, nowIso);
    }

    const key = this.trustedIssuers.get(`${directive.issuer}:${directive.integrity.key_id}`);
    if (!key) {
      issues.push({ path: "issuer", code: "unknown_issuer", message: `issuer "${directive.issuer}" / key "${directive.integrity.key_id}" is not trusted` });
      return this.rejected(directive, issues, nowIso);
    }
    const expected = directiveSignature(directive, key);
    const a = Buffer.from(expected, "hex");
    const b = Buffer.from(directive.integrity.signature.length === expected.length ? directive.integrity.signature : "0".repeat(expected.length), "hex");
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      issues.push({ path: "integrity.signature", code: "signature_invalid", message: "directive signature invalid; target or action may have changed after signing" });
      return this.rejected(directive, issues, nowIso);
    }
    if (Date.parse(directive.expires_at) < Date.parse(nowIso)) {
      issues.push({ path: "expires_at", code: "expired", message: "directive expired" });
      return this.rejected(directive, issues, nowIso);
    }
    const allowlisted = DIRECTIVE_ACTION_ALLOWLIST[directive.action];
    if (allowlisted && directive.scope !== allowlisted.max_scope) {
      issues.push({ path: "scope", code: "scope_exceeds_allowlist", message: `scope "${directive.scope}" is wider than allowlisted "${allowlisted.max_scope}"` });
      return this.rejected(directive, issues, nowIso);
    }
    if (allowlisted && directive.rollback.action !== allowlisted.rollback_action) {
      issues.push({ path: "rollback.action", code: "rollback_unsupported", message: "rollback action does not match the allowlisted rollback for this control" });
      return this.rejected(directive, issues, nowIso);
    }
    const existing = this.applied.get(directive.control_id);
    if (existing && existing.uses >= directive.max_uses) {
      issues.push({ path: "control_id", code: "replayed", message: "directive use count exhausted; replay rejected" });
      return this.rejected(directive, issues, nowIso);
    }

    this.applied.set(directive.control_id, { directive, uses: (existing?.uses ?? 0) + 1, rolled_back: false });
    const receipt = this.receipts.create(
      {
        receipt_type: "cssa.control",
        incident_id: directive.incident_id,
        decision: {
          decision_id: directive.policy_decision_id,
          policy_id: "cssa_control_registry",
          policy_version: "1.0.0",
          result: "APPLIED",
          approver: { type: directive.approval.level, id: directive.approval.approval_id },
        },
        action: {
          requested: directive.action,
          executed: directive.action,
          target_id: directive.target.executor_id ?? directive.target.principal_id ?? directive.target.tenant_id,
          scope: directive.scope,
          result: "success",
        },
        rollback: { supported: true, action_type: directive.rollback.action },
        control_lineage: { control_id: directive.control_id, policy_decision_id: directive.policy_decision_id },
      },
      nowIso,
    );
    return {
      accepted: true,
      issues: [],
      receipt,
      lineage: {
        control_origin: "sentinel_policy",
        sentinel_incident_id: directive.incident_id,
        policy_decision_id: directive.policy_decision_id,
        control_id: directive.control_id,
        policy_generated_effect: true,
      },
    };
  }

  isActive(controlId: string): boolean {
    const entry = this.applied.get(controlId);
    return entry !== undefined && !entry.rolled_back;
  }

  rollback(controlId: string, nowIso: string): ActionReceipt {
    const entry = this.applied.get(controlId);
    if (!entry) throw new Error(`unknown control ${controlId}`);
    entry.rolled_back = true;
    return this.receipts.create(
      {
        receipt_type: "cssa.control",
        incident_id: entry.directive.incident_id,
        decision: {
          decision_id: entry.directive.policy_decision_id,
          policy_id: "cssa_control_registry",
          policy_version: "1.0.0",
          result: "ROLLED_BACK",
          approver: { type: entry.directive.approval.level, id: entry.directive.approval.approval_id },
        },
        action: {
          requested: entry.directive.rollback.action,
          executed: entry.directive.rollback.action,
          target_id: entry.directive.target.executor_id ?? entry.directive.target.principal_id ?? entry.directive.target.tenant_id,
          scope: entry.directive.scope,
          result: "rolled_back",
        },
        rollback: { supported: false, rollback_of: controlId },
        control_lineage: { control_id: entry.directive.control_id, policy_decision_id: entry.directive.policy_decision_id },
      },
      nowIso,
    );
  }

  private rejected(directive: CloudSecurityControlDirective, issues: ValidationIssue[], nowIso: string): DirectiveSubmission {
    const receipt = this.receipts.create(
      {
        receipt_type: "cssa.control",
        incident_id: typeof directive.incident_id === "string" ? directive.incident_id : "unknown",
        decision: {
          decision_id: typeof directive.policy_decision_id === "string" ? directive.policy_decision_id : "unknown",
          policy_id: "cssa_control_registry",
          policy_version: "1.0.0",
          result: "REJECTED",
          approver: { type: "system", id: "cssa-validator" },
        },
        action: {
          requested: typeof directive.action === "string" ? directive.action : "unknown",
          executed: null,
          target_id: directive.target?.tenant_id ?? "unknown",
          scope: typeof directive.scope === "string" ? directive.scope : "unknown",
          result: "rejected",
          failure_reason: issues.map((issue) => `${issue.code}: ${issue.message}`).join("; "),
        },
        rollback: { supported: false },
      },
      nowIso,
    );
    return { accepted: false, issues, receipt };
  }
}
