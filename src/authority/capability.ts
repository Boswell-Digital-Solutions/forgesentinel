import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { canonicalJson, type ValidationIssue } from "../contracts/common.js";
import { validateCapabilityClaims, type CapabilityClaims, type CapabilityToken } from "../contracts/capability.js";
import type { AllowedAction, PolicyDecision } from "../contracts/policy.js";
import { GLOBAL_ALWAYS_DENY } from "./policy.js";

export interface ApprovalRecord {
  level: string;
  approver_type: "operator" | "policy" | "emergency_policy";
  approver_id: string;
  approved_at: string;
}

export interface PresentedAction {
  audience: string;
  action: string;
  target: string;
  scope: string;
}

/**
 * Scoped capability tokens (06, ADR-008). Short-lived, signed, single
 * action, exact target. MVP signing is HMAC-SHA256 with the policy-service
 * key (ADR-026); executors share verification through this service and
 * reject anything widened, expired, replayed, or over-used.
 */
export class CapabilityService {
  readonly issuer = "sentinel-policy-service";
  private readonly attempts = new Map<string, number>();

  constructor(private readonly signingKey: string, private readonly keyId: string = "key_capability_01") {}

  private sign(claims: CapabilityClaims): string {
    return createHmac("sha256", this.signingKey).update(canonicalJson(claims), "utf8").digest("hex");
  }

  issue(
    decision: PolicyDecision,
    action: AllowedAction,
    targetId: string,
    audience: string,
    approval: ApprovalRecord,
    nowIso: string,
  ): CapabilityToken {
    // Defense in depth (06): GLOBAL_ALWAYS_DENY is Sentinel's non-negotiable
    // floor. It is already enforced when PolicyService builds allowed_actions,
    // but issue() must not simply trust that a decision object came from
    // PolicyService — re-checking here means a forged or hand-built decision
    // still can't mint a capability for a globally forbidden action.
    const globalDenyReason = GLOBAL_ALWAYS_DENY[action.action_type];
    if (globalDenyReason) throw new Error(`action "${action.action_type}" is globally denied: ${globalDenyReason}`);
    // Trust boundary (finding 2026-09-19): `action` is caller-supplied, so
    // only `action_type` is used, purely as a lookup key into the policy
    // decision's own `allowed_actions`. Every field actually signed into the
    // capability below comes from that matched, trusted entry -- never from
    // the caller's copy -- so a hand-built `action` with a wider scope,
    // longer expiry, or a weaker `requires_approval` can't smuggle those
    // values into a validly-signed token.
    const entry = decision.allowed_actions.find((candidate) => candidate.action_type === action.action_type);
    if (!entry) throw new Error(`action "${action.action_type}" is not allowed by decision ${decision.policy_decision_id}`);
    if (entry.requires_approval !== "policy_allowed" && approval.level !== entry.requires_approval) {
      throw new Error(`action "${entry.action_type}" requires ${entry.requires_approval} approval, got ${approval.level}`);
    }
    const claims: CapabilityClaims = {
      iss: this.issuer,
      aud: audience,
      jti: `cap_${randomUUID().replaceAll("-", "")}`,
      incident_id: decision.incident_id,
      policy_decision_id: decision.policy_decision_id,
      policy_id: decision.policy_id,
      policy_version: decision.policy_version,
      approver_type: approval.approver_type,
      approver_id: approval.approver_id,
      action: entry.action_type,
      target: targetId,
      scope: entry.scope,
      max_attempts: 1,
      rollback_required: entry.reversible,
      exp: Math.floor(Date.parse(nowIso) / 1000) + entry.expires_in_seconds,
    };
    return { claims, signature: this.sign(claims), signature_key_id: this.keyId };
  }

  /** Executor-side validation: reject rather than guess (06 executor rules). */
  validate(token: CapabilityToken, presented: PresentedAction, nowIso: string): { ok: boolean; issues: ValidationIssue[] } {
    const issues: ValidationIssue[] = [];
    const contract = validateCapabilityClaims(token.claims);
    issues.push(...contract.issues);
    if (issues.length > 0) return { ok: false, issues };

    const expected = this.sign(token.claims);
    const a = Buffer.from(expected, "hex");
    const provided = Buffer.from(token.signature.length === expected.length ? token.signature : "0".repeat(expected.length), "hex");
    if (a.length !== provided.length || !timingSafeEqual(a, provided)) {
      issues.push({ path: "signature", code: "signature_invalid", message: "capability signature verification failed" });
      return { ok: false, issues };
    }
    if (token.claims.exp * 1000 < Date.parse(nowIso)) {
      issues.push({ path: "exp", code: "expired", message: "capability token expired" });
    }
    if (token.claims.aud !== presented.audience) {
      issues.push({ path: "aud", code: "audience_mismatch", message: `capability audience "${token.claims.aud}" does not match executor "${presented.audience}"` });
    }
    if (token.claims.action !== presented.action) {
      issues.push({ path: "action", code: "action_mismatch", message: `capability authorizes "${token.claims.action}", not "${presented.action}"` });
    }
    if (token.claims.target !== presented.target) {
      issues.push({ path: "target", code: "target_mismatch", message: "presented target differs from the approved exact target" });
    }
    if (token.claims.scope !== presented.scope) {
      issues.push({ path: "scope", code: "scope_mismatch", message: "presented scope differs from the approved scope; widened scope is rejected" });
    }
    const used = this.attempts.get(token.claims.jti) ?? 0;
    if (used >= token.claims.max_attempts) {
      issues.push({ path: "jti", code: "replayed", message: "capability token already used to its max_attempts; replay rejected" });
    }
    if (issues.length > 0) return { ok: false, issues };
    this.attempts.set(token.claims.jti, used + 1);
    return { ok: true, issues: [] };
  }
}
