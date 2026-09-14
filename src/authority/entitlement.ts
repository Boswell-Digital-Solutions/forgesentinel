import { createPublicKey, verify as edVerify, type KeyObject } from "node:crypto";
import { canonicalJson } from "../contracts/common.js";

/**
 * Ed25519-signed entitlement (03 Sentinel-License, ADR-013). The signed
 * entitlement and verified Stripe state are authoritative commercial truth;
 * Sentinel detects anomalies around them but never creates or revokes that
 * truth.
 */
export interface SignedEntitlement {
  entitlement_id: string;
  account_id: string;
  plan: string;
  features: string[];
  device_limit: number;
  issued_at: string;
  expires_at: string;
  signing_key_id: string;
  /** base64 Ed25519 signature over the canonical JSON of all other fields. */
  signature: string;
}

export function entitlementSigningPayload(entitlement: SignedEntitlement): Buffer {
  const { signature: _signature, ...unsigned } = entitlement;
  return Buffer.from(canonicalJson(unsigned), "utf8");
}

export interface EntitlementDecision {
  valid: boolean;
  reason?: string;
  /** Stale-but-valid cached entitlements keep safe local operation only. */
  requires_revalidation: boolean;
  paid_cloud_allowed: boolean;
}

/**
 * Fail-closed verifier (01 doctrine): unknown key, bad signature, or expiry
 * denies paid privilege. Offline staleness follows product policy — a valid
 * cached entitlement past `max_cache_age_ms` preserves safe local operation
 * but requires online revalidation before paid cloud features (Wave 7 exit
 * gate).
 */
export class EntitlementVerifier {
  private readonly keys = new Map<string, KeyObject>();

  constructor(private readonly maxCacheAgeMs: number = 14 * 24 * 3600 * 1000) {}

  registerKey(keyId: string, publicKeyPem: string): void {
    this.keys.set(keyId, createPublicKey(publicKeyPem));
  }

  verify(entitlement: SignedEntitlement, nowIso: string): EntitlementDecision {
    const key = this.keys.get(entitlement.signing_key_id);
    if (!key) {
      return { valid: false, reason: "unknown_signing_key", requires_revalidation: true, paid_cloud_allowed: false };
    }
    let signatureOk = false;
    try {
      signatureOk = edVerify(null, entitlementSigningPayload(entitlement), key, Buffer.from(entitlement.signature, "base64"));
    } catch {
      signatureOk = false;
    }
    if (!signatureOk) {
      return { valid: false, reason: "invalid_signature", requires_revalidation: true, paid_cloud_allowed: false };
    }
    const now = Date.parse(nowIso);
    if (Date.parse(entitlement.expires_at) < now) {
      return { valid: false, reason: "expired", requires_revalidation: true, paid_cloud_allowed: false };
    }
    if (now - Date.parse(entitlement.issued_at) > this.maxCacheAgeMs) {
      return { valid: true, reason: "stale_cached_entitlement", requires_revalidation: true, paid_cloud_allowed: false };
    }
    return { valid: true, requires_revalidation: false, paid_cloud_allowed: true };
  }
}
