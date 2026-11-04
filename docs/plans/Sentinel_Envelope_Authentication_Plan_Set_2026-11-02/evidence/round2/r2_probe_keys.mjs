import { hkdfSync, createHmac } from "node:crypto";
import { encode, deriveKey, hmac } from "./r2_encoder.mjs";
// RFC 5869 A.1
const okm = Buffer.from(hkdfSync("sha256", Buffer.from("0b".repeat(22), "hex"), Buffer.from("000102030405060708090a0b0c", "hex"), Buffer.from("f0f1f2f3f4f5f6f7f8f9", "hex"), 42)).toString("hex");
console.log("RFC5869 A.1:", okm === "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", );
const { B } = await import("./r2_reproduce.mjs?quiet");
const secret = "rT9#kq2LmZ8vB4xP7wQ1sD6fG3hJ0nC5";
const Kc = deriveKey(secret, "credential", "key_billing_01"), Ks = deriveKey(secret, "signature", "key_billing_01");
const sigBytes = encode("signature", "key_billing_01", B);
const signature = hmac(Ks, sigBytes);
const ev = structuredClone(B); ev.integrity.signature = signature;
const token = hmac(Kc, encode("credential", "key_billing_01", ev));
console.log("Kc != Ks:", !Kc.equals(Ks), "| Kc != raw secret HMAC key:", !Kc.equals(Buffer.from(secret)));
console.log("token != signature:", token !== signature);
console.log("token as signature verifies:", hmac(Ks, sigBytes) === token, "| signature as token verifies:", hmac(Kc, encode("credential", "key_billing_01", ev)) === signature);
console.log("K_signature over credential bytes == token:", hmac(Ks, encode("credential", "key_billing_01", ev)) === token);
const moved = structuredClone(ev); moved.tenant.tenant_id = "ten_other";
console.log("tenant transplant: token still verifies:", hmac(Kc, encode("credential", "key_billing_01", moved)) === token, "| signature still verifies:", hmac(Ks, encode("signature", "key_billing_01", moved)) === signature);
const sys = structuredClone(ev); delete sys.tenant;
console.log("tenant removed: token still verifies:", hmac(Kc, encode("credential", "key_billing_01", sys)) === token);
// Same secret, same key_id, two services: derived keys identical (info carries no service).
console.log("two services sharing secret+key_id derive the same K_credential:", deriveKey(secret, "credential", "k").equals(deriveKey(secret, "credential", "k")));
