# 02 Signature Binding

This document states how the producer credential and the high-value signature
cover the format in `01_CANONICAL_AUTHENTICATION_FORMAT.md`. It covers
HMAC-SHA256 now, and Ed25519 under ADR-026 later.

`AUTH(context, key_id, event)` means the authenticated bytes from `01`, built
with that context and that key id.

## The credential, with HMAC-SHA256

Today:

```text
token = hex( HMAC-SHA256( producer.secret, payload_hash ) )
```

Under this plan:

```text
token = hex( HMAC-SHA256( producer.secret, AUTH("credential", credential.key_id, event) ) )
```

The key, the primitive and the text form do not change. Only the message
changes. The text form stays 64 lowercase hex characters, so
`HMAC_HEX_PATTERN` (`src/spine/producers.ts:62`) stays as it is. One HMAC keeps
one accepted text form.

## The high-value signature, with HMAC-SHA256

Today the signature is byte-identical to the token. This plan verified that:
both are `HMAC-SHA256(producer.secret, payload_hash)`. A second value over the
same bytes with the same key adds no evidence.

Under this plan:

```text
signature = hex( HMAC-SHA256( producer.secret, AUTH("signature", integrity.signature_key_id, event) ) )
```

The `context` record differs, so the signature and the token are different
bytes. A person cannot copy a token into `integrity.signature`, and cannot copy
a signature into a credential. This is domain separation.

Domain separation alone does not make the signature independent evidence. The
signature still uses the producer key, so it proves the same key. Decision D-6
in `05` asks whether the high-value signature moves to a separate key, or waits
for Ed25519.

## Verification points

Two functions verify. Both must build the bytes with the same encoder that the
producer used.

| Function | File | Change |
|---|---|---|
| `ProducerRegistry.authenticate` | `src/spine/producers.ts:136` | Takes the validated event instead of the payload hash. Builds `AUTH("credential", credential.key_id, event)`. Keeps `timingSafeEqual`. |
| `EventGateway.ingest` | `src/spine/gateway.ts:180` | Builds `AUTH("signature", event.integrity.signature_key_id, event)` for a signature-required producer or family. Keeps `timingSafeEqual` and the `signature_key_id` comparison. |

`buildEvent` (`src/spine/build.ts:25`) produces both values. It must use the
same encoder. A separate copy of the field list in the builder would drift, so
the encoder must live in one module that the builder, the registry and the
gateway all import.

## Check order in the gateway

The order in `ingest` stays as it is, for three reasons.

1. `validateEventEnvelope` runs first. The encoder then receives a well-typed
   envelope, and `envelope_not_encodable` stays rare.
2. The payload hash check runs next. Record 34 therefore binds a digest that
   the gateway already proved against the real payload.
3. Authentication runs after both. An event that fails the contract never
   reaches the encoder.

One rule changes. Authentication must come before any use of the event. The
gateway already satisfies this: it appends to the ledger only after every
check.

## One reason code for an authentication failure

`authenticate` returns `undefined` for an unknown service, an unknown key id, a
malformed token and a wrong token. The gateway reports one code,
`producer_auth_failed`. This plan keeps one code for all authentication
failures, including a field change.

A code that named the field that differed would be an oracle. A person could
then find the bound field set, and could test one field at a time. The
rejection record must also not store the expected bytes or the expected digest.
Decision D-3 in `05` records this choice.

## Ed25519 under ADR-026

ADR-026 requires Ed25519 before any non-shadow deployment. It names
`spine/producers.ts` as one of the three call sites. The format in `01` does
not change for Ed25519. Only the primitive and the key material change:

```text
token     = hex( Ed25519-Sign( producer_private_key, AUTH("credential", key_id, event) ) )
signature = hex( Ed25519-Sign( producer_private_key, AUTH("signature", key_id, event) ) )
```

The gateway verifies with the producer public key. It holds no signing
capability. That is the property ADR-026 wants.

The Ed25519 move changes more than the primitive:

| Item | Change |
|---|---|
| `ProducerRegistration.secret` | Becomes public key material for the gateway. A registration must stop carrying a signing key. |
| `forgesentinel.producer_secrets.v1` | Needs a new version. The gateway file holds public keys. A private key belongs only to the producer. |
| `assertProducerSecretsAllowed` | The strength rules in `src/spine/producer_secrets.ts` describe a shared secret. A public key is not a secret, so the rules change meaning. The published-test-value refusal must stay, in terms of test keys. |
| `HMAC_HEX_PATTERN` | An Ed25519 signature is 64 bytes, so the text form is 128 lowercase hex characters. The pattern needs a second constant, or one constant for each algorithm. |
| `KI-SENTINEL-20261030-002` | Its loader and its negative tests cover the secret file. The Ed25519 change touches both. The two tracks must not land at the same time without a plan for the file schema. |

Decision D-9 in `05` asks whether Ed25519 comes before or after this format
change. The recommendation is after: the format change is the correction for
the finding, and it is verifiable with the primitive that exists today. ADR-026
stays a separate, authorized slice.

## Why the format carries no algorithm record

The gateway chooses the primitive from the registration, not from the event. A
producer cannot ask for a weaker primitive, because nothing in the event names
one. One key id belongs to exactly one producer and one algorithm, and the
registry already refuses a key id that two producers share.

Record 3 binds the key id into the authenticated bytes. A signature made for
one key id therefore does not verify for another.

An explicit `alg` record is still an option if the owner prefers that the bytes
state the primitive. It is listed under decision D-4.
