# 02 Signature Binding

This document states how the producer credential and the high-value signature
cover the format in `01_CANONICAL_AUTHENTICATION_FORMAT.md`. It covers
HMAC-SHA256 now, and Ed25519 under ADR-026 later.

The owner amended D-6 on 2026-11-02: the credential and the high-value
signature must use **independent keys**, not one key with two contexts. This
document states the amended design. `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md`
records the ruling.

`AUTH(context, key_id, event)` means the authenticated bytes from `01`, built
with that context and that key id.

## Key derivation (the D-6 amendment)

One producer secret derives two keys. Nothing uses the producer secret directly
as an HMAC key.

```text
SALT = "forgesentinel.event_auth.v1"                       (ASCII, not secret)

K_credential = HKDF-SHA256(ikm = producer.secret, salt = SALT,
                           info = "credential|" + key_id, L = 32)
K_signature  = HKDF-SHA256(ikm = producer.secret, salt = SALT,
                           info = "signature|"  + key_id, L = 32)
```

| Parameter | Value | Reason |
|---|---|---|
| Function | HKDF-SHA256, `node:crypto.hkdfSync("sha256", ikm, salt, info, 32)` | It is in the Node standard library, so the repository stays dependency-free. |
| `ikm` | The producer secret from the registration, as UTF-8 bytes | The root secret never becomes an HMAC key itself. |
| `salt` | The constant format name, in ASCII | The salt is a non-secret domain label. HKDF-Extract stays a secure pseudo-random function with a constant salt for the secrets the protected-environment rules admit. Those rules check length and character variety, not entropy, and `src/spine/producer_secrets.ts:68` skips them entirely outside `production` and `staging`, so a development or test secret is not strength-checked at all (review finding F9). |
| `info` | The usage, then one vertical-bar character, then **the registration's** `key_id` | The usage separates the two keys. The key id stops one producer's derived key from matching another's, even if two secrets ever matched. The key id comes from the registration, never from the event or the credential, so attacker-controlled input never selects derivation material (review finding F11). The two usage labels differ at byte 0, so no key id, not even one containing a vertical bar, produces a cross-context collision. |
| `L` | 32 bytes | It matches the SHA-256 output length, so HKDF-Expand needs one block. SHA-256's block is 64 bytes, and its security levels are 128-bit collision and 256-bit preimage (review finding F10 corrected an earlier, wrong reason). |

Both derived keys are 32 bytes. A derived key never appears in a log, an error,
a receipt or a rejection record.

**The limit, stated plainly.** HMAC is symmetric, so the gateway holds the
producer secret and can derive both keys. Derivation gives usage separation and
bounds the damage of one leaked subkey. It does not make the verifier incapable
of signing. Only an asymmetric primitive gives that, and D-9 sequences it:
Ed25519 follows this format correction. A second option, two independent root
keys in the producer-secrets file, is stronger than derivation, but it changes
the `forgesentinel.producer_secrets.v1` schema that
`KI-SENTINEL-20261030-002` owns. The Ed25519 slice changes that schema anyway,
so the two changes belong together, and `05` slice S6 records that.

## The credential

Today:

```text
token = hex( HMAC-SHA256( producer.secret, payload_hash ) )
```

Under this plan:

```text
token = hex( HMAC-SHA256( K_credential, AUTH("credential", credential.key_id, event) ) )
```

The primitive and the text form do not change. The key and the message change.
The text form stays 64 lowercase hex characters, so `HMAC_HEX_PATTERN`
(`src/spine/producers.ts:62`) stays as it is. One HMAC keeps one accepted text
form.

## The high-value signature

Today the signature is byte-identical to the token. This plan verified that:
both are `HMAC-SHA256(producer.secret, payload_hash)`. A second value over the
same bytes with the same key adds no evidence.

Under this plan:

```text
signature = hex( HMAC-SHA256( K_signature, AUTH("signature", integrity.signature_key_id, event) ) )
```

Two things now differ: the key and the `context` record. A person cannot copy a
token into `integrity.signature`, and cannot copy a signature into a
credential. Separation holds at the key and at the message, so a defect in one
layer does not remove the other.

## Verification points

Two functions verify. Both must build the bytes with the same encoder that the
producer used.

| Function | File | Change |
|---|---|---|
| `ProducerRegistry.authenticate` | `src/spine/producers.ts:136` | Takes the validated event instead of the payload hash. Derives `K_credential` from the registration. Builds `AUTH("credential", credential.key_id, event)`. Keeps `timingSafeEqual`. |
| `EventGateway.ingest` | `src/spine/gateway.ts:180` | Derives `K_signature` from the registration. Builds `AUTH("signature", event.integrity.signature_key_id, event)` for a signature-required producer or family. Keeps `timingSafeEqual`. **Compares `signature_key_id` with the registration before it verifies anything**, not inside the same condition as the comparison, so attacker-controlled input never reaches verification (review finding F11). |

Implementation note: `crypto.hkdfSync` returns an `ArrayBuffer`, not a
`Buffer`. Wrap it before use as an HMAC key.

`buildEvent` (`src/spine/build.ts:25`) produces both values. It must use the
same encoder and the same derivation. A separate copy of the field list or of
the `info` strings would drift, so one module holds the field list, the
derivation and the encoder, and the builder, the registry and the gateway all
import it.

Derivation runs once for each registration, not once for each event. The
registry may cache the two derived keys beside the registration, which is
frozen. A cache must never widen who can read a key: the derived keys stay in
the private field that holds the registration.

## Check order in the gateway

The order in `ingest` stays as it is, for three reasons.

1. `validateEventEnvelope` runs first. The encoder then receives a well-typed
   envelope, and `envelope_not_encodable` stays rare.
2. The payload hash check runs next. Record 36 therefore binds a digest that
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
rejection record must also not store the presented token, the expected bytes,
the expected digest or a derived key.

The owner approved D-3 with one condition: keep useful internal diagnostic
categories, and do not leak them to a caller. The implementation therefore
separates the two surfaces:

| Surface | Content |
|---|---|
| The `IngestResult` that a caller receives | One `ValidationIssue` with the code `producer_auth_failed` and a message that names no field and no value. |
| The rejection record in the evidence ledger, which an operator reads | The same code, plus one internal category from a closed set: `unknown_producer`, `unknown_key_id`, `malformed_token`, `envelope_mismatch`, `signature_mismatch`, `signature_key_mismatch`. |

The closed set is a vocabulary, not a field name. `envelope_mismatch` says that
the authenticated bytes did not match. It does not say which record differed,
so an operator gains a triage category and a person gains no oracle. Gate 5 in
`06` governs what else that record may hold.

## Ed25519 under ADR-026

**Open contradiction, `KI-SENTINEL-20261104-004`.** The two lines below sign the token and the
signature with one `producer_private_key`, and safeguard 6 lets the `context` record carry the
domain separation alone. The owner's D-6 amendment in `06` requires **independent keys**, not one
key with two contexts. This section is not corrected here, because the choice — two key pairs for
each producer, or an amendment of D-6 for slice S6 — is the owner's.

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

The owner ruled D-9: **Ed25519 follows this format correction**, with explicit
algorithm-transition safeguards. The format change is the correction for the
finding, and the primitive that exists today can verify it. ADR-026 stays a
separate, authorized slice, and the safeguards below are part of it.

## Why the format carries no algorithm record

The gateway chooses the primitive from the registration, not from the event. A
producer cannot ask for a weaker primitive, because nothing in the event names
one. One key id should belong to exactly one producer and one algorithm.

**Correction, review finding F8.** An earlier version of this document stated
that the registry already refuses a key id that two producers share. It does
not. `ProducerRegistry.register` keys its map on `service:key_id`
(`src/spine/producers.ts:124`) and refuses only an exact duplicate of that
pair. Key-id uniqueness is enforced in `loadProducerRegistrations`
(`src/spine/producer_secrets.ts:196-200`), which is the secrets-file loader,
over the standard profiles only. Verified by execution: registering a second
producer with the same `key_id` directly on a `ProducerRegistry` succeeds.

So the property the key-substitution argument needs does not exist yet, and
D-9 safeguard 1 below must create it rather than assume it. The registry must
refuse a `key_id` that another registered producer already uses.

Record 3 binds the key id into the authenticated bytes. A signature made for
one key id therefore does not verify for another.

The owner ruled D-4 as approved: the gateway controls the algorithm and the
version, it refuses an unsupported version, and it never negotiates an
algorithm from event input. So the gateway holds one format name and one
algorithm for each registration, and no `alg` record is needed. An explicit
`alg` record stays available for a future version if the owner wants the bytes
to state the primitive.

"Refuse an unsupported version" has one consequence worth stating. Nothing in
an event or a credential declares a version, so an unsupported version cannot
arrive as a declaration. It arrives as bytes that do not verify, and the
gateway refuses them with `producer_auth_failed`. If a later version does add a
declared version field, the gateway must hold an allowlist, must refuse any
value outside it before it verifies anything, and the declared value must also
sit inside the authenticated bytes, so the two cannot disagree.

## Algorithm-transition safeguards (D-9)

The owner approved D-9 with a condition: the Ed25519 migration needs explicit
algorithm-transition safeguards. These are the safeguards the Ed25519 slice
must implement and prove.

1. **One algorithm for one key id.** A registration declares its algorithm. A
   key id never carries two algorithms, and the registry refuses a second
   registration for a key id that exists.
2. **The gateway chooses, never the event.** The verifier takes the algorithm
   from the registration. No event field and no credential field selects it.
3. **No mixed-algorithm acceptance for one producer.** A producer is HMAC or
   Ed25519, not both. A transition replaces the registration, and the gateway
   refuses the old value from that moment.
4. **No downgrade.** Once a producer is registered for Ed25519, an HMAC token
   for that producer must fail. A test must show that.
5. **Distinct text forms.** An HMAC token is 64 lowercase hex characters. The
   Ed25519 text form is **not approved**: the table above records it as an open
   item, and `06` rules that no document may present one as approved. Once it is
   specified and approved, the pattern for each algorithm is separate, so a value
   of the wrong length fails before any verification.
6. **The derivation does not carry over.** HKDF derivation exists because HMAC
   is symmetric. An Ed25519 key is not derived from a shared secret, so the
   `info` strings are retired for that producer, and the `context` record then
   carries the domain separation alone.
7. **A key rotation is a registration change, with its own receipt.** The
   secrets-file schema change that ADR-026 needs must record which algorithm
   each key id uses, and the loader must refuse a file that omits it.
