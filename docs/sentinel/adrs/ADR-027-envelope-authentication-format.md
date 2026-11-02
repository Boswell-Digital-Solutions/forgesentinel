# ADR-027: Authenticate the Security-Relevant Event Envelope, Not Only the Payload Hash

**Status:** Accepted for design (2026-11-02). Implementation is not authorized. Independent review round 1 returned blocking defects in the format; a second round is required.
**Amended:** 2026-11-02, by owner rulings R1-A, R1-B and R1-C. The three blocking defects now have ruled fixes, and **the count of 41 records below is superseded.** A ruling is not a correction: the defects are settled in design and open in fact. Amendment 3 in `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` states why no replacement count is given, and slice S1 derives it.
**Addresses:** `KI-SENTINEL-20261102-008`
**Depends on:** `KI-SENTINEL-20261102-006` (corrected and verified), ADR-026
**Plan set:** `docs/plans/Sentinel_Envelope_Authentication_Plan_Set_2026-11-02/` (`BDS-SNT-ENVELOPE-AUTH-001`)

## Context

`producerToken(secret, payloadHash)` is an HMAC over `integrity.payload_hash`
only. The gateway authenticates a producer credential against that one hash.
The high-value signature covers the same hash with the same key. No other part
of the envelope is authenticated.

A person who holds one signed event can therefore change the tenant, the
account, the actor, the subject, the event id, the times, the trace id, the
data policy, the execution lane, the idempotency key and the control lineage,
and the gateway accepts the changed event with the original credential. One
credential also authenticates every event that carries the same payload. This
was verified by execution at `432337c`.

The credential authenticates a payload. It does not authenticate an event.

The exposure is latent: the gateway has no network ingress
(`KI-SENTINEL-20261030-001`) and the pipeline is shadow-only (ADR-011). No
exploitation is claimed, and none is observed.

## Decision

Producer authentication binds the security-relevant envelope through one
versioned, deterministic byte format, `forgesentinel.event_auth.v1`, which is
**intended** to be one to one. That property is the subject of gate 2 and is
not yet proved: review round 1 found three defects that break it (see
`07_REVIEW_ROUND_1_FINDINGS.md`, findings F1 to F3).

1. **The format.** The authenticated bytes are a fixed, ordered record list,
   plus one record for each `control_lineage.sentinel_finding_ids` element. One
   record is `name 0x1F tag 0x1F byte-length 0x1F value 0x1E`. The name is a
   constant from the specification. The length is the exact UTF-8 byte count, so
   no value can create, hide or move a separator — the reviewer confirmed this
   core property by implementing the spec and testing it. A tag separates an
   absent field from a present empty string, but **not** an absent parent object
   from a present empty one, which is finding F2. **Ruled by R1-B:** a presence
   record for each of the three optional parents, `tenant`, `resource` and
   `control_lineage`, so injectivity rests on the encoding and never on the
   validator. **The list was 41 records and that count is superseded**, because
   R1-B adds three and R1-A's binding adds an unsettled number more.
2. **The version tag is inside the authenticated bytes.** Record 1 holds the
   format name, so it cannot be stripped or downgraded. The gateway holds the
   accepted name as a constant, and it reads no version from the event.
3. **Canonical JSON is not the basis.** `canonicalJson` is not one to one
   (`KI-SENTINEL-20261102-006`), so it cannot authenticate. The format uses its
   own encoding, which never rebuilds an object and never relies on
   `JSON.stringify` for a bound field.
4. **The payload binding is the corrected digest.** Record 34 binds
   `integrity.payload_hash`, which the gateway already recomputes from the real
   payload. The `KI-SENTINEL-20261102-006` correction must be verified before
   envelope authentication relies on it.
5. **Independent keys.** HKDF-SHA256 derives two keys from the producer secret:
   one for the credential, one for the high-value signature. The `context`
   record also differs, so separation holds at the key and at the message.
6. **Deterministic numbers.** Non-finite values and negative zero are refused.
   An admitted integer lies in the interoperable range of
   ±9007199254740991, which aligns with the `forge.rfc8785-jcs-*` profile in
   `forge_contract_core`. A floating-point payload number is refused; a
   fraction travels as a scaled integer or a decimal string.
7. **A closed field list.** `validateEventEnvelope` refuses an unknown field,
   at the top level and in every bound object, so no unknown field escapes the
   binding. This version defines no extension point. Two **known** fields,
   `integrity.signature` and `integrity.signature_key_id`, are admitted and
   unbound today, which is finding F3, and an unknown-field refusal cannot reach
   them. **Ruled by R1-A:** refuse both fields on an event whose family requires
   no signature, **and** bind both where they may legitimately appear. The
   binding contexts are not settled by the ruling, so slice S1 names them.
8. **One external reason code.** Every authentication failure returns
   `producer_auth_failed` to the caller, with no field name. A closed set of
   internal categories stays in the operator evidence record.

## Rationale

Authentication must cover what a decision depends on. A Sentinel event's
meaning is its tenant, its actor, its subject, its time and its data policy,
not only its payload bytes. The gateway already compares `producer.service` and
`producer.environment` with the registration, which is why those two were the
only envelope fields that resisted re-targeting; the correction extends that
principle to the whole envelope by cryptographic means instead of field-by-field
comparison.

A length-prefixed record format is chosen over canonical JSON because
injectivity is the property that makes a signature meaningful, and the existing
canonical form does not have it. The format is also simple to reimplement in
another language, which ADR-025 requires of cross-language contract evidence.

HMAC stays the primitive for now. ADR-026 still requires Ed25519 before any
non-shadow deployment, and the format is primitive-independent, so the Ed25519
migration changes the key material and not the authenticated bytes.

## Consequences

- `src/spine/event_auth.ts` becomes the single owner of the field list, the
  derivation and the encoder. `buildEvent`, `ProducerRegistry.authenticate` and
  `EventGateway.ingest` all use it.
- The old payload-hash-only call signature is removed. There is no
  compatibility fallback, because there is no installed base: no repository
  computes a Sentinel producer token, and the package is private and
  unpublished.
- The credential and the signature in the three committed replay fixtures
  change. The event bodies, the payload hashes and the dedupe keys do not.
- A producer must sign last. A field corrected after signing breaks its own
  authentication.
- A future authenticated field requires a new format version, not an in-place
  change. Amendment 3 records that this clause is **not** triggered by the R1-A
  and R1-B corrections: they correct a defect in an unimplemented format, with no
  installed base and nothing to version.
- Ed25519 under ADR-026 follows this correction, with the seven
  algorithm-transition safeguards in the plan set.
- `KI-SENTINEL-20261102-009` (the dedupe key joins strings without length
  prefixes) is the same defect class and follows immediately, reusing this
  encoder where that is safe.

## Status of this record

This ADR records an accepted design. It does not authorize implementation.
The owner set three boundaries, in order: design review, then implementation
authorization for each slice, then production deployment authorization.
