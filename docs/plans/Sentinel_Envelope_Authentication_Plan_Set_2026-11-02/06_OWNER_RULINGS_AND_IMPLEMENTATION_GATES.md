# 06 Owner Rulings and Implementation Gates

- **Date of ruling:** 2026-11-02
- **Ruling authority:** Charlie Boswell, owner
- **Disposition at the ruling:** Design approved conditionally. Merge not authorized.
- **Since:** The owner instructed the merge on 2026-11-02. PR #32 merged as `79698ac`. Implementation stays unauthorized, and the review-round-1 findings stay open.

This document is the authoritative record of the owner's rulings on
`BDS-SNT-ENVELOPE-AUTH-001`. Where a ruling and an earlier document in this
plan set disagree, this document wins, and the earlier document must be
corrected.

## Priority

The owner rules the envelope-authentication correction a **P0 security
priority**. The verified cross-tenant event re-targeting is a
security-significant authentication failure.

**No exploitation is claimed, and none is observed.** The gateway has no
network ingress (`KI-SENTINEL-20261030-001`), the pipeline is shadow-only
(ADR-011), and every demonstration in this plan set ran in a local test
process. P0 states the priority of the correction. It does not state that an
incident happened.

## The ten rulings

| Decision | Ruling | Condition | Where the plan now states it |
|---|---|---|---|
| D-1 Payload binding | **Approved** | Depend on `KI-SENTINEL-20261102-006`. The corrected payload digest must be verified before envelope authentication relies on it. | `01`, "The payload digest"; slice S0 in `05` |
| D-2 Bound field set | **Approved, amended by R1-B** | Bind all fixed records plus one record for each control-lineage finding id. The count was 41 and is now **43**: R1-B adds a presence record for `tenant` and one for `resource`. A future authenticated field needs a versioned format change; this correction does not trigger that clause. See amendment 3. | `01`, the field table and "A future authenticated field"; amendment 3 below |
| D-3 Rejection reason code | **Approved** | Use `producer_auth_failed` externally. Keep useful internal diagnostic categories, and do not leak them to a caller. | `02`, "One reason code"; gate 5 below |
| D-4 Version and algorithm | **Approved** | The gateway controls the algorithm and the version. Refuse an unsupported version. Never negotiate an algorithm from event input. | `01`, "Format name and version tag"; `02`, "Why the format carries no algorithm record" |
| D-5 Unknown fields | **Approved** | Refuse an unknown envelope field. Define the permitted extension points, if any, in a future version. | `01`, "Why the format is one to one"; `03`, the `envelope.ts` row |
| D-6 High-value signature | **Approved with amendment** | Use domain-separated authentication **and** derive independent keys for the producer credential and the high-value signature. | `02`, "Key derivation" |
| D-7 Numeric rule | **Amend** | Define deterministic numeric canonicalization before implementation. Refuse a non-finite value and a negative zero. Align the accepted integers with `forge_contract_core`. | `01`, "Numeric canonicalization" |
| D-8 `KI-SENTINEL-20261102-009` | **Approved** | Keep it separately tracked, immediately after the envelope-authentication correction. | `05`, slice S7; the finding record |
| D-9 Ed25519 | **Approved** | The Ed25519 migration follows the format correction, with explicit algorithm-transition safeguards. | `02`, "Ed25519 under ADR-026" and "Algorithm-transition safeguards" |
| D-10 Records | **Approved** | Write a short ADR. Request the plan registry entry through the authorized `forge` change process. | `docs/sentinel/adrs/ADR-027-envelope-authentication-format.md`; `05`, "The plan registry request" |

## Amendment 1: independent keys (D-6)

The earlier text used one producer secret for the credential and for the
high-value signature, and separated them only by the `context` record. The
owner amended this. The two values must now use independent keys.

`02_SIGNATURE_BINDING.md` specifies the derivation. The summary:

- `K_credential = HKDF-SHA256(ikm = producer secret, salt = the format name, info = "credential|" + key_id, L = 32)`
- `K_signature  = HKDF-SHA256(ikm = producer secret, salt = the format name, info = "signature|" + key_id, L = 32)`

The `context` record stays. Separation then holds at the key and at the
message. `node:crypto.hkdfSync` provides HKDF-SHA256, so the repository stays
dependency-free.

**The honest limit:** under HMAC, the gateway holds the root secret, so it can
still derive either key and forge either value. Derivation bounds the damage of
a leaked subkey. It does not make the verifier incapable of signing. That
property arrives with Ed25519 under D-9, and `02` states so.

## Amendment 2: numeric canonicalization (D-7)

The earlier text deferred the numeric rule to a later ruling. The owner
amended this: the rule must exist before implementation.

`01_CANONICAL_AUTHENTICATION_FORMAT.md` now specifies it, and aligns it with
the `forge.rfc8785-jcs-*` profile in `forge_contract_core`
(`forge_contract_core/model_certification.py`). The summary:

- Refuse `NaN`, `+Infinity`, `-Infinity` and `-0`.
- Admit an integer in the range −9007199254740991 to 9007199254740991, which is
  `MAX_JCS_SAFE_INTEGER` in `forge_contract_core` and `Number.MAX_SAFE_INTEGER`
  in JavaScript. Encode it as decimal digits, with `-` for a negative value, no
  leading zero and no exponent.
- Refuse a floating-point number, as signing profile v1 does. A quantity that
  needs a fraction uses a scaled integer, as `confidence_percent` does, or a
  decimal string.
- Refuse a duplicate object key and a lone surrogate.

## The five implementation gates

Each gate is a condition for the implementation, not a suggestion. The slice
that claims a gate must name the test that proves it.

### Gate 1: no unauthenticated compatibility fallback

A legacy credential must never authenticate a mutable envelope. There is no
dual-accept path, no feature flag and no fallback to the payload-hash-only
token.

- The gateway accepts one format. `03_COMPATIBILITY_AND_CALLER_IMPACT.md`
  states the position, and no installed base needs otherwise.
- Proof: case NEG-E07 in `04`. A token that is a correct HMAC over the payload
  hash alone is refused.
- A test must also show that no code path computes the old token. The slice
  removes the old call signature instead of keeping it beside the new one.

### Gate 2: the canonical encoding must be injective

Two different supported events must never give the same authenticated bytes.

- The format intends the property by construction: an explicit byte length for
  every value, constant field names, a closed field list, and a tag that
  separates an absent field from a present empty string. **Review round 1
  showed the property does not hold as specified** — findings F1, F2 and F3 —
  so this gate is open, and the length-prefix core is sound while the field set
  and the type rules are not. **The three corrections are ruled (R1-A, R1-B and
  R1-C, 2026-11-02) and not yet applied.** The gate stays open until slice S1
  implements them and review round 2 re-attacks them against a frozen commit. A
  ruling is not a correction.
- Proof: group H in `04`. It has a property test over a seeded generator and
  adversarial cases. The repository has no property-testing dependency, and it
  stays dependency-free, so the generator is a small seeded function in the
  test file. The seed is fixed and recorded, so a failure is reproducible.
- The adversarial cases must include separator injection, a boundary shift
  between two adjacent fields, an absent field against a present empty string,
  and a value that contains the record and unit separators.

### Gate 3: verify before side effects

An authentication failure must happen before de-duplication, a ledger write of
an accepted event, routing and downstream publication.

- The current order already authenticates before the dedupe lookup and before
  the accepted-event append (`src/spine/gateway.ts`). The slice must not move
  authentication later.
- One exception is deliberate: a rejection writes its own evidence record. That
  write is the gate-5 security telemetry, and it is not a side effect of an
  accepted event.
- Proof: group J in `04`. A failed authentication leaves no dedupe entry, no
  accepted ledger record, and no detector or Sentinel Prime input.

### Gate 4: test tenant isolation explicitly

The negative tests must cover cross-tenant, cross-account, actor, subject,
producer-identity and control-lineage substitution.

- Substitution is stronger than alteration: it moves a real field value from
  one signed event to another signed event.
- Proof: group B and group I in `04`. Group I adds the substitution cases.

### Gate 5: preserve operational evidence

An authentication failure must produce protected security telemetry. The
telemetry must not expose a credential or a sensitive payload.

- **Corrected, review finding F30.** An earlier version of this section said
  the record stores the envelope and not the credential. The *token* does not
  reach it, which is right. But `src/spine/gateway.ts:158` interpolates
  `credential.service` and `credential.key_id` into the failure message, which
  goes into `rejection_reasons` **and** back to the caller. Both fields are
  unbounded, unvalidated caller input. Verified by execution: a 200-character
  `key_id` with a NUL byte reached both. That also breaks the D-3 condition
  that the caller's message name no field and no value.
  `KI-SENTINEL-20261102-013` records it.
- **Open design item, with a recommended shape:** the rejection record stores
  the whole envelope, including the payload. For an authentication failure the
  envelope is unauthenticated, so its `data_policy` is unauthenticated too. A
  `restricted` payload can therefore be stored under a forged `internal` label.
- **Worse than that framing, review findings F31 to F33.** Three verified
  defects sit under this gate, and none needs a forged label:
  `cloudProjection` skips every data-policy check for a record whose kind is
  not `event`, so an honestly labelled `restricted`, `cloud_allowed: false`
  payload is published in full whenever an event is rejected
  (`KI-SENTINEL-20261102-011`); a rejection takes its `tenant_id` from the
  unauthenticated envelope and `queryByTenant` trusts it
  (`KI-SENTINEL-20261102-012`); and `LedgerRecord` has no field in which a
  value can be marked observed and untrusted, while `tenant_id` is the one
  field used for access control (review finding F34). All three live in
  `src/spine/ledger.ts`, which `03` now lists in scope.
  Recommendation 1 below states the recommended record shape. It is a
  recommendation, not a ruling, so the slice must still state the chosen shape,
  and `doc/system/03-runtime-boundary.md` must describe it. The `tenant_id`
  part of that shape is no longer open, because R1-E rules it.
- **A fourth defect, `KI-SENTINEL-20261102-016`.** The ledger writes its own
  cross-tenant denial telemetry with `kind: "event"`, `validation: "accepted"`
  and the **requested** tenant's id (`src/spine/ledger.ts:115-127`). Three
  readers trust those labels, so `events()` returns a body that is not an
  envelope, `src/runtime.ts:255` throws and stops `runShadow`, `cloudProjection`
  throws, and the probed tenant reads the denied principal and its home tenant.
  It is latent, because only `test/` calls `queryByTenant`. It shares F34's root
  cause: one `tenant_id` field means both "about" and "readable by".
- **R1-D and R1-E are ruled (2026-11-02).** A separate authorized change carries
  these four defects, sequenced before S4, and a record of unauthenticated
  provenance carries no top-level `tenant_id`. See "Owner rulings on review
  round 1" below. Neither ruling authorizes implementation.
- The record must never hold the presented token, the expected bytes, the
  expected digest or a derived key.
- D-3 applies here. An internal diagnostic category may say which group failed,
  for an operator reading protected telemetry. The caller sees
  `producer_auth_failed` and nothing more. The rejection record is operator
  evidence, so it may carry the internal category; the `IngestResult` returned
  to a caller must not.

## Owner recommendations pending formal ruling (2026-11-02)

The owner checked PR #32 on GitHub and recorded four recommended rulings.
**These are recommendations, not approvals.** The owner stated so explicitly.
They are not recorded here as owner rulings, they do not authorize
implementation, and the ten rulings above are unaffected by them.

The owner's observations from that check: the pull request is a draft, it is
mergeable, it is unmerged, every changed file is documentation, and GitHub
reports no submitted pull-request review.

### Recommendation 1: approve the payload-excluding rejection record (gate 5)

For an authentication failure, the record retains only:

- the permitted non-payload envelope metadata;
- a payload digest;
- a generic external failure code;
- a restricted internal diagnostic category.

Three constraints come with it:

1. **Do not trust the rejected envelope's `data_policy` classification to
   determine storage access.** The classification is attacker-chosen on an
   unauthenticated event, so it must not decide what is stored, who may read
   it, or how long it is kept.
2. **The digest is an observed, untrusted value.** The record must identify it
   that way. It is not proof of authenticity, and a reader must not treat a
   matching digest as evidence that the producer sent the event.
3. **No secrets, tokens, authentication bytes or sensitive payload content**
   belong in the record.

This resolves the open design item under gate 5, subject to a formal ruling.
Group K in `04` must assert the chosen shape, including that the digest is
labelled untrusted.

### Recommendation 2: one implementation pull request, with separate evidence stages (S3 and S4)

The recommendation keeps slices S3 and S4 in one pull request, and adds an
ordered evidence procedure:

1. The independent reviewer **reproduces the negative-test failures against the
   pinned vulnerable base**, before examining the corrected implementation.
2. The record states the **exact commit, the exact command, the cases and the
   results** of that reproduction.
3. Only then does the reviewer read the corrected implementation.
4. The combined pull request must pass the new negative tests **and** the
   positive regression controls before it is merge-eligible.
5. **No skipped security tests.** A skipped case is not evidence.

`05` carries this procedure in "The order of S3 and S4".

### Recommendation 3: independent design review is required before proceeding

A green documentation check does not substitute for this review. The review
must assess six axes:

| Axis | Where the plan answers it |
|---|---|
| Canonical-encoding injectivity | `01`, "Why the format is one to one"; group H in `04` |
| HKDF key separation | `02`, "Key derivation" |
| Unknown-field refusal | `01`, the D-5 condition; `03`, the `envelope.ts` row |
| Tenant isolation | Group B and group I in `04` |
| Rejection-record confidentiality | Gate 5 above; recommendation 1; group K in `04` |
| `KI-SENTINEL-20261102-006` dependency closure | `01`, "The payload digest"; slice S0 in `05` |

### Recommendation 4: S0 remains a hard prerequisite

The corrected payload digest **and its adversarial tests** must be
independently verified before envelope authentication may rely on it.
**Merging S0 alone is insufficient.** `05` states this in the S0 row and in the
S0 note.

### Review status, stated precisely

Independent design review **round 1 is complete**, and its verdict is **not
safe to proceed to implementation authorization as written**.
`07_REVIEW_ROUND_1_FINDINGS.md` holds the findings, the verdict and what this
author re-verified. No pull-request review is submitted on GitHub, so the
review of record is that document and not a GitHub review state; the owner
decides whether it satisfies recommendation 3.

Round 1 found three blocking defects in the format, four in the test matrix and
the rejection-record axis, and two false statements of present code behaviour.
A second round is needed after the owner rules on the candidate fixes. Nothing
in this plan set may be read as an approved design.

**Status of that condition (2026-11-02):** the owner has ruled on the fixes for
all three format defects — R1-A, R1-B and R1-C — and on R1-D and R1-E. Three
decisions stay open: R1-F, R1-G and R1-H. The rulings are recorded below.

Round 2 is still required, and the rulings do not reduce what it must do. They
change its target from a candidate fix to an implementation, so round 2 cannot
start until slice S1 and slice S2 exist. R1-H is itself one of the three open
decisions, and it governs whether `07` satisfies recommendation 3 or a submitted
GitHub review is also required. No GitHub review has ever been submitted on this
track.

## Owner rulings on review round 1 (2026-11-02)

Independent review round 1 surfaced eight open decisions, R1-A to R1-H, in
`07_REVIEW_ROUND_1_FINDINGS.md`. The owner ruled five of them. Three stay open:
R1-F, R1-G and R1-H.

R1-D and R1-E were ruled first, and R1-A, R1-B and R1-C followed on the same
day. A ruling settles what the correction is. It does not authorize the
correction, and it does not make the correction exist.

### R1-A: refuse the two signature fields, and bind them

**Ruled.** Both measures, not one.

1. **Refuse** `integrity.signature` and `integrity.signature_key_id` on an event
   whose family requires no signature. `validateEventEnvelope` already resolves
   the family entry, so the condition costs nothing.
2. **Bind** both fields in every context where they may legitimately appear,
   with the absent tag when they are not present.

The two close different holes. Binding alone stops a third party adding or
altering the fields, but on a no-signature family an unverified value is still
stored as accepted evidence, so `KI-SENTINEL-20261102-014` would stay open.
Refusal closes that, because the field cannot be present at all. Refusal alone
would leave the signature-required case resting on the verification path rather
than on the credential binding.

### R1-B: presence records for two optional parents, plus the validator

**Ruled.** A presence record for each affected optional parent, tag `b`, **and**
the R1-C validator rules. Gate 2 requires the *encoding* to be injective, so
that property must not depend on the validator behaving.

**Two parents are affected, not the three the candidate fix named.** Verified by
execution at `4225489`:

| Parent | Absent | Present `{}` | Presence record |
|---|---|---|---|
| `resource` | admitted | admitted | **Required** |
| `tenant`, system-scoped family | admitted | admitted | **Required** |
| `control_lineage` | admitted | refused | Not required |

`control_lineage` needs none, because `validateEventEnvelope` already requires
`control_origin` and `policy_generated_effect` when it is present, so a present
empty one cannot pass.

The validator-only alternative is refused as insufficient. For `resource` it
cannot work alone, because `validateEventEnvelope` never reads `resource` at any
depth today.

### R1-C: type-validate every declared field, and compare types in the drift test

**Ruled.** `validateEventEnvelope` type-validates **every declared field**, and
the R-5 drift test compares **types as well as names**.

Measured at `4225489`: a wrong-typed value is admitted in **18 of 18** declared
optional fields, because the validator never reads `resource` at any depth,
never reads `integrity.signature` or `integrity.signature_key_id`, never reads
`control_lineage.sentinel_finding_ids`, and never reads `tenant.account_id`,
`actor.session_id`, `actor.api_key_fingerprint`, `correlation.run_id`,
`correlation.parent_event_id`, `location.region` or `location.country`.

Two reasons for the full scope. The encoder must refuse an unencodable value in
any case, so a permissive validator only turns a clean validation error into a
runtime `envelope_not_encodable` rejection — review finding F5's contract-valid
but unencodable class. Validating up front makes "passes validation, therefore
encodable" an invariant that S1 and S2 rely on. And a drift test that compares
names only lets a later change loosen a type and reopen F1 without failing CI.

## Amendment 3: the bound record count, 41 to 43 (D-2, by R1-B)

Ruling D-2 fixed the bound set at 41 records, "the 41 fixed records plus one
record for each control-lineage finding id". R1-B adds a presence record for
`tenant` and one for `resource`, so the fixed count becomes **43**.

D-2 also said a future authenticated field needs a versioned format change. That
clause is not triggered here. These two records correct a defect that review
found in an unimplemented format, before any producer emits it. There is no
installed base and nothing to version, consistent with the no-backwards-
compatibility rule in `CLAUDE.md`.

Three artifacts go stale with the count, and slice S1 owns all three: the
worked example in `01` (41 records, 1479 bytes), its byte count, and the golden
vector. The round-1 reviewer reproduced the 1479-byte value byte for byte, so
the regenerated example needs the same independent reproduction.

### R1-D: a separate change carries `src/spine/ledger.ts`, before S4

**Ruled.** A separate authorized change carries the `src/spine/ledger.ts`
defects. It is sequenced **before** S4, and not after, because gate 5 must have
an implementable foundation when S4 records the rejection-record shape.

That change carries four defects: `KI-SENTINEL-20261102-011`,
`KI-SENTINEL-20261102-012`, `KI-SENTINEL-20261102-016` and review finding F34.

The reason to separate them: three of the four are not authentication defects.
`-011`, `-016` and F34 are reachable or latent independently of envelope
authentication, so they do not wait on the six open format decisions.
Separation also keeps S4 reviewable as an authentication change, and it keeps
the reproduce-first evidence stage in recommendation 2 free of ledger failures.

This ruling settles the question that the `src/spine/ledger.ts` row in
`03_COMPATIBILITY_AND_CALLER_IMPACT.md` deferred.

**This is not implementation authorization.** The separate change needs its own
explicit authorization, as every slice does.

### R1-E: an unauthenticated record carries no top-level `tenant_id`

**Ruled.** The omission rule, with the observed value held in metadata.

- A ledger record of unauthenticated provenance carries **no top-level
  `tenant_id`**.
- The claimed tenant stays inside the recommendation-1 metadata block, as an
  explicitly named observed value.
- No query path filters on that value.
- `LedgerRecord` gets **no** new top-level provenance field.

Why: `tenant_id` is optional already, so omission needs no shape change. An
absent field cannot be filtered into a victim tenant's view, so the rule is
fail-closed by construction. A second tenant-like top-level field is the trap
that review finding F34 names, because a later reader filters on it.

Verified by execution at `79698ac`. A rejection record with no `tenant_id`
returns 0 records from `queryByTenant` for the claimed tenant, stays visible to
`all()` for a system or auditor reader, and keeps the field absent through
`appendCorrection`.

**Amendment to R1-E as worded.** R1-E said "a rejection record carries no
`tenant_id`". That wording does not reach `KI-SENTINEL-20261102-016`, because
the cross-tenant denial record is not a rejection: the ledger stores it with
`validation: "accepted"` and `kind: "event"`. The ruling therefore binds on
**unauthenticated provenance**, and not on the `rejection` kind. It extends to
the `kind` and the `validation` labels, because the damage in `-016` comes from
a record that falsely claims to be an accepted event.

## Findings disposition

| Finding | Owner disposition | Effect on this track |
|---|---|---|
| `KI-SENTINEL-20261102-006` | A hard prerequisite. It must not be closed on passing tests alone. The corrected digest semantics and its negative tests must be verified. | Slice S0. Envelope authentication must not rely on the payload digest until that verification exists. |
| `KI-SENTINEL-20261102-009` | Accepted as a separate security-relevant integrity defect, not an encoding cleanup. A collision that silently drops a legitimate event threatens the reliability of the evidence ledger. | Slice S7, immediately after this track. It reuses the encoder where that is safe. The finding record carries the ruling. |
| `KI-SENTINEL-20261102-010` | Accepted as a documentation and verification-tool defect. A command that reports success while it rejects every fixture is misleading. | A separate change. It corrects the exit status and the documentation. Not part of this track. |

## Authorization boundaries

Three boundaries, in order. Each needs its own explicit authorization.

1. **Design review.** This plan set, revised with these rulings, goes to
   independent review. PR #32 was kept in draft for that, then merged on the
   owner's instruction as `79698ac`. Round 1 is complete and its verdict is
   "not safe to proceed to implementation authorization as written", so this
   boundary is **not** cleared: a second round follows the owner's rulings on
   the candidate fixes. Merging the documentation did not clear it.
2. **Implementation authorization.** Each slice in `05` needs the owner's
   explicit authorization. Design approval is not implementation authorization.
3. **Production deployment authorization.** Separate again. The gateway stays
   shadow-only, with no network ingress, until the correction is implemented
   and independently verified.

## Evidence standard

402 passing tests establish that the existing suite passes. They do not
establish that authentication is secure. The demonstrated envelope alterations
are stronger evidence than the green CI result. The negative-test matrix in
`04` exists to close that gap, and it closes it only when the cases fail
against the base commit first.
