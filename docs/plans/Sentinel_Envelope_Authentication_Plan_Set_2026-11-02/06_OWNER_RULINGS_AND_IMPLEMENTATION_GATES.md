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
| D-2 Bound field set | **Approved; the count is superseded by R1-A and R1-B** | Bind all fixed records plus one record for each control-lineage finding id. **The count of 41 is superseded, and amendment 3 states no replacement**: R1-B adds three parent presence records, and R1-A's binding adds an unsettled number more, so the total is not yet derivable. Slice S1 derives and publishes it. A future authenticated field needs a versioned format change; this correction does not trigger that clause. | Amendment 3 below. The field table in `01` is stale and still shows 41 rows. |
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

Round 2 is still required, and the rulings do not reduce what it must do.

**Round 2 reviews the corrected design, not an implementation.** An earlier draft
of this paragraph said round 2 could not start until slices S1 and S2 existed.
That created a circular gate: the authorization boundaries below put design
review before implementation authorization, so a round 2 that needed S1 and S2
could never start. Round 2 therefore reviews `01` once it carries the corrected
format — the three parent presence records, the R1-A binding and refusal, the
R1-C type rules, the regenerated field table, the worked example and the derived
record count. Whether a later round also re-attacks the running implementation is
a separate question, and the gate-2 proof in `04` covers that at S1.

R1-H is one of the three open decisions, and it governs whether `07` satisfies
recommendation 3 or a submitted GitHub review is also required. No GitHub review
has ever been submitted on this track.

## Owner rulings on review round 1 (2026-11-02)

Independent review round 1 surfaced eight open decisions, R1-A to R1-H, in
`07_REVIEW_ROUND_1_FINDINGS.md`. The owner ruled five of them. Three stay open:
R1-F, R1-G and R1-H.

R1-D and R1-E were ruled first, and R1-A, R1-B and R1-C followed on the same
day. A ruling settles what the correction is. It does not authorize the
correction, and it does not make the correction exist.

### R1-A: refuse the two signature fields, and bind them

**The owner's ruling.** Both measures, not one.

1. **Refuse** `integrity.signature` and `integrity.signature_key_id` on an event
   whose family requires no signature.
2. **Bind** both fields in every context where they may legitimately appear,
   with the absent tag when they are not present.

The rest of this section is the plan author's record of the supporting facts, and
not part of the ruling.

The two measures close different holes. Binding alone stops a third party adding
or altering the fields. But on a no-signature family an unverified value is still
stored as accepted evidence, so `KI-SENTINEL-20261102-014` would stay open.
Refusal closes that, because the field cannot be present at all. Refusal alone
would leave the signature-required case resting on the verification path rather
than on the credential binding.

`validateEventEnvelope` already resolves the family entry, so the condition in
measure 1 needs no new lookup.

**Two details are not settled by this ruling, and slice S1 or S2 must settle and
record them.** The refusal needs a reason code, and `unknown_envelope_field` is
the wrong one, because both fields are known — that is review finding F16's
lesson. And `01` states that the format does not bind `integrity.signature`,
because it is an output of the format, so measure 2 needs the contexts named
before the bound record count can be derived. Amendment 3 covers the second
point.

### R1-B: a presence record for every optional parent, plus the validator

**The owner's ruling.** Add a presence record for **each** optional parent
object — `tenant`, `resource` and `control_lineage` — with tag `b`, **and** apply
the R1-C validator rules.

**The owner's stated reason.** Gate 2 requires the *encoding* to be injective, so
that property must not depend on the validator behaving.

The rest of this section is the plan author's record of the supporting facts, and
not part of the ruling.

The present-empty form is admitted for two of the three parents today. Verified
by execution at `4225489`:

| Parent | Absent | Present `{}` |
|---|---|---|
| `resource` | admitted | admitted |
| `tenant`, system-scoped family | admitted | admitted |
| `control_lineage` | admitted | refused |

**An earlier draft of this section exempted `control_lineage` on the strength of
that third row, and the owner rejected the exemption.** The exemption
contradicted the ruling's own reason: it made injectivity rest on
`validateEventEnvelope` requiring `control_origin` and `policy_generated_effect`,
which is the dependency the ruling forbids. An exemption rule of that shape is
also unstable, because it changes whenever the validator changes, and R1-C
changes the validator. The ruling applies the encoder-only principle to all three
parents, so no later change to the validator can reopen F2.

The validator-only alternative was rejected as insufficient. For `resource` it
cannot work alone in any case, because `validateEventEnvelope` never reads
`resource` at any depth today.

### R1-C: type-validate every declared field, and compare types in the drift test

**The owner's ruling.** `validateEventEnvelope` type-validates **every declared
field**, and the R-5 drift test compares **types as well as names**.

The rest of this section is the plan author's record of the supporting facts, and
not part of the ruling.

**The measurement, stated precisely.** `EventEnvelope` and its member interfaces
declare **17** optional fields. At `4225489`, **15 of those 17 admit a
wrong-typed value**.

The two that hold are the `tenant` and `control_lineage` **parents**, which the
validator type-checks: `tenant: 123` and `control_lineage: "x"` both fail
validation, verified at `4225489`.

An earlier draft said "18 of 18 declared optional fields". That was wrong. It
reported a count of ad-hoc probes as though it were a count of fields. Several
probes targeted one field, two targeted fields that `EventResource` declares
**required**, and the probe set did not cover all 17. A probe count measures
nothing about field coverage, so it is not reported here.

The validator never reads `resource` at any depth, never reads
`integrity.signature` or `integrity.signature_key_id`, never reads
`control_lineage.sentinel_finding_ids`, and never reads `tenant.account_id`,
`actor.session_id`, `actor.api_key_fingerprint`, `correlation.run_id`,
`correlation.parent_event_id`, `location.region` or `location.country`. It reads
`control_lineage.control_id`, `sentinel_incident_id` and `policy_decision_id`
only when `control_origin` is `sentinel_policy`, so those three are untyped on
the other two origins.

Two reasons for the full scope. The encoder must refuse an unencodable value in
any case. A permissive validator only turns a clean validation error into a
runtime `envelope_not_encodable` rejection, which is review finding F5's
contract-valid but unencodable class. Validating up front makes "passes
validation, therefore encodable" an invariant that S1 and S2 rely on. And a
drift test that compares names only lets a later change loosen a type and reopen
F1 without failing CI.

#### R1-C, further owner rulings (2026-11-02)

Three rulings extend R1-C after the measurement correction. Each one is the
owner's. The author's supporting record follows them, and is marked.

**1. The measurement is a baseline, and not a test inventory.** The 15 of 17
figure records the state at `4225489`. It does not define what the test covers.
Slice S2 validates **every declared field, including required nested fields**.

**2. `integrity.signature` needs syntax validation, and not a string-type check
alone.** The field is validated against an explicitly approved representation.
The validator checks the **encoding, the length and the canonical form** against
that representation. An arbitrary hex-only rule must not go in while a
cryptographic format is unsettled. The representation comes first, and the
syntax rule follows it.

**3. Sequencing against S6 is a staged implementation dependency, and not a
weakened validation requirement.** Slice S2 may be implemented before slice S6
only while its contract validation stays fail-closed. Five conditions hold:

1. All **51** declared fields are inside S2's validation scope and inside its
   drift-test scope.
2. `integrity.signature` must be validated against an explicitly approved
   representation **before any event that carries it is accepted**.
3. No provisional hex-only rule is authorized, and no permissive string fallback
   is authorized.
4. If S6 establishes the final Ed25519 representation, S2 must enforce that
   representation before a signature-bearing event becomes admissible.
5. No security gate counts as satisfied by a skipped test, a deferred test or an
   expected-failing test.

This separates implementation scheduling from security acceptance. The purpose
is to let development continue where that is safe, and to stop an unfinished
signature contract from becoming an authentication bypass.

**Neither slice gains authorization from this ruling.** S2 stays unauthorized,
and R1-F, R1-G, R1-H and the independent design boundary come first. This
sequencing ruling grants S6 no new implementation authorization.

**The author's record: the declared field total is 51.** Measured at `4225489`,
with the field list extracted from `src/contracts/envelope.ts` and not written by
hand. `envelope.ts` declares **51** fields: **34** required and **17** optional.

| Measure | Count |
|---|---|
| Declared fields | **51** — 34 required, 17 optional |
| Admit a wrong-typed value | **17** — 15 optional, 2 required |
| Already refuse a wrong-typed value | **34** — 32 required, 2 optional parents |

The 2 required fields that admit a wrong-typed value are
`resource.resource_type` and `resource.resource_id`. Each one is reachable only
through the optional `resource` parent, which the validator never reads, so this
is a parent-reachability gap and not an optional-field gap. The 2 optional
fields that already refuse are the `tenant` and `control_lineage` parents.

**The author's record: an approved representation already exists, per
algorithm.** `02_SIGNATURE_BINDING.md` states the text form for each algorithm,
so condition 2 is satisfiable for the current algorithm, and S2 does not wait on
S6 for it.

| Algorithm | Text form | Where | State |
|---|---|---|---|
| HMAC-SHA256 | 64 lowercase hex | `02`, "The text form stays 64 lowercase hex characters" | Approved and enforced |
| Ed25519 | 128 lowercase hex | `02`, "Ed25519 under ADR-026" | Specified, not implemented |

`HMAC_HEX_PATTERN` is `/^[0-9a-f]{64}$/` (`src/spine/producers.ts:62`), and the
gateway applies it to `integrity.signature` today (`src/spine/gateway.ts:186`).
So the 64-hex form is not provisional and it is not arbitrary. It is the stated
form of the approved algorithm, which D-4 puts under the gateway's control.
Condition 3 therefore does not bar it. Condition 4 binds S6, and `02` already
records that one pattern constant cannot express both lengths.

**The author's record: three consequences S2 must carry.**

- **Seven families require a signature**: `billing`, `license`, `cssa`,
  `sentinel`, `operator`, `hermes` and `smith`
  (`SIGNATURE_REQUIRED_FAMILIES`, `src/contracts/families.ts:28`). A rule that
  refused every signature-bearing event would make all seven inadmissible, so
  condition 2 must be met by enforcing the HMAC form, and not by blanket
  refusal.
- **No golden event fixture carries `integrity.signature`.** The two golden
  fixtures that carry a `signature` are *directives*, which
  `validateControlDirectiveShape` validates. The three replay fixtures carry
  none. So this rule breaks no existing event fixture.
- **The constant must not be duplicated.** `HMAC_HEX_PATTERN` lives in
  `src/spine/producers.ts`, and `validateEventEnvelope` lives in
  `src/contracts/`. S2 must choose where one shared constant lives, because two
  copies drift, and risk R-5 names that drift.

### R1-D: a separate change carries `src/spine/ledger.ts`, before S4

**Ruled.** A separate authorized change carries the `src/spine/ledger.ts`
defects. It is sequenced **before** S4, and not after, because gate 5 must have
an implementable foundation when S4 records the rejection-record shape.

That change carries four defects: `KI-SENTINEL-20261102-011`,
`KI-SENTINEL-20261102-012`, `KI-SENTINEL-20261102-016` and review finding F34.

The reason to separate them: three of the four are not authentication defects.
`-011`, `-016` and F34 are reachable or latent independently of envelope
authentication, so they do not wait on the format corrections.
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

## Amendment 3: D-2's bound record count is superseded, and no new count is stated (by R1-A and R1-B)

Ruling D-2 fixed the bound set at 41 records, "the 41 fixed records plus one
record for each control-lineage finding id". **That count is superseded. This
amendment states no replacement count, because the count is not yet
determinable.**

Two ruled corrections feed it, and only one of them is countable today:

1. **R1-B** adds a presence record for each of the three optional parents, which
   is three records.
2. **R1-A** binds `integrity.signature` and `integrity.signature_key_id` where
   they may legitimately appear. `01` currently states that the format does not
   bind `integrity.signature`, because it is an output of the format. How many
   records that binding adds, and in which contexts, is not settled by the
   ruling, so the total cannot be derived from it.

**An earlier draft of this amendment stated 43, and that number was wrong.** It
counted R1-B's parents as two rather than three, and it ignored R1-A's records
altogether. The number is retracted rather than corrected, because a stated
count that no document can derive is the drift this plan set has already had to
correct twice.

Slice S1 derives and publishes the authoritative count, with the field table,
the regenerated worked example and the golden vector in one place.

D-2 also said a future authenticated field needs a versioned format change. That
clause is not triggered here. These records correct a defect that review found in
an unimplemented format, before any producer emits it. There is no installed base
and nothing to version, consistent with the no-backwards-compatibility rule in
`CLAUDE.md`.

Four artifacts are stale, and slice S1 owns all four: the field table in `01`,
which still has 41 rows; the worked example in `01`, which is 41 records and 1479
bytes; the record **indices** cited across `01`, `02`, `04`, `05` and ADR-027,
which shift when records are inserted; and the golden vector. The round-1
reviewer reproduced the 1479-byte value byte for byte, so the regenerated example
needs the same independent reproduction.

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
   boundary is **not** cleared. The owner ruled on all three format fixes on
   2026-11-02, so what remains is round 2 against the corrected `01`, with a
   frozen commit named before it starts. Merging the documentation did not clear
   it, and neither did the rulings.
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
