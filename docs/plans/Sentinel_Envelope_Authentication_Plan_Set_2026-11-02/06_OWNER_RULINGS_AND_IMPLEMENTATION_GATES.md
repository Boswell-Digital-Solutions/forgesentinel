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
| D-2 Bound field set | **Approved; the count is superseded by R1-A and R1-B** | Bind all fixed records plus one record for each control-lineage finding id. **The count of 41 is superseded, and amendment 3 states no replacement**: R1-B adds three parent presence records, and R1-A's binding adds an unsettled number more, so the total is not yet derivable. The design-stage regeneration of `01` derives it before round 2 (the ruling on `KI-SENTINEL-20261104-001` below). A future authenticated field needs a versioned format change; this correction does not trigger that clause. | Amendment 3 below. The field table in `01` is stale and still shows 41 rows. |
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

Every failure **before successful authentication** must produce protected
security telemetry. The telemetry must not expose a credential or a sensitive
payload.

The gate was first written for an authentication failure alone. Ruling 5 of
2026-11-02 extends it to every pre-authentication failure, on the principle that
a malformed envelope is not more trustworthy than one with an invalid token. The
five-element record below is the **maximum allowable shape** for all of them,
and untrusted tenant information must not control routing, storage or evidence
visibility.

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
  **No longer open: ruled on 2026-11-02.** The owner ruled a payload-free,
  fail-closed quarantine record, narrower than recommendation 1. See "Ruling 1"
  below for the five permitted elements and the two prohibitions. The slice no
  longer chooses the record shape; it implements the ruled one, and
  `doc/system/03-runtime-boundary.md` must describe it. The `tenant_id` part was
  already closed by R1-E, and the ruling extends it from storage to routing.
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

## Owner recommendations, now ruled (2026-11-02)

> **All four recommendations below are RULED as of 2026-11-02.** See
> "Owner rulings on the four recommendations" after this section. The
> recommendation text is kept because the rulings refer to it, and because
> ruling 1 **tightens** recommendation 1 rather than adopting it unchanged.

The owner checked PR #32 on GitHub and recorded four recommended rulings.
**At the time they were recommendations, not approvals.** The owner stated so
explicitly. They did not authorize implementation, and the ten rulings above
were unaffected by them.

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

## Owner rulings on the four recommendations (2026-11-02)

The owner ruled all four recommendations, and stated the dispositions as a
table. The ruling opens with the principle that **green documentation CI does
not establish security approval.**

| Item | Disposition |
|---|---|
| Independent design review | **Authorize** |
| Gate 5 rejection records | **Payload-free, fail-closed quarantine** |
| S3/S4 ordering | **Approve the combined pull request, with separately demonstrated negative tests** |
| S0 / `KI-SENTINEL-20261102-006` | **Require an independently verified digest correction** |
| S1 to S5 | **Hold**, pending review and the prerequisites |
| Plan registry | **Follow the authorized `forge` change process** |
| PR #32 merge | **Hold** |

The ruling restates one binding requirement from the first ruling: the newly
discovered mutable fields must be **either authenticated or explicitly excluded
with a documented security justification**. There is no third category.

### Ruling 1: the quarantine record is narrower than recommendation 1

The owner ruled a **payload-free, fail-closed quarantine** record, on the
principle: **never trust an unauthenticated envelope's classification labels.**

For an authentication failure the record holds only these five things:

| Element | Source |
|---|---|
| A receipt timestamp | The gateway's own trusted clock. Never `occurred_at` or `observed_at`. |
| A rejection identifier | Generated by the gateway. Never `event_id`. |
| The failure reason | `producer_auth_failed`, plus one internal category from the closed set in `02`. |
| Bounded non-sensitive diagnostics | A fixed, bounded set. Not free-form envelope content. |
| A digest of the received bytes | So an operator can match a rejection to a known event. |

Two prohibitions come with it. The record **must not** persist the untrusted
payload, and the gateway **must not** use the envelope's purported tenant
information for routing.

**This is narrower than recommendation 1, and the difference matters.**
Recommendation 1 retained "the permitted non-payload envelope metadata". The
ruling does not. Envelope metadata is replaced by a fixed, bounded diagnostic
set, because the envelope's `data_policy`, `tenant` and `actor` labels are all
attacker-chosen on an unauthenticated event. Retaining the envelope retains
attacker-chosen metadata, which is the defect rather than the fix.

The three constraints in recommendation 1 survive unchanged, and the second one
still applies: the digest is an **observed, untrusted** value, and the record
must identify it that way. A matching digest is not evidence of authenticity.

This closes the open design item under gate 5. Group K in `04` must assert the
chosen shape, including the untrusted label on the digest. The slice no longer
chooses the shape; it implements this one.

**Consistency with R1-E.** R1-E already ruled that a record of unauthenticated
provenance carries no top-level `tenant_id`. This ruling is consistent with it
and goes further, because it also forbids *routing* on the purported tenant,
not only storing it.

**What the gateway does today, measured.** `src/spine/gateway.ts` has **ten**
`this.reject(` call sites. **Eight** pass `event.tenant?.tenant_id`. **Two**
pass `undefined`: line 140, the contract-validation failure, and line 175, the
`tenant_required` refusal. Counted with
`grep -n "this\.reject(" src/spine/gateway.ts` at `58723e2`.

An earlier version of this section said the gateway interpolates the purported
tenant into *every* rejection, and that *each* failure path passes it. Both are
false, and an independent reviewer caught them. The correction matters in a
specific way: the contract-validation path — the one ruling 5's rationale
leans on hardest — is already one of the two that pass `undefined`. So the
authentication paths are the weaker ones here, not the contract path.

The work is therefore narrower than the earlier text implied: eight call sites
change, not ten, and the two that already pass `undefined` are the model. Slice
SL carries the ledger side under R1-D.

**This case is now settled — see "Ruling 5" below.** An earlier version of this
section left open whether the quarantine shape governs a **contract**-failure
record, which happens before authentication. The owner ruled on 2026-11-02 that
it does, and that the rule reaches **every** pre-authentication failure. The
slice no longer raises it.

### Ruling 2: the combined pull request structure is approved; implementing it is not

**What is approved is the shape of the change, not permission to make it.** The
owner clarified this on 2026-11-02, because the earlier wording approved "the
combined pull request" while S1 to S5 were held, and a reader could take the
first as overriding the second.

Stated as two separate things:

| Question | Answer |
|---|---|
| May S3 and S4 arrive as one pull request, rather than two? | **Yes.** The arrangement is approved. |
| May anyone write, open or merge that pull request now? | **No.** Implementation and merge authorization are withheld. |

So the combined-PR arrangement is the approved structure **for when
implementation is authorized**. It is not itself an authorization. Approval of a
structure never implies permission to build it, and the S1-to-S5 hold is
unaffected by this ruling. Each slice still needs its own explicit
authorization, and the required security gates must be satisfied before a merge.

The condition on the structure: the reviewer captures evidence that the negative
tests **fail against the vulnerable baseline** and **pass against the corrected
implementation**, and that evidence is **preserved as a review artifact**.

So the five-step procedure in recommendation 2 stands, with step 2 now binding
rather than advisory, and with one addition: the reproduction record is an
artifact that outlives the review conversation. A combined pull request that
shows only a green result does not satisfy this gate. The artifact must show
both runs.

### Ruling 3: the independent design review is authorized

Authorized, and round 1 is the review of record. This also answers **R1-H**:
the owner authorized the review without requiring a submitted GitHub
pull-request review, so `07_REVIEW_ROUND_1_FINDINGS.md` satisfies
recommendation 3.

A second review round is still required after the plan set is corrected,
because round 1's verdict was *not safe to proceed to implementation
authorization as written*.

### Ruling 4: S0 stays a hard prerequisite, verified

Unchanged from recommendation 4, now ruled. The corrected payload digest **and
its adversarial tests** must be independently verified before envelope
authentication relies on the digest. Merging S0 alone is insufficient.

## Owner rulings on the PR #39 review (2026-11-02)

**Provenance, stated exactly.** The owner inspected PR #39 through GitHub and
reported its state — open, draft, mergeable, documentation-only, head
`361b7e6`, four changed files — then **recorded this third set of rulings in the
operator session, not on the pull request.** No GitHub comment and no GitHub
review was submitted on PR #39: `gh pr view 39 --json comments,reviews` returns
zero of each. That is consistent with the rest of this track, where `06`
already records that no GitHub review has ever been submitted.

So the durable artifact for these rulings is this document and the matching
entry in `docs/KNOWN_ISSUES.md`. A reader who looks for them on the pull request
will not find them. An earlier version of this section said "the owner reviewed
PR #39 on GitHub and recorded a third set of rulings", which misstated where the
rulings were recorded; an independent reviewer caught it, and this is the
correction.

The disposition is: **accept the security direction, retain the new finding, and
keep the implementation hold.** Two further rulings close the two items that
PR #39 had left open or unclear.

| Item | Ruling |
|---|---|
| PR #32 history | **Confirmed.** The merge was previously authorized and recorded. |
| Gate 5 | **Accept** the stricter five-element quarantine model. |
| Contract failures | **Apply** the same fail-closed quarantine requirements to every pre-authentication rejection. See ruling 5. |
| `KI-SENTINEL-20261102-017` | **Accept** the finding. Require an explicit correction and regression tests. See ruling 6. |
| R1-F / R1-G | **Remain open.** Each needs its own separate decision. |
| Review round 2 | **Require a frozen commit and an independent adversarial assessment.** |
| PR #39 | **Remain draft** until the two additional rulings are reflected and reviewed. |
| S1 to S5 | **Continue holding** implementation authorization. |

The owner also ruled on the scope of the new finding: it is legitimate on the
documented reproduction, and it **does not justify declaring an authentication
bypass**. `KI-SENTINEL-20261102-017` states that already, and it must keep
stating it.

### Ruling 5: a contract rejection must not become an alternate security path

The principle the owner stated: **a malformed envelope is not more trustworthy
than an envelope with an invalid authentication token.**

So gate 5 extends to **every failure that occurs before successful
authentication**, not only to an authentication failure. That covers a contract
validation failure, a payload-hash mismatch, a producer-identity mismatch, an
environment-boundary refusal, an event-type refusal, a tenant-required refusal,
and an encoder refusal.

Two constraints bind all of them:

1. **The five-element record is the maximum allowable shape.** It is a ceiling,
   not a template. A pre-authentication rejection may hold less. It may never
   hold more.
2. **Untrusted tenant information must not control routing, storage or evidence
   visibility.** This is wider than the earlier wording, which named routing
   alone. All three are now closed.

The reason the earlier framing was wrong: a rejection path that keeps more of
the envelope than the authentication path becomes the cheaper way to get
attacker-chosen metadata into the evidence ledger. The weaker path then sets the
real boundary, and the stricter one is decoration.

This reaches more code than ruling 1 did, though not as much as an earlier
version of this section claimed. That text said every failure path in
`EventGateway.ingest` passes the purported tenant to `this.reject`, and that
the contract-failure paths do so before any authentication. **Both are false.**
Measured at `58723e2`: ten `this.reject(` call sites, eight passing
`event.tenant?.tenant_id`, and two passing `undefined` — line 140, the
contract-validation failure, and line 175, the `tenant_required` refusal.

So the contract path, which this rationale leaned on, already behaves. The
ruling still stands on its principle, and the principle is what makes it a
ruling: a malformed envelope is not more trustworthy than one with an invalid
token, so the rule must be stated for the whole pre-authentication class rather
than discovered path by path. But the evidence for it is the eight
authentication-side sites, not a universal defect.

Slice SL carries the ledger side under R1-D. Group K in `04` must assert the
shape for each pre-authentication failure class, not only for
`producer_auth_failed`, and it must not assume that every class is wrong today.

### Ruling 6: correct `KI-SENTINEL-20261102-017` structurally, not by pattern alone

> **Merge-order dependency.** This document **cites**
> `KI-SENTINEL-20261102-017` and does not **define** it. The finding record
> lives in `docs/KNOWN_ISSUES.md`, in a separate pull request, because the owner
> instructed that the finding records and the plan-set ruling records be split.
> **That pull request must merge first.** If this document reaches `master`
> alone, `master` carries a ruling against a finding that does not exist there,
> and the finding-id sequence holes at `-017`. An independent reviewer raised
> this; it is a sequencing constraint, not a defect in either change.

The owner accepted the finding and ruled the shape of its correction. **Do not
rely exclusively on field-pattern restrictions.** A pattern that forbids the
separator is a denylist on a value, and it constrains what a legitimate key id
may be.

The ruled correction has two parts:

1. **An injective composite-key encoding** for the registry key, so the map key
   cannot be ambiguous whatever the field values are. The one-to-one encoder in
   `01_CANONICAL_AUTHENTICATION_FORMAT.md` is the right basis, which is the same
   reasoning that ruling D-8 applied to `dedupeKey`.
2. **Independent verification of both identity fields after the lookup.** The
   resolved registration's `service` and `key_id` must each be compared with the
   credential's claimed value. The lookup succeeding is not the check.

Together these preserve flexibility in what a key id may contain while
preventing an ambiguous credential identity. A pattern may still be added, but
it is not the control.

The regression suite must include the **demonstrated colon-shift collision**:
one registration with `service: "usage-metering"` and `key_id: "a:b"`, and the
credential pair `{ service: "usage-metering:a", key_id: "b" }`, which
authenticates today and must not after the correction.

### Review round 2 requires a frozen commit

The owner ruled that round 2 needs a **frozen commit** and an **independent
adversarial assessment**. The revision under review must be pinned and named
before the review starts, so the reviewer and the author are reading the same
bytes.

This closes a real process failure. A second adversarial review ran against
`e0a4b52` while the plan set moved four pull requests ahead of it, and it
rediscovered findings that round 1 had already recorded and that the owner had
already ruled on. The process finding is recorded with the round-2 requirements
in `07_REVIEW_ROUND_1_FINDINGS.md`.

### The "PR #32 merge: Hold" line is already overtaken

The ruling table says **PR #32 merge: Hold**. PR #32 was merged earlier the
same day, as `79698ac`, **on the owner's own instruction**, and
`KI-SENTINEL-20261102-008` records that merge and what it did not do. Four
further pull requests merged after it — #33, #34, #35 and #36 — and master is
at `fee3125`.

So this is a stale line in the ruling, not a conflict between the owner and the
repository. The hold was written against the state before that merge. It is
recorded here only so a later reader of the ruling does not expect to find
PR #32 open.

The disposition that the merge **is not implementation authorization** stands,
and the merge record already states it. S1 to S5 remain held.

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
all three format defects — R1-A, R1-B and R1-C — and on R1-D and R1-E, and
later on R1-H. **Two** decisions stay open: R1-F and R1-G. The rulings are
recorded below.

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

**R1-H is ruled**, in "Ruling 3" above: the owner authorized the independent
design review without requiring a submitted GitHub review, so `07` satisfies
recommendation 3. No GitHub review has ever been submitted on this track, and
none is required. An earlier version of this paragraph called R1-H open, which
contradicted the ruling recorded in the same file.

## Owner rulings on review round 1 (2026-11-02)

Independent review round 1 surfaced eight open decisions, R1-A to R1-H, in
`07_REVIEW_ROUND_1_FINDINGS.md`. The owner ruled **six** of them — R1-A to R1-E,
and R1-H. **Two** stay open: R1-F and R1-G.

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

**The measurement, stated precisely — this is what the code does, not what
governance requires.** `EventEnvelope` and its member interfaces declare **17**
optional fields. The number of those that admit a wrong-typed value is
**conditional**, not flat: it is **15 of 17** when `control_origin` is
`operator` or `standing_policy`, and **12 of 17** when it is `sentinel_policy`,
measured at `4225489`. The matrix later in this section states both axes.

An earlier version of this paragraph gave "15 of those 17" as a flat figure,
which contradicted the rule two subsections below that the admit count "must
never be stated flat". An independent reviewer caught the contradiction; this is
the correction. The governance requirement is unaffected by the measurement:
**S2 validates every declared field regardless of what admits a wrong-typed
value today.**

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

**Three** rulings extend R1-C after the measurement correction. Each one is the
owner's. The author's supporting record follows them, and is marked.

> **Attribution challenged, and upheld. 2026-11-03.**
>
> An independent review reported the third ruling — the S2 and S6 sequencing —
> as an invented owner ruling, on two grounds: that no owner-attributable source
> in the repository carries a sequencing permission, and that the phrase "may be
> implemented before" appears nowhere else. On that report, a correction was
> merged that moved the item into the author's record, called it "never an owner
> ruling", and said its authority was withdrawn. **That correction was wrong,
> and this entry reverses it.**
>
> **The primary evidence.** The owner issued the ruling in an operator session
> on **2026-11-02 at 19:48:46Z**, in a message recorded as human-origin from the
> desktop client. His own heading was `Owner ruling — R1-C / S6 ordering`, and
> his own words were: *"Approve a staged implementation dependency, not a
> weakened validation requirement. S2 may be implemented before S6 only if its
> contract validation remains fail-closed"*, followed by the five conditions
> below and by *"This separates implementation scheduling from security
> acceptance."* The same message closed with *"S2: Remains unauthorized."* The
> five conditions in this document match that source.
>
> **The re-confirmation.** Challenged on 2026-11-03, the owner replied, at
> 05:31:30Z and in full: *"the sequencing ruling stands, I issued it"*.
>
> **Why the challenge failed, stated so it is not repeated.** Neither ground was
> evidence of invention. This file is where an operator-session ruling enters the
> repository, so a ruling's first appearance here has **no earlier repository
> trace by construction** — a search that finds none has measured only that the
> ruling is new. Every undisputed ruling on this track shows the same absence.
> The second ground, the unique phrase, is non-evidence for the same reason.
>
> **What the withdrawal cost.** Three documents were changed to say the owner
> had withdrawn an authority he had in fact issued and then re-confirmed. No
> artifact anywhere recorded such a withdrawal, so correcting an unsourced
> owner-attributed grant was done by writing an unsourced owner-attributed
> withdrawal. `KI-SENTINEL-20261102-020` records the episode and the control.
>
> **The one correct point in the challenge stands**, and is applied below:
> "may be implemented before" is an **ordering constraint and not permission to
> begin**. Slice S2 remains unauthorized.
>
> **How to challenge a ruling here.** A challenge goes to the owner, because the
> repository cannot settle an attribution question on its own. A ruling the owner
> withdraws is recorded as withdrawn, with the date and the owner's words, and
> never as an invention.

**1. The measurement is a baseline, and not a test inventory.** The measured
admit count records the state at `4225489`, and it does not define what the test
covers. Slice S2 validates **every declared field, including required nested
fields**. The count is a **range** and not a constant, so do not cite "15 of 17"
or any other single figure on its own. The matrix below states it.

**2. `integrity.signature` needs syntax validation, and not a string-type check
alone.** The field is validated against an explicitly approved representation.
The validator checks the **encoding, the length and the canonical form** against
that representation. An arbitrary hex-only rule must not go in while a
cryptographic format is unsettled. The representation comes first, and the
syntax rule follows it.

**3. Sequencing against S6 is a staged implementation dependency, and not a
weakened validation requirement.** This is the owner's ruling, issued
2026-11-02 and re-confirmed 2026-11-03; the attribution note above holds the
provenance and the challenge that failed against it.

In the owner's words: *"Approve a staged implementation dependency, not a
weakened validation requirement. S2 may be implemented before S6 only if its
contract validation remains fail-closed."* Five conditions hold:

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

In the owner's words, this *"separates implementation scheduling from security
acceptance."* The purpose is to let development continue where that is safe, and
to stop an unfinished signature contract from becoming an authentication bypass.

**Neither slice gains authorization from this ruling.** S2 stays unauthorized,
and R1-F, R1-G and the independent design boundary come first. The owner's own
message said so in the same breath as the ruling: *"S2: Remains unauthorized."*
This sequencing ruling grants S6 no implementation authorization either.

**Ordering is not permission to begin.** A reviewer read "may be implemented
before S6" as licence to start S2, and that reading is wrong. The ruling fixes
an **order** between two slices for the time when each is authorized. It
authorizes neither. That was the one sound point in the 2026-11-03 challenge,
and it is kept.

**The author's record: the declared field total is 51.** Measured at `fee3125`,
whose `src/` and `fixtures/` are identical to `4225489`. The field list came from
`src/contracts/envelope.ts` by extraction, and not by hand. `envelope.ts`
declares **51** fields: **34** required and **17** optional.

**The admit count is conditional, and it must never be stated flat.** It depends
on two envelope values. Every scenario below uses one probe for each of the 51
fields, with a positive control for each field, and it accepts a refusal only
when the refusal names the probed path.

| Family scoping | `control_origin` | Admit, of 51 | Optional | Required |
|---|---|---|---|---|
| tenant-scoped | `operator` or `standing_policy` | 17 | 15 of 17 | 2 of 34 |
| tenant-scoped | `sentinel_policy` | 14 | 12 of 17 | 2 of 34 |
| system-scoped | `operator` or `standing_policy` | **18** | 15 of 17 | **3 of 34** |
| system-scoped | `sentinel_policy` | 15 | 12 of 17 | 3 of 34 |

**18 of 51 is the worst case, and 14 of 51 is the best case.** A slice that
reports one number without both conditions reports a scenario, and not the
validator.

Two axes move the count:

- **`control_origin`** moves three optional fields. `validateEventEnvelope` reads
  `control_id`, `sentinel_incident_id` and `policy_decision_id` only when
  `control_origin` is `sentinel_policy` (`src/contracts/envelope.ts:221-225`). On
  `operator` and on `standing_policy` it never reads them, so each admits a
  wrong-typed value.
- **Family scoping** moves one **required** field. `tenant.tenant_id` is declared
  required. On a tenant-scoped family the validator reads it
  (`src/contracts/envelope.ts:152-157`). On a system-scoped family the other
  branch checks only `isRecord(tenant)` and never reads `tenant_id`
  (`:158-160`), so `tenant.tenant_id: 123` is admitted. That is the third
  admitting required field in the two system-scoped rows, and `tenant_id` is the
  tenant isolation key. **Three** families are system-scoped — `sentinel`,
  `centipede` and `yellowjacket` (`SYSTEM_SCOPED_FAMILIES`,
  `src/contracts/families.ts:29`) — which is **14 of the 119 canonical event
  types**. Count the families and the types separately here: 14 is also the
  total family count, so "14 families" reads plausibly and is wrong.
  `KI-SENTINEL-20261102-019` records this gap as a security finding, because the
  correction belongs to the validator and not to this measurement. R1-C already
  covers it, so it needs no new ruling.

The other 2 required fields that admit are `resource.resource_type` and
`resource.resource_id`. Each is reachable only through the optional `resource`
parent, which the validator never reads, so that is a parent-reachability gap
and not an optional-field gap. The 2 optional fields that always refuse are the
`tenant` and `control_lineage` parents.

**A probe count is not a field count, and this plan set does not report one.**
`01` states that rule. Three method requirements follow from it, and slice S2's
test must meet each one:

1. Seed an optional parent in a minimal **valid** shape before probing a leaf
   inside it. A naive write to `control_lineage.<leaf>` auto-creates the parent
   as `{<leaf>: ...}`, which then fails for a missing `control_origin` and a
   missing `policy_generated_effect`. That refusal says nothing about the probed
   leaf. Under `sentinel_policy` the seed must also carry valid
   `control_id`, `sentinel_incident_id` and `policy_decision_id`, because the
   validator makes all three required in that case.
2. Require the refusal to **name the probed path**. Check `issues[].path`, and
   not only `ok === false`. A refusal for another reason is not evidence about
   the field under probe.
3. Run a **positive control** for every field, and require it to validate. Where
   the fixture already carries a valid value, use that value. Synthesising one
   measures the harness: an earlier measurement set each required parent to `{}`,
   whose children then failed, and reported 8 fields as unmeasurable that are in
   fact refused correctly.

**The author's record: an approved representation already exists, per
algorithm.** `02_SIGNATURE_BINDING.md` states the text form for each algorithm,
so condition 2 is satisfiable for the current algorithm, and S2 does not wait on
S6 for it.

| Algorithm | Text form | Where | State |
|---|---|---|---|
| HMAC-SHA256 | 64 lowercase hex | `src/spine/producers.ts:62` (`HMAC_HEX_PATTERN`), applied to `integrity.signature` at `src/spine/gateway.ts:186` | Approved and enforced in code |
| Ed25519 | 128 lowercase hex | `02`, the `HMAC_HEX_PATTERN` row — recorded as an **open implementation item**, not an approved representation | **Not approved. Not settled.** |

**Two corrections to this table, 2026-11-03.**

The HMAC row previously cited `02`, "The text form stays 64 lowercase hex
characters". That sentence is in `02` under `## The credential`, and **its
subject is `credential.token`, not `integrity.signature`**. `## The high-value
signature` states no text form at all. The fact is still true for the
signature — the gateway applies `HMAC_HEX_PATTERN` to it — but the authority is
the code, not that sentence. An independent reviewer caught the misattribution.
The argument "`02` already answers it" does not survive; the code does.

The Ed25519 row previously read "Specified, not implemented", which overstated
it. `02` records the 128-hex form in the row that says `HMAC_HEX_PATTERN` "needs
a second constant, or one constant for each algorithm" — that is an open item,
not a settled representation. The owner ruled: **do not introduce an arbitrary
hex-only requirement while the cryptographic format is unsettled; the
representation must be specified first.** So S2 must not enforce a 128-hex rule,
and no document in this plan set may present one as approved.

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

**Corrected by the owner ruling on `KI-SENTINEL-20261104-001` (2026-11-04).** An earlier version
said slice S1 derives and publishes the count. The design-stage regeneration of `01` now derives it,
with the field table and the worked example, before round 2. Slice S1 implements the reviewed format.

D-2 also said a future authenticated field needs a versioned format change. That
clause is not triggered here. These records correct a defect that review found in
an unimplemented format, before any producer emits it. There is no installed base
and nothing to version, consistent with the no-backwards-compatibility rule in
`CLAUDE.md`.

Four artifacts are stale: the field table in `01`, which still has 41 rows; the
worked example in `01`, which is 41 records and 1479 bytes; the record **indices**
cited across `01`, `02`, `04`, `05` and ADR-027, which shift when records are
inserted; and the golden vector. Under the 2026-11-04 ruling the design-stage
regeneration corrects the first three before round 2, and slice S1 owns the
golden vector, which must reproduce the reviewed worked example. The round-1
reviewer reproduced the 1479-byte value byte for byte, so the regenerated example
needs the same independent reproduction.

## Owner ruling on KI-SENTINEL-20261104-001 (2026-11-04): the format is settled in design, before round 2

**Provenance.** In the operator session on 2026-11-04, the owner relayed recommended ruling text for
`KI-SENTINEL-20261104-001` (option 1 of the three that entry lists), which itself said it was "recommended
owner-ruling language, not a ruling already entered into the repository". The owner then approved it
**as written**, in the same session, and ruled the derivation method below. This section records that
approval. The principle the owner stated: *design review must approve the security contract before
implementation is permitted to realize it.*

**Disposition: option 1 — a design-stage correction, with implementation authorization withheld.**

1. **Signing contexts are defined before round 2.** The design must enumerate explicitly which
   envelope fields and contextual identifiers `integrity.signature` covers. At minimum, tenant
   identity and all security-relevant routing and interpretation context must be cryptographically
   bound, so that an otherwise valid signed event cannot be transplanted into another tenant.
2. **`01` is regenerated as a documentation-only change.** The field table, the worked example and
   the record count become prerequisites for round 2, not deliverables of slice S1. S1 may later
   implement the reviewed format. It cannot define the format retroactively.
3. **Round 2 stays a genuine independent review gate.** The reviewer assesses the complete signing
   contract, the canonicalization rules, the tenant-binding properties and the worked example before
   the design is accepted.
4. **S1 stays unauthorized.** No gateway encoder, signer, verifier or enforcement code may begin on
   the strength of this ruling.
5. **The security findings stay open.** `KI-SENTINEL-20261102-008` (P0, tenant transplant) and `-011`
   cannot be closed by documentation. Closure needs implementation evidence, negative tests and
   independent review.

**The evidence round 2 requires:**

| Evidence | Round 2 requirement |
|---|---|
| Signing coverage | Explicit inclusion rules for each field and context |
| Canonicalization | A deterministic, unambiguous signed-byte representation |
| Tenant isolation | Rejection of cross-tenant replay and transplant, defined |
| Worked example | A complete representative envelope, with the derivation of the signature input |
| Field table | Consistent with the signing rules |
| Record count | Recomputed and reconciled against the authoritative format |
| Decision traceability | R1-F and R1-G stay visibly open unless separately ruled |

**The derivation method (ruled the same day).** The byte-exact worked example is derived with a
**disposable derivation script kept in this plan set as design evidence**. It is not shipped, nothing
in `src/` imports it, and it is not wired into the gateway. The round-2 reviewer reproduces its output
independently, as the round-1 reviewer reproduced the 1479-byte example. A script that is design
evidence is not the reference encoder of option 3, which this ruling did not choose.

**A constraint the ruling states.** The precise field set and the cryptographic representation must
be established from the format contract itself. This ruling does not supply them, and they must not be
invented from its summary.

**What changes in this plan set.** S1 no longer owns the count, the field table, the worked example or
R1-A's binding contexts; the design-stage regeneration of `01` settles all four before round 2. A
regenerated table shifts the record **indices** cited in `01`, `02`, `04`, `05` and ADR-027, so the
regeneration brings them into line in the same change, or round 2 would review an inconsistent design.
The golden vector stays with S1, and it must reproduce the reviewed worked example byte for byte.

**What it does not do.** It authorizes no implementation, enforcement, deployment, credential change
or merge. It does not rule R1-F or R1-G. `KI-SENTINEL-20261104-001` stays open until the regenerated
`01` exists and round 2 can start against a frozen commit.

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
3. **Deployment authorization.** Separate again. The gateway stays shadow-only,
   with no network ingress, until the correction is implemented and
   independently verified. The workspace rule is "deployed", never "production"
   or "live", so this boundary is named for the act and not for an environment.

## Evidence standard

402 passing tests establish that the existing suite passes. They do not
establish that authentication is secure. The demonstrated envelope alterations
are stronger evidence than the green CI result. The negative-test matrix in
`04` exists to close that gap, and it closes it only when the cases fail
against the base commit first.
