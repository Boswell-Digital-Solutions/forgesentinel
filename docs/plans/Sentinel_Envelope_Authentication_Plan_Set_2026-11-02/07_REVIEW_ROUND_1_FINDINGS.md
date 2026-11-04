# 07 Independent Review, Round 1

- **Date:** 2026-11-02
- **Reviewed:** the plan set at `568b97d`, plus the live source at that head
- **Reviewer:** an independent session with no exposure to the plan author's reasoning. It was given the plan set, the source, the owner's six binding requirements, the five implementation gates and the owner's six review axes.
- **Verdict:** **not safe to proceed to implementation authorization as written.**
- **Status:** No pull-request review is submitted on GitHub. This document is the review of record. The owner ruled that it satisfies recommendation 3 (R1-H, answered by ruling 3 in `06`).

The reviewer implemented the format from `01` and reproduced the worked example
byte for byte — 41 records, 1479 bytes — before making any claim, so the
collisions below are defects in the specification and not transcription errors.

The plan author re-verified every blocking finding by execution before
recording it here. Each row below says so.

## What round 1 confirmed as sound

These were attacked and held:

- **The length-prefix core.** A separator byte moved between adjacent fields, a
  value containing a complete later record, a present empty string against an
  absent field, and a two-byte character against two ASCII characters at equal
  byte length all give different bytes. A lone surrogate is refused rather than
  folded to `U+FFFD`.
- **The HKDF parameterization.** `hkdfSync` argument order is right, RFC 5869
  test vector A.1 reproduces exactly through it, the two derived keys are
  distinct, and `"credential|"` against `"signature|"` cannot collide for any
  key id. The stated limit — that HMAC leaves the gateway able to forge either
  value — is accurate.
- **The account of the original defect.** All 26 rows of the verified-behaviour
  table in `00_README.md` reproduce, including the three governing results:
  one token for two different events with the same payload, event B accepted
  with event A's credential, and the signature byte-identical to the token.
- **Every line-number citation** in the plan set lands where the plan says.
- **The no-installed-base argument.** No implementation of the producer token
  exists in the other 62 checkouts; every hit is a comment or a plan file.
- **Authorization hygiene.** The reviewer looked for an implicit implementation
  authorization or a claim that CI is security evidence, and found none.

## Blocking findings

| # | Finding | Re-verified | Where it is recorded |
|---|---|---|---|
| F1 | `control_lineage.sentinel_finding_ids` type confusion collides. `["a","b"]`, `"ab"` and `{0:"a",1:"b",length:2}` encode identically, and `validateEventEnvelope` admits all three. The spec refused only a bad array **element**, never a non-array. | Yes. All three validate; `length`, `[0]` and `[1]` are identical for the first three. | `01`, the encoder failure rules; ADV-H11 and NEG-L03 in `04` |
| F2 | An absent optional parent object and a present empty one encode identically. `resource` absent against `resource: {}` — both valid, both accepted, same bytes. The same holds for `tenant` on a system-scoped family. | Yes, including the gateway accepting `resource: {}` with the original credential. | `01`, the absent-field section; ADV-H10 and NEG-L04 in `04` |
| F3 | `integrity.signature` and `integrity.signature_key_id` are admitted, unbound in the credential context, and unverified on an event that needs no signature. | Yes. A 64-character bogus signature with `signature_key_id: "key_attacker"` was accepted and stored; so was a non-hex signature with a numeric key id. | `01`, "Ruling R1-A, settled in the design"; `KI-SENTINEL-20261102-014`; ADV-H08 and NEG-L02 in `04` |
| F16 | ADV-H08 documented one of those collisions as correct behaviour, on the false premise that the strict validator would refuse the pair. Both are known fields that the validator never reads. | Yes, by F3. | `04`, ADV-H08 rewritten |
| F30 | `06` stated as verified that the rejection record does not hold the credential. The token does not, but `credential.service` and `credential.key_id` are interpolated into the failure message, which reaches the ledger **and** the caller. Both are unbounded, unvalidated input. | Yes. A 200-character `key_id` with a NUL byte reached both; the caller message was 259 characters. | `06`, gate 5 corrected; `KI-SENTINEL-20261102-013`; EVD-K09 in `04` |
| F31 | `cloudProjection` returns a rejection record's whole body before any data-policy check, so a `restricted`, `content_included: true`, `cloud_allowed: false` payload is published in full whenever an event is rejected. The same payload on an accepted event is correctly suppressed. | Yes. The projection of the rejection contained the manuscript string and the API key; the accepted event projected `null`. | `KI-SENTINEL-20261102-011`; EVD-K10 in `04`; `03` scope |
| F32 | EVD-K07 was written as a comparison, so it passes against today's code, which treats both classifications identically by publishing both. | Yes, by F31. | `04`, EVD-K07 given an absolute predicate |
| F33 | A rejection takes `tenant_id` from the unauthenticated envelope and `queryByTenant` trusts it, so a forged tenant id puts an attacker-chosen record in a victim tenant's evidence view. `src/spine/ledger.ts` was not in the plan's file scope, so the gate-5 cases were unimplementable. | Yes. `queryByTenant("ten_victim", …)` returned the forged rejection. | `KI-SENTINEL-20261102-012`; `03` scope; EVD-K11 in `04` |

## Should-fix findings applied to the plan

| # | Finding | Applied in |
|---|---|---|
| F4 | The unknown-field refusal must cover every bound object, not only the top level. Only `03` said so. | `01`, ADR-027 |
| F5 | `validateEventEnvelope` admits wrong-typed bound fields, creating a contract-valid but unencodable class the plan did not close. | `01`, numeric section; R-5 in `05` |
| F6 | The `c` tag had no canonical form, and `key_id` has no character set. | `01`, the tag table |
| F7 | R-5's drift test is unimplementable without a named exclusion list, and that list is where F3 re-enters. | R-5 in `05` |
| F8 | `02` claimed the registry refuses a key id two producers share. It does not; only the secrets-file loader does. | `02`, the algorithm section; D-9 safeguard 1 |
| F9 | The salt justification claimed the production rules enforce entropy. They check length and variety, and are skipped outside production and staging. | `02`, the parameter table |
| F10 | `L = 32` was justified as the "block security level". It is the output length. | `02`, the parameter table |
| F11 | The spec did not say whose `key_id` derives `K_signature`, and the gateway compares `signature_key_id` inside the same condition as the verification. | `02`, the parameter table and the verification points |
| F12 | `forge_contract_core` **accepts** and normalizes the JSON token `-0`; only `-0.0` is refused. Refusing it here is a deliberate stricter divergence, not an alignment. | `01`, numeric section |
| F13 | The duplicate-key rule cannot be enforced at the validator: `JSON.parse` discards duplicates first. It needs a raw-text scan at intake. | `01`, numeric section |
| F14 | "No bound envelope field carries a number from the event" is false of what the envelope admits, and a rule was omitted on the strength of it. | `01`, numeric section |
| F17 | Gate 2's property suite would pass against an implementation with no length prefix at all, and PROP-H02 was PROP-H01's contrapositive. | `04`, PROP-H02 replaced by a decoder round trip |
| F18 | Ten cases already pass at the base commit and prove nothing about envelope authentication, and three were counted toward a gate. | `04`, controls marked and removed from coverage |
| F19 | ORD-J03 is structurally vacuous: a rejection is invisible to the detectors whether or not authentication works. | `04`, ORD-J03 marked a control |
| F20 | Eight attacks had no case, including the obvious one: change the payload and recompute the hash. | `04`, group L |
| F21 | EVD-K01's "no part of the presented token" is untestable. | `04`, exact predicate |
| F22 | Gate 1's grep is the wrong instrument, because `producerToken` keeps its name with a changed meaning. | G9 in `05`, now a nominal type |
| F23 | `04` said "four of five gates", and its coverage index omitted EVD-K06 to K08. | `04`, both corrected |
| F25 | `03` gave a false reason for the directive fixtures not changing: the generator writes 64 zero characters and never imports `src/authority/`. | `03`, fixture table |
| F34 | "An observed, untrusted value" is not representable: `LedgerRecord` has no provenance field, and `tenant_id` is the access-control field. | `06`, gate 5; `03` scope |
| F36 | A digest only identifies a payload the operator already holds, so for a novel attack payload the evidence is gone; and the permitted metadata still includes `actor.api_key_fingerprint`. | R-12 in `05` |

## Findings recorded as current-code defects

Five findings are defects in the code at `origin/master`, not in the plan. They
are recorded in `docs/KNOWN_ISSUES.md` and each was re-verified by execution:

| Finding | Entry |
|---|---|
| F31 | `KI-SENTINEL-20261102-011` — the rejection cloud projection skips every data-policy check |
| F33 | `KI-SENTINEL-20261102-012` — a rejection's tenant id comes from the unauthenticated envelope |
| F30 | `KI-SENTINEL-20261102-013` — the failure message copies unbounded credential text into the ledger and the caller |
| F3 | `KI-SENTINEL-20261102-014` — an unverified signature is stored as accepted evidence |
| F26 | `KI-SENTINEL-20261102-015` — the de-duplication map is not rebuilt, so a verbatim replay is accepted by a fresh process |

## Process finding

**F0.** The plan set was edited three times while the reviewer was reading it,
and three test cases and a whole section appeared mid-review. The reviewer
froze a snapshot and cited it throughout, and confirmed `MANIFEST.md` was
self-consistent at that snapshot. The lesson stands: a review cannot be signed
off against a target that changes under it. **Round 2 must run against a frozen
commit, named in this document before the review starts.**

## Open design decisions for the owner

Round 1 does not propose rulings. These are the decisions it surfaced.

**Two are ruled (2026-11-02): R1-D and R1-E.** `06` holds both rulings, and an
amendment to R1-E's wording, which did not reach the denial record in
`KI-SENTINEL-20261102-016`. R1-A, R1-B and R1-C followed on the same day, and
ruling 3 in `06` later answered R1-H, so **six are ruled and two stay open: R1-F
and R1-G**. The table below gives each one. Amendment 3 in `06`
supersedes D-2's bound record count of 41 and states no replacement (which the regeneration of `01` (2026-11-04) later derived: 46 fixed records), because
R1-B adds three parent presence records and R1-A's binding added a number
unsettled at the time.

Round 1's findings and its verdict are unchanged by those rulings. The verdict
stands: not safe to proceed to implementation authorization as written. The
rulings say what the corrections are. No correction is implemented, so F1, F2
and F3 are settled in design and open in fact.

| ID | Decision |
|---|---|
| R1-A | **RULED, see `06`.** F3: refuse `integrity.signature` and `signature_key_id` on an event that needs no signature, or bind both in every context. Ruled: **both**, because binding alone leaves `KI-SENTINEL-20261102-014` open. |
| R1-B | **RULED, see `06`.** F2: add a presence record for each optional parent object, or refuse a present empty parent in the validator. The first keeps injectivity in the encoding. Ruled: presence records **and** the validator rules, for **all three** optional parents — `tenant`, `resource` and `control_lineage`. An earlier draft exempted `control_lineage` because the validator already refuses a present empty one, and the owner rejected that exemption, since it rested on the validator behaving — the dependency the ruling forbids. |
| R1-C | **RULED, see `06`.** F1 and F5: how far the validator's type rules go, and whether the drift test compares types as well as names. Ruled: **every declared field** is type-validated, and the drift test compares types as well as names. Measured at `fee3125`: the admit count is **conditional on the family scoping and on `control_origin`**, and it runs from 14 to **18** of 51 declared fields; the optional-field part is 15 of 17 on `operator` and `standing_policy`, and 12 of 17 on `sentinel_policy`. Two earlier figures were stated flat and are superseded: "18 of 18", which conflated a probe count with a field count, and "15 of 17", which named one scenario. `06` holds the matrix, the two reasons and the three method rules. **Three further rulings followed on the same day**, all in `06`: that measurement is a baseline and not a test inventory, so S2's scope is all **51** declared fields; that `integrity.signature` gets syntax validation for encoding, length and canonical form, and not a string-type check alone; and that sequencing against S6 is a staged implementation dependency, so S2 may be implemented before S6 only while its contract validation stays fail-closed. The third was challenged on 2026-11-03 as an invented ruling and **upheld**: the owner issued it on 2026-11-02 and re-confirmed it, and `06` holds the provenance. "May be implemented before" is an ordering constraint and not permission to begin. Neither S2 nor S6 gained authorization. |
| R1-D | **RULED, see `06`.** F33, F31, F34: whether this track carries the `src/spine/ledger.ts` changes, or a separate authorized change does. Gate 5 cannot be met without them. Ruled: a separate change, as slice SL, sequenced before S4. |
| R1-E | **RULED, see `06`.** F34: a new `LedgerRecord` provenance field, or a rule that a rejection record carries no `tenant_id`. Ruled: the omission rule, bound on unauthenticated provenance rather than on the `rejection` kind, with the claimed tenant held in metadata. |
| R1-F | F12: confirm that refusing `-0` is a deliberate divergence from `forge_contract_core`, and accept the ADR-025 cross-language consequence. |
| R1-G | F13: which boundary enforces the duplicate-key rule, given that `JSON.parse` discards duplicates. |
| R1-H | **RULED, see `06`.** Whether this document satisfies the owner's recommendation 3, or a submitted GitHub review is required as well. Ruled: the owner authorized the independent design review without requiring a submitted GitHub review, so this document satisfies recommendation 3. Round 1 stays the review of record. A second review round is still required. |

## What round 2 must cover

1. The ruled fixes for F1, F2 and F3, re-attacked. R1-A, R1-B and R1-C name
   them, so round 2 attacks a corrected design and not a candidate. In scope:
   the three parent presence records, the R1-A binding and refusal, the R1-C type
   rules, the regenerated field table, the worked example and the record count,
   all produced by the design-stage regeneration of `01` that the owner ruling on `KI-SENTINEL-20261104-001` in `06` (2026-11-04) requires before round 2.
   Round 2 reviews the corrected `01`, not a running implementation — an earlier
   draft said round 2 needed slices S1 and S2 to exist, which contradicted the
   authorization boundaries in `06`.
2. The decoder round trip that replaces PROP-H02.
3. The gate-5 record shape against `src/spine/ledger.ts`. The shape is no longer
   "once chosen": ruling 1 fixed it at five elements, and **ruling 5 extends it
   to every pre-authentication failure**, with the five-element record as a
   maximum rather than a template. So round 2 must check each
   pre-authentication failure class, not only `producer_auth_failed`. R1-D moves
   that file to slice SL, before S4, so round 2 assesses the shape against SL
   and not against this track.
4. The ruled `KI-SENTINEL-20261102-017` correction: an injective composite-key
   encoding for the registry key, plus independent verification of both identity
   fields after the lookup. Ruling 6 forbids resting the fix on a field pattern
   alone, so round 2 must check that the encoding and the post-lookup checks are
   what carry it.
5. **A frozen commit, named before the review starts.** Ruled by the owner on
   2026-11-02, together with an independent adversarial assessment.

### Round 2: the frozen commit (named 2026-11-04)

**Round 2 reviews commit `3cae2dd` (`3cae2dd560ba20e69b6249f21cb2174db13e8f4d`)**, `master` after pull
request #47. That commit carries the regenerated `01`, its derivation script, and the corrections
of the four-lane retest (`KI-SENTINEL-20261104-007`). The review reads those bytes and no later
ones: a change merged after `3cae2dd` is not under review, and a finding that a later commit already
corrects is still reported against `3cae2dd`.

**Authorization.** The operator authorized round 2 on 2026-11-04 in these words: "proceed —
tentatively authorized". The authorization is recorded as tentative. It covers naming this commit
and commissioning the independent review. It decides none of the open owner decisions — R1-F, R1-G,
and `KI-SENTINEL-20261104-004` to `-006` — and it authorizes no implementation.

**Order, per the process finding above.** The reviewer first reads the current
`docs/KNOWN_ISSUES.md` and this document, then reviews `3cae2dd`. Round 2's findings become a
document of record in this plan set, as round 1's did.

**Round 2 ran on 2026-11-04** against `3cae2dd`. Its findings are `08_REVIEW_ROUND_2_FINDINGS.md`:
verdict **safe to proceed to implementation authorization with the conditions listed**, with two
blocking findings that hold slices SL, S2, S3 and S4 (not the S1 encoder). **The owner accepted `08`
as the round-2 review of record on 2026-11-04, and cleared authorization boundary 1 conditionally,
for S1 only** (`06`, owner disposition on review round 2).

### Why the frozen commit is a ruling and not a preference

A second adversarial review ran against `e0a4b52` after round 1. It found no
defect that round 1 had not already found. Its findings mapped one to one onto
F1, F2, F3, F5, F6, F8 and `KI-SENTINEL-20261102-015` — all already recorded,
and five already ruled on by the owner.

Two causes, both avoidable:

1. The review did not begin by reading the latest authoritative findings. Round 1
   and the rulings were already on `master`.
2. The revision under review was not frozen or announced. The plan set moved four
   pull requests ahead while the review ran, so the reviewer assessed text the
   repository had already corrected.

So a review now starts with two steps, in this order: **read the current
`docs/KNOWN_ISSUES.md` and the current review of record**, then **name and
freeze the commit under review**. A review that skips the first step re-derives
known findings and reports them as new. That costs effort, and it can read as
independent confirmation when it is an echo.

One finding did come out of that review, `KI-SENTINEL-20261102-017`, because it
sat beside round-1 finding F8 rather than inside it. That is the yield to expect
from a duplicated review: the margin, not the body.
