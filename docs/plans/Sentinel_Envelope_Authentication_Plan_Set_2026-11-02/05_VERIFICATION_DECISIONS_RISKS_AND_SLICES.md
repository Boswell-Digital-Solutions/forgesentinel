# 05 Verification, Decisions, Risks and Slices

## Verification gates

Every implementation slice must pass these gates. Run them in this order.

| Gate | Command | What it proves |
|---|---|---|
| G1 Build | `npm ci --ignore-scripts && npm run build` | The source compiles under TypeScript 5.6. |
| G2 Suite | `node --test dist/test/*.test.js` | Every test passes. The base commit `432337c` has 402 tests and 0 failures. |
| G3 Negative tests | the same command, with `test/event_auth.test.ts` present | Each case in `04_NEGATIVE_TEST_MATRIX.md` gives the required status and reason code. |
| G4 Fixture determinism | `npm run fixtures && git diff --exit-code -- fixtures` | The committed fixtures match a fresh generation. |
| G5 Fixture diff shape | a scripted check over the three replay files | Only `credential.token` and `integrity.signature` changed. No event body changed. |
| G6 Documentation | `bash doc/system/BUILD.sh && git diff --exit-code -- doc` | `doc/SNTSYSTEM.md` matches its parts. This is the documentation CI. |
| G7 Golden vector | a test that re-encodes `fixtures/golden/event_auth.v1.vector.json` | The implementation reproduces the committed bytes, digest and HMAC. |
| G8 Independent review | a review round by a reviewer who did not write the change | No blocking defect. PR #21 needed three rounds; one round is not a rule. |
| G9 No legacy credential path | the type system, plus a source check over `src/` | The authenticated bytes are a distinct nominal type, so the compiler refuses a raw string where `AUTH` bytes are required. A grep alone is the wrong instrument: `producerToken` keeps its name with a changed meaning, so `producerToken(secret, event.integrity.payload_hash)` would recreate the legacy token and pass any grep (review finding F22). NEG-E07 proves it at the gateway. |

### Gates that are not available today

`doc/system/06-verification.md` lists this operator command:

```bash
node dist/src/cli.js replay fixtures/replay/compound_account_compromise.jsonl
```

That command cannot succeed on the committed fixtures today. The committed
fixtures carry `producer.environment: "production"`. With
`SENTINEL_ENVIRONMENT=test` and the fixture secrets, the gateway rejects all 44
lines with `environment_boundary`. With `SENTINEL_ENVIRONMENT=production`, the
loader refuses the published fixture secrets and the CLI exits with code 2.
`KI-SENTINEL-20261102-010` records this. Use G2 for the end-to-end check: the
suite re-signs the fixtures with fresh random secrets through `resign`.

### What the gates do not prove

Owner requirement 6 governs this section.

- A green suite does not show that event authentication is secure. The suite
  passed 402 tests at `432337c` while the gateway accepted every change in the
  table in `00_README.md`.
- A clean review does not show it either. PRs #21, #24, #27 and #29 each
  hardened the producer boundary and each merged after an independent review.
  This defect survived all four.
- G4 proves that generation is deterministic. It does not prove that the
  generated credential authenticates the right bytes.
- Only the negative tests in `04` show that an altered event is refused, and
  only when they fail against the base commit first.

## Decisions, as the owner ruled them

The owner ruled all ten decisions on 2026-11-02. Seven are approved, D-6 is
approved with an amendment, D-7 is amended, and **D-2's bound record count is
superseded** by rulings R1-A and R1-B — see amendment 3 in `06`.
`06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` holds the authoritative record
with every condition. The summary:

| ID | Decision | Ruling | The condition that binds the implementation |
|---|---|---|---|
| D-1 | How the payload is bound | Approved | Depend on `KI-SENTINEL-20261102-006`. The corrected digest must be **verified** before envelope authentication relies on it. |
| D-2 | The bound field set | Approved; **the count is superseded** | Bind all fixed records plus one record for each control-lineage finding id. **The count of 41 is superseded by rulings R1-A and R1-B, and no replacement is stated**: R1-B adds three parent presence records, and R1-A's binding added a number unsettled at the time. The regeneration of `01` (2026-11-04) derived it: **46 fixed records**, plus one for each finding id. See amendment 3 in `06`. A future authenticated field needs a versioned format change. |
| D-3 | The rejection reason code | Approved | `producer_auth_failed` externally. Keep internal diagnostic categories, and do not leak them. |
| D-4 | Version and algorithm handling | Approved | The gateway controls both. Refuse an unsupported version. Never negotiate an algorithm from event input. |
| D-5 | Unknown envelope fields | Approved | Refuse them. Define permitted extension points, if any, in a future version. |
| D-6 | The high-value signature | **Approved with amendment** | Domain separation **and** independent derived keys for the credential and the signature. |
| D-7 | Numeric discipline | **Amended** | Define deterministic numeric canonicalization before implementation. Refuse non-finite values and negative zero. Align integers with `forge_contract_core`. |
| D-8 | `KI-SENTINEL-20261102-009` | Approved | Separately tracked, immediately after this correction. |
| D-9 | The Ed25519 order | Approved | After the format correction, with explicit algorithm-transition safeguards. |
| D-10 | The records | Approved | A short ADR, and a plan registry entry requested through the authorized `forge` change process. |

No **D-series** decision in this plan set is open. Review round 1 then raised
eight further decisions, R1-A to R1-H; six are ruled — R1-A to R1-E, and R1-H
through ruling 3 in `06` — and **two stay open: R1-F and R1-G**. `07_REVIEW_ROUND_1_FINDINGS.md` holds them. The next
boundary is independent design review, then implementation authorization for each
slice.

## The owner's implementation gates

Five gates bind the implementation. `06` states each one in full. The proof for
each lives in `04_NEGATIVE_TEST_MATRIX.md`:

| Gate | Proof |
|---|---|
| 1 No unauthenticated compatibility fallback | NEG-E07, and gate G9 below |
| 2 The canonical encoding must be injective | Group H: a seeded property suite and nine adversarial cases (ADV-H03 to ADV-H11) |
| 3 Verify before side effects | Group J |
| 4 Test tenant isolation explicitly | Group B and group I |
| 5 Preserve operational evidence | Group K |

## The plan registry request (D-10)

D-10 is approved: request the registry entry through the authorized `forge`
change process. **This pull request does not change the `forge` repository.**
The organization registry
(`forge/docs/canonical/plan_registry_v1.json`) holds one entry for this
repository today, `BDS-FS-ROADMAP-001`, with `plan_path: docs/plans`.

The requested row, for whoever makes that change:

```json
{
  "plan_id": "BDS-SNT-ENVELOPE-AUTH-001",
  "title": "Sentinel Envelope Authentication Correction",
  "version": "v1",
  "owner_repository": "Boswell-Digital-Solutions/forgesentinel",
  "scope": "repository",
  "lifecycle_status": "approved",
  "plan_path": "docs/plans/Sentinel_Envelope_Authentication_Plan_Set_2026-11-02",
  "tracking_issue": null,
  "implementation": {
    "completed_slices": 0,
    "total_slices": 8,
    "evidence_status": "missing_closeout"
  },
  "next_action": "Independent design review of the revised plan, then slice S0 (the KI-SENTINEL-20261102-006 correction, verified).",
  "blocker": "KI-SENTINEL-20261102-006 must be corrected and verified before envelope authentication relies on the payload digest.",
  "doc_system_paths": ["doc/system/03-runtime-boundary.md"],
  "last_verified": null,
  "archive": null,
  "superseded_by": null,
  "closeout_reason": null
}
```

`lifecycle_status` is `approved` under the protocol in
`forge/docs/canonical/plan_registry_protocol_v1.md`: the design is accepted and
no implementation slice is underway. It becomes `in_progress` when the owner
authorizes the first slice.

## Risks

| ID | Risk | Mitigation |
|---|---|---|
| R-1 | The encoder becomes the trust root. A defect in it is a defect in authentication. | One module, one field list, a committed golden vector, an independent review, and the negative tests written first. |
| R-2 | Enforcement before the `KI-SENTINEL-20261102-006` correction authenticates the envelope and leaves the payload malleable. | D-1, as ruled: the corrected digest must be **verified**, not only landed. Cases NEG-F06 and NEG-F07 hold the track open. The owner's disposition forbids closing `KI-SENTINEL-20261102-006` on passing tests alone. |
| R-3 | A test helper that both signs and verifies hides a defect, and every test still passes. | Rule 2 in `04`: a case builds its own input and does not call `resign` or `buildEvent` for the value under test. |
| R-4 | A producer that corrects `observed_at`, a data-policy field or a trace id after signing breaks its own authentication. | This is a producer-implementation cost, not a migration cost. No producer exists yet. State the rule in `doc/system/03-runtime-boundary.md`: sign last. |
| R-5 | A new envelope field is added later, and nobody adds it to the field list. It is then unbound and malleable. | Add a drift test: the bound field list must cover every field that `validateEventEnvelope` admits, minus a **named** exclusion list with a reason for each entry. Review finding F7 showed the test is unimplementable without that list, because `payload` (bound through record 36), `integrity.signature` and `integrity.signature_key_id` are admitted and not bound; an unstated exclusion list is exactly where finding F3 re-enters. The test must also compare leaf **types**, not only field names (review finding F5). **R1-C rules that type comparison in (2026-11-02), and R1-A shrinks the exclusion list.** Under R1-A, `integrity.signature` and `integrity.signature_key_id` are refused on a no-signature event and bound where they may appear, so they leave the exclusion list instead of sitting on it unstated. That removes the route by which F3 re-entered. `payload` stays on the exclusion list, bound through the payload-digest record. Whether it is the **only** remaining entry is for slice S2 to determine and name, because R1-C widens what the validator admits a type rule for, and because `01` described `integrity.signature` as an output of the format rather than an input to it. The regeneration of `01` (2026-11-04) settled that: the signature is bound in the `credential` context and is the absent form in the `signature` context, and `01`'s reconciliation names `payload` as the one exclusion, bound through the digest. **The drift test covers all 51 declared fields, by R1-C's further ruling.** A newly declared field with no type rule must fail the test, so the test reads the declared field list and does not hold a hand-written copy of today's 17 admissions. |
| R-6 | The Ed25519 slice changes `ProducerRegistration`, the secrets-file schema and the strength rules, which `KI-SENTINEL-20261030-002` also owns. | D-9. Do not run the two tracks at the same time. |
| R-7 | 103 fixture lines change at once, and a reviewer cannot read 103 token changes. | G5: a scripted check that only `credential.token` and `integrity.signature` changed. |
| R-8 | A real producer is built in another repository and implements the old token. | The golden vector is the cross-repository agreement. No repository implements the token today, so nothing is stranded now. |
| R-13 | The format is not injective as specified (review findings F1, F2 and F3), so gate 2 is not met and the central claim of the plan is false today. | A design round before any slice is authorized. **The owner ruled all three fixes on 2026-11-02** — R1-A, R1-B and R1-C — and `01` marks each defect in place with its ruled fix. `07_REVIEW_ROUND_1_FINDINGS.md` holds the evidence. The risk is **not retired**: a ruling is not a correction, so gate 2 stays open until slice S1 implements the fixes and review round 2 re-attacks the corrected design. |
| R-14 | The gate-5 record shape cannot be implemented inside the declared file scope, because `src/spine/ledger.ts` owns the cloud projection, the tenant filter and the record shape. | **Ruled by R1-D (2026-11-02): a separate authorized change, slice SL, carries `ledger.ts`, sequenced before S4.** `KI-SENTINEL-20261102-011`, `-012`, `-016` and review finding F34 go with it. `03` records that this track changes no line of `ledger.ts`. The risk is not retired, because slice SL is not authorized. |
| R-9 | The plan binds a fixed record list, plus one record for each finding id, so the authenticated bytes grow from 71 bytes to roughly a kilobyte or two for an event with no lineage, and more with one. | HMAC-SHA256 over a few kilobytes is not a measurable cost at this volume. **The old 41-record, 1479-byte figures are superseded** by rulings R1-A and R1-B, and no replacement is stated — see amendment 3 in `06`. The regeneration of `01` (2026-11-04) derived the count: 46 fixed records. Measured on its examples, the authenticated bytes are 1597 for the golden event and 1841 and 1908 for the constructed billing event's two inputs (corrected after review round 2, R2-F7: the earlier figures were those of a superseded example B). Slice S1 may record a timing measurement against them. |
| R-10 | Key derivation is a new step, so a defect in the `info` records or the salt gives two producers one key, or gives one value both keys. | The `info` holds four length-prefixed records (label, context, audience, key id; `02`, revised for O-2), and one module owns them. Known answers pin the output (`09`, T-18). Cases NEG-E08 to NEG-E10 prove that a wrong key fails. A test asserts that two producers with the same secret still get different derived keys. |
| R-11 | The numeric rule refuses a floating-point payload number, so a future producer that sends a decimal cost breaks. | The rule is stated before implementation (D-7), and `01` names the two admitted forms: a scaled integer and a decimal string. No committed event payload holds a non-integer number, so nothing breaks today. `doc/system/03-runtime-boundary.md` must state the rule for producer authors. |
| R-12 | Gate 5 changes what a rejection record holds, so an operator loses the rejected payload that the ledger keeps today. | The slice states the chosen shape and records the trade. The recommendation keeps the payload digest, so an operator can still match a rejected event to a **known** payload. Review finding F36 sharpened the trade: a digest identifies a payload the operator already holds, so for a novel attack payload the evidence is gone. Accept that explicitly. The permitted metadata must also be enumerated field by field, not defined by exclusion, because `actor.api_key_fingerprint` is a per-key identifier that reaches the record today. |

## Proposed slices

Each slice needs its own authorization. No slice adds ingress. The gateway
stays shadow-only throughout (owner requirement 5).

| Slice | Content | Gates | Authorization |
|---|---|---|---|
| S0 | The `KI-SENTINEL-20261102-006` correction: make the canonical form one to one, and add the D-7 numeric rule to the payload path and to `validateEventEnvelope`. **The corrected digest semantics and their adversarial tests must be independently verified**, per the D-1 condition. **Merging S0 alone is insufficient**: the verification, not the merge, is what unblocks enforcement. | G1, G2, G4, G6, G8 | Separate. It is its own finding, and its own authorization. |
| SL | `src/spine/ledger.ts`: the R1-E omission rule for a record of unauthenticated provenance; a data-policy gate for every record kind (`KI-SENTINEL-20261102-011`); the denial record's `kind`, `validation` and tenant labelling, with body validation in `events()` so no mislabelled record enters the accepted-event stream (`KI-SENTINEL-20261102-016`); and the rejection tenant id (`KI-SENTINEL-20261102-012`). | G5 | Separate, under R1-D. **Sequenced before S4.** |
| S1 | `src/spine/event_auth.ts`: the field list, the encoder, the HKDF derivation, the unit tests, the group H property and adversarial suite, and the golden vector. Nothing calls it from the gateway. **Under R1-B the fixed list gains a presence record for each of `tenant`, `resource` and `control_lineage`**, and under R1-A both signature fields are bound where they may appear. **S1 implements the reviewed format and does not define it** (the owner ruling on `KI-SENTINEL-20261104-001` in `06`, 2026-11-04). The binding contexts, the record count, the field table, the record indices and the worked example are settled in `01` by a documentation-only regeneration before round 2, and round 2 reviews them. S1 owns the golden vector, which must reproduce the reviewed worked example byte for byte. An earlier version of this row gave S1 the count, the contexts and the table; that made round 2 depend on S1, and S1 on round 2. **The owner's disposition on review round 2 (`06`, 2026-11-04) lets S1 advance to implementation authorization review; `09` is the request. S1 is not authorized.** | G1, G2, G4, G6, G7 | This track. |
| S2 | The unknown-field refusal in `validateEventEnvelope`, with tests, and the drift test from R-5. **Under R1-C its scope is all 51 declared fields** — 34 required and 17 optional — and not only the fields that admit a wrong-typed value today. **That admit count is conditional, and it must not be stated flat.** It is 17 of 51 on a tenant-scoped family and 18 of 51 on a system-scoped one when `control_origin` is `operator` or `standing_policy`, and 14 or 15 of 51 when `control_origin` is `sentinel_policy`; `06` holds the matrix and the two reasons. The baseline is not a test inventory. S2's test must seed each optional parent in a valid shape, require each refusal to name the probed path, and run a positive control for every field, because an earlier measurement that did none of those three reported two wrong numbers. **Under R1-A it refuses `integrity.signature` and `integrity.signature_key_id` on a no-signature event**, and **under R1-C it validates `integrity.signature` for encoding, length and canonical form** against the approved representation for the algorithm in force. For HMAC-SHA256 that is 64 lowercase hex, whose authority is `HMAC_HEX_PATTERN` (`src/spine/producers.ts:62`) as the gateway applies it to `integrity.signature` (`src/spine/gateway.ts:186`), and **not** the sentence in `02` about `credential.token`. **No Ed25519 representation is approved**, so S2 must not enforce a 128-hex rule: the owner ruled that the representation must be specified before any hex-only requirement goes in. A permissive string fallback is not authorized either. The drift test compares types as well as names. **S2 may precede S6 only while its contract validation stays fail-closed**, by the owner's ruling of 2026-11-02, which he re-confirmed on 2026-11-03 after a challenge reported it as invented; `06` holds the provenance and the five conditions. That ordering is not permission to begin, and S2 stays unauthorized. Every signature-bearing event stays refused unless its signature matches an approved representation. S2 also chooses and records the refusal reason code, which must not be `unknown_envelope_field`, because both fields are known (review finding F16), and it chooses where the one shared hex-pattern constant lives, because two copies drift. | G1, G2, G4, G6 | This track. |
| S3 | The negative tests from `04`: groups A to K. | G1, G3 | This track. See the note below. |
| S4 | `buildEvent`, `producerToken`, `ProducerRegistry.authenticate` and the gateway signature check use the format and the derived keys. The old payload-hash-only call signature is **removed**, not kept beside the new one (gate 1). The gate-5 rejection-record shape is recorded, with its `tenant_id` rule fixed by R1-E and implemented by SL. Fixtures regenerated. Test support updated. | G1 to G9 | This track. |
| S5 | `doc/system/` updates, the rebuilt `doc/SNTSYSTEM.md`, and the `KI-SENTINEL-20261102-008` record. ADR-027 already exists from the design phase; S5 updates its status if the implementation changes a decision. | G6, G8 | This track. |
| S6 | Ed25519 under ADR-026, with the producer-secrets file schema change and the seven algorithm-transition safeguards in `02`. | G1 to G9 | Separate. ADR-026 and `KI-SENTINEL-20261030-002`. |
| S7 | `dedupeKey` adopts the encoder (`KI-SENTINEL-20261102-009`). The owner rules this a security-relevant integrity defect, so it follows immediately and reuses the encoder where that is safe. | G1 to G6 | Separate, under D-8. |

S0 is a prerequisite, not a part of this track. The owner's D-1 condition makes
its verification, not its merge, the thing that unblocks enforcement, and
recommendation 4 in `06` restates it: merging S0 alone is insufficient, and the
adversarial tests for the corrected digest must be independently verified.

SL is a prerequisite too, by ruling R1-D. It is not a part of this track, and it
comes before S4, because gate 5 must have an implementable foundation when S4
records the rejection-record shape. Three of its four defects — `-011`, `-016`
and F34 — are not authentication defects, so they do not wait on the open
format decisions (R1-F and R1-G). The separation also keeps recommendation 2's reproduce-first
evidence stage free of ledger failures, because a reviewer reproducing the
negative-test failures against the pinned vulnerable base must not have to sort
an authentication failure from a ledger failure.

SL needs its own authorization. R1-D rules where the work goes, not that it may
start.

### The order of S3 and S4

S3 proves itself by failing. Each case in groups A, B, C and D must fail
against the base commit, because the gateway accepts the altered event today.
This repository has no mechanism for a test that is expected to fail, and CI
must stay green on `master`.

Two honest options:

1. **Land S3 and S4 in one pull request.** The reviewer reads the test file
   first, checks out the base commit, runs the tests there, and records that
   groups A to D fail. Then the reviewer reads the implementation. This is the
   recommendation.
2. **Land S3 first with the cases skipped**, each with a recorded reason. This
   is weaker: a skipped test proves nothing, and a later author can leave it
   skipped.

Option 1 keeps the evidence and keeps `master` green. The record in
`KI-SENTINEL-20261102-008` must state who ran the tests against the base
commit, and what the result was.

#### The recommended evidence procedure

The owner recommends option 1 with an ordered evidence procedure (recommendation
2 in `06`, since ruled as ruling 2: the combined pull-request structure is
approved, and implementing it is not):

1. The independent reviewer reproduces the negative-test failures **against the
   pinned vulnerable base**, before reading the corrected implementation.
2. The record states the exact commit, the exact command, the cases and the
   results of that reproduction.
3. Only then does the reviewer read the corrected implementation.
4. The combined pull request must pass the new negative tests **and** the
   positive regression controls in group G before it is merge-eligible.
5. No skipped security tests. A skipped case is not evidence, so a case that
   cannot run is a blocker and not a note.

Step 1 is what makes the matrix evidence rather than decoration. A reviewer who
reads the implementation first knows what the tests are shaped around, and can
no longer judge whether they would have caught the defect.

## What this track does not authorize

- No network ingress, no listener, no queue consumer and no HTTP route.
- No deployment, and no change to a secret, a key or an environment variable.
- No change to the shadow-mode boundary (ADR-011).
- No claim that authentication is secure until the negative tests pass and an
  independent reviewer confirms them.

The owner set three authorization boundaries, in order: **design review first,
implementation authorization second, deployment authorization
separately.** Design approval is not implementation authorization, and a merged
implementation is not deployment authorization.
