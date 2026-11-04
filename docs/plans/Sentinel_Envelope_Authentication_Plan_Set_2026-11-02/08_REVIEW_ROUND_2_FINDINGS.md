# 08 Independent Review, Round 2

- **Date:** 2026-11-04
- **Reviewer:** an independent session with no exposure to the plan author's reasoning. It read `docs/KNOWN_ISSUES.md` (every `KI-SENTINEL-2026110x` entry) and `07_REVIEW_ROUND_1_FINDINGS.md` before it read anything else.
- **Frozen commit:** `3cae2dd560ba20e69b6249f21cb2174db13e8f4d`. Every file:line below is at this commit. The review read a read-only export of it, and ran the code in a detached worktree of the same commit. `MANIFEST.md` hashes match all nine plan-set files at this commit.
- **Scope:** the four items in `07`, "What round 2 must cover"; the owner's six review axes (`06`, recommendation 3); the evidence table in `06`, "Owner ruling on KI-SENTINEL-20261104-001"; ADR-027; and `src/contracts/envelope.ts` and `src/spine/*.ts`.
- **Verdict:** **safe to proceed to implementation authorization with the conditions listed.**
  The format, the HKDF key derivation and the tenant binding held every attack in this round, including an independent re-implementation that reproduced all three worked examples byte for byte and a 60,000-envelope seeded fuzz with no collision. The defects this round found are in the gate-5 rejection-record shape, in the pre-authentication rejection text, in the test matrix and in the allocation of ruling 6. They block slices SL, S3 and S4 until they are corrected. They do not block the encoder.
- **Status:** No pull-request review is submitted on GitHub. This document is the review of record for round 2 if the owner accepts it, as ruling 3 accepted `07` for round 1.

## Method

All commands run from `round2-work/` next to the export, with Node v22.23.4.

| Step | Command or artifact | Result |
|---|---|---|
| Plan-set script | `node evidence/derive_01_regeneration.mjs` (from the plan-set directory) | Exit 0. Positive control 41 records, 1479 bytes, `00db04fb…aeb1`. A: 46 records, 1597 bytes. B1: 48, 1841. B2: 48, 1908. All 17 checks pass. Output saved as `derive_out.txt`. |
| Script isolation | `grep import evidence/derive_01_regeneration.mjs` | Imports `node:crypto`, `node:fs`, `node:path`, `node:url` only. Nothing from `src/`. |
| Independent encoder | `r2_encoder.mjs`, written from the text of `01` alone, before the script source was read | Reproduces A `ecb0d8f4…f998`, B1 `76d0514c…94d4` and B2 `c8bf31c6…3ec2` exactly. Example B's payload digest `39de473d…adfe` also reproduces. |
| Decoder | `decode()` in `r2_encoder.mjs`, a strict parser under the fixed schedule | Round trip passes on A, B1 and B2. |
| Fuzz | `node r2_fuzz.mjs 60000` (mulberry32, seed 20261104) | 96,250 encodings, 96,250 distinct byte strings, 0 collisions, 0 round-trip failures, 0 byte strings shared between the `credential` and `signature` contexts. Values include `0x1F`, `0x1E`, a complete embedded record, `"true"`, `"-"` and multi-byte characters. |
| Keys | `node r2_probe_keys.mjs` | RFC 5869 A.1 reproduces. `K_credential ≠ K_signature`. A token used as a signature, a signature used as a token, and `K_signature` over credential bytes all fail. A tenant transplant and a tenant removal break both values. |
| Code | `git worktree add --detach wt 3cae2dd…`, `npm ci --ignore-scripts && npm run build`, `node --test dist/test/*.test.js` | 402 tests, 402 pass, 0 skipped. `git diff --stat 432337c 3cae2dd -- src fixtures` is empty, so the code is the base the plan set measured. |
| Code probes | `node r2_probe_code.mjs`, `r2_probe_msgs.mjs`, `r2_probe_parents.mjs`, `r2_probe_proph02.mjs` | Results cited in the findings below. |

## What round 2 confirmed as sound

These were attacked and held.

- **The length-prefix core, at the regenerated layout.** No collision in the fuzz. A strict decoder recovers every record under the fixed schedule. Names are constants, the length is exact, and the tag separates absent from present-empty. Round 1 confirmed the core at 41 records; it holds at 46.
- **The ruled F1 fix.** `Array.isArray` refuses `"ab"` and `{0:"a",1:"b",length:2}`. A hole is refused. An empty array is the count `0` with no element records. The count precedes the elements, so an element cannot be added or removed.
- **The ruled F2 fix.** Records 13, 22 and 40 separate an absent parent from a present one. With the `KI-SENTINEL-20261104-003` failure rules, a present empty parent is refused by the encoder for all three parents (`r2_probe_parents.mjs`). F2 is closed twice, as `-003` says.
- **The ruled F3 fix.** Records 38 and 39 bind both signature fields in the `credential` context. In the `signature` context, record 39 is always absent and record 3 must equal record 38. R1-A refuses both fields on a no-signature family. A changed `signature_key_id` changes the credential input.
- **Context separation.** Record 2 differs between the two contexts, and the two derived keys differ. No fuzzed byte string occurs in both contexts.
- **HKDF key separation.** The `info` strings differ at byte 0 (`c` against `s`), so no key id can make them collide. The key id comes from the registration (`02:34`). The stated limit, that the gateway can derive both keys under HMAC, is accurate.
- **Tenant re-targeting.** Records 13 to 15 bind the tenant in both contexts. Moving example B to `ten_other`, and removing its tenant, both break the token and the signature.
- **The 51 declared fields.** This review counted `src/contracts/envelope.ts:36-118` by hand: 5 top-level leaves, 35 nested leaves (40 in all), 7 required objects, 3 optional parents and `payload`. That is 51, with 34 required and 17 optional. `01:448-463` reconciles each one, and every leaf record index in `01:455` is correct.
- **Record citations.** Every record-index citation in `01`, `02`, `04`, `05`, ADR-027 and `docs/KNOWN_ISSUES.md` names the field the regenerated table gives that index.
- **Signing coverage.** `01:369-399` enumerates what each context covers, field by field, and states the computation order (signature first, then the credential that binds it).
- **The stated limits of tenant isolation** (`01:410-419`) are accurate: a producer's key can sign for any tenant, no record binds an audience, and HMAC lets the gateway derive both keys.
- **Decision traceability.** R1-F and R1-G stay visibly open in `01:602`, `01:645`, `06:574`, `07` and `MANIFEST.md`. `KI-SENTINEL-20261104-004`, `-005` and `-006` are marked open where they apply.
- **Example B validates today** under `validateEventEnvelope`, and the fixtures hold no non-integer payload number and no `integrity.signature` (103 replay lines scanned), so the D-7 rule and R1-A break no committed fixture.

### The owner's six axes

| Axis | Result |
|---|---|
| Canonical-encoding injectivity | **Holds in the design**, by fuzz, decoder and independent reproduction. The proof the matrix specifies has two defects (R2-F3, R2-F4). |
| HKDF key separation | **Holds.** One residual rationale defect (R2-F8). |
| Unknown-field refusal | **Specified, under-defined.** The mechanism and the prototype-named keys are not specified (R2-F6). It also creates a new attacker-text channel (R2-F2). |
| Tenant isolation | **Holds in the design** against a party without the key, with the limits stated. Two limits need an owner decision (O-2, O-3). |
| Rejection-record confidentiality | **Not implementable as written** (R2-F1, R2-F2). |
| `KI-SENTINEL-20261102-006` dependency closure | **Declared and gated, not closed.** Record 36 binds the digest, D-1 and ruling 4 gate it on a verified S0, and NEG-F06 and NEG-F07 hold it open. `-006` still reproduces at this commit (`r2_probe_code.mjs` P2). |

### The evidence the KI-SENTINEL-20261104-001 ruling requires

| Evidence | Result |
|---|---|
| Signing coverage | Present and correct (`01:369-399`, the context columns of the table). |
| Canonicalization | Deterministic and unambiguous. Reproduced and fuzzed. |
| Tenant isolation | Defined (`01:401-419`). Reproduced. |
| Worked example | Complete. A and B reproduce byte for byte from an independent encoder. B has every new record. |
| Field table | Consistent with the signing rules and with the contract. |
| Record count | 46 fixed records, plus one per finding id. Recomputed independently. One stale downstream figure (R2-F7). |
| Decision traceability | R1-F and R1-G stay visibly open. |

## Blocking findings

These block authorization of the slices they name. None of them blocks slice S1's encoder.

### R2-F1 — The gate-5 record shape cannot be implemented as written, and two rulings disagree about it (blocks SL and S4)

Round 2 item 3. Three defects, each verified.

1. **R1-E keeps the claimed tenant, and ruling 1 and EVD-K02 forbid it.** `06:967-968` (R1-E): "The claimed tenant stays inside the recommendation-1 metadata block, as an explicitly named observed value." `06:323-328` (ruling 1) removes the recommendation-1 metadata, because the envelope's `tenant` label is attacker-chosen. `04:277` (EVD-K02) requires "nothing from the envelope". `06:338-341` calls ruling 1 "consistent with" R1-E. For R1-E's second bullet it is not. Slice SL implements "the R1-E omission rule" (`05:157`), so an implementer who follows R1-E stores an unbounded attacker-chosen tenant string that ruling 5 (`06:463-468`) bars from the record. `docs/KNOWN_ISSUES.md:245` (the R1-D and R1-E bullet of `KI-SENTINEL-20261102-008`) repeats the R1-E wording. This needs an owner decision (O-1).
2. **The gateway never receives bytes, so "a digest of the received bytes" (`06:317`) has no input.** `EventGateway.ingest(rawEvent: unknown, …)` (`src/spine/gateway.ts:135`) receives a parsed value. `parseReplayJsonl` (`src/spine/replay.ts:24`) discards the line text. Measured (`r2_probe_code.mjs` P7): `{"x":1,"x":2}`, `{"x":2}`, `{"x":2.0}` and `{"x":2e0}` are four different received texts and give one parsed value and one `hashPayload`. An implementation therefore computes a re-serialization digest, which is `canonicalJson` and not one to one until S0 (`KI-SENTINEL-20261102-006`). No document says which. The ruled purpose, "so an operator can match a rejection to a known event", needs one named digest definition on both sides.
3. **The five-element ceiling is not mapped onto `LedgerRecord`.** `EvidenceLedger.append` (`src/spine/ledger.ts:69-83`) always writes `ledger_seq`, `ingested_at` and `source_hash`, and the caller must supply `kind`, `validation`, `gateway_version` and `transformation_version` (`:13-25`). A rejection record today has ten keys (`r2_probe_code.mjs` P4). `06:463-465` makes five elements "the maximum allowable shape", and EVD-K02 says the record holds "exactly the five elements". No document says whether the ceiling applies to `body` or to the record, or which `LedgerRecord` field carries each element (for example, whether `ingested_at` is the receipt timestamp and `ledger_seq` the rejection identifier). EVD-K02 is not writable as a test until it does.

- **Severity:** blocking for SL and S4. Design defect, not an implementation gap: the documents give an implementer no consistent shape.
- **Fix:** an owner decision on O-1; one table in `06` or `05` that maps each ruled element to a `LedgerRecord` field and states the ceiling's scope; a named digest definition, or a change to `ingest` that passes the received text.

### R2-F2 — Pre-authentication rejection text carries unbounded attacker input, and group K does not test it per class (blocks S2, S3 and S4)

Round 2 item 3, and ruling 5.

- **Evidence, current code.** Contract-failure messages interpolate the raw value. `src/contracts/envelope.ts:148` (`unknown_event_type`), `src/contracts/common.ts:57` (`invalid_enum`, reached by `actor.actor_type`, `producer.environment`, `data_policy.sensitivity`, `data_policy.retention_class`, `location.execution_lane`, `control_lineage.control_origin`) and `src/contracts/version.ts:39` (`invalid_semver`). Measured (`node r2_probe_msgs.mjs`): a 50,000-character value with a NUL byte gives a 50,057 to 50,111 character message for each of the four codes, NUL included. Through the gateway (`r2_probe_code.mjs` P3): a 100,000-character `event_type` with NUL and ESC bytes gives a 100,104-character message in the caller's `IngestResult` and in the ledger record's `rejection_reasons`.
- **Why it is a design finding, not only a code defect.** Ruling 5 (`06:455-468`) puts the contract-validation failure under the five-element ceiling, with "bounded non-sensitive diagnostics" and "not free-form envelope content" (`06:316`). But the ruled "failure reason" element is defined only for authentication: `producer_auth_failed` plus a category from the closed set in `02:144`. No document defines the failure reason, or the caller-facing message, for the other six pre-authentication classes. Slice S2 then adds the unknown-field refusal (`01:955`, `03:59`). Its natural form names the unknown key in `path` and `message`, and that key is attacker-chosen at any length. The design does not forbid that.
- **The test gap.** `04:263-269` says group K "must assert the record shape for each class". No case does. EVD-K01 to K09 and K11 are written for an authentication failure. EVD-K10 says "fails any check" and tests only the cloud projection. EVD-K09 covers only `credential.service` and `credential.key_id`.
- **Relation to known ids.** `KI-SENTINEL-20261102-013` records the same class at `src/spine/gateway.ts:158` only. Its "Related bound" bullet notes that contract rejections consume ledger sequence space, not that their messages carry attacker text. This finding is a different site and a different design gap, so it is recorded as new.
- **Severity:** blocking for S2, S3 and S4. Without it, the contract path is the cheaper route for attacker text into the ledger, which is the exact failure ruling 5 names.
- **Fix:** define a closed failure-reason vocabulary and a fixed, bounded message for every pre-authentication class; forbid attacker-chosen text in `path` and `message`, including the unknown-field key name; add one group-K case per class with an oversized, control-character value.

## Should-fix findings

### R2-F3 — ADV-H10, NEG-L04 and PROP-H01 contradict the encoder failure rules (S1, S3)

- `01:169-178` refuses a present optional parent whose required child is absent. `KI-SENTINEL-20261104-003` records that a present empty parent is therefore refused. Measured (`r2_probe_parents.mjs`): `resource: {}`, `tenant: {}` on a system-scoped type and `control_lineage: {}` are all refused by the encoder.
- `04:207` (ADV-H10) still requires "the bytes must differ for each", asserted "on the encoder". One side has no bytes, so the case cannot pass as written.
- `04:302` (NEG-L04) still requires reason code `producer_auth_failed`. The encoder refuses first, so the code is `envelope_not_encodable` (`01:163`).
- `04:199` (PROP-H01) varies each bound field to "absent". An absent required field is refused, so the generator must not count those as encodings.
- A side observation, not a defect: with the failure rules, every optional parent has a required child, so the presence records carry no information that the child records lack. Removing them leaves the absent and minimal-present forms distinct (`r2_probe_parents.mjs`). R1-B requires them anyway, as defence in depth.
- **Severity:** should-fix. An implementer who makes ADV-H10 pass would have to weaken a ruled failure rule.

### R2-F4 — The PROP-H02 decoder round trip passes against an encoder that drops a field (S1)

- `04:200` asserts that decode(encode(e)) returns "the original bound projection … under the fixed field schedule". If the projection is built from the same schedule as the encoder, a field missing from the schedule is missing from both sides.
- Measured (`node r2_probe_proph02.mjs`): with `location.country` removed from the schedule, the round trip passes for two envelopes that differ only in `location.country`, and the two give identical bytes.
- This is the class of review finding F17 (a proof that passes against a broken encoder), on the replacement case.
- **Fix:** build the expected projection from the declared field list of `src/contracts/envelope.ts`, independently of `event_auth.ts`, and assert that it has all 40 leaves and 3 parents. Or state in `04` that PROP-H02 proves decodability only, and that R-5's drift test carries completeness.

### R2-F5 — Ruling 6 (KI-SENTINEL-20261102-017) has no slice, no verification point, no test case and no encoding (S4)

- Round 2 item 4. `grep` over the plan set finds ruling 6 only in `06:494-527` and `07:148-151`.
- `05:154-164` allocates it to no slice. `02:91-94` lists the changes to `ProducerRegistry.authenticate` and omits the post-lookup comparison of `service` and `key_id`. `04` has no case for the colon-shift regression that ruling 6 requires. `01` defines an envelope encoder, not a two-field composite key, so "the one-to-one encoder in `01` is the right basis" (`06:513-515`) is not yet a specification.
- Measured (`r2_probe_code.mjs` P8): the colon-shift credential still authenticates at this commit, as `-017` records.
- Round 2 cannot check that "the encoding and the post-lookup checks are what carry it", because neither is designed.
- **Fix:** name the slice (S4 changes `authenticate`; `-017` suggests S7); add the post-lookup check to `02`'s verification table; add a NEG-L case for the ruled regression; specify the composite key as a two-record use of `01`'s record encoding.

### R2-F6 — The unknown-field refusal does not specify its mechanism or the prototype-named keys (S2)

- `01:947-963` and `03:59` require refusal of an unknown field "at the top level and in every bound object". They do not say how membership is tested, or that a key named `__proto__`, `constructor` or `toString` is unknown.
- Measured (`r2_probe_code.mjs` P5): `JSON.parse` keeps `"__proto__"` as an own key at the top level and inside `tenant`; the gateway accepts and stores the event. An allowlist written as an object literal reports `"__proto__" in allow`, `"constructor" in allow` and `allow["toString"]` all as known (P5c). `Object.assign({}, parsed)` then gives the copy a `resource` inherited from the `__proto__` value, which the authenticated bytes recorded as absent (P5b).
- The encoder reads own properties in the reviewer's implementation, so the bytes stay correct. The risk is a consumer of the stored body that copies with a setter-based copy, the same consumer `KI-SENTINEL-20261102-006` names for the payload.
- **Fix:** state that the refusal enumerates own keys and tests them against a closed `Set` (or with `Object.hasOwn` on a null-prototype table); state that the encoder reads own properties only; add NEG-A28 and NEG-A29 variants with `__proto__` and `constructor` keys.

### R2-F7 — R-9 states the superseded example-B byte counts (documentation)

- `05:144`: "1849 and 1917 for the constructed billing event's two inputs". The script and `01:794`, `01:850` give **1841** and **1908**. The figures are from the two-key-id example that the retest replaced (`KI-SENTINEL-20261104-007`, item 4).
- **Severity:** low. The same stale-figure class that `-007` closed elsewhere.

### R2-F8 — The HKDF `info` rationale relies on key-id uniqueness that the registry does not enforce until S6 (low)

- `02:34`: "The key id stops one producer's derived key from matching another's, even if two secrets ever matched." `02:192-203` (finding F8) shows the registry does not refuse a shared key id, and D-9 safeguard 1, which creates that rule, sits in the Ed25519 slice S6 (`02:229-231`).
- Measured: two services with the same secret and key id derive the same `K_credential` (`r2_probe_keys.mjs`). It is not a forgery: record 4 binds `producer.service` and the gateway compares it with the registration (`src/spine/gateway.ts:161`).
- **Fix:** move the key-id uniqueness rule into the HMAC slices, or correct the sentence. Ruling 6 (R2-F5) also allows two registrations that differ only by a colon shift once the composite key is injective, which is one more reason to state the uniqueness rule for HMAC.

## Findings confirmed against existing ids

| Id | Round 2 result |
|---|---|
| F1, F2, F3 (round 1) | **Confirmed closed in the design.** Re-attacked with the regenerated layout; each held. Open in the code: the gateway still accepts `resource: {}` and a bogus signature, as `07` and `-007` say. |
| F17 (round 1) | **Partly closed.** The decoder replaces the old PROP-H02, but the new case passes against a field-dropping encoder (R2-F4). |
| F8 (round 1) | **Confirmed corrected in `02:192-203`.** One sentence still relies on the property (R2-F8). |
| `KI-SENTINEL-20261102-006` | **Confirmed open.** The `__proto__` payload collision reproduces at this commit (P2). The dependency is declared and gated (D-1, ruling 4, NEG-F06, NEG-F07). |
| `KI-SENTINEL-20261102-008` | **Confirmed open in the code, closed in the design.** A tenant transplant with the original credential is `accepted` at this commit (P1). Under the design it fails in both contexts. |
| `KI-SENTINEL-20261102-009`, `-015` | **Confirmed open.** `01:406-408` leaves verbatim replay to de-duplication, which these records show is not injective and not durable. |
| `KI-SENTINEL-20261102-011`, `-012`, `-016` | **Confirmed open** (P4: the rejection record holds the whole envelope and the claimed `tenant_id`). Slice SL carries them. R2-F1 affects the shape SL must implement. |
| `KI-SENTINEL-20261102-013` | **Confirmed open** at `src/spine/gateway.ts:158`. The same class reaches the contract path, recorded as new under R2-F2. NEG-L08's "stated bound" and design decision 8 (`01:487-488`) leave the intake size limit allocated to no slice. |
| `KI-SENTINEL-20261102-014` | **Confirmed open in the code.** Closed in the design by records 38, 39 and the R1-A refusal. |
| `KI-SENTINEL-20261102-017` | **Confirmed open** (P8). The ruled correction is not in the design (R2-F5). |
| `KI-SENTINEL-20261102-018` | **Confirmed corrected** at this commit: `01:240-255`, `05:159` and `06:829-838` state the count as a range with both conditions. |
| `KI-SENTINEL-20261102-019` | **Confirmed open.** R1-C and S2 cover it. |
| `KI-SENTINEL-20261104-001` | **Confirmed open, and this review is its closing step.** `07:98-99` and `MANIFEST.md:34` require the frozen commit to be named in `07` before the review starts. A commit cannot contain its own hash, so the frozen commit was named in the review brief instead. This document names it. The entry can close when `08` is merged and the owner accepts it. |
| `KI-SENTINEL-20261104-003` | **Confirmed closed in the design** (the encoder refuses all four `actor` forms and every present empty parent). Its side effect makes three cases in `04` stale (R2-F3). |
| `KI-SENTINEL-20261104-004`, `-005`, `-006` | **Confirmed open**, and marked where they apply (`02:153-157`, `01:428-431`, `01:604-606`). |
| `KI-SENTINEL-20261104-007` | **Confirmed.** A second independent re-implementation reproduced every stated value, and the five corrections it lists are in place. |

## Open owner decisions

1. **O-1 (from R2-F1):** does a pre-authentication record keep the claimed tenant as a named observed value, as R1-E says, or keep nothing from the envelope, as ruling 1, ruling 5 and EVD-K02 say? If it keeps it, state its bound and its character set.
2. **O-2:** accept the stated limit that no record binds an audience or a deployment (`01:416-417`), or add one now. Adding a record now costs one row and a regenerated example. After S1 it costs a format version (`01:490-497`).
3. **O-3:** accept that a producer registration is not tenant-scoped (`01:413-415`), so a key holder can sign for any tenant, or put registration tenant scoping on a slice.
4. **O-4 (from R2-F1):** how the gate-5 digest is defined: over the received text, which changes the `ingest` signature, or over a named canonical form after S0.
5. Still open from earlier rounds: R1-F, R1-G, `KI-SENTINEL-20261104-004`, `-005` and `-006`.

## Conditions for implementation authorization

1. S0 is corrected and independently verified before any slice relies on record 36 (D-1, ruling 4). Unchanged.
2. R2-F1 and R2-F2 are corrected in the plan set, and O-1 and O-4 are ruled, before SL, S2, S3 or S4 is authorized.
3. R2-F3 and R2-F4 are corrected in `04` before S1 is authorized, because group H is S1's test suite.
4. R2-F5 is allocated to a slice, with its test case, before S4 is authorized.
5. R2-F6 is specified in `01` and `04` before S2 is authorized.
6. R2-F7 and R2-F8 are corrected in the next documentation change.

## What a later round must cover

1. The corrections for R2-F1 to R2-F6, against a new frozen commit.
2. The S1 implementation: the golden vector must reproduce example A (`ecb0d8f4…f998`) byte for byte, and a reviewer must re-run an independent encoder and the fuzz against it.
3. The S0 correction, verified independently, before any reliance on record 36.
4. The reproduce-first evidence stage of ruling 2 for S3 and S4, against the pinned base `432337c` (equal in `src/` and `fixtures/` to `3cae2dd`).

## Artifacts

All in `round2-work/` next to this file: `r2_encoder.mjs`, `r2_reproduce.mjs`, `r2_fuzz.mjs`, `r2_probe_code.mjs`, `r2_probe_msgs.mjs`, `r2_probe_parents.mjs`, `r2_probe_keys.mjs`, `r2_probe_proph02.mjs`, `derive_out.txt`. The code probes import from the worktree `wt/dist/src`. The worktree was removed after the run, so the shared checkout carries no extra registration. To re-run the probes, recreate it with the commands in "Method".

---

*Archival note, added by the plan author when this review entered the plan set (2026-11-04). Nothing
above this line is changed. The artifacts listed under "Artifacts" are copied unchanged to
`evidence/round2/`. They expect the layout "Method" describes, with the frozen export as a sibling
directory: export `3cae2dd` to `round2-frozen/`, copy `evidence/round2/` to `round2-work/` beside it,
and run each script from `round2-work/`; a probe that needs the compiled code also needs a detached
worktree of `3cae2dd`. (Corrected 2026-11-04: an earlier version of this note said to run them from
`evidence/round2/` itself, which fails.) `MANIFEST.md` pins each file. Two should-fix
findings were corrected in the same pull request, because they were the author's own errors: R2-F3
in `04` (ADV-H10, NEG-L04, PROP-H01) and R2-F7 in `05` (R-9). The other findings stay open, with the
conditions this review lists. This document becomes the review of record for round 2 if the owner
accepts it.*
