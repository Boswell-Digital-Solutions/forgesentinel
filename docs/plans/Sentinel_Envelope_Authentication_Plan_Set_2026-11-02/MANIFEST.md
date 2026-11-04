# Sentinel Envelope Authentication Plan Set Manifest

- Plan ID: **BDS-SNT-ENVELOPE-AUTH-001**
- Finding: **KI-SENTINEL-20261102-008**
- Generated: **2026-11-02**
- Revision: **rulings R1-A to R1-E recorded; amendment 3 supersedes D-2's bound record count of 41 and states no replacement; slice SL added; three further R1-C rulings recorded — the measurement is a conditional baseline (14 to 18 of 51, by family scoping and `control_origin`) and S2's scope is all 51 declared fields, and `integrity.signature` gets syntax validation; owner rulings on the four recommendations applied; PR #39 review rulings 5 and 6 applied; gate 5 extended to every pre-authentication failure; two round-1 decisions open (R1-F, R1-G; R1-H ruled); the owner ruling on KI-SENTINEL-20261104-001 (2026-11-04) moves the format's count, contexts, field table and worked example to a documentation-only regeneration of `01` before round 2; **`01` regenerated 2026-11-04: 46 fixed records, R1-A's binding contexts settled, signing coverage enumerated, worked examples derived by `evidence/derive_01_regeneration.mjs`**; **revised after the four-lane retest of `de52ad3` (KI-SENTINEL-20261104-007): encoder failure rules for required fields and objects, the signature-context key-id rule, example B with one key id; three owner decisions recorded open (KI-SENTINEL-20261104-004 to -006)**; **round 2's frozen commit named in `07`: `3cae2dd` (2026-11-04), operator authorization tentative; KI-SENTINEL-20261104-001 closed**; implementation stays unauthorized**
- Remediated: **blocking items 7 and 8 are corrected (2026-11-03): no Ed25519 representation is presented as approved, the HMAC text-form citation names the code that enforces it rather than a sentence about `credential.token`, and the flat admit figure is stated conditionally. Blocking item 6 was **withdrawn as a finding**: the S2-before-S6 sequencing ruling is the owner's, issued 2026-11-02 and re-confirmed 2026-11-03, and the text that called it invented is removed. `KI-SENTINEL-20261102-020` records that episode and its control.**
- Amended on: **4225489**, then **fee3125**, then **6c492dd**
- Base commit: **432337c**
- Merged as: **79698ac**
- Markdown documents: **8**

| File | Bytes | SHA-256 |
|---|---:|---|
| `00_README.md` | 12109 | `3801319e36e2382069f0a87c489e234e3ca76fe0f893e4d68b3ca8772421c667` |
| `01_CANONICAL_AUTHENTICATION_FORMAT.md` | 57944 | `4eba639b0c1ae84b0ee0009253f90e39da7fe096ae83e8fd427e461245eefd32` |
| `02_SIGNATURE_BINDING.md` | 14383 | `f79decc5b256a335052191c03437a21588b9879b6b34406de8b27240b024cdc1` |
| `03_COMPATIBILITY_AND_CALLER_IMPACT.md` | 10220 | `e3bf4f401618060de72b8c9b0bb39f218435c1f0d38f9345214a4c863e6de471` |
| `04_NEGATIVE_TEST_MATRIX.md` | 30160 | `c7ecda75be19f6b12aa52635d3984fdb6ff49b7d30caa61c04f2aaa220a97e39` |
| `05_VERIFICATION_DECISIONS_RISKS_AND_SLICES.md` | 23915 | `773ba1c97c03eecc3c9515868c7e6574573a3f95ace558bdcd0e99ef18e8fcdb` |
| `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` | 65112 | `9d89cc6e7843d1c88d859c5876a7d468f8fde7dd9b144174079aa833ed5df8f4` |
| `07_REVIEW_ROUND_1_FINDINGS.md` | 18723 | `cf1ebd5dabe31b38915df6a49ac64cb73f6db1f1578093796a101dc84b61814b` |

Design evidence, frozen with the documents:

| File | Bytes | SHA-256 |
|---|---:|---|
| `evidence/derive_01_regeneration.mjs` | 22075 | `60bfd96f0a7c871f191f145882abe847c1470d55281dc7ed5ebae04b66db8d08` |

The hashes above cover the documents as they stand. They are not a statement that the content is current.

Amendment 3 in `06` superseded the bound record count, so four things in this plan set were knowingly stale: the 41-row field table in `01`, the 41-record and 1479-byte worked example in `01`, every record **index** cited in `01`, `02`, `04`, `05`, `docs/KNOWN_ISSUES.md` and `docs/sentinel/adrs/ADR-027-envelope-authentication-format.md`, and the golden vector. Each site is marked where it sits. The regeneration of `01` on 2026-11-04 corrected the first three, under the owner ruling on `KI-SENTINEL-20261104-001` in `06`. Slice S1 owns the golden vector, which must reproduce example A of `01` byte for byte.

Round 2 must run against a frozen commit, named in `07_REVIEW_ROUND_1_FINDINGS.md` before the review starts (review finding F0). It is named: `3cae2dd`.

Round 2 assesses the gate-5 record shape against slice SL, not against this track, because ruling R1-D moved `src/spine/ledger.ts` out of it.
