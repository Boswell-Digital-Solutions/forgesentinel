# Sentinel Envelope Authentication Plan Set Manifest

- Plan ID: **BDS-SNT-ENVELOPE-AUTH-001**
- Finding: **KI-SENTINEL-20261102-008**
- Generated: **2026-11-02**
- Revision: **rulings R1-A to R1-E recorded; amendment 3 supersedes D-2's bound record count of 41 and states no replacement; slice SL added; three further R1-C rulings recorded — the measurement is a conditional baseline (14 to 18 of 51, by family scoping and `control_origin`) and S2's scope is all 51 declared fields, and `integrity.signature` gets syntax validation; owner rulings on the four recommendations applied; PR #39 review rulings 5 and 6 applied; gate 5 extended to every pre-authentication failure; two round-1 decisions open (R1-F, R1-G; R1-H ruled); the owner ruling on KI-SENTINEL-20261104-001 (2026-11-04) moves the format's count, contexts, field table and worked example to a documentation-only regeneration of `01` before round 2; **`01` regenerated 2026-11-04: 46 fixed records, R1-A's binding contexts settled, signing coverage enumerated, worked examples derived by `evidence/derive_01_regeneration.mjs`**; implementation stays unauthorized**
- Remediated: **blocking items 7 and 8 are corrected (2026-11-03): no Ed25519 representation is presented as approved, the HMAC text-form citation names the code that enforces it rather than a sentence about `credential.token`, and the flat admit figure is stated conditionally. Blocking item 6 was **withdrawn as a finding**: the S2-before-S6 sequencing ruling is the owner's, issued 2026-11-02 and re-confirmed 2026-11-03, and the text that called it invented is removed. `KI-SENTINEL-20261102-020` records that episode and its control.**
- Amended on: **4225489**, then **fee3125**, then **6c492dd**
- Base commit: **432337c**
- Merged as: **79698ac**
- Markdown documents: **8**

| File | Bytes | SHA-256 |
|---|---:|---|
| `00_README.md` | 11993 | `88a0ac4450757072e9cd54786c3d343b0ab30ed3b788adacebb866c27a1d148c` |
| `01_CANONICAL_AUTHENTICATION_FORMAT.md` | 51115 | `8f69760b9d5eb055f072110432c229767e2eb7db26f5b8a7e4721bc620e2dc95` |
| `02_SIGNATURE_BINDING.md` | 13763 | `2293bffe1d91fad599f34071ac4fcd257fea83146318d72bfba4acec42fd7f0e` |
| `03_COMPATIBILITY_AND_CALLER_IMPACT.md` | 9965 | `5868b52f6f3a8197fb73731146cbf75381412f0ca62ca12d6f68f88589b6d3ba` |
| `04_NEGATIVE_TEST_MATRIX.md` | 29609 | `cc2493987c9870da2267e8c9492a1100ea503f7f73961a3ab890806f04c8d75e` |
| `05_VERIFICATION_DECISIONS_RISKS_AND_SLICES.md` | 23628 | `d18f4b930ec3f9243bbc417df7d0f18597ccdd5f379716204322b866c7f4c357` |
| `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` | 64435 | `0123ee686f7b2dddffe1d9b5b9f7b5b8112f1273be02b96d44e0a3ed96b4a1eb` |
| `07_REVIEW_ROUND_1_FINDINGS.md` | 17565 | `8498eaa97fa47b54b669c5356d7a07eb62b58b9b232c8007a1727c2b112f04ff` |

Design evidence, frozen with the documents:

| File | Bytes | SHA-256 |
|---|---:|---|
| `evidence/derive_01_regeneration.mjs` | 14852 | `dd02d1cd593176a2cfa35e35d0ea00fbbdbd1dc56af0301577b4aceed9955b33` |

The hashes above cover the documents as they stand. They are not a statement that the content is current.

Amendment 3 in `06` superseded the bound record count, so four things in this plan set were knowingly stale: the 41-row field table in `01`, the 41-record and 1479-byte worked example in `01`, every record **index** cited in `01`, `02`, `04`, `05`, `docs/KNOWN_ISSUES.md` and `docs/sentinel/adrs/ADR-027-envelope-authentication-format.md`, and the golden vector. Each site is marked where it sits. The regeneration of `01` on 2026-11-04 corrected the first three, under the owner ruling on `KI-SENTINEL-20261104-001` in `06`. Slice S1 owns the golden vector, which must reproduce example A of `01` byte for byte.

Round 2 must run against a frozen commit, named in `07_REVIEW_ROUND_1_FINDINGS.md` before the review starts (review finding F0).

Round 2 assesses the gate-5 record shape against slice SL, not against this track, because ruling R1-D moved `src/spine/ledger.ts` out of it.
