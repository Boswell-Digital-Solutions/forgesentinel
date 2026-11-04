# Sentinel Envelope Authentication Plan Set Manifest

- Plan ID: **BDS-SNT-ENVELOPE-AUTH-001**
- Finding: **KI-SENTINEL-20261102-008**
- Generated: **2026-11-02**
- Revision: **rulings R1-A to R1-E recorded; amendment 3 supersedes D-2's bound record count of 41 and states no replacement; slice SL added; three further R1-C rulings recorded — the measurement is a conditional baseline (14 to 18 of 51, by family scoping and `control_origin`) and S2's scope is all 51 declared fields, and `integrity.signature` gets syntax validation; owner rulings on the four recommendations applied; PR #39 review rulings 5 and 6 applied; gate 5 extended to every pre-authentication failure; two round-1 decisions open (R1-F, R1-G; R1-H ruled); the owner ruling on KI-SENTINEL-20261104-001 (2026-11-04) moves the format's count, contexts, field table and worked example to a documentation-only regeneration of `01` before round 2; implementation stays unauthorized**
- Remediated: **blocking items 7 and 8 are corrected (2026-11-03): no Ed25519 representation is presented as approved, the HMAC text-form citation names the code that enforces it rather than a sentence about `credential.token`, and the flat admit figure is stated conditionally. Blocking item 6 was **withdrawn as a finding**: the S2-before-S6 sequencing ruling is the owner's, issued 2026-11-02 and re-confirmed 2026-11-03, and the text that called it invented is removed. `KI-SENTINEL-20261102-020` records that episode and its control.**
- Amended on: **4225489**, then **fee3125**, then **6c492dd**
- Base commit: **432337c**
- Merged as: **79698ac**
- Markdown documents: **8**

| File | Bytes | SHA-256 |
|---|---:|---|
| `00_README.md` | 11982 | `766dafcc5216b0f8d07d11df2993bd1ab17a82e8ddb7518690f1bd1ba5938200` |
| `01_CANONICAL_AUTHENTICATION_FORMAT.md` | 38217 | `559f258bf3e3ce245d80573058b44eb5d512121d30f5da2fa8160044831413b5` |
| `02_SIGNATURE_BINDING.md` | 13763 | `0a3229eba0d78777121061ff126f48ecb865c6dc6dca927ae7082c5a28aa47d1` |
| `03_COMPATIBILITY_AND_CALLER_IMPACT.md` | 9965 | `5868b52f6f3a8197fb73731146cbf75381412f0ca62ca12d6f68f88589b6d3ba` |
| `04_NEGATIVE_TEST_MATRIX.md` | 29342 | `00ebe62e9b38cec8a96d18704d509d53edb5c74f518461cf28acade413b42b94` |
| `05_VERIFICATION_DECISIONS_RISKS_AND_SLICES.md` | 23572 | `da943727bd601b78b38a6639009282b46588389c4a110d4b82a54938f1ab00ed` |
| `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` | 64318 | `59607dc1871c87a0d1116cd4e02aa897d8125179924811083dac4f1651808b90` |
| `07_REVIEW_ROUND_1_FINDINGS.md` | 17487 | `08e6b29adb3256432239e671bb816ec163be5a9b09c823e1d8d24fda6d4e3364` |

The hashes above cover the documents as they stand. They are not a statement that the content is current.

Amendment 3 in `06` supersedes the bound record count, so four things in this plan set are knowingly stale: the 41-row field table in `01`, the 41-record and 1479-byte worked example in `01`, every record **index** cited in `01`, `02`, `04`, `05`, `docs/KNOWN_ISSUES.md` and `docs/sentinel/adrs/ADR-027-envelope-authentication-format.md`, and the golden vector. Each site is marked where it sits. Under the owner ruling on `KI-SENTINEL-20261104-001` in `06` (2026-11-04), a documentation-only regeneration of `01` corrects the first three before round 2, and slice S1 owns the golden vector, which must reproduce the reviewed worked example.

Round 2 must run against a frozen commit, named in `07_REVIEW_ROUND_1_FINDINGS.md` before the review starts (review finding F0).

Round 2 assesses the gate-5 record shape against slice SL, not against this track, because ruling R1-D moved `src/spine/ledger.ts` out of it.
