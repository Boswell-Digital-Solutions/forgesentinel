# Sentinel Envelope Authentication Plan Set Manifest

- Plan ID: **BDS-SNT-ENVELOPE-AUTH-001**
- Finding: **KI-SENTINEL-20261102-008**
- Generated: **2026-11-02**
- Revision: **rulings R1-A to R1-E recorded; amendment 3 supersedes D-2's bound record count of 41 and states no replacement; slice SL added; three further R1-C rulings recorded, with ruling 3's provenance re-confirmed by the owner on 2026-11-03 after a review challenged it — the measurement is a conditional baseline (14 to 18 of 51, by family scoping and `control_origin`) and S2's scope is all 51 declared fields, `integrity.signature` gets syntax validation, and S2 may precede S6 under five fail-closed conditions; three round-1 decisions open (R1-F, R1-G, R1-H); implementation stays unauthorized**
- Base commit: **432337c**
- Merged as: **79698ac**
- Amended on: **4225489**, then **fee3125**, then **6c492dd**. `fee3125` recorded rulings R1-A to R1-C and amended six plan files and ADR-027; `6c492dd` recorded the three further R1-C rulings and the conditional admit count. An earlier revision of this line named `1773813`, which amended no plan file — it touched `docs/KNOWN_ISSUES.md` only — and omitted `fee3125`, which both this plan set and `KI-SENTINEL-20261102-018` cite as a measurement commit
- Markdown documents: **8**

| File | Bytes | SHA-256 |
|---|---:|---|
| `00_README.md` | 11758 | `a1e430174b275516c0dd6632e185f3fba1b09ec134d4f0252e6093cb4583ea8e` |
| `01_CANONICAL_AUTHENTICATION_FORMAT.md` | 37729 | `6c62fed8719e392d8fe649d1a6456bf34c093597b121d586de548b2128e2495b` |
| `02_SIGNATURE_BINDING.md` | 13763 | `0a3229eba0d78777121061ff126f48ecb865c6dc6dca927ae7082c5a28aa47d1` |
| `03_COMPATIBILITY_AND_CALLER_IMPACT.md` | 9965 | `5868b52f6f3a8197fb73731146cbf75381412f0ca62ca12d6f68f88589b6d3ba` |
| `04_NEGATIVE_TEST_MATRIX.md` | 29204 | `afb21f53e2c856726190c264019da813b03058149db759ae39cf58ae3cc667a6` |
| `05_VERIFICATION_DECISIONS_RISKS_AND_SLICES.md` | 22885 | `2bef3fee28274855a9d397e16ad5cd39b6c4012e0b836ecc75b63f37d99788cf` |
| `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` | 44527 | `0e6f8bb87414a5689e4b1f73bc8b403177e2ec5e4951ea7b061d337f5f64729b` |
| `07_REVIEW_ROUND_1_FINDINGS.md` | 14683 | `6976a6c61f128a409b90de86cdd1565f87ab9a94655ab029e9a8cd927ea6b1ed` |

The hashes above cover the documents as they stand. They are not a statement that the content is current.

Amendment 3 in `06` supersedes the bound record count, so four things in this plan set are knowingly stale and slice S1 regenerates them: the 41-row field table in `01`, the 41-record and 1479-byte worked example in `01`, every record **index** cited in `01`, `02`, `04`, `05`, `docs/KNOWN_ISSUES.md` and `docs/sentinel/adrs/ADR-027-envelope-authentication-format.md`, and the golden vector. Each site is marked where it sits.

Round 2 must run against a frozen commit, named in `07_REVIEW_ROUND_1_FINDINGS.md` before the review starts (review finding F0).

Round 2 assesses the gate-5 record shape against slice SL, not against this track, because ruling R1-D moved `src/spine/ledger.ts` out of it.
