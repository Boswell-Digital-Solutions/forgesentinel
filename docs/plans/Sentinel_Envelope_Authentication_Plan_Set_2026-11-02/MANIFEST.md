# Sentinel Envelope Authentication Plan Set Manifest

- Plan ID: **BDS-SNT-ENVELOPE-AUTH-001**
- Finding: **KI-SENTINEL-20261102-008**
- Generated: **2026-11-02**
- Revision: **rulings R1-A to R1-E recorded; amendment 3 supersedes D-2's bound record count of 41 and states no replacement; slice SL added; three further R1-C rulings recorded — the measurement is a conditional baseline (14 to 18 of 51, by family scoping and `control_origin`) and S2's scope is all 51 declared fields, and `integrity.signature` gets syntax validation; owner rulings on the four recommendations applied; PR #39 review rulings 5 and 6 applied; gate 5 extended to every pre-authentication failure; two round-1 decisions open (R1-F, R1-G; R1-H ruled); implementation stays unauthorized**
- Contested: **blocking items 6, 7 and 8 are open against the content merged by #37 and #38, including the S2-before-S6 sequencing claim in `06`. The owner ruled that a sequencing decision does not become authoritative by appearing in documentation, and routed the remediation to the owning session. This manifest records that content as present, not as accepted.**
- Amended on: **4225489**, then **fee3125**, then **6c492dd**
- Base commit: **432337c**
- Merged as: **79698ac**
- Markdown documents: **8**

| File | Bytes | SHA-256 |
|---|---:|---|
| `00_README.md` | 11758 | `a1e430174b275516c0dd6632e185f3fba1b09ec134d4f0252e6093cb4583ea8e` |
| `01_CANONICAL_AUTHENTICATION_FORMAT.md` | 37050 | `f255332d481ff56677ee3bcd8158c9e66a38e3182c945d2c3ade7bbe8b65e15f` |
| `02_SIGNATURE_BINDING.md` | 13763 | `0a3229eba0d78777121061ff126f48ecb865c6dc6dca927ae7082c5a28aa47d1` |
| `03_COMPATIBILITY_AND_CALLER_IMPACT.md` | 9965 | `5868b52f6f3a8197fb73731146cbf75381412f0ca62ca12d6f68f88589b6d3ba` |
| `04_NEGATIVE_TEST_MATRIX.md` | 29204 | `afb21f53e2c856726190c264019da813b03058149db759ae39cf58ae3cc667a6` |
| `05_VERIFICATION_DECISIONS_RISKS_AND_SLICES.md` | 22463 | `1b6d260e4c0e2eec2e785d76d0bacea098b9558d3eb6d7647699800611a77990` |
| `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` | 51122 | `3279f0e71335714bdd52f38953131dba6a5703520bb9b87674596d3f373a72ab` |
| `07_REVIEW_ROUND_1_FINDINGS.md` | 16917 | `761fd06934d8c8ab059d736c7ec3c6d32a6814069e8a7c14dc9d3d9357549241` |

The hashes above cover the documents as they stand. They are not a statement that the content is current.

Amendment 3 in `06` supersedes the bound record count, so four things in this plan set are knowingly stale and slice S1 regenerates them: the 41-row field table in `01`, the 41-record and 1479-byte worked example in `01`, every record **index** cited in `01`, `02`, `04`, `05`, `docs/KNOWN_ISSUES.md` and `docs/sentinel/adrs/ADR-027-envelope-authentication-format.md`, and the golden vector. Each site is marked where it sits.

Round 2 must run against a frozen commit, named in `07_REVIEW_ROUND_1_FINDINGS.md` before the review starts (review finding F0).

Round 2 assesses the gate-5 record shape against slice SL, not against this track, because ruling R1-D moved `src/spine/ledger.ts` out of it.
