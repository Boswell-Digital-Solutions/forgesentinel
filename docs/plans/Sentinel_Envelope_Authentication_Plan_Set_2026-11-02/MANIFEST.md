# Sentinel Envelope Authentication Plan Set Manifest

- Plan ID: **BDS-SNT-ENVELOPE-AUTH-001**
- Finding: **KI-SENTINEL-20261102-008**
- Generated: **2026-11-02**
- Revision: **rulings R1-A to R1-E recorded; amendment 3 supersedes D-2's bound record count of 41 and states no replacement; slice SL added; three round-1 decisions open (R1-F, R1-G, R1-H); implementation stays unauthorized**
- Base commit: **432337c**
- Merged as: **79698ac**
- Amended on: **1773813**, then **4225489**
- Markdown documents: **8**

| File | Bytes | SHA-256 |
|---|---:|---|
| `00_README.md` | 11699 | `6878e4c10b1d1237d414b0bc6c785f3484ce87a9a78c34a4d90cc0ba7adf7833` |
| `01_CANONICAL_AUTHENTICATION_FORMAT.md` | 34024 | `e9c2e6e8a6afa58945e1255398fc81c805c191ed77f052111f0cae823d8cceba` |
| `02_SIGNATURE_BINDING.md` | 13763 | `0a3229eba0d78777121061ff126f48ecb865c6dc6dca927ae7082c5a28aa47d1` |
| `03_COMPATIBILITY_AND_CALLER_IMPACT.md` | 9965 | `5868b52f6f3a8197fb73731146cbf75381412f0ca62ca12d6f68f88589b6d3ba` |
| `04_NEGATIVE_TEST_MATRIX.md` | 28895 | `8bad54ff091cd1609068799adb25ceaca3c0f643b6a2be4486836be0a99275df` |
| `05_VERIFICATION_DECISIONS_RISKS_AND_SLICES.md` | 21167 | `3bfe70040ca62fc4850234522f4a310da1b967b5141dfa136c76f400492c3290` |
| `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` | 30365 | `2f45aa32b8c5e65f1aa00c71a8bc1db1ede494d14d4623ec2fa2dd0c393420e3` |
| `07_REVIEW_ROUND_1_FINDINGS.md` | 14029 | `73bf56a7381dc0074b976bb11762792244feeebbd0b1c466fed986b174213089` |

The hashes above cover the documents as they stand. They are not a statement that the content is current.

Amendment 3 in `06` supersedes the bound record count, so four things in this plan set are knowingly stale and slice S1 regenerates them: the 41-row field table in `01`, the 41-record and 1479-byte worked example in `01`, every record **index** cited in `01`, `02`, `04`, `05` and `docs/sentinel/adrs/ADR-027-envelope-authentication-format.md`, and the golden vector. Each site is marked where it sits.

Round 2 must run against a frozen commit, named in `07_REVIEW_ROUND_1_FINDINGS.md` before the review starts (review finding F0).

Round 2 assesses the gate-5 record shape against slice SL, not against this track, because ruling R1-D moved `src/spine/ledger.ts` out of it.
