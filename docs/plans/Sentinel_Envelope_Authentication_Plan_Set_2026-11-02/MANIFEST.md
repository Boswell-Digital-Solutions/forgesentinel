# Sentinel Envelope Authentication Plan Set Manifest

- Plan ID: **BDS-SNT-ENVELOPE-AUTH-001**
- Finding: **KI-SENTINEL-20261102-008**
- Generated: **2026-11-02**
- Revision: **rulings R1-A to R1-E recorded; amendment 3 raises the bound record count from 41 to 43; slice SL added; three round-1 decisions open; implementation stays unauthorized**
- Base commit: **432337c**
- Merged as: **79698ac**
- Amended on: **1773813**, then **4225489**
- Markdown documents: **8**

| File | Bytes | SHA-256 |
|---|---:|---|
| `00_README.md` | 10917 | `fab575719fa99fda45866a091495178f840209dff73d1ed73c533de314450464` |
| `01_CANONICAL_AUTHENTICATION_FORMAT.md` | 31672 | `a2168150ed139589daa07596c9c6cdd4625b0c767b6b2d3e24c500bf458cc781` |
| `02_SIGNATURE_BINDING.md` | 13763 | `0a3229eba0d78777121061ff126f48ecb865c6dc6dca927ae7082c5a28aa47d1` |
| `03_COMPATIBILITY_AND_CALLER_IMPACT.md` | 9965 | `5868b52f6f3a8197fb73731146cbf75381412f0ca62ca12d6f68f88589b6d3ba` |
| `04_NEGATIVE_TEST_MATRIX.md` | 28649 | `0df3e3ca9a6e2855a1dc10e627e08ff36f4eda1afd015e6965f52e690ead6be6` |
| `05_VERIFICATION_DECISIONS_RISKS_AND_SLICES.md` | 19463 | `e5cd75c44a4fc6c7c36be26ce4e0d3438e41bddd194cf81c2023165f6c217d19` |
| `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` | 26143 | `9867ba51658f36b2bc267bbf4e9098139e69a8fb1bd06318453f881b53a374b6` |
| `07_REVIEW_ROUND_1_FINDINGS.md` | 13332 | `793d0e098409c45014894279c4f7e050f43fbc9ed4fa3405e099bca2a70f980b` |

The byte counts and the worked example in `01` are **stale by design**: amendment 3 supersedes the 41-record, 1479-byte example, and slice S1 regenerates it. The hashes above cover `01` as it stands, which is the document that records the rulings and marks its own example superseded.

Round 2 must run against a frozen commit, named in `07_REVIEW_ROUND_1_FINDINGS.md` before the review starts (review finding F0).

Round 2 assesses the gate-5 record shape against slice SL, not against this track, because ruling R1-D moved `src/spine/ledger.ts` out of it.
