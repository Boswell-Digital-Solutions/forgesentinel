# Sentinel Envelope Authentication Plan Set Manifest

- Plan ID: **BDS-SNT-ENVELOPE-AUTH-001**
- Finding: **KI-SENTINEL-20261102-008**
- Generated: **2026-11-02**
- Revision: **rulings R1-D and R1-E recorded; slice SL added; six round-1 decisions open; implementation stays unauthorized**
- Base commit: **432337c**
- Merged as: **79698ac**
- Amended on: **1773813**
- Markdown documents: **8**

| File | Bytes | SHA-256 |
|---|---:|---|
| `00_README.md` | 10917 | `fab575719fa99fda45866a091495178f840209dff73d1ed73c533de314450464` |
| `01_CANONICAL_AUTHENTICATION_FORMAT.md` | 26417 | `7f2bea8a8358222d5158c19de1214bf2eb05ab283c05d0291666224ef7b3604b` |
| `02_SIGNATURE_BINDING.md` | 13763 | `0a3229eba0d78777121061ff126f48ecb865c6dc6dca927ae7082c5a28aa47d1` |
| `03_COMPATIBILITY_AND_CALLER_IMPACT.md` | 9965 | `5868b52f6f3a8197fb73731146cbf75381412f0ca62ca12d6f68f88589b6d3ba` |
| `04_NEGATIVE_TEST_MATRIX.md` | 27281 | `d9946371ca2549fb39f2e010fa3e17e534ee0b586ca5de7a3e314b69a3512dc2` |
| `05_VERIFICATION_DECISIONS_RISKS_AND_SLICES.md` | 18458 | `eb165f5e1d0554d5389a4df7d2f0a3c64741b26babe14529b4318dcf976805e4` |
| `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` | 20958 | `a2f9a64d21fd387587ea0346078c1bafc17efee47ae8f10ee7ed6137febd2110` |
| `07_REVIEW_ROUND_1_FINDINGS.md` | 12284 | `417ef173fba4cbfdcd054f2e0cefb3995482a410b99725fe1b83bf50c56f2e9e` |

Round 2 must run against a frozen commit, named in `07_REVIEW_ROUND_1_FINDINGS.md` before the review starts (review finding F0).

Round 2 assesses the gate-5 record shape against slice SL, not against this track, because ruling R1-D moved `src/spine/ledger.ts` out of it.
