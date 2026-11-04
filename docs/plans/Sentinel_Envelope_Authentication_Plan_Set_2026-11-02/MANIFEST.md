# Sentinel Envelope Authentication Plan Set Manifest

- Plan ID: **BDS-SNT-ENVELOPE-AUTH-001**
- Finding: **KI-SENTINEL-20261102-008**
- Generated: **2026-11-02**
- Revision: **rulings R1-A to R1-E recorded; amendment 3 supersedes D-2's bound record count of 41 and states no replacement; slice SL added; three further R1-C rulings recorded — the measurement is a conditional baseline (14 to 18 of 51, by family scoping and `control_origin`) and S2's scope is all 51 declared fields, and `integrity.signature` gets syntax validation; owner rulings on the four recommendations applied; PR #39 review rulings 5 and 6 applied; gate 5 extended to every pre-authentication failure; two round-1 decisions open (R1-F, R1-G; R1-H ruled); the owner ruling on KI-SENTINEL-20261104-001 (2026-11-04) moves the format's count, contexts, field table and worked example to a documentation-only regeneration of `01` before round 2; **`01` regenerated 2026-11-04: 46 fixed records, R1-A's binding contexts settled, signing coverage enumerated, worked examples derived by `evidence/derive_01_regeneration.mjs`**; **revised after the four-lane retest of `de52ad3` (KI-SENTINEL-20261104-007): encoder failure rules for required fields and objects, the signature-context key-id rule, example B with one key id; three owner decisions recorded open (KI-SENTINEL-20261104-004 to -006)**; **round 2's frozen commit named in `07`: `3cae2dd` (2026-11-04), operator authorization tentative; KI-SENTINEL-20261104-001 closed**; **review round 2 ran against `3cae2dd` (`08`): safe to proceed to implementation authorization with the conditions listed; R2-F3 and R2-F7 corrected**; implementation stays unauthorized**
- Remediated: **blocking items 7 and 8 are corrected (2026-11-03): no Ed25519 representation is presented as approved, the HMAC text-form citation names the code that enforces it rather than a sentence about `credential.token`, and the flat admit figure is stated conditionally. Blocking item 6 was **withdrawn as a finding**: the S2-before-S6 sequencing ruling is the owner's, issued 2026-11-02 and re-confirmed 2026-11-03, and the text that called it invented is removed. `KI-SENTINEL-20261102-020` records that episode and its control.**
- Amended on: **4225489**, then **fee3125**, then **6c492dd**
- Base commit: **432337c**
- Merged as: **79698ac**
- Markdown documents: **9**

| File | Bytes | SHA-256 |
|---|---:|---|
| `00_README.md` | 12438 | `bb9da03d35c7e2a1fcf800f8e8111e65d2b607eee8f761302685ce788d518988` |
| `01_CANONICAL_AUTHENTICATION_FORMAT.md` | 57944 | `4eba639b0c1ae84b0ee0009253f90e39da7fe096ae83e8fd427e461245eefd32` |
| `02_SIGNATURE_BINDING.md` | 14383 | `f79decc5b256a335052191c03437a21588b9879b6b34406de8b27240b024cdc1` |
| `03_COMPATIBILITY_AND_CALLER_IMPACT.md` | 10220 | `e3bf4f401618060de72b8c9b0bb39f218435c1f0d38f9345214a4c863e6de471` |
| `04_NEGATIVE_TEST_MATRIX.md` | 30853 | `97b240c3ea4e618464510b827723fb51be87e7e5de0f1f9c9a603ff8efdb2760` |
| `05_VERIFICATION_DECISIONS_RISKS_AND_SLICES.md` | 24013 | `3401b267c3df8bf5366bc20c015b8ca29c30e6974e36836b5a46632460d3b590` |
| `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` | 65371 | `cd6454764c6c9ebd4bfbed852d941e9e96fccae106a87dc87e3186a32ba5f0b1` |
| `07_REVIEW_ROUND_1_FINDINGS.md` | 18995 | `623b8973166695a9a059a08c75ce3616c2de186656e64643c623f499d1644bf5` |
| `08_REVIEW_ROUND_2_FINDINGS.md` | 26214 | `6c6ce5aa5a63655ced1bbd6211d1cbff5940403c65d6732fc39ec9d4300797f1` |

Design evidence, frozen with the documents:

| File | Bytes | SHA-256 |
|---|---:|---|
| `evidence/derive_01_regeneration.mjs` | 22075 | `60bfd96f0a7c871f191f145882abe847c1470d55281dc7ed5ebae04b66db8d08` |
| `evidence/round2/derive_out.txt` | 11337 | `87d254b3c4f834a155b66eacbf11bfb682b7aae353f6aa0667d215701696b476` |
| `evidence/round2/r2_encoder.mjs` | 8835 | `7f57c7c1b0c029ad99aa93632e7b0a3e1d08956974a4f27c08adc8bc9310c995` |
| `evidence/round2/r2_fuzz.mjs` | 3459 | `605b274ae0fef511ecd3a843303ff47e44d9cdc75d79d81e910cec051464bd17` |
| `evidence/round2/r2_probe_code.mjs` | 6805 | `b39e3753f9c74046e93b1067fb4c59175fa2843616eaa0647f2afb5951fdae37` |
| `evidence/round2/r2_probe_keys.mjs` | 2098 | `36b6dd3ad17b7a1aa09bb1f6fcfdc0abdbc7901a2201ef1f6edd6256216d9698` |
| `evidence/round2/r2_probe_msgs.mjs` | 843 | `ba295051778ef608eca7a9c639f2d8a01c42dc33105dfbe2350e724ae36565df` |
| `evidence/round2/r2_probe_parents.mjs` | 1491 | `7f6ed9bff532df7f6dd676db8ed2eb204e748e7babc45f1bad9547c1f95f31c5` |
| `evidence/round2/r2_probe_proph02.mjs` | 891 | `48bd7df3fadc17d079e0d049ffb349d806e27163aaa1091fcd41d235abd5136f` |
| `evidence/round2/r2_reproduce.mjs` | 3053 | `518e5be001429bf146df4316ea5fa76e0a0dddc019bf41e6f81d789c30874f1e` |

The hashes above cover the documents as they stand. They are not a statement that the content is current.

Amendment 3 in `06` superseded the bound record count, so four things in this plan set were knowingly stale: the 41-row field table in `01`, the 41-record and 1479-byte worked example in `01`, every record **index** cited in `01`, `02`, `04`, `05`, `docs/KNOWN_ISSUES.md` and `docs/sentinel/adrs/ADR-027-envelope-authentication-format.md`, and the golden vector. Each site is marked where it sits. The regeneration of `01` on 2026-11-04 corrected the first three, under the owner ruling on `KI-SENTINEL-20261104-001` in `06`. Slice S1 owns the golden vector, which must reproduce example A of `01` byte for byte.

Round 2 must run against a frozen commit, named in `07_REVIEW_ROUND_1_FINDINGS.md` before the review starts (review finding F0). It is named: `3cae2dd`.

Round 2 assesses the gate-5 record shape against slice SL, not against this track, because ruling R1-D moved `src/spine/ledger.ts` out of it.
