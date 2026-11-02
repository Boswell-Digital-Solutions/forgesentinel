# 05 Verification, Decisions, Risks and Slices

## Verification gates

Every implementation slice must pass these gates. Run them in this order.

| Gate | Command | What it proves |
|---|---|---|
| G1 Build | `npm ci --ignore-scripts && npm run build` | The source compiles under TypeScript 5.6. |
| G2 Suite | `node --test dist/test/*.test.js` | Every test passes. The base commit `432337c` has 402 tests and 0 failures. |
| G3 Negative tests | the same command, with `test/event_auth.test.ts` present | Each case in `04_NEGATIVE_TEST_MATRIX.md` gives the required status and reason code. |
| G4 Fixture determinism | `npm run fixtures && git diff --exit-code -- fixtures` | The committed fixtures match a fresh generation. |
| G5 Fixture diff shape | a scripted check over the three replay files | Only `credential.token` and `integrity.signature` changed. No event body changed. |
| G6 Documentation | `bash doc/system/BUILD.sh && git diff --exit-code -- doc` | `doc/SNTSYSTEM.md` matches its parts. This is the documentation CI. |
| G7 Golden vector | a test that re-encodes `fixtures/golden/event_auth.v1.vector.json` | The implementation reproduces the committed bytes, digest and HMAC. |
| G8 Independent review | a review round by a reviewer who did not write the change | No blocking defect. PR #21 needed three rounds; one round is not a rule. |

### Gates that are not available today

`doc/system/06-verification.md` lists this operator command:

```bash
node dist/src/cli.js replay fixtures/replay/compound_account_compromise.jsonl
```

That command cannot succeed on the committed fixtures today. The committed
fixtures carry `producer.environment: "production"`. With
`SENTINEL_ENVIRONMENT=test` and the fixture secrets, the gateway rejects all 44
lines with `environment_boundary`. With `SENTINEL_ENVIRONMENT=production`, the
loader refuses the published fixture secrets and the CLI exits with code 2.
`KI-SENTINEL-20261102-010` records this. Use G2 for the end-to-end check: the
suite re-signs the fixtures with fresh random secrets through `resign`.

### What the gates do not prove

Owner requirement 6 governs this section.

- A green suite does not show that event authentication is secure. The suite
  passed 402 tests at `432337c` while the gateway accepted every change in the
  table in `00_README.md`.
- A clean review does not show it either. PRs #21, #24, #27 and #29 each
  hardened the producer boundary and each merged after an independent review.
  This defect survived all four.
- G4 proves that generation is deterministic. It does not prove that the
  generated credential authenticates the right bytes.
- Only the negative tests in `04` show that an altered event is refused, and
  only when they fail against the base commit first.

## Decisions the owner must make

| ID | Decision | Options | Recommendation |
|---|---|---|---|
| D-1 | How the payload is bound | A: bind `integrity.payload_hash` and depend on the `KI-SENTINEL-20261102-006` correction. B: define a recursive encoder in this track and bind a second digest. | A. One payload digest. The dependency is explicit, and `KI-SENTINEL-20261102-006` already has a proposed correction. |
| D-2 | The bound field set | The requirement-1 minimum (8 fields). The full set in `01` (41 records and the lineage array). | The full set. The check confirmed that every added field is alterable today, and `data_policy` and `control_lineage` carry privacy and ADR-022 meaning. |
| D-3 | The rejection reason code | One code, `producer_auth_failed`, for every authentication failure. A distinct code for each cause. | One code. A code that names the differing field is an oracle. |
| D-4 | Version and algorithm handling | The gateway holds one format name as a constant. The credential declares a version and the gateway holds an allowlist. Add an explicit `alg` record. | One constant, and no `alg` record. The key id already binds the algorithm, and the gateway chooses the primitive from the registration. |
| D-5 | Unknown envelope fields | Refuse an unknown field in an event envelope. Leave the validator as it is. | Refuse. Without it the field list is not closed, and an unbound field stays malleable. |
| D-6 | The high-value signature | Keep the producer key with domain separation. Move to a separate signing key. Wait for Ed25519. | Keep the producer key with domain separation now. A separate key is a key-management change, and it belongs with ADR-026. |
| D-7 | Payload number discipline | Refuse `-0`, `NaN` and a non-finite number. Also refuse a non-integer number, which matches `forge.rfc8785-jcs-sha256.v1` in `forge_contract_core`. | Refuse the first set now. No event payload in the committed fixtures holds a non-integer number; the non-integer values are in findings and incidents, which a producer does not sign. The stricter rule needs a separate ruling, because a future cost payload may need a decimal. |
| D-8 | `KI-SENTINEL-20261102-009`, the dedupe key | Correct it in this track, with the same encoder. Correct it in its own track. Accept it. | Its own track, immediately after this one. It is the same defect class, but it changes de-duplication behaviour, and that needs its own tests. |
| D-9 | The Ed25519 order (ADR-026) | Ed25519 after this format change. Ed25519 first. Both in one change. | After. The format change is the correction for the finding, and the primitive that exists today can verify it. Ed25519 also changes the producer-secrets file schema, which touches `KI-SENTINEL-20261030-002`. |
| D-10 | The records | Write a new ADR for the format. Record the format in `doc/system/` only. Add a plan id to the organization plan registry. | Write a short ADR, because the format is a trust root and ADR-026 names the signing decisions. The registry today holds one entry for this repository, `BDS-FS-ROADMAP-001`, with `plan_path: docs/plans`. A separate plan id is a change in the `forge` repository, and this pull request does not make it. |

## Risks

| ID | Risk | Mitigation |
|---|---|---|
| R-1 | The encoder becomes the trust root. A defect in it is a defect in authentication. | One module, one field list, a committed golden vector, an independent review, and the negative tests written first. |
| R-2 | Enforcement before the `KI-SENTINEL-20261102-006` correction authenticates the envelope and leaves the payload malleable. | D-1. Cases NEG-F06 and NEG-F07 hold the track open until the correction lands. |
| R-3 | A test helper that both signs and verifies hides a defect, and every test still passes. | Rule 2 in `04`: a case builds its own input and does not call `resign` or `buildEvent` for the value under test. |
| R-4 | A producer that corrects `observed_at`, a data-policy field or a trace id after signing breaks its own authentication. | This is a producer-implementation cost, not a migration cost. No producer exists yet. State the rule in `doc/system/03-runtime-boundary.md`: sign last. |
| R-5 | A new envelope field is added later, and nobody adds it to the field list. It is then unbound and malleable. | Add a drift test: the bound field list must cover every field that `validateEventEnvelope` admits. The test fails when the two sets differ. |
| R-6 | The Ed25519 slice changes `ProducerRegistration`, the secrets-file schema and the strength rules, which `KI-SENTINEL-20261030-002` also owns. | D-9. Do not run the two tracks at the same time. |
| R-7 | 103 fixture lines change at once, and a reviewer cannot read 103 token changes. | G5: a scripted check that only `credential.token` and `integrity.signature` changed. |
| R-8 | A real producer is built in another repository and implements the old token. | The golden vector is the cross-repository agreement. No repository implements the token today, so nothing is stranded now. |
| R-9 | The plan binds 41 records, so the authenticated bytes grow from 71 bytes to about 1.5 kB for each event. | HMAC-SHA256 over 1.5 kB is not a measurable cost at this volume. Record a measurement in the slice if the owner wants one. |

## Proposed slices

Each slice needs its own authorization. No slice adds ingress. The gateway
stays shadow-only throughout (owner requirement 5).

| Slice | Content | Gates | Authorization |
|---|---|---|---|
| S0 | The `KI-SENTINEL-20261102-006` correction: make the canonical form one to one. | G1, G2, G4, G6 | Separate. It is its own finding. |
| S1 | `src/spine/event_auth.ts`, the field list, the encoder, its unit tests, and the golden vector. Nothing calls it from the gateway. | G1, G2, G4, G6, G7 | This track. |
| S2 | The unknown-field refusal in `validateEventEnvelope`, with tests, and the drift test from R-5. | G1, G2, G4, G6 | This track. |
| S3 | The negative tests from `04`. | G1, G3 | This track. See the note below. |
| S4 | `buildEvent`, `producerToken`, `ProducerRegistry.authenticate` and the gateway signature check use the format. Fixtures regenerated. Test support updated. | G1 to G7 | This track. |
| S5 | `doc/system/` updates, the rebuilt `doc/SNTSYSTEM.md`, the ADR under D-10, and the `KI-SENTINEL-20261102-008` record. | G6, G8 | This track. |
| S6 | Ed25519 under ADR-026, with the producer-secrets file schema change. | G1 to G8 | Separate. ADR-026 and `KI-SENTINEL-20261030-002`. |
| S7 | `dedupeKey` adopts the encoder (`KI-SENTINEL-20261102-009`). | G1 to G6 | Separate, under D-8. |

### The order of S3 and S4

S3 proves itself by failing. Each case in groups A, B, C and D must fail
against the base commit, because the gateway accepts the altered event today.
This repository has no mechanism for a test that is expected to fail, and CI
must stay green on `master`.

Two honest options:

1. **Land S3 and S4 in one pull request.** The reviewer reads the test file
   first, checks out the base commit, runs the tests there, and records that
   groups A to D fail. Then the reviewer reads the implementation. This is the
   recommendation.
2. **Land S3 first with the cases skipped**, each with a recorded reason. This
   is weaker: a skipped test proves nothing, and a later author can leave it
   skipped.

Option 1 keeps the evidence and keeps `master` green. The record in
`KI-SENTINEL-20261102-008` must state who ran the tests against the base
commit, and what the result was.

## What this track does not authorize

- No network ingress, no listener, no queue consumer and no HTTP route.
- No deployment, and no change to a secret, a key or an environment variable.
- No change to the shadow-mode boundary (ADR-011).
- No claim that authentication is secure until the negative tests pass and an
  independent reviewer confirms them.
