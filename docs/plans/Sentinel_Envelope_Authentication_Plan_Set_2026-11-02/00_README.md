# Sentinel Envelope Authentication Plan Set

- **Plan ID:** `BDS-SNT-ENVELOPE-AUTH-001`
- **Finding:** `KI-SENTINEL-20261102-008`
- **Date:** 2026-11-02
- **Owner and decision authority:** Charlie Boswell
- **Priority:** P0 security, by owner ruling of 2026-11-02
- **Status:** Design approved conditionally by the owner; **independent review round 1 returned blocking defects.** **Implementation not authorized.**
- **Merged:** 2026-11-02, as `79698ac`, a squash of PR #32, on the owner's instruction. The merge lands documentation. It is not implementation authorization, and it closes none of the review findings.

This plan set is a design document. It is not an authorization to change code.
Each implementation slice needs its own explicit authorization from the owner.
The gateway stays in shadow mode, with no network ingress, until the correction
is implemented and independently verified (owner requirement 5).

The owner ruled all ten D-series decisions on 2026-11-02, amended three of them,
and added five implementation gates. The owner then checked the pull request and
recorded four further **recommendations**, which are explicitly not approvals.
Review round 1 later raised eight more decisions, R1-A to R1-H; the owner ruled
**six** of them on the same day — R1-A to R1-E, and R1-H through ruling 3 in
`06` — and **two stay open: R1-F and R1-G**.
**`06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` is the authoritative record,
and it wins over any earlier text in this plan set.** It separates the rulings
from the recommendations.

**Independent design review round 1 is complete and its verdict is "not safe
to proceed to implementation authorization as written".** It found three
blocking defects in the format itself: the encoding is not one to one, and two
admitted envelope fields are not bound. `07_REVIEW_ROUND_1_FINDINGS.md` holds
the findings. **The owner ruled all three fixes on 2026-11-02 — R1-A, R1-B and
R1-C — and a ruling is not a correction**: the three defects are settled in
design and open in fact. Gate 2 stays open until slice S1 applies them **and**
review round 2 re-attacks them against a frozen commit.
Round 2 reviews the corrected `01` and still needs a frozen commit named before
it starts. No pull-request review is submitted on GitHub, so the review of record
is that document. A green documentation check is not a substitute for any of
this.

**The record count is regenerated.** D-2 fixed it at 41, and amendment 3 in `06`
superseded that. the regeneration of `01` (2026-11-04) settled R1-A's binding contexts and derived the
replacement: **46 fixed records**, plus one for each finding id. The field table and
the worked examples in `01` are current, and its derivation script is in `evidence/`. Slice S1 implements the reviewed format and cannot define it (the owner ruling on
`KI-SENTINEL-20261104-001` in `06`, 2026-11-04).

The owner rules the correction a **P0 security priority**. The verified
cross-tenant event re-targeting is a security-significant authentication
failure. **No exploitation is claimed, and none is observed:** the gateway has
no network ingress, the pipeline is shadow-only, and every demonstration here
ran in a local test process.

## The defect

`producerToken(secret, payloadHash)` is an HMAC over `integrity.payload_hash`
only (`src/spine/producers.ts:35`). `buildEvent` builds the credential from
that token (`src/spine/build.ts:69`). The gateway authenticates the credential
against the same one hash (`src/spine/gateway.ts:156`). The high-value
signature covers the same hash with the same key (`src/spine/gateway.ts:187`).

No other part of the envelope is authenticated.

The credential authenticates a payload. It does not authenticate an event.

## Verified behaviour at the base commit

This plan re-verified the finding by execution at `432337c` (`origin/master`).
The check used a production `SentinelRuntime` with fresh random producer
secrets. It changed one field in a signed event, then ingested the changed
event with the original credential.

| Field changed after signing | Gateway result | Reason code |
|---|---|---|
| `tenant.tenant_id` (`ten_demo` to `ten_other`) | accepted | — |
| `tenant.account_id` | accepted | — |
| `actor.actor_id` | accepted | — |
| `actor.actor_type` | accepted | — |
| `subject.subject_id` | accepted | — |
| `subject.subject_type` | accepted | — |
| `event_id` | accepted | — |
| `event_type`, in prefix and canonical (`usage.tokens.recorded` to `usage.retry.recorded`) | accepted | — |
| `occurred_at`, moved earlier | accepted | — |
| `observed_at`, moved later | accepted | — |
| `correlation.trace_id` | accepted | — |
| `location.execution_lane` (`cloud` to `local`) | accepted | — |
| `data_policy.sensitivity` (`internal` to `restricted`) | accepted | — |
| `data_policy.cloud_allowed` (`true` to `false`) | accepted | — |
| `data_policy.retention_class` (`security_365d` to `transient_7d`) | accepted | — |
| `producer.instance_id` | accepted | — |
| `producer.version` | accepted | — |
| `integrity.idempotency_key` | accepted | — |
| `control_lineage` added | accepted | — |
| `control_lineage` removed from a signed lineage event | accepted | — |
| unknown top-level field added | accepted | — |
| `event_type`, outside the producer prefix | rejected | `event_type_not_allowed` |
| `event_type`, not a canonical type | rejected | `unknown_event_type` |
| `producer.service` | rejected | `producer_identity_mismatch` |
| `producer.environment` | rejected | `environment_boundary` |
| payload field (positive control) | rejected | `payload_hash_mismatch` |

Three further results from the same run govern the design.

1. **One credential authenticates every event with the same payload.** Two
   different events with the same payload got the same token. The gateway
   accepted event B with event A's credential. The defect is therefore not only
   field alteration. A credential is transferable between events.
2. **An unknown envelope field passes validation.** `validateEventEnvelope`
   does not refuse an unknown field. The gateway accepted an added top-level
   field, and the ledger stored it. A field that no rule refuses and no
   signature covers stays malleable.
3. **The high-value signature equals the credential token, byte for byte.**
   Both are `HMAC-SHA256(producer.secret, payload_hash)`. A second value over
   the same bytes with the same key proves nothing more than the first.

## Evidence discipline

The full test suite passes at `432337c`: 402 tests, 0 failures. The suite
passed while the gateway accepted every change in the table above. The
documentation CI also passes at this commit.

A clean review and a green CI run do not show that event authentication is
secure (owner requirement 6). PR #21, #24, #27 and #29 each hardened the
producer boundary, and each merged green. The defect in this plan survived all
four. Only the negative tests in `04_NEGATIVE_TEST_MATRIX.md` can show that a
changed event is refused, and they must exist before any production
enforcement (owner requirement 4).

## Scope

In scope for this plan set:

- the canonical byte format that a producer authenticates;
- the field set the format binds;
- how HMAC-SHA256 covers that format now;
- how Ed25519 covers the same format later (ADR-026);
- the compatibility position;
- the changes to fixtures, `buildEvent` and test support;
- the negative-test matrix;
- the verification gates, the owner decisions, the risks and the slices.

Not in scope for this plan set, and not changed by it:

- any source code, test or fixture;
- any credential, secret or key;
- any deployment or ingress surface;
- an Ed25519 implementation;
- the `forge_contract_core` contract corpus.

## Documents

| File | Purpose |
|---|---|
| `00_README.md` | The defect, the verified behaviour, the scope, this index |
| `01_CANONICAL_AUTHENTICATION_FORMAT.md` | The exact byte format: fields, order, encoding, version tag, absent fields |
| `02_SIGNATURE_BINDING.md` | HMAC now, Ed25519 later, domain separation, verification points |
| `03_COMPATIBILITY_AND_CALLER_IMPACT.md` | No installed base, no shim; fixtures, `buildEvent`, test support |
| `04_NEGATIVE_TEST_MATRIX.md` | The negative tests and the positive controls |
| `05_VERIFICATION_DECISIONS_RISKS_AND_SLICES.md` | Gates, the ruled decisions, risks, proposed slices, the plan registry request |
| `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` | **Authoritative.** The ten D-series rulings, the three amendments, the five implementation gates, the four recommendations pending ruling, the five round-1 rulings R1-A to R1-E, the findings disposition, the authorization boundaries |
| `07_REVIEW_ROUND_1_FINDINGS.md` | Independent review round 1: the verdict, the blocking defects, what was re-verified, and the design decisions — five ruled, three open |
| `MANIFEST.md` | File sizes and SHA-256 digests |

## Sources read for this plan

Repository documentation under `doc/system/`:

- `doc/system/02-contract-surface.md` — contract truth lives in `src/contracts/`; golden fixtures are cross-language contract evidence.
- `doc/system/03-runtime-boundary.md` — the gateway has no network ingress; it authenticates with HMAC over the payload hash; producer secrets come from protected configuration.
- `doc/system/06-verification.md` — which CI runs for which change; the documentation CI rebuilds `doc/SNTSYSTEM.md` and fails on drift.

Findings and decisions:

- `docs/KNOWN_ISSUES.md`: `KI-SENTINEL-20261102-008` (this finding), `KI-SENTINEL-20261102-006` (the canonical form is not one to one), `KI-SENTINEL-20261030-002` (producer secrets from protected configuration), `KI-SENTINEL-20261030-001` (no ingress surface), `KI-SENTINEL-20261102-007` (the ledger can persist a body it did not hash), `KI-SENTINEL-20261102-009` (the dedupe key joins strings without length prefixes).
- `docs/sentinel/adrs/ADR-026-hmac-signing-for-mvp.md` — Ed25519 replaces HMAC before any non-shadow deployment.
- `docs/sentinel/adrs/ADR-027-envelope-authentication-format.md` — the decision record for this format, written under ruling D-10.
- `forge_contract_core/model_certification.py` — the `forge.rfc8785-jcs-*` signing profile, which the D-7 numeric rule aligns with.
- `docs/sentinel/adrs/ADR-025-typescript-reference-and-golden-fixtures.md` — the golden fixtures carry cross-language contract evidence.
- `docs/plans/Forge_Sentinel_Integrated_Plan_Set_2026-06-11/04_EVENT_EVIDENCE_AND_INCIDENT_CONTRACTS.md` — the canonical event contract.

Source read: `src/spine/producers.ts`, `src/spine/gateway.ts`, `src/spine/build.ts`,
`src/spine/replay.ts`, `src/contracts/common.ts`, `src/contracts/envelope.ts`,
`src/contracts/families.ts`, `test/support/producers.ts`, `tools/gen-fixtures.ts`.

## Definition of done for the whole track

The track is complete only when all of these hold:

1. A producer authenticates the security-relevant envelope, not only the payload hash.
2. The authentication format carries a version tag inside the authenticated bytes.
3. The format is deterministic and one to one. Two different envelopes never give the same bytes. **Not met today:** review round 1 produced distinct, validator-admitted, gateway-accepted envelope pairs with identical bytes.
4. The gateway refuses an altered event and a cross-tenant event.
5. The negative tests in `04_NEGATIVE_TEST_MATRIX.md` pass, and an independent reviewer wrote or reviewed them.
6. An independent review of the implementation found no blocking defect.
7. `doc/system/03-runtime-boundary.md` describes the implemented format, and `doc/SNTSYSTEM.md` is rebuilt.
8. `KI-SENTINEL-20261102-008` records the correction, the verification and the residual items.
9. The five implementation gates in `06` each have a named, passing proof.
10. The owner authorizes each step. Design approval is not implementation
    authorization, and merging is not deployment authorization.
