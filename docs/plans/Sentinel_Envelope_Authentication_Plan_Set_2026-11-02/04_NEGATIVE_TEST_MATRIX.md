# 04 Negative Test Matrix

Owner requirement 4: independent negative tests must exist before any
production enforcement.

## Rules for these tests

1. **The tests come before the enforcement.** Write them against the current
   code first. Each case in group A, B, C and D then fails, because the gateway
   accepts the altered event today. That failure is the evidence that the test
   is real.
2. **A test must not use the code under test to make its own input.** A case
   must build the altered event and the forged credential directly. It must not
   call `resign` or `buildEvent` to produce the value under test. A defect in
   the encoder would otherwise make both sides agree, and every test would pass.
3. **An independent reviewer writes or reviews the tests.** The author of the
   implementation must not be the only author of its negative tests.
4. **Each case asserts three things:** the status is `rejected`; the reason code
   is exactly the code in the table; the ledger holds no accepted record for
   that event.
5. **A rejection must not name the field that differed.** Group A uses one code,
   `producer_auth_failed`, for every case. A test that expects a field name
   would lock in an oracle.
6. The new file is `test/event_auth.test.ts`. The existing `test/gateway.test.ts`
   keeps the contract and boundary cases.

`Today` is the verified behaviour at `432337c`. `Required` is the behaviour the
correction must produce.

## Group A: the bound envelope fields

Each case signs a valid event, changes one field, and ingests the changed event
with the original credential.

| Case | Field changed | Today | Required | Reason code |
|---|---|---|---|---|
| NEG-A01 | `tenant.tenant_id` | accepted | rejected | `producer_auth_failed` |
| NEG-A02 | `tenant.account_id` | accepted | rejected | `producer_auth_failed` |
| NEG-A03 | `tenant` removed from a tenant-scoped event | rejected, `tenant_required` | rejected | `tenant_required` or `producer_auth_failed` |
| NEG-A04 | `actor.actor_id` | accepted | rejected | `producer_auth_failed` |
| NEG-A05 | `actor.actor_type` | accepted | rejected | `producer_auth_failed` |
| NEG-A06 | `actor.session_id` added where it was absent | accepted | rejected | `producer_auth_failed` |
| NEG-A07 | `subject.subject_id` | accepted | rejected | `producer_auth_failed` |
| NEG-A08 | `subject.subject_type` | accepted | rejected | `producer_auth_failed` |
| NEG-A09 | `event_id` | accepted | rejected | `producer_auth_failed` |
| NEG-A10 | `occurred_at`, moved earlier | accepted | rejected | `producer_auth_failed` |
| NEG-A11 | `observed_at`, moved later | accepted | rejected | `producer_auth_failed` |
| NEG-A12 | `schema_version` (same major) | accepted | rejected | `producer_auth_failed` |
| NEG-A13 | `correlation.trace_id` | accepted | rejected | `producer_auth_failed` |
| NEG-A14 | `location.execution_lane`, `cloud` to `local` | accepted | rejected | `producer_auth_failed` |
| NEG-A15 | `data_policy.sensitivity`, `internal` to `restricted` | accepted | rejected | `producer_auth_failed` |
| NEG-A16 | `data_policy.cloud_allowed`, `true` to `false` | accepted | rejected | `producer_auth_failed` |
| NEG-A17 | `data_policy.retention_class`, `security_365d` to `transient_7d` | accepted | rejected | `producer_auth_failed` |
| NEG-A18 | `data_policy.content_included` | accepted | rejected | `producer_auth_failed` |
| NEG-A19 | `producer.instance_id` | accepted | rejected | `producer_auth_failed` |
| NEG-A20 | `producer.version` | accepted | rejected | `producer_auth_failed` |
| NEG-A21 | `integrity.idempotency_key` | accepted | rejected | `producer_auth_failed` |
| NEG-A22 | `resource` added where it was absent | accepted | rejected | `producer_auth_failed` |
| NEG-A23 | `control_lineage` removed from a signed lineage event | accepted | rejected | `producer_auth_failed` |
| NEG-A24 | `control_lineage` added to an event that had none | accepted | rejected | `producer_auth_failed` |
| NEG-A25 | `control_lineage.policy_generated_effect`, `true` to `false` | accepted | rejected | `producer_auth_failed` |
| NEG-A26 | one `control_lineage.sentinel_finding_ids` element removed | accepted | rejected | `producer_auth_failed` |
| NEG-A27 | `integrity.payload_hash` changed, payload unchanged | rejected, `payload_hash_mismatch` | rejected | `payload_hash_mismatch` |
| NEG-A28 | unknown top-level field added | accepted, and stored | rejected | `unknown_envelope_field` |
| NEG-A29 | unknown field added inside `actor` | accepted | rejected | `unknown_envelope_field` |

The owner's requirement-1 minimum is covered by NEG-A01, A02, A04, A07, A09,
A10 and the payload cases in group F. The other cases cover the fields this
plan adds, each of which the check confirmed is alterable today.

## Group B: cross-tenant replay

| Case | Construction | Today | Required | Reason code |
|---|---|---|---|---|
| NEG-B01 | Sign an event for `ten_demo`. Change `tenant_id` to `ten_other`. Keep the credential. | accepted | rejected | `producer_auth_failed` |
| NEG-B02 | The same, on a signature-required event (`billing.subscription.changed`). | accepted | rejected | `producer_auth_failed` |
| NEG-B03 | Sign two events for two tenants. Ingest event B with event A's credential. | accepted | rejected | `producer_auth_failed` |
| NEG-B04 | A tenant-scoped producer emits an event with no tenant. | rejected, `tenant_required` | rejected | `tenant_required` |
| NEG-B05 | A credential from producer X on an event whose `producer.service` is Y. | rejected, `producer_identity_mismatch` | rejected | `producer_identity_mismatch` |
| NEG-B06 | An event for another environment, with a valid credential. | rejected, `environment_boundary` | rejected | `environment_boundary` |

NEG-B03 is the sharpest case. Two different events with the same payload have
the same token today, so one credential authenticates both. After the
correction, one credential authenticates one envelope.

## Group C: event_id replay and de-duplication

| Case | Construction | Today | Required | Reason code |
|---|---|---|---|---|
| NEG-C01 | Sign an event. Change `event_id`. Keep the credential. | accepted | rejected | `producer_auth_failed` |
| NEG-C02 | Ingest the same signed event twice. | second is `duplicate` | second is `duplicate` | — |
| NEG-C03 | Change `event_id` and re-sign with the real key. | accepted | accepted | — |
| NEG-C04 | Change `event_id` and keep `integrity.idempotency_key`. | accepted | rejected | `producer_auth_failed` |

NEG-C02 and NEG-C03 are controls. De-duplication must still work, and a
producer must still be able to emit a second, genuinely different event.

## Group D: event_type changes

| Case | Construction | Today | Required | Reason code |
|---|---|---|---|---|
| NEG-D01 | `usage.tokens.recorded` to `usage.retry.recorded`, in the producer prefix and canonical | accepted | rejected | `producer_auth_failed` |
| NEG-D02 | `usage.tokens.recorded` to `identity.session.created`, outside the prefix | rejected, `event_type_not_allowed` | rejected | `event_type_not_allowed` or `producer_auth_failed` |
| NEG-D03 | A type that is not canonical | rejected, `unknown_event_type` | rejected | `unknown_event_type` |
| NEG-D04 | A signature-required type changed to a type that needs no signature | accepted if in prefix | rejected | `producer_auth_failed` |

NEG-D01 is the case the owner's record names. The gateway accepts it today,
because the prefix check and the canonical-type check both pass.

## Group E: credential and signature substitution

| Case | Construction | Today | Required | Reason code |
|---|---|---|---|---|
| NEG-E01 | Copy `credential.token` into `integrity.signature` on a signature-required event. | accepted; the two values are identical today | rejected | `signature_invalid` |
| NEG-E02 | Copy `integrity.signature` into `credential.token`. | accepted | rejected | `producer_auth_failed` |
| NEG-E03 | A valid signature with another producer's `signature_key_id`. | rejected, `signature_invalid` | rejected | `signature_invalid` |
| NEG-E04 | A token made with the published fixture secret, against a production runtime. | rejected, `producer_auth_failed` | rejected | `producer_auth_failed` |
| NEG-E05 | A token in upper-case hex, or 63 characters. | rejected, `producer_auth_failed` | rejected | `producer_auth_failed` |
| NEG-E06 | A credential that is not an object with three strings. | rejected, `producer_credential_malformed` | rejected | `producer_credential_malformed` |

NEG-E01 and NEG-E02 prove the domain separation in `02_SIGNATURE_BINDING.md`.
Both fail today for the same reason: the token and the signature are the same
bytes.

## Group F: the format and the encoder

| Case | Construction | Required | Reason code |
|---|---|---|---|
| NEG-F01 | An absent optional field changed to a present empty string | rejected | `producer_auth_failed` |
| NEG-F02 | A present empty string changed to an absent field | rejected | `producer_auth_failed` |
| NEG-F03 | A field value that moves a separator, for example a `tenant_id` that contains `0x1F` | rejected | `producer_auth_failed` |
| NEG-F04 | Two envelopes whose only difference is which field holds a separator byte | the two authenticated byte strings differ | — |
| NEG-F05 | A string with an unpaired surrogate in a bound field | rejected | `envelope_not_encodable` |
| NEG-F06 | A payload with an added `__proto__` key, original credential | rejected | depends on the `KI-SENTINEL-20261102-006` correction; see `01` |
| NEG-F07 | A payload with `null` changed to `1e400`, original credential | rejected | depends on the same correction |
| NEG-F08 | The committed golden vector re-encoded by the implementation | the bytes, the digest and the HMAC match the fixture | — |

NEG-F06 and NEG-F07 are the payload cases. They record the hard dependency in
`01`. If the `KI-SENTINEL-20261102-006` correction has not landed, these two
cases still fail, and the track is not complete.

## Group G: positive controls

A matrix of refusals proves nothing on its own. A gateway that refuses
everything passes group A.

| Case | Construction | Required |
|---|---|---|
| POS-01 | An unaltered signed event | accepted |
| POS-02 | An unaltered signature-required event | accepted |
| POS-03 | An event with no tenant, from a system-scoped producer | accepted |
| POS-04 | An event with every optional field present | accepted |
| POS-05 | An event with every optional field absent | accepted |
| POS-06 | An event with a `control_lineage` and three finding ids | accepted |
| POS-07 | The three committed replay fixtures, re-signed, end to end | the ledgers match the committed expectations |
| POS-08 | A second, genuinely different event from the same producer | accepted, and not a duplicate |
| POS-09 | A payload field changed and the event re-signed | accepted |

POS-07 is the regression control for the whole pipeline: the detector nodes,
Sentinel Prime and the policy decisions must give the same output as before.

## Coverage statement

| Owner requirement 1 field | Cases |
|---|---|
| `tenant_id` | NEG-A01, NEG-A03, NEG-B01, NEG-B02, NEG-B04 |
| `account_id` | NEG-A02 |
| `actor_id` | NEG-A04 |
| `subject_id` | NEG-A07 |
| `event_id` | NEG-A09, NEG-C01, NEG-C04 |
| `event_type` | NEG-D01 to NEG-D04 |
| `occurred_at` | NEG-A10 |
| payload digest | NEG-A27, NEG-F06, NEG-F07, POS-09 |
| cross-tenant replay | NEG-B01, NEG-B02, NEG-B03 |
| `event_id` replay | NEG-C01, NEG-C02, NEG-C04 |
| positive control | POS-01 to POS-09 |
