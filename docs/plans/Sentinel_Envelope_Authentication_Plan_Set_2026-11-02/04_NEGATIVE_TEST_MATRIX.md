# 04 Negative Test Matrix

Owner requirement 4: independent negative tests must exist before any
production enforcement.

The owner added five implementation gates on 2026-11-02
(`06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md`). All five are proved here:

| Gate | Group |
|---|---|
| 1 No unauthenticated compatibility fallback | NEG-E07 |
| 2 The canonical encoding must be injective | Group H |
| 3 Verify before side effects | Group J |
| 4 Test tenant isolation explicitly | Group B and group I |
| 5 Preserve operational evidence | Group K |

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
   implementation must not be the only author of its negative tests. Under
   recommendation 2 in `06`, that reviewer also reproduces the failures against
   the pinned vulnerable base **before** reading the corrected implementation,
   and records the exact commit, command, cases and results.
4. **Each case asserts three things:** the status is `rejected`; the reason code
   is exactly the code in the table; the ledger holds no accepted record for
   that event.
5. **A rejection must not name the field that differed.** Group A uses one code,
   `producer_auth_failed`, for every case. A test that expects a field name
   would lock in an oracle.
6. The new file is `test/event_auth.test.ts`. The existing `test/gateway.test.ts`
   keeps the contract and boundary cases.
7. **No skipped security test.** A skipped case proves nothing. A case that
   cannot run is a blocker, not a note.

`Today` is the verified behaviour at `432337c`. `Required` is the behaviour the
correction must produce.

**A case whose `Today` already reads `rejected` is a control, not gate
coverage.** Review finding F18 reproduced all of them — NEG-A03, A27, B04,
B05, B06, D02, D03, E05, E06 and SUB-I08 — and noted that several admit an
alternative reason code, so they pass even if authentication is absent
entirely. They belong in the suite, because a correction must not break them.
They must not be counted toward a gate. The coverage index below marks them.

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
| NEG-E07 | A token that is a correct HMAC over the payload hash alone, in the pre-correction form. | accepted | rejected | `producer_auth_failed` |
| NEG-E08 | A token made with `K_signature` instead of `K_credential`, over the correct `credential` bytes. | not applicable | rejected | `producer_auth_failed` |
| NEG-E09 | A signature made with `K_credential` instead of `K_signature`, over the correct `signature` bytes. | not applicable | rejected | `signature_invalid` |
| NEG-E10 | A token made with the producer secret used directly as the HMAC key, with no derivation. | not applicable | rejected | `producer_auth_failed` |

NEG-E07 proves gate 1: no unauthenticated compatibility fallback. The test must
compute the old value itself, from the payload hash, because the old function
must no longer exist in the source. A grep test must also show that no module
computes an HMAC over `payload_hash` alone.

NEG-E08, NEG-E09 and NEG-E10 prove the D-6 amendment. Each uses a key that the
derivation did not intend for that value. All three fail today for one reason:
there is no derivation, and one key signs both values.

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

## Group H: injectivity (gate 2)

Gate 2: two different supported events must never give the same authenticated
bytes. These cases test the encoder directly, not through the gateway.

The repository has no property-testing dependency, and it stays
dependency-free. The generator is therefore a small function in the test file,
driven by a fixed recorded seed, so a failure reproduces exactly.

**Review finding F17 replaced the original PROP-H02.** It asserted that equal
bytes imply equal projections, which is the contrapositive of PROP-H01 and so
asserts nothing new, at the cost of about 50 million pair comparisons. The
reviewer also showed that PROP-H01 alone is weak proof: a generator over
well-typed random values would pass against an implementation that **omitted
the length prefix entirely**, because distinct random values still give
distinct bytes. A decoder is the sound proof. An encoding that is provably
decodable under a fixed schedule is injective by construction, and the fixed
adversarial cases carry the rest.

| Case | Construction | Required |
|---|---|---|
| PROP-H01 | Generate 10,000 envelopes from the seed. Vary each bound field: present, absent (an **optional** field only), empty, a separator byte, a multi-byte character, a long value, and a lineage array of 0 to 3 ids. An absent **required** field and an absent or non-object required parent are generated as well, and counted separately: each must be **refused** by the encoder (R2-F3). | No two distinct encodable envelopes give the same bytes, and every refusal case is refused. The test compares a map of bytes to envelope. |
| PROP-H02 | **A decoder.** Recover the bound projection from the authenticated bytes, and assert a round trip for every generated envelope and every fixture. **The expected projection is built from the declared fields of `src/contracts/envelope.ts`, independently of `event_auth.ts` and its schedule** (corrected after review round 2, R2-F4). | The decoded projection holds every one of the 40 declared leaves and 3 optional parents, and the decode of an encode returns the original projection, field for field, including every absent-versus-empty distinction. **Mutant control:** an encoder whose schedule drops one field must fail this case. An earlier version built the expected projection from the encoder's own schedule, so a dropped field was missing from both sides and the round trip passed; `08` measured it with `location.country`. `evidence/s1_preconditions/r2f4_proph02_check.mjs` shows the corrected property failing that mutant and passing the encoder. |
| ADV-H03 | Move a separator between two adjacent fields: put the next field's name and value inside the previous field's value. | The two byte strings differ. |
| ADV-H04 | A value that contains `0x1F`, a value that contains `0x1E`, and a value that contains both. | The bytes stay unambiguous, and the length prefix states the true count. |
| ADV-H05 | A value that is the complete text of a later record. | The two byte strings differ. |
| ADV-H06 | An absent field against a present empty string, for each optional field. | The bytes differ for every field. |
| ADV-H07 | A lineage array of 2 ids against one of 3 where the third is empty. | The count record differs, so the bytes differ. |
| ADV-H08 | Two envelopes that differ only in `integrity.signature` or `integrity.signature_key_id`. | **Updated by ruling R1-A (2026-11-02).** Split the case by family. On an event that needs **no** signature, both envelopes are **refused**, because R1-A refuses the two fields outright, so there is no pair to compare. On an event that **requires** a signature, the fields may appear, and the case asserts the context table in `01`, which the regeneration of `01` (2026-11-04) settled: in the `credential` context both fields are bound (records 38 and 39), so the two envelopes give different credential inputs; in the `signature` context `signature_key_id` is bound (records 3 and 38) and `integrity.signature` is always the absent form (record 39), so two envelopes that differ only in `integrity.signature` give the **same** signature input, by design, and must differ in their credential input. R1-A did **not** settle the contexts; the design did, and round 2 reviews it. One constraint is fixed regardless: `integrity.signature` cannot be bound into the `signature` context, because a value cannot be an input to the bytes it signs. Before the correction both envelopes are accepted by a real gateway, so this is a live collision and not correct behaviour. |
| ADV-H10 | An absent optional parent object against a present empty one, for `tenant`, `resource` and `control_lineage`. | **Updated by ruling R1-B (2026-11-02), and corrected after review round 2 (R2-F3).** On the **encoder**, for each of the three parents: the absent form encodes; the present **empty** form is **refused** with `envelope_not_encodable`, because `01`'s failure rule requires a present optional parent to carry its required fields; and the absent form and a **minimal present** form (the parent with only its required fields) give different bytes, with the presence record `false` against `true`. An earlier version required the absent and empty forms to give different bytes, which the failure rule makes impossible. The case must not rely on `validateEventEnvelope` refusing a present empty parent. The ruling applies the encoder-only principle to all three precisely so that a later validator change cannot reopen F2, and a test that leans on the validator would hide that regression. |
| ADV-H11 | `sentinel_finding_ids` as `["a","b"]`, as `"ab"`, and as `{0:"a",1:"b",length:2}`. | The encoder refuses the second and the third. The bytes for the first differ from any refusal (finding F1). **Under ruling R1-C the validator also refuses the second and the third**, so the case asserts refusal at both boundaries. Note that `Array.isArray` is `false` for both the second and the third, so the case must not assert that the three are distinguishable from each other — only that everything which is not an array is refused. |
| ADV-H09 | A string with an unpaired surrogate. | The encoder refuses it. It never produces bytes. |

**ADV-H08 was wrong in review round 1, and it is corrected here.** It
previously asserted that equal bytes were correct for a field the format does
not bind, and justified that with a premise the reviewer falsified: the strict
validator does **not** refuse those two envelopes, because
`integrity.signature` and `integrity.signature_key_id` are **known** fields
that `validateEventEnvelope` never reads. Both members of the pair were
ingested into a real gateway and both were accepted. A case that documents a
live collision as an invariant is worse than no case, so this one now asserts
the corrected behaviour.

## Group I: substitution (gate 4)

Gate 4: test tenant isolation explicitly. Substitution is stronger than
alteration. Each case takes a real value from one signed event and puts it on
another signed event, with that event's own credential.

| Case | Construction | Today | Required | Reason code |
|---|---|---|---|---|
| SUB-I01 | Event X's `tenant` object onto event Y. | accepted | rejected | `producer_auth_failed` |
| SUB-I02 | Event X's `tenant.account_id` onto event Y, same tenant. | accepted | rejected | `producer_auth_failed` |
| SUB-I03 | Event X's `actor` object onto event Y. | accepted | rejected | `producer_auth_failed` |
| SUB-I04 | Event X's `subject` object onto event Y. | accepted | rejected | `producer_auth_failed` |
| SUB-I05 | Event X's `producer` object onto event Y, both from the same registration. | accepted for `instance_id` and `version` | rejected | `producer_auth_failed` |
| SUB-I06 | Event X's `control_lineage` onto event Y, which had none. | accepted | rejected | `producer_auth_failed` |
| SUB-I07 | Event Y's `control_lineage` removed and put onto event X. | accepted | rejected | `producer_auth_failed` |
| SUB-I08 | Event X's `integrity` object onto event Y, payload unchanged. | rejected, `payload_hash_mismatch` | rejected | `payload_hash_mismatch` or `producer_auth_failed` |
| SUB-I09 | Event X's credential onto event Y, same payload, different tenant. | accepted | rejected | `producer_auth_failed` |
| SUB-I10 | Event X's `integrity.signature` onto event Y, both signature-required from the same producer. | accepted when the payloads match | rejected | `signature_invalid` |

SUB-I06 and SUB-I07 are the ADR-022 cases. Lineage substitution can make a
policy-produced effect read as independent confirmation, or hide that an effect
came from a control.

## Group J: verify before side effects (gate 3)

Gate 3: an authentication failure must happen before de-duplication, a ledger
write of an accepted event, routing and downstream publication.

| Case | Construction | Required |
|---|---|---|
| ORD-J01 | Ingest an event whose authentication fails. | No dedupe entry exists for its key. A later genuine event with that key is accepted, not reported as a duplicate. |
| ORD-J02 | Ingest an event whose authentication fails. | The ledger holds one rejection record and no accepted record for that event. |
| ORD-J03 | Ingest an event whose authentication fails, through `SentinelRuntime`. | No detector, no Sentinel Prime input and no policy decision sees the event. **This case is a control, not gate-3 proof** (review finding F19): `EvidenceLedger.events()` filters to `kind === "event" && validation === "accepted"` (`src/spine/ledger.ts:108`), so a rejection is structurally invisible to the detectors whether or not authentication works. It passes today and would pass against a broken implementation. |
| ORD-J04 | Ingest a replay file whose second line fails authentication. | The remaining lines still process, and the summary counts one rejection. |
| ORD-J05 | Read the order of checks in `ingest`. | Contract validation, then the payload-hash check, then authentication, then the signature check, then de-duplication, then the append. A test asserts the reason code of an event that would fail two checks, so the order is observable. |

ORD-J01 is the sharp one. A dedupe entry written before authentication would
let a forged event suppress a genuine one, which is the defect class of
`KI-SENTINEL-20261102-009`.

## Group K: operational evidence (gate 5)

Gate 5: every failure before successful authentication must produce protected
security telemetry, and must not expose a credential or a sensitive payload.
Ruling 5 in `06` extends the gate from an authentication failure to that whole
class — a contract failure, a payload-hash mismatch, a producer-identity
mismatch, an environment-boundary refusal, an event-type refusal, a
tenant-required refusal and an encoder refusal — and this group must assert the
record shape for each class.

| Case | Construction | Required |
|---|---|---|
| EVD-K01 | Ingest an event whose authentication fails. Serialize the rejection record. | The text contains neither the full presented token nor any contiguous run of 16 or more of its characters, and no expected bytes, expected digest or derived key. Review finding F21: "no part of" is untestable, because any two hex characters occur by chance in long hex text. |
| EVD-K09 | The same, with a `credential.service` and a `credential.key_id` of 200 attacker-chosen characters including a NUL byte. | Neither value reaches the record, and neither reaches the caller's message. Verified to fail today: both reach both (`KI-SENTINEL-20261102-013`). |
| EVD-K10 | Ingest a `restricted`, `content_included: true`, `cloud_allowed: false` event that fails any check. Call `cloudProjection` on the rejection record. | It returns no payload content and no `data_policy` from the rejected envelope. Verified to fail today: the projection returns the whole body, with no data-policy check at all (`KI-SENTINEL-20261102-011`). |
| EVD-K11 | Ingest a failing event naming another tenant. Call `queryByTenant` for that tenant. | The forged record is not in that tenant's view. Verified to fail today (`KI-SENTINEL-20261102-012`). |
| EVD-K02 | The same, with a `restricted` payload and `content_included: true`. | The record holds exactly the five elements of ruling 1 in `06` — the gateway's own receipt timestamp, a gateway-generated rejection identifier, the failure reason, the fixed bounded set of non-sensitive diagnostics, and a digest of the received bytes labelled as observed and untrusted — and nothing from the envelope. |
| EVD-K06 | Read the record's payload digest field. | It is labelled an observed, untrusted value. A reader cannot mistake it for proof that the producer sent the event. |
| EVD-K07 | Ingest a failing event whose `data_policy` claims `sensitivity: public` and `cloud_allowed: true`, and one that claims `restricted`. | **Absolute predicate, not a comparison:** the record and its cloud projection carry no payload content and no `data_policy` field from the rejected envelope, whatever it claimed. Review finding F32: the original comparative wording passes against today's broken code, which treats both classifications identically by publishing both. |
| EVD-K08 | Ingest a failing event with a forged `tenant.tenant_id` naming another tenant. | The record does not become readable to that tenant on the strength of the forged value. |
| EVD-K03 | The same. Read the `IngestResult` the caller receives. | One issue, code `producer_auth_failed`, with no field name, no value and no internal category. |
| EVD-K04 | The same. Read the rejection record. | It carries one internal category from the closed set in `02_SIGNATURE_BINDING.md`. |
| EVD-K05 | Ingest an event whose authentication fails. Read every log line and every thrown error. | No secret, no derived key and no token appears. |

EVD-K02 asserts the shape that ruling 1 fixed. An earlier version left the shape
to the slice and recommended keeping non-payload envelope metadata; ruling 1
removed that metadata, and the slice no longer chooses the shape. The test must
not be written to pass whatever the code happens to do.

EVD-K06 to EVD-K08 come from recommendation 1 in `06`. They exist because every
value on a failing event is attacker-chosen: the digest is observed and not
proof, and the `data_policy` and the tenant on a rejected envelope must not
reach any decision about storage, access or retention.

## Group L: attacks review round 1 found missing

| Case | Construction | Today | Required | Reason code |
|---|---|---|---|---|
| NEG-L01 | Change the payload **and** recompute `integrity.payload_hash` to match, then ingest with the original credential. | accepted | rejected | `producer_auth_failed` |
| NEG-L02 | Add `integrity.signature` and `signature_key_id` to an event that needs no signature. | accepted and stored | rejected | A validation refusal, per ruling R1-A. **Not `unknown_envelope_field`**: both are known fields, which is review finding F16's lesson. Slice S2 chooses and records the exact code. |
| NEG-L03 | `sentinel_finding_ids` as a string, and as an array-like object. | accepted | rejected | `envelope_not_encodable` at the encoder, and a validation refusal at `validateEventEnvelope` under ruling R1-C. Both boundaries refuse it. |
| NEG-L04 | A present empty `tenant`, `resource` or `control_lineage`, against the absent parent. | accepted | rejected | `envelope_not_encodable`, from `01`'s failure rule for a present optional parent without its required fields — or the validator's own refusal, if slice S2 rules that `validateEventEnvelope` refuses a present empty parent first. It is never accepted. All three parents are in scope. *(Corrected after review round 2, R2-F3: an earlier version expected `producer_auth_failed`, but the encoder refuses before any credential is compared.)* |
| NEG-L05 | A raw replay line with a duplicate JSON key. | the later value wins silently | refused at intake | a new intake code |
| NEG-L06 | A `key_id` containing the HKDF `info` separator, registered for two producers. | registration accepted | the registry refuses the second registration | `ProducerRegistrationError` |
| NEG-L07 | Ingest a signed event, then ingest it verbatim through a fresh gateway over the same ledger. | accepted | duplicate, or a stated non-goal | — |
| NEG-L08 | Submit many failing events with large credentials, and measure the ledger growth. | unbounded | a stated bound | — |

NEG-L01 is the attack the matrix most obviously lacked: an attacker who holds a
signed event and wants a different payload simply recomputes the hash the
gateway recomputes. Today it succeeds. The format binds record 36, so the
correction refuses it — which makes this the single best positive proof that
the envelope binding works.

NEG-L07 and NEG-L08 are outside owner requirement 3, and they belong to
`KI-SENTINEL-20261102-015` and `KI-SENTINEL-20261102-013`. They are listed so
the plan does not leave a reader assuming replay and resource use are handled.

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
| cross-tenant replay | NEG-B01, NEG-B02, NEG-B03 (B04, B05 and B06 are controls, not coverage) |
| `event_id` replay | NEG-C01, NEG-C02, NEG-C04 |
| positive control | POS-01 to POS-09 |

| Owner implementation gate | Cases |
|---|---|
| 1 No unauthenticated compatibility fallback | NEG-E07, plus a source check that no module computes an HMAC over the payload hash alone |
| 2 Injective canonical encoding | PROP-H01, PROP-H02, ADV-H03 to ADV-H11 |
| 3 Verify before side effects | ORD-J01 to ORD-J05 |
| 4 Explicit tenant isolation | NEG-B01 to NEG-B06, SUB-I01 to SUB-I10 |
| 5 Protected operational evidence | EVD-K01 to EVD-K11 |
| D-6 independent keys | NEG-E08, NEG-E09, NEG-E10 |
| D-7 numeric canonicalization | NEG-F06, NEG-F07, and the payload-number cases that slice S0 owns |
