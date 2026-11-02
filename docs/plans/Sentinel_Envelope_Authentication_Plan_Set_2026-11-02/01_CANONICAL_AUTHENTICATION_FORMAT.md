# 01 Canonical Authentication Format

This document specifies the exact bytes a producer authenticates. It answers
owner requirements 1 and 2: bind the security-relevant envelope, and use a
versioned, deterministic format.

The owner ruled on this document on 2026-11-02. D-1, D-2, D-4 and D-5 are
approved with conditions, and D-7 is amended: the numeric rule must exist
before implementation. See `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md`.

**Review round 1 found three blocking defects in this document.** The format as
specified here is **not** one to one, and two admitted fields are not bound.
`07_REVIEW_ROUND_1_FINDINGS.md` holds the findings, each reproduced by
execution. The defects are marked in place below. Do not implement this
document until the owner rules on the candidate fixes.

## Format name and version tag

The format name is `forgesentinel.event_auth.v1`.

The name is the first record of the authenticated bytes. A person who changes
the name changes the bytes, so the signature fails. The name is therefore not
strippable and not downgradable.

The gateway holds the accepted name as a constant. It does not read a format
name from the event or from the credential. A producer cannot ask the gateway
for an older format.

This satisfies D-4 as ruled: the gateway controls the version and the
algorithm, it refuses an unsupported version, and it never negotiates an
algorithm from event input. `02_SIGNATURE_BINDING.md` states what a refusal of
an unsupported version means in practice.

## Why the format is not canonical JSON

`canonicalJson` (`src/contracts/common.ts:140`) is not one to one.
`KI-SENTINEL-20261102-006` records three cases: the rebuild step drops a
`__proto__` key, `JSON.stringify` writes `-0` as `0`, and it writes a
non-finite number as `null`. A format that is not one to one cannot
authenticate. Two different envelopes would give the same bytes, so one
signature would cover both.

This format therefore uses its own encoding. The encoding never builds an
object, so it has no `__proto__` rebuild defect. It carries an explicit byte
length for every value, so no value can create, hide or move a separator.

## The record encoding

The authenticated bytes are the concatenation of one record for each field, in
the order of the table below. There is no prefix, no suffix and no newline.

One record is:

```text
<name> 0x1F <tag> 0x1F <length> 0x1F <value> 0x1E
```

| Part | Rule |
|---|---|
| `<name>` | The field name from the table, in ASCII. The encoder uses the constant from the table. It never reads a name from the event. |
| `0x1F` | The ASCII unit separator, one byte. |
| `<tag>` | One ASCII character. The table gives the tag for each field. |
| `<length>` | The byte count of `<value>` in UTF-8, as decimal ASCII digits, with no sign and no leading zero. A zero length is the single digit `0`. |
| `<value>` | The value bytes in UTF-8. The length states the exact count, so a value that contains `0x1F` or `0x1E` is harmless. |
| `0x1E` | The ASCII record separator, one byte. |

The tags are:

| Tag | Meaning | Value bytes |
|---|---|---|
| `s` | A present string | The string in UTF-8 |
| `b` | A present boolean | The text `true` or `false` |
| `c` | A present count | The count as decimal ASCII digits, with no sign and no leading zero, exactly as `<length>` is written. A zero count is the single digit `0`. (Pinned by review finding F6; the earlier text left the form open to a second-language implementer.) |
| `-` | An absent field | None. The length is `0`. |

## How an absent optional field is represented

An absent field uses the tag `-` and the length `0`, and it has no value bytes.
The record is still present. The field order never changes.

A field is absent when the event omits it, or when its parent object is absent.
Example: an event with no `tenant` gives `-` for `tenant.tenant_id` and `-` for
`tenant.account_id`.

**BLOCKING DEFECT, review finding F2.** This rule makes an absent parent object
and a present empty parent object encode identically. Verified by execution:
an event with no `resource` and the same event with `resource: {}` both pass
`validateEventEnvelope`, both are accepted by the gateway, and both give the
same authenticated bytes. The same holds for `tenant` on a system-scoped
family. Two different supported events therefore share one signature, which is
what gate 2 forbids.

Candidate fix, **not ruled**: add one presence record for each optional parent
object — `tenant`, `resource` and `control_lineage` — with tag `b` and the
value `true` or `false`. The parent's presence then changes the bytes. The
alternative, refusing a present empty parent in the validator, is weaker: it
leaves the format relying on the validator for injectivity rather than on the
encoding.

A present empty string uses the tag `s` with the length `0`. An absent field and
a present empty string therefore have different bytes. This difference matters:
without it, a person could delete an optional field and keep the signature.

The encoder treats a JavaScript `undefined` value as absent. It treats `null`
in a bound envelope field as an error, because no bound field accepts `null`.

## Encoder failure rules

The encoder fails closed. It refuses these inputs, and the gateway then rejects
the event with the reason code `envelope_not_encodable`:

- a value with the wrong type for its tag, for example a number where the table says `s`;
- a string that contains an unpaired surrogate. Node replaces an unpaired
  surrogate with `U+FFFD` during UTF-8 conversion. Two different strings would
  then give the same bytes, so the encoding would stop being one to one;
- a bound object field that is present but is not an object;
- a `sentinel_finding_ids` that is not an array, or an array with an element
  that is not a string. **This rule is new, from review finding F1.** The
  earlier text refused only a bad element, so a value that merely behaves like
  an array passed. A string and an array-like object both have `length` and
  index access, so `["a","b"]`, `"ab"` and `{0:"a",1:"b",length:2}` all encoded
  identically, and `validateEventEnvelope` admits all three. `Array.isArray`
  is the check.

## The field list and the order

The order below is part of the format. The encoder uses this order. It never
sorts at run time, because a sort depends on a collation that can change.

| # | Field name | Tag | Source |
|---:|---|---|---|
| 1 | `auth_format` | `s` | The constant `forgesentinel.event_auth.v1` |
| 2 | `context` | `s` | The constant `credential` or `signature` (see `02_SIGNATURE_BINDING.md`) |
| 3 | `key_id` | `s` | `credential.key_id` for `credential`; `event.integrity.signature_key_id` for `signature` |
| 4 | `producer.service` | `s` | Event |
| 5 | `producer.instance_id` | `s` | Event |
| 6 | `producer.version` | `s` | Event |
| 7 | `producer.environment` | `s` | Event |
| 8 | `event_id` | `s` | Event |
| 9 | `event_type` | `s` | Event |
| 10 | `schema_version` | `s` | Event |
| 11 | `occurred_at` | `s` | Event |
| 12 | `observed_at` | `s` | Event |
| 13 | `tenant.tenant_id` | `s` or `-` | Event |
| 14 | `tenant.account_id` | `s` or `-` | Event |
| 15 | `actor.actor_type` | `s` | Event |
| 16 | `actor.actor_id` | `s` | Event |
| 17 | `actor.session_id` | `s` or `-` | Event |
| 18 | `actor.api_key_fingerprint` | `s` or `-` | Event |
| 19 | `subject.subject_type` | `s` | Event |
| 20 | `subject.subject_id` | `s` | Event |
| 21 | `resource.resource_type` | `s` or `-` | Event |
| 22 | `resource.resource_id` | `s` or `-` | Event |
| 23 | `resource.classification` | `s` or `-` | Event |
| 24 | `correlation.trace_id` | `s` | Event |
| 25 | `correlation.run_id` | `s` or `-` | Event |
| 26 | `correlation.parent_event_id` | `s` or `-` | Event |
| 27 | `location.execution_lane` | `s` | Event |
| 28 | `location.region` | `s` or `-` | Event |
| 29 | `location.country` | `s` or `-` | Event |
| 30 | `data_policy.content_included` | `b` | Event |
| 31 | `data_policy.sensitivity` | `s` | Event |
| 32 | `data_policy.retention_class` | `s` | Event |
| 33 | `data_policy.cloud_allowed` | `b` | Event |
| 34 | `integrity.payload_hash` | `s` | Event. This is the payload digest. See the section below. |
| 35 | `integrity.idempotency_key` | `s` | Event |
| 36 | `control_lineage.control_origin` | `s` or `-` | Event |
| 37 | `control_lineage.policy_generated_effect` | `b` or `-` | Event |
| 38 | `control_lineage.sentinel_incident_id` | `s` or `-` | Event |
| 39 | `control_lineage.policy_decision_id` | `s` or `-` | Event |
| 40 | `control_lineage.control_id` | `s` or `-` | Event |
| 41 | `control_lineage.sentinel_finding_ids.count` | `c` or `-` | Event. The element count. |
| 42 … | `control_lineage.sentinel_finding_ids.0`, `.1`, … | `s` | Event. One record for each element, in array order. |

The count at record 41 comes before the elements. The count binds the array
length, so a person cannot add or remove an element and keep the signature.
When `sentinel_finding_ids` is absent, record 41 uses `-` and no element record
follows.

`integrity.signature` and `credential.token` are the outputs of the format.
The format does not bind them.

**BLOCKING DEFECT, review finding F3.** `integrity.signature_key_id` is also
unbound in the `credential` context: record 3 carries it only when the context
is `signature`. Both fields are admitted by `validateEventEnvelope`, which
never reads them, and the gateway evaluates them only when a signature is
required. Verified by execution: an added `integrity.signature` of 64 `a`
characters with `signature_key_id: "key_attacker"` was accepted on a
`usage.tokens.recorded` event and stored inside the accepted record, and so
was a non-hex signature with a numeric key id. A corrected gateway built from
this document would still accept both, because nothing binds or refuses them.
`KI-SENTINEL-20261102-014` records the current-code defect.

Candidate fixes, **not ruled**: (a) refuse both fields on an event that
requires no signature, and bind them in the `credential` context when a
signature is required; or (b) bind both in every context, with the absent tag
when they are not present. Option (a) keeps the bytes shorter and makes the
refusal explicit. Either way the unknown-field refusal cannot help here,
because both are known fields.

### A future authenticated field needs a versioned format change

D-2 is approved with this condition. The field list is part of the format, not
a configuration value. Adding a field, removing one, changing a tag or changing
the order changes the authenticated bytes for every event, so it is a new
format version with a new name, for example
`forgesentinel.event_auth.v2`. A version is never added in place, and the
gateway accepts one version at a time unless the owner authorizes an allowlist.

The same rule governs a new envelope field in the contract. The field list and
`validateEventEnvelope` must change together. Risk R-5 in `05` names the drift
test that holds the two sets equal.

### Why each group is bound

- Records 8 to 14, 16 and 20 are the owner's requirement-1 minimum: the event
  id, the event type, the times, the tenant, the account, the actor and the
  subject.
- Records 4 to 7 bind the producer identity. The gateway already compares
  `producer.service` and `producer.environment` with the registration. Records
  5 and 6 are not compared today, and the check confirmed that both are
  alterable.
- Records 15, 19 and 24 to 26 bind the actor type, the subject type and the
  correlation. The check confirmed that all are alterable. A changed
  `subject_type` moves an event to another subject class.
- Records 27 to 33 bind the execution lane and the data policy. These fields
  govern privacy and retention. The check confirmed that a person can change
  `sensitivity`, `retention_class` and `cloud_allowed` on a signed event.
- Record 35 binds the idempotency key.
- Records 36 to 42 bind the control lineage. ADR-022 uses the lineage to stop a
  policy-produced effect counting as independent confirmation. The check
  confirmed that a person can remove the lineage from a signed event, and can
  add one to an event that had none. An unbound lineage defeats ADR-022.
- Records 1 to 3 bind the format, the context and the key id. They stop a
  format downgrade, a credential-for-signature swap and a key substitution.

## The payload digest

Record 34 binds `integrity.payload_hash`. That string is the payload digest.
The gateway already recomputes it from the actual payload
(`src/spine/gateway.ts:144`) and rejects a mismatch with
`payload_hash_mismatch`. The format therefore binds the payload through
record 34, and the gateway binds record 34 to the real payload bytes.

This chain is only as strong as the digest. `KI-SENTINEL-20261102-006` shows
that `hashPayload` is not one to one today. A person can add a `__proto__` key
to a signed payload, or change `null` to `Infinity`, and the digest does not
change.

**This plan therefore declares a hard dependency: the correction of
`KI-SENTINEL-20261102-006` must land before enforcement of this format.**
Without it, the envelope is authenticated and the payload is not.

The owner approved D-1 with a condition: **the corrected payload digest must be
verified before envelope authentication relies on it.** Landing the correction
is not enough, and a passing suite is not enough. Slice S0 in `05` is complete
only when the corrected digest semantics and the negative tests for them are
independently verified. Cases NEG-F06 and NEG-F07 in `04` hold this track open
until that verification exists. The owner's disposition of
`KI-SENTINEL-20261102-006` says the same: it must not be closed on passing
tests alone.

`KI-SENTINEL-20261102-006` already proposes the correction: build a canonical
object with a null prototype or with `Object.defineProperty`, so every own key
appears; and refuse `-0`, `NaN` and a non-finite number, or encode each one
distinctly. That correction is sufficient for record 34.

### Alternative: a second digest in this track

The alternative removes the dependency. This track defines its own recursive
encoder for a JSON value, computes its own payload digest, and binds that
digest as a new record. The envelope authentication then holds even while
`hashPayload` stays not one to one.

The alternative costs more: the recursive encoder needs rules for objects,
arrays, strings, numbers, booleans and `null`, and it needs its own golden
vectors. It also puts two payload digests in the system, which a later reader
can confuse.

The ecosystem already has a canonical digest convention,
`forge.rfc8785-jcs-sha256.v1`, owned by `forge_contract_core`. A second digest
in this repository must not contradict it. **The owner ruled option A:** depend
on the `KI-SENTINEL-20261102-006` correction, and keep one payload digest. The
alternative is recorded here for the record, and it is not the chosen path.

## Numeric canonicalization

The owner amended D-7: the numeric rule must exist before implementation. This
section is that rule. It aligns with the integer-only JCS signing profile that
`forge_contract_core` implements in
`forge_contract_core/model_certification.py` (the profile constants there are
`forge.rfc8785-jcs-ed25519.v1` and `.v2`; the digest name
`forge.rfc8785-jcs-sha256.v1` that this plan quotes comes from that
repository's `CLAUDE.md` and RFCs, not from that module — review finding F15).

**One rule here is deliberately stricter than the ecosystem profile, and it is
a divergence, not an alignment.** Review finding F12 verified by execution that
`forge_contract_core` **accepts** the JSON token `-0` and normalizes it: it
parses to `0` and encodes as `0`, because Python routes `-0` through the
integer parser. Only the float form `-0.0` is refused there. JavaScript's
`JSON.parse` yields `-0`, which `Object.is` distinguishes. So the same bytes
are admitted by the ecosystem authority and refused here. Refusing is right
under the owner's D-7 ruling, and it must be recorded as a stricter divergence,
because ADR-025 makes cross-language parity a contract property.

### Where the rule applies

**No bound field is typed as a number.** The 41 fixed records are strings,
booleans and one count, each finding-id record is a string, and the encoder
produces the count from the array length.

That is a statement about the format, not about what the envelope admits.
Review finding F14 corrected an earlier, stronger sentence here. Verified by
execution: `validateEventEnvelope` admits a number in a bound string field —
`tenant.account_id = 12345` validates and the gateway accepts it — so the
encoder does receive event-supplied numbers. The encoder refuses them by its
wrong-type rule, which is the safe outcome, but the format does not get to
claim it never sees one. The validator must refuse a wrong-typed bound field
as well, so a non-conforming event never reaches the encoder and never gets
signed (review finding F5).

The rule therefore applies in two other places:

1. **The payload digest.** Record 34 binds `integrity.payload_hash`, which the
   corrected canonical form computes over the payload. Payload numbers are
   event input, so the rule belongs to the `KI-SENTINEL-20261102-006`
   correction, and this plan depends on it (D-1).
2. **The contract validator.** `validateEventEnvelope` must refuse a payload
   number that the rule forbids, so a non-conforming event never reaches the
   encoder and never gets signed. It must refuse a wrong-typed bound envelope
   field for the same reason (review finding F5), and it must refuse a
   `sentinel_finding_ids` that is not an array of strings (review finding F1).

**The duplicate-key rule cannot be enforced at the validator.** Review finding
F13 verified that `JSON.parse('{"x":1,"x":2}')` gives `{"x":2}` with one key:
the duplicate is gone before any validator runs, and `parseReplayJsonl`
(`src/spine/replay.ts:24`) is a plain `JSON.parse`. Python gets this property
free through `object_pairs_hook`; TypeScript does not. Enforcing it needs a
raw-text scan or a custom parser **at the intake boundary**, before parsing.
This is an open design item, and the slice that owns it must say which
boundary does the work.

### The rule

| Case | Treatment |
|---|---|
| `NaN` | Refused. |
| `+Infinity`, `-Infinity` | Refused. |
| Negative zero (`-0`) | Refused. `Object.is(value, -0)` identifies it; `value === 0` does not. |
| A floating-point number | Refused, as signing profile v1 refuses it. |
| An integer from −9007199254740991 to 9007199254740991 | Admitted. The bound is `MAX_JCS_SAFE_INTEGER` in `forge_contract_core` and `Number.MAX_SAFE_INTEGER` in JavaScript. Both are 2^53 − 1. |
| An integer outside that range | Refused. A double cannot hold it exactly, so two systems can disagree about its value. |
| A duplicate object key | Refused. Two keys that collide make the canonical text ambiguous. |
| A lone UTF-16 surrogate, in a key or a string | Refused. `forge_contract_core` refuses it, and the encoder in this document refuses it. |

An admitted integer is written as decimal ASCII digits, with a leading `-` for
a negative value, with no leading zero, no `+`, no exponent and no fraction.
That is `str(value)` in `forge_contract_core` and `String(value)` in
JavaScript for every admitted value.

Key order is unchanged. `forge_contract_core` sorts object keys by UTF-16 code
unit, and JavaScript's default `Array.prototype.sort` on strings does the same,
so the current canonical form already agrees on ordering.

### What a producer does with a fraction

A quantity that needs a fraction must not be a JSON float. Two forms are
admitted:

- a scaled integer, as `forge_contract_core` uses for `confidence_percent`;
- a decimal string, which the encoder treats as a string.

The producer chooses, and the event family documents the choice.

### Effect on the committed fixtures

No event payload in the committed fixtures holds a non-integer number. The
non-integer values in `fixtures/golden/` are risk dimensions inside a finding
and an incident (`likelihood`, `impact`, `confidence`, `evidence_quality`,
`contribution`). A producer does not sign those artifacts, so the rule does not
reach them. The rule therefore breaks no committed fixture today.

It does constrain a future producer. A cost or rate payload must use a scaled
integer or a decimal string. `doc/system/03-runtime-boundary.md` must state
this when the slice lands.

## Worked example

The example uses the committed golden event
`fixtures/golden/event.usage_tokens_recorded.json`, the context `credential`
and the key id `key_usage_01`. The escaped form shows `0x1F` as `\x1f` and
`0x1E` as `\x1e` with a line break. The real bytes have no line break.

```text
auth_format\x1fs\x1f27\x1fforgesentinel.event_auth.v1\x1e
context\x1fs\x1f10\x1fcredential\x1e
key_id\x1fs\x1f12\x1fkey_usage_01\x1e
producer.service\x1fs\x1f14\x1fusage-metering\x1e
producer.instance_id\x1fs\x1f17\x1fusage-metering-01\x1e
producer.version\x1fs\x1f5\x1f1.0.0\x1e
producer.environment\x1fs\x1f10\x1fproduction\x1e
event_id\x1fs\x1f16\x1fevt_golden_usage\x1e
event_type\x1fs\x1f21\x1fusage.tokens.recorded\x1e
schema_version\x1fs\x1f5\x1f1.0.0\x1e
occurred_at\x1fs\x1f24\x1f2026-06-09T12:00:00.000Z\x1e
observed_at\x1fs\x1f24\x1f2026-06-09T12:00:00.000Z\x1e
tenant.tenant_id\x1fs\x1f8\x1ften_demo\x1e
tenant.account_id\x1fs\x1f9\x1facct_2041\x1e
actor.actor_type\x1fs\x1f7\x1fservice\x1e
actor.actor_id\x1fs\x1f18\x1fneuroforge-gateway\x1e
actor.session_id\x1f-\x1f0\x1f\x1e
actor.api_key_fingerprint\x1f-\x1f0\x1f\x1e
subject.subject_type\x1fs\x1f7\x1faccount\x1e
subject.subject_id\x1fs\x1f9\x1facct_2041\x1e
resource.resource_type\x1f-\x1f0\x1f\x1e
resource.resource_id\x1f-\x1f0\x1f\x1e
resource.classification\x1f-\x1f0\x1f\x1e
correlation.trace_id\x1fs\x1f20\x1ftrc_evt_golden_usage\x1e
correlation.run_id\x1f-\x1f0\x1f\x1e
correlation.parent_event_id\x1f-\x1f0\x1f\x1e
location.execution_lane\x1fs\x1f5\x1fcloud\x1e
location.region\x1f-\x1f0\x1f\x1e
location.country\x1f-\x1f0\x1f\x1e
data_policy.content_included\x1fb\x1f5\x1ffalse\x1e
data_policy.sensitivity\x1fs\x1f8\x1finternal\x1e
data_policy.retention_class\x1fs\x1f13\x1fsecurity_365d\x1e
data_policy.cloud_allowed\x1fb\x1f4\x1ftrue\x1e
integrity.payload_hash\x1fs\x1f71\x1fsha256:3188a5357f5c7b5f0514fe1708f52faddfeb23bc31b43af7240b99cd595f4e61\x1e
integrity.idempotency_key\x1fs\x1f16\x1fevt_golden_usage\x1e
control_lineage.control_origin\x1f-\x1f0\x1f\x1e
control_lineage.policy_generated_effect\x1f-\x1f0\x1f\x1e
control_lineage.sentinel_incident_id\x1f-\x1f0\x1f\x1e
control_lineage.policy_decision_id\x1f-\x1f0\x1f\x1e
control_lineage.control_id\x1f-\x1f0\x1f\x1e
control_lineage.sentinel_finding_ids.count\x1f-\x1f0\x1f\x1e
```

This example has 41 records and 1479 bytes. It has 41 because the golden event
carries no control lineage: an event with a lineage array adds one record for
each finding id, so 41 is the floor and not the count for every event. A
planning script produced the example from the committed fixture. It is illustrative. The implementation slice commits the
authoritative vector as a golden fixture, with the bytes, the digest and the
HMAC over a published test key (see `03_COMPATIBILITY_AND_CALLER_IMPACT.md`).

## Why the format is one to one

Three properties give the guarantee:

1. Every record carries the exact byte length of its value. A value cannot
   create or hide a separator, so the record boundaries are fixed.
2. Every field name is a constant from the table. An event cannot add, rename
   or reorder a record.
3. The field list is closed, and the tag distinguishes an absent field from a
   present empty string.

Two different bound envelopes therefore give two different byte strings **once
findings F1, F2 and F3 are corrected**. As this document stands, that claim is
false: review round 1 produced distinct, validator-admitted, gateway-accepted
envelope pairs that encode identically. The property is the intent and the
subject of gate 2. It is not yet established.

The closed field list has one condition: the envelope must carry no field
outside the list. `validateEventEnvelope` does not refuse an unknown field
today, and the check confirmed that the gateway accepts one and the ledger
stores it. The implementation must therefore refuse an unknown field in an
event envelope, or an unbound field stays malleable.

The owner approved D-5 with a condition: **define the permitted extension
points, if any, in a future version.** This version has none. An unknown field
is refused with `unknown_envelope_field`.

The refusal must cover **the top level and every bound object**, which is the
wording in `03_COMPATIBILITY_AND_CALLER_IMPACT.md`. Review finding F4 noted
that this document, `06` and ADR-027 said only "an unknown envelope field": on
the narrow reading, `producer.extra`, `data_policy.extra`, `integrity.extra`,
`tenant.extra` and `control_lineage.extra` all stay unbound and malleable, and
the verified-behaviour table tested only an unknown **top-level** field. The
broad reading is the required one.

An unknown-field refusal still cannot close the field list on its own: review
finding F3 shows two **known** fields that are admitted and unbound. A later
version that wants an extension point must do three things: name the point in
the format, bind its content in the authenticated bytes, and state what a
consumer may do with a field it does not recognize. An unauthenticated
extension point is the defect this plan corrects, so it must never be added as
a convenience.

Two known fields are unbound today, which is review finding F3. Until that is
corrected, this document must not claim that every field is bound.

## Related finding

`KI-SENTINEL-20261102-009` records the same class of defect in `dedupeKey`
(`src/spine/gateway.ts:27`). That function joins caller-controlled strings with
`|` and `:`, with no length prefix and no escape. Two different events can give
one dedupe key, and the gateway then reports the second as a duplicate and
never records it. The encoder in this plan is the correct basis for that key.

The owner ruled D-8: that finding is a separate security-relevant integrity
defect, it stays separately tracked, and it follows immediately after this
correction, reusing this encoder where that is safe. Slice S7 in `05` carries
it.
