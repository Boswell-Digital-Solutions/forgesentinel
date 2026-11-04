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
execution. The defects are marked in place below.

**The owner ruled all three fixes on 2026-11-02** — R1-A for F3, R1-B for F2 and
R1-C for F1 and F5. Each marking below now states the ruled fix.
`06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` is the authoritative record.

**Regenerated on 2026-11-04 under the owner ruling on `KI-SENTINEL-20261104-001` in `06` (2026-11-04).** The field table, the
signing coverage, the record count and the worked examples below carry rulings R1-A and R1-B.
This is a documentation-only change, and it is the design that review round 2 assesses. It is
not an implementation: no encoder, signer, verifier or gateway change exists, slice S1 stays
unauthorized, and the findings it corrects stay open until S1 implements the design and an
independent review verifies it.

- **The bound layout is 46 fixed records**, plus one record for each element of
  `control_lineage.sentinel_finding_ids`. D-2's count of 41 is superseded (amendment 3 in `06`).
- **The worked examples are regenerated** by a disposable derivation script kept as design
  evidence, `evidence/derive_01_regeneration.mjs`. Nothing in `src/` imports it. Its positive
  control reproduces the superseded 41-record, 1479-byte example byte for byte, so the encoder it
  uses is the format round 1 verified.
- **The golden vector stays with slice S1**, and it must reproduce example A below byte for byte.
- **R1-F and R1-G stay open.** This regeneration does not decide them.

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

**RULED, R1-B (2026-11-02).** Add a presence record for **each** optional parent
object — `tenant`, `resource` and `control_lineage` — with tag `b` and the value
`true` or `false`, **and** tighten the validator under R1-C. Both, not one: gate
2 requires the *encoding* to be injective, so that property must not depend on
the validator behaving.

**Applied in this regeneration:** records 13, 22 and 40 of the table below are the three presence
records, each placed directly before the fields of its parent.

Three parents, so three records. The present-empty form is admitted for two of
the three today. Verified by execution at `4225489`:

| Parent | Absent | Present `{}` |
|---|---|---|
| `resource` | admitted | **admitted** |
| `tenant`, system-scoped family | admitted | **admitted** |
| `control_lineage` | admitted | refused |

**An earlier draft exempted `control_lineage` on the strength of that third row,
and the owner rejected the exemption.** The exemption contradicted the ruling's
own reason: it rested on `validateEventEnvelope` requiring `control_origin` and
`policy_generated_effect`, which is the dependency the ruling forbids. An
exemption rule of that shape is also unstable, because it changes whenever the
validator changes, and R1-C changes the validator. All three parents get a
record, so no later change to the validator can reopen F2.

The alternative, refusing a present empty parent in the validator alone, was
rejected as insufficient. For `resource` it **cannot** work on its own:
`validateEventEnvelope` never reads `resource` at any depth today, so that
option silently depends on the R1-C type rules anyway.

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
  that is not a string. **This rule is new, from review finding F1, and the
  owner ruled it under R1-C.** The earlier text refused only a bad element, so a
  value that merely behaves like an array passed. A string and an array-like
  object both have `length` and index access, so `["a","b"]`, `"ab"` and
  `{0:"a",1:"b",length:2}` all encoded identically, and `validateEventEnvelope`
  admits all three. `Array.isArray` is the check. Verified at `4225489`: all
  three give `length=2`, `[0]="a"` and `[1]="b"`, so no length or index test can
  tell them apart. `Array.isArray` does **not** separate the three from each
  other — it is `false` for both `"ab"` and `{0:"a",1:"b",length:2}` — and it
  does not need to. The rule refuses everything that is not an array, so one
  array test is enough, and the two non-arrays need no distinction.

**RULED, R1-C (2026-11-02).** The encoder rule above is necessary and not
sufficient. `validateEventEnvelope` must type-validate **every declared field**,
and the R-5 drift test must compare **types as well as names**.

**The scope is all 51 declared fields, by a further R1-C ruling.** `envelope.ts`
declares 51 fields, which is 34 required and 17 optional. The measurement below
is a baseline, and it is not a test inventory. `integrity.signature`
also gets syntax validation, for encoding, length and canonical form, against the
approved representation for the algorithm in force. For HMAC-SHA256 that form is
64 lowercase hex, and its authority is `HMAC_HEX_PATTERN`
(`src/spine/producers.ts:62`) as the gateway applies it to `integrity.signature`
(`src/spine/gateway.ts:186`) — **not** the sentence in `02` about
`credential.token`, which an earlier version of this paragraph cited.
**No Ed25519 representation is approved:** `02` records the 128-hex form as an
open implementation item that needs a second pattern constant, and the owner
ruled that the representation must be specified before any hex-only requirement
goes in. A permissive string fallback is not authorized either. `06` holds the
**three** further R1-C rulings, including the owner's sequencing ruling of
2026-11-02, which he re-confirmed on 2026-11-03 after a challenge. "May be
implemented before S6" fixes an **order** and is not permission to begin; S2
remains unauthorized.

**Two different rules reach `integrity.signature`, and only one of them is
R1-C's.** The field is declared `string`, so the two cases separate:

- `integrity.signature: 123` violates the **declared type**. It is admitted
  today, so the field counts inside R1-C's type scope.
- `integrity.signature: "NOT-HEX"` is a valid `string`, so it violates **no
  declared type**. It is also admitted today. Only the syntax rule refuses it,
  and that rule is the R1-A and R1-C format measure, not a type check.

A type rule alone therefore leaves a non-hex signature admitted. The encoder
would still refuse to bind it, which is review finding F5's class, so the syntax
rule is what closes the gap at validation time.

**The measurement, stated precisely, and it is conditional.** `EventEnvelope` and
its member interfaces declare **17** optional fields, inside **51** declared
fields. The number that admit a wrong-typed value depends on two envelope
values, so **no single figure states it**. `06` holds the full matrix. The
summary:

| Family scoping | `control_origin` | Admit, of 51 | Optional |
|---|---|---|---|
| tenant-scoped | `operator` or `standing_policy` | 17 | 15 of 17 |
| tenant-scoped | `sentinel_policy` | 14 | 12 of 17 |
| system-scoped | `operator` or `standing_policy` | **18** | 15 of 17 |
| system-scoped | `sentinel_policy` | 15 | 12 of 17 |

**Cite 18 of 51 as the worst case, and name both conditions.** "15 of 17" is the
optional-field count for two of the four scenarios, and an earlier revision of
this section stated it flat, which was wrong.

`control_origin` moves three optional fields, because the validator reads
`control_id`, `sentinel_incident_id` and `policy_decision_id` only when
`control_origin` is `sentinel_policy` (`src/contracts/envelope.ts:221-225`).
Family scoping moves one **required** field, because `tenant.tenant_id` is read
on a tenant-scoped family (`:152-157`) and never read on a system-scoped one
(`:158-160`).

The two optional fields that always hold are the `tenant` and `control_lineage`
**parents**, which the validator type-checks: `tenant: 123` and
`control_lineage: "x"` both fail validation.

A probe count is not a field count, and this document does not report one. Slice
S2's test must seed each optional parent in a valid shape, require each refusal
to name the probed path, and run a positive control for every field. `06`
records why each rule exists.

An earlier draft of this section said "18 of 18 declared optional fields". That
was wrong. It reported a count of ad-hoc probes as though it were a count of
fields, and the two are not the same: several probes targeted one field, two
targeted fields that `EventResource` declares **required**, and the probe set did
not cover all 17. The probe count is not a measurement of field coverage and is
not reported here.

The cause is structural rather than a single missing check.
`validateEventEnvelope` never reads `resource` at any depth, never reads
`integrity.signature` or `integrity.signature_key_id`, never reads
`control_lineage.sentinel_finding_ids`, and never reads `tenant.account_id`,
`actor.session_id`, `actor.api_key_fingerprint`, `correlation.run_id`,
`correlation.parent_event_id`, `location.region` or `location.country`. It reads
`control_lineage.control_id`, `sentinel_incident_id` and `policy_decision_id`
only when `control_origin` is `sentinel_policy`, so those three are untyped on
the other two origins. So `resource: "not-an-object"`, `location.country: 44` and
`resource.classification: "banana"` are all admitted today.

Two reasons the ruling goes this far. First, the encoder must refuse an
unencodable value in any case, so a permissive validator only converts a clean
validation error into a runtime `envelope_not_encodable` rejection — review
finding F5's contract-valid but unencodable class. Validating up front makes
"passes validation, therefore encodable" an invariant that S1 and S2 can rely
on. Second, a drift test that compares names only lets a later change loosen a
type and reopen F1 without failing CI.

## The field list and the order

The order below is part of the format. The encoder uses this order. It never
sorts at run time, because a sort depends on a collation that can change.

**This table is regenerated (2026-11-04).** It has 46 fixed rows: the three context records, the
40 leaf fields that the contract declares, and R1-B's three presence records. An earlier version
had 41 rows; the derivation script's control reproduces that layout, and the section
"Reconciliation with the contract" below accounts for every one of the 51 declared fields.

| # | Field name | Tag | Source | `credential` context | `signature` context |
|---:|---|---|---|---|---|
| 1 | `auth_format` | `s` | The constant `forgesentinel.event_auth.v1` | bound | bound |
| 2 | `context` | `s` | The constant `credential` or `signature` | `credential` | `signature` |
| 3 | `key_id` | `s` | `credential.key_id` for `credential`; `integrity.signature_key_id` for `signature` | bound | bound |
| 4 | `producer.service` | `s` | Event | bound | bound |
| 5 | `producer.instance_id` | `s` | Event | bound | bound |
| 6 | `producer.version` | `s` | Event | bound | bound |
| 7 | `producer.environment` | `s` | Event | bound | bound |
| 8 | `event_id` | `s` | Event | bound | bound |
| 9 | `event_type` | `s` | Event | bound | bound |
| 10 | `schema_version` | `s` | Event | bound | bound |
| 11 | `occurred_at` | `s` | Event | bound | bound |
| 12 | `observed_at` | `s` | Event | bound | bound |
| 13 | `tenant` | `b` | Presence: `true` when the event carries a `tenant` object (R1-B) | bound | bound |
| 14 | `tenant.tenant_id` | `s` or `-` | Event | bound | bound |
| 15 | `tenant.account_id` | `s` or `-` | Event | bound | bound |
| 16 | `actor.actor_type` | `s` | Event | bound | bound |
| 17 | `actor.actor_id` | `s` | Event | bound | bound |
| 18 | `actor.session_id` | `s` or `-` | Event | bound | bound |
| 19 | `actor.api_key_fingerprint` | `s` or `-` | Event | bound | bound |
| 20 | `subject.subject_type` | `s` | Event | bound | bound |
| 21 | `subject.subject_id` | `s` | Event | bound | bound |
| 22 | `resource` | `b` | Presence: `true` when the event carries a `resource` object (R1-B) | bound | bound |
| 23 | `resource.resource_type` | `s` or `-` | Event | bound | bound |
| 24 | `resource.resource_id` | `s` or `-` | Event | bound | bound |
| 25 | `resource.classification` | `s` or `-` | Event | bound | bound |
| 26 | `correlation.trace_id` | `s` | Event | bound | bound |
| 27 | `correlation.run_id` | `s` or `-` | Event | bound | bound |
| 28 | `correlation.parent_event_id` | `s` or `-` | Event | bound | bound |
| 29 | `location.execution_lane` | `s` | Event | bound | bound |
| 30 | `location.region` | `s` or `-` | Event | bound | bound |
| 31 | `location.country` | `s` or `-` | Event | bound | bound |
| 32 | `data_policy.content_included` | `b` | Event | bound | bound |
| 33 | `data_policy.sensitivity` | `s` | Event | bound | bound |
| 34 | `data_policy.retention_class` | `s` | Event | bound | bound |
| 35 | `data_policy.cloud_allowed` | `b` | Event | bound | bound |
| 36 | `integrity.payload_hash` | `s` | Event. The payload digest; see the section below. | bound | bound |
| 37 | `integrity.idempotency_key` | `s` | Event | bound | bound |
| 38 | `integrity.signature_key_id` | `s` or `-` | Event (R1-A) | bound | bound; equal to record 3 |
| 39 | `integrity.signature` | `s` or `-` | Event (R1-A) | bound | **always `-`**: this context produces the value, so it can never be an input |
| 40 | `control_lineage` | `b` | Presence: `true` when the event carries a `control_lineage` object (R1-B) | bound | bound |
| 41 | `control_lineage.control_origin` | `s` or `-` | Event | bound | bound |
| 42 | `control_lineage.policy_generated_effect` | `b` or `-` | Event | bound | bound |
| 43 | `control_lineage.sentinel_incident_id` | `s` or `-` | Event | bound | bound |
| 44 | `control_lineage.policy_decision_id` | `s` or `-` | Event | bound | bound |
| 45 | `control_lineage.control_id` | `s` or `-` | Event | bound | bound |
| 46 | `control_lineage.sentinel_finding_ids.count` | `c` or `-` | Event. The element count. | bound | bound |
| 47 … | `control_lineage.sentinel_finding_ids.0`, `.1`, … | `s` | Event. One record for each element, in array order. | bound | bound |

The count at record 46 comes before the elements. The count binds the array
length, so a person cannot add or remove an element and keep the signature.
When `sentinel_finding_ids` is absent, record 46 uses `-` and no element record
follows.

`credential.token` is an output of the format and is never bound. `integrity.signature` is the
output of the `signature` context and is bound only in the `credential` context (below).

### Signing coverage

The owner ruling on `KI-SENTINEL-20261104-001` requires the design to enumerate what
`integrity.signature` covers, and requires that tenant identity and all security-relevant routing
and interpretation context are bound, so that a valid signed event cannot be transplanted into
another tenant. This section is that enumeration.

**What the high-value signature covers.** `integrity.signature` is an HMAC over
`AUTH("signature", integrity.signature_key_id, event)` (`02`). Those bytes are every record of the
table in its `signature` column:

- the three context records: the format name, the context `signature` and the signature key id;
- every one of the 40 leaf fields of the envelope except `integrity.signature` itself, which is
  always the absent form in this context;
- the three presence records;
- the finding-id count and every element.

So the signature covers, by name: the tenant (`tenant.tenant_id`, `tenant.account_id`, and the
presence of `tenant`), the producer identity and environment, the event type and schema version
that the gateway routes and interprets by, the actor and the subject, the resource and its
classification, the correlation, the execution lane and location, the whole data policy, the
payload digest, the idempotency key, the signature key id and the control lineage.

**What the credential covers.** The credential token is an HMAC over
`AUTH("credential", credential.key_id, event)`. Those bytes are every record in the `credential`
column: the same set, with `integrity.signature` **bound** as record 39.

**Computation order.** Because the credential binds the signature, a producer computes the
signature first, writes it to `integrity.signature`, and then computes the credential over the
event that carries it. `buildEvent` (`src/spine/build.ts`) produces both values, and S1 must keep
that order.

**Tenant isolation, defined.** Records 13 to 15 bind the tenant in both contexts. An event moved to
another tenant has different bytes in both contexts, so its credential fails as
`envelope_mismatch` and, on a signature-required family, its signature fails as
`signature_mismatch`. That is the transplant `KI-SENTINEL-20261102-008` records, and it is closed
in this design. It stays open in fact until S1 implements the design and review verifies it. A
verbatim replay of an unchanged event into the same tenant is not a format question: the
idempotency key is bound (record 37), and the de-duplication defects are
`KI-SENTINEL-20261102-009` and `-015`.

### Ruling R1-A, settled in the design

R1-A ruled both measures, and left open which contexts bind the two signature fields. The design
settles that:

1. **Refuse.** `validateEventEnvelope` refuses `integrity.signature` and
   `integrity.signature_key_id` on an event whose family requires no signature. Such an event
   therefore encodes both records as `-`.
2. **Bind, in every context where they may appear.**
   - `integrity.signature_key_id` is record 38 in **both** contexts. In the `signature` context it
     equals record 3, so it is bound twice; the duplication is harmless and keeps one layout.
   - `integrity.signature` is record 39. In the `credential` context it is bound. In the
     `signature` context the record is **always** the absent form, because a value cannot be an
     input to the bytes it signs. Record 2 binds the context, so this constant cannot be confused
     with an absent signature in the other context.

**Review finding F3 is closed in the design by records 38 and 39.** Round 1 verified that an added
`integrity.signature` with `signature_key_id: "key_attacker"` was accepted on a
`usage.tokens.recorded` event, because the credential bound neither field. Under this design the
refusal stops that event, and on a signature-required family the credential binds both fields.
The derivation script checks the binding: changing `signature_key_id` leaves the old layout's
credential input unchanged, as round 1 found, and changes the new one. `KI-SENTINEL-20261102-014`
records the current-code defect, and it stays open until S1.

### Reconciliation with the contract

The contract, `src/contracts/envelope.ts`, declares **51** fields: 34 required and 17 optional.
Each is covered in exactly one way:

| Kind | Fields | How the format covers it |
|---|---|---|
| Leaf | 40: the 38 leaves of the earlier table, and `integrity.signature` and `integrity.signature_key_id` | One record each (records 4 to 12, 14 to 21, 23 to 39, 41 to 46). `sentinel_finding_ids` is one leaf with a count record and one record per element. |
| Optional object | 3: `tenant`, `resource`, `control_lineage` | A presence record each (13, 22, 40), and its leaves. |
| Required object | 7: `producer`, `actor`, `subject`, `correlation`, `location`, `data_policy`, `integrity` | Through its leaves. A required object is always present, so its presence carries no information. |
| Payload | 1: `payload` | Through `integrity.payload_hash` (record 36), which the gateway recomputes from the payload. This depends on the `KI-SENTINEL-20261102-006` correction (D-1). |

40 + 3 + 7 + 1 = 51. No declared field is left unbound and unexplained, which is the owner's rule
that a mutable field is either authenticated or excluded with a documented justification. Risk R-5's
drift test in `05` needs exactly this list: `payload` is its one exclusion, bound through the
digest.

### Design decisions round 2 must attack

These are choices of this design, not rulings. Round 2 assesses each:

1. **The presence record is named after its parent** (`tenant`, `resource`, `control_lineage`), with
   tag `b`. A parent name cannot collide with a leaf name, because every leaf name has a dot.
2. **One layout for both contexts.** Record 39 is a constant absent form in the `signature`
   context, rather than two field lists with two index sets.
3. **The signature is computed before the credential**, because the credential binds it.
4. **`integrity.signature_key_id` is bound twice in the `signature` context**, as records 3 and 38.
5. **The placement of the new records**: each presence record directly before its parent's
   fields, and the two signature fields after `integrity.idempotency_key`.

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

Record numbers are those of the regenerated table.

- Records 8 to 15, 17 and 21 are the owner's requirement-1 minimum: the event
  id, the event type, the times, the tenant, the account, the actor and the
  subject. Record 13 binds whether the tenant is present at all.
- Records 4 to 7 bind the producer identity. The gateway already compares
  `producer.service` and `producer.environment` with the registration. Records
  5 and 6 are not compared today, and the check confirmed that both are
  alterable.
- Records 16, 20 and 26 to 28 bind the actor type, the subject type and the
  correlation. The check confirmed that all are alterable. A changed
  `subject_type` moves an event to another subject class.
- Records 22 to 25 bind the resource and its presence (R1-B).
- Records 29 to 35 bind the execution lane and the data policy. These fields
  govern privacy and retention. The check confirmed that a person can change
  `sensitivity`, `retention_class` and `cloud_allowed` on a signed event.
- Record 37 binds the idempotency key.
- Records 38 and 39 bind the two signature fields (R1-A, above).
- Records 40 to 47 bind the control lineage and its presence. ADR-022 uses the
  lineage to stop a policy-produced effect counting as independent confirmation.
  The check confirmed that a person can remove the lineage from a signed event,
  and can add one to an event that had none. An unbound lineage defeats ADR-022.
- Records 1 to 3 bind the format, the context and the key id. They stop a
  format downgrade, a credential-for-signature swap and a key substitution.

## The payload digest

Record 36 binds `integrity.payload_hash`. That string is the payload digest.
The gateway already recomputes it from the actual payload
(`src/spine/gateway.ts:144`) and rejects a mismatch with
`payload_hash_mismatch`. The format therefore binds the payload through
record 36, and the gateway binds record 36 to the real payload bytes.

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
distinctly. That correction is sufficient for record 36.

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

**Owner decision R1-F is open:** confirm that refusing `-0` is a deliberate divergence from
`forge_contract_core`, and accept the ADR-025 cross-language consequence. This regeneration does
not decide it.

### Where the rule applies

**No bound field is typed as a number.** The fixed records are strings,
booleans and one count, each finding-id record is a string, and the encoder
produces the count from the array length. R1-B adds three parent presence
records, and all three are booleans, so this statement still holds whatever the
final count is.

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

1. **The payload digest.** Record 36 binds `integrity.payload_hash`, which the
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
boundary does the work. **Owner decision R1-G is open:** which boundary enforces the
duplicate-key rule. This regeneration does not decide it.

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

**Regenerated on 2026-11-04** by `evidence/derive_01_regeneration.mjs`, a disposable derivation
script kept as design evidence (the owner ruling on `KI-SENTINEL-20261104-001`). It uses the Node
standard library only and reads nothing from `src/`, so a reviewer can reproduce every value below
with `node derive_01_regeneration.mjs` and nothing else. The escaped form shows `0x1F` as `\x1f`
and `0x1E` as `\x1e` with a line break. The real bytes have no line break.

The digests below are SHA-256 over the authenticated bytes, so a reviewer can compare a
reproduction in one value. They are not HMACs: S1's golden vector carries the HMACs over a published
test key.

**The script's positive control.** On the committed golden event it first encodes the superseded
41-record layout, and it stops unless that gives 41 records and 1479 bytes — the example that round
1 reproduced byte for byte. It also checks that its payload-digest method reproduces the golden
event's digest. Both pass, so the encoder below is the format round 1 verified, with the
regeneration applied.

### Example A — the committed golden event, `credential` context

`fixtures/golden/event.usage_tokens_recorded.json`, key id `key_usage_01`. The `usage` family
requires no signature, so R1-A refuses both signature fields and records 38 and 39 are absent. The
event has a tenant and no resource and no control lineage, so the presence records are `true`,
`false` and `false`.

**46 records, 1597 bytes, SHA-256 `ecb0d8f47b26861ecb4c6413a70571a891e83019744318ff74da2015d37cf998`.**

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
tenant\x1fb\x1f4\x1ftrue\x1e
tenant.tenant_id\x1fs\x1f8\x1ften_demo\x1e
tenant.account_id\x1fs\x1f9\x1facct_2041\x1e
actor.actor_type\x1fs\x1f7\x1fservice\x1e
actor.actor_id\x1fs\x1f18\x1fneuroforge-gateway\x1e
actor.session_id\x1f-\x1f0\x1f\x1e
actor.api_key_fingerprint\x1f-\x1f0\x1f\x1e
subject.subject_type\x1fs\x1f7\x1faccount\x1e
subject.subject_id\x1fs\x1f9\x1facct_2041\x1e
resource\x1fb\x1f5\x1ffalse\x1e
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
integrity.signature_key_id\x1f-\x1f0\x1f\x1e
integrity.signature\x1f-\x1f0\x1f\x1e
control_lineage\x1fb\x1f5\x1ffalse\x1e
control_lineage.control_origin\x1f-\x1f0\x1f\x1e
control_lineage.policy_generated_effect\x1f-\x1f0\x1f\x1e
control_lineage.sentinel_incident_id\x1f-\x1f0\x1f\x1e
control_lineage.policy_decision_id\x1f-\x1f0\x1f\x1e
control_lineage.control_id\x1f-\x1f0\x1f\x1e
control_lineage.sentinel_finding_ids.count\x1f-\x1f0\x1f\x1e
```

### Example B — a signature-required family, both inputs

**This envelope is constructed for the design.** No committed fixture holds an event of a
signature-required family. It uses `billing.subscription.changed`, the billing event type the
repository's tests use most, and it exercises every new record: all three parents present, two
finding ids and both signature fields. Its payload digest is computed the way the golden digest is.
Its `integrity.signature` is an illustrative value of the approved syntax, 64 lowercase hex, and
not an HMAC.

**B1, the signature input** — `AUTH("signature", "key_billing_sig_01", event)`, the bytes the
high-value signature covers. Record 39 is the absent form, whatever the event carries.

**48 records, 1849 bytes, SHA-256 `bc47a1f77a6ccecd3ed2f6f1e5a2449f085f0912880f3a730e70cddfde316279`.**

```text
auth_format\x1fs\x1f27\x1fforgesentinel.event_auth.v1\x1e
context\x1fs\x1f9\x1fsignature\x1e
key_id\x1fs\x1f18\x1fkey_billing_sig_01\x1e
producer.service\x1fs\x1f15\x1fbilling-service\x1e
producer.instance_id\x1fs\x1f18\x1fbilling-service-01\x1e
producer.version\x1fs\x1f5\x1f1.4.0\x1e
producer.environment\x1fs\x1f10\x1fproduction\x1e
event_id\x1fs\x1f19\x1fevt_example_billing\x1e
event_type\x1fs\x1f28\x1fbilling.subscription.changed\x1e
schema_version\x1fs\x1f5\x1f1.0.0\x1e
occurred_at\x1fs\x1f24\x1f2026-11-04T09:00:00.000Z\x1e
observed_at\x1fs\x1f24\x1f2026-11-04T09:00:01.000Z\x1e
tenant\x1fb\x1f4\x1ftrue\x1e
tenant.tenant_id\x1fs\x1f8\x1ften_demo\x1e
tenant.account_id\x1fs\x1f9\x1facct_2041\x1e
actor.actor_type\x1fs\x1f8\x1foperator\x1e
actor.actor_id\x1fs\x1f10\x1fop_charlie\x1e
actor.session_id\x1f-\x1f0\x1f\x1e
actor.api_key_fingerprint\x1f-\x1f0\x1f\x1e
subject.subject_type\x1fs\x1f12\x1fsubscription\x1e
subject.subject_id\x1fs\x1f8\x1fsub_7781\x1e
resource\x1fb\x1f4\x1ftrue\x1e
resource.resource_type\x1fs\x1f12\x1fsubscription\x1e
resource.resource_id\x1fs\x1f8\x1fsub_7781\x1e
resource.classification\x1fs\x1f12\x1fconfidential\x1e
correlation.trace_id\x1fs\x1f23\x1ftrc_evt_example_billing\x1e
correlation.run_id\x1fs\x1f6\x1frun_42\x1e
correlation.parent_event_id\x1f-\x1f0\x1f\x1e
location.execution_lane\x1fs\x1f5\x1fcloud\x1e
location.region\x1fs\x1f9\x1fus-east-1\x1e
location.country\x1f-\x1f0\x1f\x1e
data_policy.content_included\x1fb\x1f5\x1ffalse\x1e
data_policy.sensitivity\x1fs\x1f12\x1fconfidential\x1e
data_policy.retention_class\x1fs\x1f13\x1fsecurity_365d\x1e
data_policy.cloud_allowed\x1fb\x1f4\x1ftrue\x1e
integrity.payload_hash\x1fs\x1f71\x1fsha256:39de473dec94c28e7c2376880a524c31572d13096ea06ea64e8fa1de6060adfe\x1e
integrity.idempotency_key\x1fs\x1f19\x1fevt_example_billing\x1e
integrity.signature_key_id\x1fs\x1f18\x1fkey_billing_sig_01\x1e
integrity.signature\x1f-\x1f0\x1f\x1e
control_lineage\x1fb\x1f4\x1ftrue\x1e
control_lineage.control_origin\x1fs\x1f15\x1fsentinel_policy\x1e
control_lineage.policy_generated_effect\x1fb\x1f4\x1ftrue\x1e
control_lineage.sentinel_incident_id\x1fs\x1f8\x1finc_0091\x1e
control_lineage.policy_decision_id\x1fs\x1f7\x1fpd_0117\x1e
control_lineage.control_id\x1fs\x1f20\x1fctl_cloud_route_hold\x1e
control_lineage.sentinel_finding_ids.count\x1fc\x1f1\x1f2\x1e
control_lineage.sentinel_finding_ids.0\x1fs\x1f8\x1ffnd_0301\x1e
control_lineage.sentinel_finding_ids.1\x1fs\x1f8\x1ffnd_0302\x1e
```

**B2, the credential input** — `AUTH("credential", "key_billing_cred_01", event)`, computed after
the signature is written. Record 39 binds the signature.

**48 records, 1917 bytes, SHA-256 `cd6be4cae6ae2a6c8a50ff81b6a73b0cf5bc0687d1d3b268a993410202fed07e`.**

```text
auth_format\x1fs\x1f27\x1fforgesentinel.event_auth.v1\x1e
context\x1fs\x1f10\x1fcredential\x1e
key_id\x1fs\x1f19\x1fkey_billing_cred_01\x1e
producer.service\x1fs\x1f15\x1fbilling-service\x1e
producer.instance_id\x1fs\x1f18\x1fbilling-service-01\x1e
producer.version\x1fs\x1f5\x1f1.4.0\x1e
producer.environment\x1fs\x1f10\x1fproduction\x1e
event_id\x1fs\x1f19\x1fevt_example_billing\x1e
event_type\x1fs\x1f28\x1fbilling.subscription.changed\x1e
schema_version\x1fs\x1f5\x1f1.0.0\x1e
occurred_at\x1fs\x1f24\x1f2026-11-04T09:00:00.000Z\x1e
observed_at\x1fs\x1f24\x1f2026-11-04T09:00:01.000Z\x1e
tenant\x1fb\x1f4\x1ftrue\x1e
tenant.tenant_id\x1fs\x1f8\x1ften_demo\x1e
tenant.account_id\x1fs\x1f9\x1facct_2041\x1e
actor.actor_type\x1fs\x1f8\x1foperator\x1e
actor.actor_id\x1fs\x1f10\x1fop_charlie\x1e
actor.session_id\x1f-\x1f0\x1f\x1e
actor.api_key_fingerprint\x1f-\x1f0\x1f\x1e
subject.subject_type\x1fs\x1f12\x1fsubscription\x1e
subject.subject_id\x1fs\x1f8\x1fsub_7781\x1e
resource\x1fb\x1f4\x1ftrue\x1e
resource.resource_type\x1fs\x1f12\x1fsubscription\x1e
resource.resource_id\x1fs\x1f8\x1fsub_7781\x1e
resource.classification\x1fs\x1f12\x1fconfidential\x1e
correlation.trace_id\x1fs\x1f23\x1ftrc_evt_example_billing\x1e
correlation.run_id\x1fs\x1f6\x1frun_42\x1e
correlation.parent_event_id\x1f-\x1f0\x1f\x1e
location.execution_lane\x1fs\x1f5\x1fcloud\x1e
location.region\x1fs\x1f9\x1fus-east-1\x1e
location.country\x1f-\x1f0\x1f\x1e
data_policy.content_included\x1fb\x1f5\x1ffalse\x1e
data_policy.sensitivity\x1fs\x1f12\x1fconfidential\x1e
data_policy.retention_class\x1fs\x1f13\x1fsecurity_365d\x1e
data_policy.cloud_allowed\x1fb\x1f4\x1ftrue\x1e
integrity.payload_hash\x1fs\x1f71\x1fsha256:39de473dec94c28e7c2376880a524c31572d13096ea06ea64e8fa1de6060adfe\x1e
integrity.idempotency_key\x1fs\x1f19\x1fevt_example_billing\x1e
integrity.signature_key_id\x1fs\x1f18\x1fkey_billing_sig_01\x1e
integrity.signature\x1fs\x1f64\x1f0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\x1e
control_lineage\x1fb\x1f4\x1ftrue\x1e
control_lineage.control_origin\x1fs\x1f15\x1fsentinel_policy\x1e
control_lineage.policy_generated_effect\x1fb\x1f4\x1ftrue\x1e
control_lineage.sentinel_incident_id\x1fs\x1f8\x1finc_0091\x1e
control_lineage.policy_decision_id\x1fs\x1f7\x1fpd_0117\x1e
control_lineage.control_id\x1fs\x1f20\x1fctl_cloud_route_hold\x1e
control_lineage.sentinel_finding_ids.count\x1fc\x1f1\x1f2\x1e
control_lineage.sentinel_finding_ids.0\x1fs\x1f8\x1ffnd_0301\x1e
control_lineage.sentinel_finding_ids.1\x1fs\x1f8\x1ffnd_0302\x1e
```

### What the script checks

| Check | Result |
|---|---|
| The B1 signature input does not change when `integrity.signature` changes | pass |
| The B2 credential input changes when `integrity.signature` changes | pass |
| A changed `signature_key_id` leaves the old layout's credential input unchanged (F3, as round 1 found) and changes the new one | pass |
| An absent `resource` and a present empty `resource` collide in the old layout (F2, as round 1 found) and differ in the new one | pass |
| Moving example B to another tenant changes both the signature input and the credential input (`KI-SENTINEL-20261102-008`) | pass |

Each check that shows a defect closed also shows the old layout still has it, so no check passes
for want of a real difference.

The superseded example — 41 records and 1479 bytes, with no presence records and no signature
fields — survives only as the script's control. It must not be cited as current.

## Why the format is one to one

Three properties give the guarantee:

1. Every record carries the exact byte length of its value. A value cannot
   create or hide a separator, so the record boundaries are fixed.
2. Every field name is a constant from the table. An event cannot add, rename
   or reorder a record.
3. The field list is closed, and the tag distinguishes an absent field from a
   present empty string.

Two different bound envelopes therefore give two different byte strings **once
findings F1, F2 and F3 are corrected**. This regeneration corrects F2 and F3 in
the design: the presence records separate an absent parent from an empty one, and
records 38 and 39 with R1-A's refusal close the unbound signature fields. F1 is a
validator rule (R1-C), so it is corrected in the validator, not in the bytes. The
property is the intent and the subject of gate 2.

**The fixes are now in the design and not in the code.** Review round 2 attacks
this design against a frozen commit. The property is established in fact only when
slice S1 implements it and an independent review verifies that implementation. A
design is not a correction, and gate 2 stays open until then.

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

Two known fields are unbound in the code today, which is review finding F3. The design
binds them (records 38 and 39) and refuses them where no signature is required. The
claim that every field is bound is a claim about this design. It becomes true of the
gateway when slice S1 implements it, not when the design is recorded.

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
