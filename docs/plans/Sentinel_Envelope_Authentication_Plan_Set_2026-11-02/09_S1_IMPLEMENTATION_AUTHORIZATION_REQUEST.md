# 09 Slice S1 — Implementation Authorization Request

- **Status:** **A request. Nothing in this document is authorized.** The owner's disposition on
  review round 2 (2026-11-04, in `06`) lets S1 "advance to implementation authorization review" and
  asks for "an S1-only implementation authorization request specifying files, interfaces,
  invariants, tests, and rollback boundaries". This is that request.
- **Slice:** S1 in `05`: "`src/spine/event_auth.ts`: the field list, the encoder, the HKDF
  derivation, the unit tests, the group H property and adversarial suite, and the golden vector.
  Nothing calls it from the gateway."
- **Design under implementation:** `01` and `02` at the frozen commit `3cae2dd`, reviewed by round 2
  (`08`, accepted as the review of record). S1 implements that design and does not define it.
- **Decision needed before authorization:** O-2, audience binding (section 6). It changes S1
  whichever way it is decided.

## 1. The owner's preconditions, and their state

| # | Precondition (owner disposition) | State | Evidence |
|---|---|---|---|
| 1 | The R2-F3 and R2-F4 corrections are verified in the test matrix | **Met.** R2-F3: ADV-H10, NEG-L04 and PROP-H01 hold on two independent encoders, 28 of 28 checks. R2-F4: PROP-H02 is corrected in `04` to take its expected field set from the contract, and the corrected property fails the field-dropping mutant of `08` and passes the encoder. | `evidence/s1_preconditions/r2f3_matrix_check.mjs`, `r2f4_proph02_check.mjs` |
| 2 | The encoder's outputs match the frozen canonical vectors | **A gate of the implementation**, defined in section 4: the three worked examples of `01` at `3cae2dd`. | `01`, "Worked example" |
| 3 | Credential and signature domain separation remains enforced | **An invariant of the implementation**, I-6 to I-8 below, each with a test. | `02`, "Key derivation" |
| 4 | No rejection-record, registration or authentication-policy behaviour is introduced through S1 | **A scope rule**, section 2: S1 changes no existing module, and a source check fails the build if any existing module imports `event_auth.ts`. | Section 2; test T-12 |
| 5 | Tests and evidence are reproducible from committed sources | **A rule for every artifact below**: the vector, the test key and every script are committed, and nothing reads a secret from the environment. | Section 4 |

## 2. Files

S1 adds files. It changes only the four existing files marked below, and each change is additive.

| File | Change |
|---|---|
| `src/spine/event_auth.ts` | **New.** The field schedule, the encoder, the HKDF derivation and the MAC helper (section 3). |
| `test/event_auth.test.ts` | **New.** The S1 test suite (section 4). The decoder for PROP-H02 lives here, not in `src/`. |
| `fixtures/golden/event_auth.v1.vector.json` | **New.** The golden vector, per `03`: the envelope, the context, the key id, the authenticated bytes as hex, their SHA-256, and the HMAC under a named test key. |
| `fixtures/golden/manifest.json` | Gains the vector's entry. |
| `tools/gen-fixtures.ts` | Generates the vector, so gate G4 holds. It changes no other fixture. |
| `doc/system/02-contract-surface.md` | Adds the vector to the cross-language contract evidence (`03`). |
| `doc/SNTSYSTEM.md` | Rebuilt with `bash doc/system/BUILD.sh`. |

**S1 does not change:** `src/spine/gateway.ts`, `producers.ts`, `ledger.ts`, `producer_secrets.ts`,
`build.ts`, `src/contracts/envelope.ts`, `src/index.ts`, or any replay fixture. The validator rules
belong to S2, the gateway wiring to S3, the rejection record to SL and S4, the registry rules to S6.
`event_auth.ts` is not exported from `src/index.ts` in this slice, so nothing outside the tests can
call it.

## 3. Interfaces

```ts
// src/spine/event_auth.ts — every function is pure: no I/O, no clock, no environment, no global state.

export const AUTH_FORMAT = "forgesentinel.event_auth.v1";
export type AuthContext = "credential" | "signature";

/** The authenticated bytes. A distinct nominal type, so a raw string or a payload hash cannot be
 *  passed where these bytes are required (gate G9). */
export type AuthBytes = Uint8Array & { readonly __brand: "forgesentinel.AuthBytes" };

/** One row of the fixed schedule: 46 rows, in 01's order. Element records follow row 46. */
export interface FieldSpec {
  readonly name: string;                    // the constant record name
  readonly kind: "s" | "b" | "c" | "presence" | "context";
  readonly required: boolean;               // per src/contracts/envelope.ts
}
export const FIELD_SCHEDULE: readonly FieldSpec[];

/** The refusal of 01's encoder failure rules. Its code is envelope_not_encodable. Its message names
 *  the rule and the field, never a value. */
export class EnvelopeNotEncodable extends Error { readonly code: "envelope_not_encodable"; }

/** AUTH(context, keyId, event) of 01. Throws EnvelopeNotEncodable. In the `signature` context,
 *  `keyId` must equal event.integrity.signature_key_id. */
export function encodeAuth(context: AuthContext, keyId: string, event: EventEnvelope): AuthBytes;

/** K_context of 02: HKDF-SHA256(ikm = secret, salt = AUTH_FORMAT, info = context + "|" + keyId, L = 32).
 *  keyId is the registration's, never the event's. */
export function deriveAuthKey(secret: Uint8Array, context: AuthContext, registrationKeyId: string): Uint8Array;

/** hex(HMAC-SHA256(key, bytes)): 64 lowercase hex. */
export function authMacHex(key: Uint8Array, bytes: AuthBytes): string;
```

There is no verify function, no comparison, no registry lookup and no reason-code mapping. Those are
authentication policy, and precondition 4 keeps them out of S1.

## 4. Tests and gates

The suite is `test/event_auth.test.ts`. Every property has a **mutant control**: a seeded broken
encoder against which the property must fail, so no property passes for want of a real difference
(the lesson of review findings F17 and R2-F4).

| Id | Test | Source |
|---|---|---|
| T-1 | **Frozen vectors.** `encodeAuth` reproduces `01`'s examples at `3cae2dd`: A (46 records, 1597 bytes, SHA-256 `ecb0d8f4…f998`), B1 (48, 1841, `76d0514c…94d4`) and B2 (48, 1908, `c8bf31c6…3ec2`), byte for byte. | Precondition 2 |
| T-2 | **Golden vector (G7).** The committed vector re-encodes to its bytes, its SHA-256 and its HMAC under the named test key. Its bytes are example A's. | `03`; G7 |
| T-3 | PROP-H01, as corrected for R2-F3: no two distinct encodable envelopes give the same bytes, and every refusal case is refused. | `04` |
| T-4 | PROP-H02, as corrected for R2-F4: the decoded projection has every leaf and parent that `envelope.ts` declares, taken from the contract and not from the schedule; and the round trip holds. | `04`; R2-F4 |
| T-5 | ADV-H03 to ADV-H11, including ADV-H10 as corrected for R2-F3. | `04` |
| T-6 | **R-5 drift test.** `FIELD_SCHEDULE`'s names, kinds and required flags equal the declared fields and types of `envelope.ts`, with `payload` as the one exclusion. | `05`, R-5 |
| T-7 | **Failure rules.** Each rule of `01` refuses with `envelope_not_encodable`: a required field or object absent or not an object, a present optional parent without its required fields, a wrong type, `null`, a lone surrogate, a non-array or holed `sentinel_finding_ids`, a `signature`-context key id that is not `integrity.signature_key_id`. | `01` |
| T-8 | **HKDF.** RFC 5869 test case A.1 reproduces, and `deriveAuthKey` gives `K_credential ≠ K_signature` for one secret and key id. | `02` |
| T-9 | **Domain separation.** A credential MAC does not equal a signature MAC over the same event, and record 2 makes the two inputs differ. | `02`; precondition 3 |
| T-10 | **Record 39.** In the `signature` context the input does not change with `integrity.signature`; in the `credential` context it does. | `01` |
| T-11 | **Tenant binding.** Moving an event to another tenant, or removing its tenant, changes both inputs. | `01`; `-008` |
| T-12 | **Isolation.** A source check fails if any file under `src/` other than `event_auth.ts` imports it. | Precondition 4 |

The gates S1 must pass, from `05`: **G1** build, **G2** suite (402 existing tests plus the new ones,
0 failures), **G4** fixture determinism, **G6** documentation, **G7** golden vector, and **G9**'s
nominal-type part. **G8**, an independent review of the S1 change against a frozen commit, comes
before merge. No skipped test counts as evidence (recommendation 2, item 5, ruled as ruling 2).

**Reproducibility (precondition 5).** The vector uses a key from `test/support/producers.ts`, which
is already public and which a production or staging runtime refuses (`KI-SENTINEL-20261030-002`),
and the vector names it and states that it is a test key. Every check above runs from committed
sources with `npm ci --ignore-scripts && npm test`.

## 5. Rollback boundaries

- **S1 is additive.** It adds one module, one test file and one fixture, and it extends one
  generator and two documents. Nothing at run time calls the module.
- **Rollback is a revert of the S1 commit.** No data, no ledger, no configuration, no secret and no
  replay fixture changes, so a revert needs no migration and leaves the gateway as it is today.
- **Stop and revert when:** a frozen vector does not reproduce (T-1); a gate fails; a file outside
  section 2 changes; any existing module imports `event_auth.ts` (T-12); or the independent review
  (G8) finds a blocking defect.
- **What a rollback does not undo.** Nothing: S1 creates no state outside the repository.

## 6. Open decisions that bear on S1

| Decision | Effect on S1 | Request |
|---|---|---|
| **O-2, audience binding** (owner direction: "Require explicit audience binding for authenticated envelopes. The audience must be validated against the intended receiving authority.") | **Changes S1 either way.** (a) A bound audience record in the authenticated bytes changes the v1 layout: the 46 records, the frozen vectors and `01` change, and the change needs its own review before S1 can match "the frozen canonical vectors". (b) Binding the audience in key derivation (`info` gains the receiving authority) leaves the layout and the vectors unchanged, but changes `deriveAuthKey` and T-8. (c) Binding it outside S1, in the registration, needs the O-3 scope model first. | **Rule the mechanism before S1 is authorized.** Under (a), the frozen vectors of precondition 2 become those of the revised `01`. |
| R1-F (`-0`), `-006` (float-shaped tokens) | None. No bound record is numeric (`01`); they govern the payload digest and the intake. | None for S1. |
| R1-G (duplicate keys) | None. It governs the intake boundary. | None for S1. |
| `-004` (one Ed25519 key) | None. It governs S6. | None for S1. |
| `-005` (producer-required signature) | None. It governs the gateway's refusal, S2 and S3. | None for S1. |
| R2-F8 (the HKDF `info` rationale and key-id uniqueness) | `deriveAuthKey` takes the registration's key id; uniqueness is enforced at S6 (D-9 safeguard 1). S1 adds no registry rule. | None for S1; the rationale in `02` is corrected separately. |

## 7. What this request asks for

Authorization to implement S1 exactly as sections 2 to 5 state, **after** O-2's mechanism is ruled,
with no rejection-record, registration, authentication-policy, gateway, deployment or enforcement
change. S2, S3, S4, SL and S6 stay blocked.
