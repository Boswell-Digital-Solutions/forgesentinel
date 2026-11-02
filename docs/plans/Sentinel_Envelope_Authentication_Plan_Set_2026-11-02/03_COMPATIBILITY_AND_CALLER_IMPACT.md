# 03 Compatibility and Caller Impact

## The compatibility position: no installed base, so no shim

The workspace rule is explicit (`forge/CLAUDE.md`, "Deployment status"): nothing
is in production until the owner says so, and no repository writes
backwards-compatibility code. There is no shim, no deprecated alias, no
fallback to old behaviour and no migration layer. The shape changes, and every
caller changes with it.

Three facts make that rule safe here.

1. **The gateway has no network ingress** (`KI-SENTINEL-20261030-001`,
   `doc/system/03-runtime-boundary.md`). An event reaches it through
   `sentinel replay <file>` or through a library caller. No service posts to it.
2. **No other repository computes a Sentinel producer token.** A search of the
   other repository checkouts in this workspace for `producerToken`,
   `ProducerCredential` and `forgesentinel` found no implementation. The workspace
   holds 63 git checkouts, so the search covered the other 62. Every hit
   is an inventory record, a plan file, or a comment about the CSSA watchdog's
   outbound DataForge key. That key is `DATAFORGE_CSSA_TOKEN`. It is a different
   credential, and this plan does not change it.
3. **The package is private and unpublished** (`"private": true` in
   `package.json`). No external consumer depends on the current token.

The six registered producers (`identity-service`, `usage-metering`,
`neuroforge`, `billing-service`, `cssa`, `forgeagents`) are profiles in
`STANDARD_PRODUCER_PROFILES`. No real service signs events as any of them
today.

So the gateway must accept exactly one format. It must not accept a credential
over the payload hash alone after this change lands. A dual-accept path would
leave the defect reachable, and nothing needs it.

This is now owner gate 1: **no unauthenticated compatibility fallback. A legacy
credential must not silently retain the ability to authenticate a mutable
envelope.** Three consequences bind the implementation:

1. There is no dual-accept path, no feature flag and no environment variable
   that restores the old behaviour.
2. The old call signature is removed, not kept beside the new one. A function
   that still computes an HMAC over the payload hash alone is a latent fallback,
   even when nothing calls it. Gate G9 in `05` is a source check for that.
3. Case NEG-E07 in `04` proves the refusal at the gateway: a correct HMAC over
   the payload hash alone is rejected with `producer_auth_failed`.

The one compatibility rule that does apply: when a real producer is built in
another repository, that repository and this one must agree at the moment the
second change merges. The golden vector in this plan exists for that purpose.

## Source changes

| File | Change |
|---|---|
| `src/spine/event_auth.ts` (new) | The single encoder. It exports the format name, the field list and a function that returns the authenticated bytes for a context, a key id and a validated envelope. Nothing else holds a copy of the field list. |
| `src/spine/producers.ts` | `producerToken` takes the authenticated bytes, not the payload hash. `ProducerRegistry.authenticate` takes the validated event. `HMAC_HEX_PATTERN` is unchanged. |
| `src/spine/gateway.ts` | `ingest` passes the event to `authenticate`. The signature check builds the `signature` context bytes. A new reason code, `envelope_not_encodable`, covers an envelope the encoder refuses. |
| `src/spine/build.ts` | `buildEvent` builds the token and the signature from the encoder. The envelope is assembled first, then signed, because the signature covers the whole envelope. |
| `src/contracts/envelope.ts` | `validateEventEnvelope` refuses an unknown field, at the top level and in each bound object (ruling D-5). Without this, an unbound field stays malleable. |
| `src/index.ts` | Exports the new module. |
| `src/spine/ledger.ts` | **Added to scope by review finding F33.** Gate 5 and the owner's recommendation 1 cannot be implemented without it. `cloudProjection` skips every data-policy check for a record whose kind is not `event` (`KI-SENTINEL-20261102-011`), `queryByTenant` filters on a `tenant_id` that a rejection took from an unauthenticated envelope (`KI-SENTINEL-20261102-012`), and `LedgerRecord` has no field in which a value can be marked observed and untrusted (review finding F34). The owner must rule on whether this track carries those changes or a separate one does. |

`src/spine/replay.ts` needs no change. The `ReplayLine` shape, `{ event,
credential }`, stays as it is.

`src/runtime.ts` needs no change. It wires the registry, the gateway and the
ledger, and it signs nothing.

`src/spine/gateway.ts` carries one further change that review finding F30
requires: the authentication-failure message must stop interpolating
`credential.service` and `credential.key_id`, which are unbounded,
unvalidated caller input today (`KI-SENTINEL-20261102-013`). The D-3 ruling
already forbids a caller message that names a field or a value, and the
current message breaks it.

## Fixture changes

| Fixture | Change |
|---|---|
| `fixtures/replay/compound_account_compromise.jsonl` | 44 lines. Every `credential.token` changes. Each `integrity.signature` on a signature-required line changes. |
| `fixtures/replay/usage_spike_only.jsonl` | 35 lines. Same change. |
| `fixtures/replay/agent_drift.jsonl` | 24 lines. Same change. |
| `fixtures/golden/event.usage_tokens_recorded.json` | No change. The file holds an envelope with no credential and no signature. |
| `fixtures/golden/directive.*.json` | No change. A control directive carries a placeholder signature: `tools/gen-fixtures.ts:284` writes 64 zero characters and the generator never imports `src/authority/`. The conclusion stands, and the earlier reason — that `src/authority/cssa-control.ts` signed it — was false (review finding F25). |
| `fixtures/assurance/EAS-*.json` | No change. They carry no credential. The CI step that records their SHA-256 digests stays valid. |
| `fixtures/golden/event_auth.v1.vector.json` (new) | The authoritative vector: the envelope, the context, the key id, the authenticated bytes as hex, the SHA-256 of those bytes, and the HMAC under a named test key. `fixtures/golden/manifest.json` gains its entry. |

The event bodies do not change, so the payload hashes, the dedupe keys and the
ledger order stay the same. Only the credential and the signature values
change. Regenerate with `npm run fixtures`, then commit the result.

The vector needs a key that is safe to publish. The fixture secrets in
`test/support/producers.ts` are already public, and a production or staging
runtime refuses them (`KI-SENTINEL-20261030-002`). The vector must name the key
it used, and must state that the key is a test key.

## Test support changes

| File | Change |
|---|---|
| `test/support/producers.ts` | `resign` recomputes the token and the signature from the envelope, not from the payload hash. It already receives the whole line, so it has the envelope it needs. It must stop assigning the token into `integrity.signature`: under the new format those two values differ. |
| `test/gateway.test.ts:79` | Builds a token by hand from the payload hash. It must build the authenticated bytes instead. |
| `test/producer_secrets.test.ts:202` | Forges a token from a payload hash for a negative test. The forgery must use the new format, or the test proves nothing. |
| `test/producer_secrets.test.ts:231` | Asserts that each committed fixture line carries the expected token. The expectation changes with the format. |
| `test/producer_secrets.test.ts:243` | Asserts that an empty key and a NUL-padded key give the same HMAC. The message changes, the property does not. |
| `test/e2e.replay.test.ts:21-23` | Calls `resign` on the three replay fixtures. No change, if `resign` is correct. |

Thirteen test files call `buildEvent`. They take the credential from its
return value, so they need no change when `buildEvent` is correct. That is also
a risk: a defect in `buildEvent` would make every one of them pass. The
negative tests in `04_NEGATIVE_TEST_MATRIX.md` must therefore build their
altered events and their forged credentials directly, and must not use `resign`
or `buildEvent` to produce the value under test.

## Documentation changes

The implementation slice must update these in the same change:

- `doc/system/03-runtime-boundary.md` — the "Producer Authentication" section
  states that the gateway authenticates with HMAC over the payload hash. It
  must state the new format, the bound field set, the version tag, the new
  reason codes, and the unknown-field refusal.
- `doc/system/02-contract-surface.md` — add the new golden vector to the
  cross-language contract evidence.
- `doc/SNTSYSTEM.md` — rebuild with `bash doc/system/BUILD.sh`. The
  documentation CI fails on drift.
- `docs/KNOWN_ISSUES.md` — record the correction, the verification and the
  residual items under `KI-SENTINEL-20261102-008`.
- `docs/sentinel/implementation-status.md` — if it names the producer
  authentication state.

ADR-026 needs no amendment. The format is primitive-independent, and ADR-026
still requires Ed25519 before any non-shadow deployment. The owner ruled D-10,
so the format has its own short decision record:
`docs/sentinel/adrs/ADR-027-envelope-authentication-format.md`. It is written,
and it states that it authorizes no implementation.
