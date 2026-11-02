# Known Issues

This document tracks known issues in the Forge Sentinel repository. Record a
finding here in the same session that you find it. Chat is not durable.

## Authority-layer findings from a fresh security review — CLOSED 2026-09-19

A security review (a fresh pass, distinct from the 17 findings PR #14 already fixed on
2026-09-14) found three real gaps in the capability/executor/gateway layer. All three
were spot-checked directly against source, not just asserted. None is wired to a live
network surface today (forgesentinel has no deployment yet), but all three matter before
any real deployment, since they sit exactly on the authority boundary the capability
system exists to enforce.

- **`rollback()` has no authentication.** `src/authority/executor.ts:72` (and the same
  pattern in `src/authority/yellowjacket.ts:70`): every forward action requires a valid,
  signed, single-use capability token, but `rollback(original: ActionReceipt, nowIso)`
  takes the *entire receipt object* as its only input — no capability, no signature
  check. `ActionReceipt.integrity.hash` is a plain SHA-256 (not an HMAC) and isn't
  checked here regardless. Since TypeScript types don't exist at runtime, anything that
  can construct an object shaped like an `ActionReceipt` can call `rollback()` and
  revert any target's state (e.g. release another target's MFA requirement, resume a
  paused key) without ever holding a capability. `CssaControlRegistry.rollback()`
  (`src/authority/cssa-control.ts:192`) does this correctly — it accepts only an opaque
  ID and looks up its own trusted internal state. `IdentityAuthority`/`YellowJacketAuthority`
  should do the same instead of trusting the caller's object.
  **Status: FIXED.** `CapabilityValidatedAuthority.rollback()` (`src/authority/authority-base.ts`)
  now requires a capability token, validated the same way `execute()` validates one for the
  forward action, scoped to the receipt's own declared rollback action/target. The two
  adapters no longer implement `rollback()` themselves — they implement only the state
  transition (`applyRollback()`); the capability check and receipt shape live once in the
  base class. Covered by `test/capability.test.ts` ("rollback without a valid capability is
  rejected...").

- **`CapabilityService.issue()` signs caller-supplied fields it never validates.**
  `src/authority/capability.ts:39-72`: it checks that `action.action_type` exists in
  `decision.allowed_actions` (an existence check only), then signs `action.scope`,
  `action.expires_in_seconds`, and `action.reversible` verbatim into the token — never
  cross-checking these against the matched `decision.allowed_actions` entry's own values.
  A caller that hand-builds an `AllowedAction` with the right `action_type` but a wider
  `scope`, longer `expires_in_seconds`, or `requires_approval: "policy_allowed"` (skipping
  the approval-level check entirely) gets a validly-signed capability carrying the forged
  values; `validate()` downstream only checks internal token self-consistency and can't
  catch this. Same trust-boundary class PR #14 partially hardened for `GLOBAL_ALWAYS_DENY`
  in this same function, left incomplete for every other field. Not reachable from any
  code in this repo today — only an external operator-console caller would trigger it.
  **Status: FIXED.** `issue()` now uses `action.action_type` only as a lookup key into
  `decision.allowed_actions`; every field actually signed into the capability (`scope`,
  `expires_in_seconds`, `reversible`, and the `requires_approval` check) comes from that
  matched, trusted entry, never from the caller's copy. Covered by `test/capability.test.ts`
  ("capability issue() signs the matched decision entry's own fields...").

- **Gateway dedupe key omits `tenant_id`.** `dedupeKey()`, `src/spine/gateway.ts:23-35`:
  the idempotency key is `producer.service | event_id | event_type | subject |
  time-bucket | payload_hash` — no tenant. Producers are registered once per *service*,
  not per tenant (`src/runtime.ts:27-32`), so a same-hour event-id/subject/payload-hash
  collision from two different tenants behind the same producer would return
  `status: "duplicate"` with `record` pointing at the *other* tenant's ledger entry —
  a real gap against this file's own tenant-isolation invariant, though it requires an
  ID collision from an already-trusted producer to trigger. No test covers this path.
  **Status: FIXED.** `dedupeKey()` now includes `event.tenant?.tenant_id` in the hashed
  key. Covered by `test/gateway.test.ts` ("dedupe key includes tenant...").

**Verification**: `npm test` passes — 294 of 294 tests, exit 0.

---

## doc/system layout does not match the audit tool — CLOSED 2026-09-20

- **Location**: `doc/system/` — was the seven numbered subdirectories.
- **Status**: CLOSED. Migrated to the flat `NN-kebab-case.md` layout directly
  under `doc/system/`.
- **Cause**: The numbered-subdirectory convention was never the real standard.
  `forge`'s own `scripts/audit_doc_system_shape.py` (see its module docstring
  and `git log`) records that the subdirectory shape was introduced
  2026-06-22 from a same-day snapshot of ForgeAgents used as an "exemplar,"
  was never part of the documented compliance gate, and contradicted both
  `docs/canonical/documentation_protocol_v1.md` and the company-wide BDS
  Documentation Protocol v2.0. PR #141 (`forge`, merged 2026-09-11) retired
  that standard in the root repo and the tooling itself; this repository (and
  most others) had already copied the erroneous convention before the
  correction and were never migrated back.
- **Fix**: Moved each `NN-*.md` section file out of its subdirectory to
  `doc/system/` directly, removed the empty subdirectories, updated
  `BUILD.sh` to glob `doc/system/[0-9][0-9]-*.md` at depth 1 instead of
  requiring the seven named subfolders, and updated `_index.md`'s section
  table to the flat paths. `bash doc/system/BUILD.sh` passes; the only diff
  in the compiled `doc/SNTSYSTEM.md` is the version/date header and the
  table's file-path column.
- **Note for other repos**: this was a single-repo migration to bring
  forgesentinel in line with the tooling's actual (corrected) standard, not a
  fleet-wide migration. Other repos still carrying the subdirectory
  convention remain open work, tracked separately.

---

## Repository baseline defects — CLOSED 2026-09-14

The repository did not meet the BDS repository-documentation baseline. All four
items below are fixed.

- **`LICENSE` was absent.** Five of the seven `cloud-systems` repositories carry
  the proprietary license. This repository did not. Fixed: added `LICENSE` with
  the same text that the governing `forge` repository uses.
- **`package.json` declared `"license": "UNLICENSED"`.** This contradicted the
  intended proprietary license. Fixed: `"SEE LICENSE IN LICENSE"`.
- **`package.json` declared `"private": "true"` as a string.** npm expects a
  boolean. The string is truthy, so the behaviour was correct by accident.
  Fixed: `"private": true`.
- **`package.json` declared `"main": "index.js"`.** No such file exists. The
  build writes to `dist/`. Fixed: `"main": "dist/src/index.js"` plus a `types`
  entry. `tsconfig.json` sets `declaration: true`, so both files exist after a
  build.

**Verification**: `npm test` passes — 182 of 182 tests, exit 0.

---

_Last updated: 2026-09-20_

## No secret scan or dependency audit in CI — OPEN 2026-10-02

Found while scoping CI to the change type. `.github/workflows/ci.yml` is the only workflow. It runs `npm ci --ignore-scripts`, `npm run build` and `node --test dist/test/*.test.js`. No workflow runs a secret scan, a dependency audit (`npm audit`), CodeQL, or an egress check. For the security layer of the ecosystem this is a gap in the evidence, not in the tests. The CI-scope change does not add or remove any scan: it filters `ci.yml` only, and `doc/system/06-verification.md` states that a future secret scan must run on every change.
Status: OPEN. Closed when a secret scan that runs on every change is added, and the owner decides about the other scans.

## KI-SENTINEL-20261030-003: The fixture generator fails on Windows — OPEN 2026-10-30

- **Classification**: Tooling defect. Not a security defect. It has no effect on the runtime or on CI, which runs on Linux.
- **Discovery source**: forgesentinel PR #21 (the KI-SENTINEL-20261030-002 correction). The operator ruled that it is filed separately.
- **Verified at**: `6ca9ce981a48706df1708bb31cffe6a884f93f38` (`origin/master`), 2026-10-30, on Windows 11 with Node 22.17.1.
- **Evidence**: `tools/gen-fixtures.ts:18` sets `const ROOT = new URL("../..", import.meta.url).pathname;`. On Windows, `pathname` is `/C:/Forge/...`, and `join` then makes `C:\C:\Forge\...`.
- **Observed behavior**: `npm run fixtures` fails before it writes a file, with `ENOENT: no such file or directory, mkdir 'C:\C:\Forge\...\fixtures\replay'`. On Linux, `pathname` is a valid path, and the generator works.
- **Proposed correction**: Use `fileURLToPath(new URL("../..", import.meta.url))` from `node:url`. Then confirm that `npm run fixtures` on Windows and on Linux makes no change under `fixtures/`.
- **Correction implemented (2026-11-02, unverified)**: Branch `fix/sentinel-followups`, operator-authorized as one isolated PR with KI-SENTINEL-20261030-003, -006 and KI-SENTINEL-20261102-001, -002. `tools/gen-fixtures.ts` uses `fileURLToPath`. On Windows, `npm run fixtures` now completes, and all 12 regenerated fixture files match the committed content after line endings are normalized. The independent review of PR #27 ran it on Linux (WSL Ubuntu, Node 20), and all fixture files were byte-identical there too.
- **Status**: Open — recorded, unresolved until the correction is verified.

## KI-SENTINEL-20261030-001: doc/system does not describe the Event Gateway or the ingress surface — OPEN 2026-10-30

- **Classification**: Documentation drift. This entry does not claim a runtime defect.
- **Discovery source**: `forge` PR #325 (BDS-XMACH-CALLER-BOUNDARY-001, WP00).
- **Verified at**: `9c9de3a4036e8a4d0ae9416c9ae41ff23e7b9964` (`origin/master`), 2026-10-30.
- **Evidence**:
  - `src/spine/gateway.ts:48` declares `class EventGateway`. Line 71 authenticates the producer. Lines 93-107 do the signature check for signature-required producers and event families.
  - `src/runtime.ts:81` builds the gateway inside `SentinelRuntime`. `src/runtime.ts:241` feeds events to it through `replayInto`.
  - `src/cli.ts:62-66`: `sentinel replay <file>` reads a JSONL file and sends each line to the gateway. `src/cli.ts:101-113`: `sentinel watch-cssa` makes outbound calls only. It sends findings to `ingestSourceFindings` (`src/runtime.ts:316`), not to the gateway.
  - No file in `src/` opens a listener (no `createServer`, no `listen`, no HTTP framework).
- **Observed behavior**: The Event Gateway is an in-process TypeScript class. It has no network ingress. The only paths that feed events to it are the `replay` CLI command and library callers that construct `SentinelRuntime`.
- **Documentation claim**: `doc/system/03-runtime-boundary.md` (the whole file, 11 lines) describes the shadow pipeline and the CSSA watchdog worker. It does not mention the Event Gateway, producer authentication, or the `replay` input path. It does not state that the gateway has no network ingress. Only `README.md:29` and `CLAUDE.md:21` describe the gateway.
- **Proposed correction**: Add an "Event Gateway" section to `doc/system/03-runtime-boundary.md`. State that the gateway is in-process, that it has no network listener, and that `sentinel replay <file>` and library callers are the only ingress paths. Then run `bash doc/system/BUILD.sh` and commit the rebuilt `doc/SNTSYSTEM.md`.
- **Status**: Open — recorded, unresolved until the correction is verified.

## KI-SENTINEL-20261030-002: The "production" runtime uses fixed test producer secrets — OPEN 2026-10-30 — security — priority review requested

- **Classification**: Security — priority review requested. The operator asked for a priority security review of this item, separate from the documentation drift in KI-SENTINEL-20261030-001.
- **Discovery source**: `forge` PR #325 (BDS-XMACH-CALLER-BOUNDARY-001, WP00).
- **Verified at**: `9c9de3a4036e8a4d0ae9416c9ae41ff23e7b9964` (`origin/master`), 2026-10-30.
- **Evidence**:
  - `src/runtime.ts:25-34`: `standardProducers(environment)` returns six producer registrations with literal HMAC secrets: `test-secret-identity`, `test-secret-usage`, `test-secret-neuroforge`, `test-secret-billing`, `test-secret-cssa`, `test-secret-agents`. Each registration takes the `environment` argument, so the same secrets apply in every environment.
  - `src/runtime.ts:79,83`: the `SentinelRuntime` constructor sets the default `environment` to `"production"` and always registers `standardProducers(environment)`. No other code path registers producers. No code reads a producer secret from an environment variable, a file, or a secret store. `process.env` is read only at `src/cli.ts:102-108`, for the DataForge client and the worker state path.
  - `src/cli.ts:65` (`replay`) and `src/cli.ts:111` (`watch-cssa`) construct `new SentinelRuntime("production")`.
  - `src/contracts/envelope.ts:16`: the valid environment strings are `production`, `staging`, `development`, `test`, and `local`. All five get the same fixed secrets.
  - `src/spine/producers.ts:27-29,42-50`: producer authentication is `HMAC-SHA256(secret, payload_hash)`. `src/spine/gateway.ts:93-107`: the "signature" for signature-required producers (`billing-service`, `cssa`) and signature-required event families is the same HMAC with the same secret.
  - `src/index.ts:31` exports `src/runtime.ts`. Thus `standardProducers` and `SentinelRuntime` are public library API.
  - The secrets are in git history since `ab45859` (2026-06-11, the first implementation commit). The GitHub repository `Boswell-Digital-Solutions/forgesentinel` is PUBLIC. Thus the values are public.
- **Defect**: A runtime with the label `"production"` authenticates producers with secrets that are public. A person who knows the secrets can compute a valid producer token and a valid signature for any payload. The gateway then accepts the event as authentic from that producer. This includes `billing-service` (`billing.` and `license.` events) and `cssa` (`cssa.` events), which the design marks as high-value and signature-required.
- **What an attacker can forge**: With a known key, an attacker can make the gateway accept a fabricated event from any of the six producers, for any tenant, in the environment of the runtime. The event goes into the evidence ledger as accepted evidence. The detector nodes and Sentinel Prime then use it. The result can be false findings, false incidents, and false policy decisions. The dedupe key includes the payload hash (`src/spine/gateway.ts:27-39`), so this review did not find a practical way to suppress a different real event with a forged one.
- **Bounds on impact (verified)**:
  - The gateway has no network ingress (see KI-SENTINEL-20261030-001). To exploit this defect, an attacker must feed events in. Today the only paths are a replay file given to `sentinel replay <file>` (each line carries its own credential, `src/spine/replay.ts:6-9,32-33`) or code that calls `SentinelRuntime` as a library.
  - The pipeline runs in shadow mode (ADR-011). Policy decisions and findings are advisory. No authority action runs without an operator-approved capability. The capability signing key and the CSSA directive signing key are constructor arguments (`src/authority/capability.ts:31`, `src/authority/cssa-control.ts:30`). They are not these producer secrets, and `src/` contains no fixed value for them.
  - `watch-cssa` does not use the gateway. This defect does not expose it.
  - The repository has no deployment configuration (no Dockerfile, no Render configuration).
  - ADR-026 (`docs/sentinel/adrs/ADR-026-hmac-signing-for-mvp.md:26-28`) already requires a change to Ed25519 at `spine/producers.ts` before any non-shadow deployment. It does not address where the producer secrets come from, or the `"production"` label on fixed test values.
- **Severity assessment**: Medium, latent. Current exploitability is low: there is no network ingress, no deployment, and the output is shadow-only. The defect is real because the code labels the fixed public keys as `"production"` and has no path to load real keys. Any future ingress (an HTTP endpoint, a queue consumer, or an operator who replays an untrusted file) makes forged evidence possible with no further step. At that point the severity becomes High, because producer authentication at the gateway is the trust root for all evidence. This is a pre-deployment blocker, not an active incident.
- **Proposed correction** (this record does not authorize it; the security review decides):
  1. Load producer secrets from a secret source for each environment. Keep the fixed values only for tests and fixtures, under a name that says so.
  2. Make the runtime refuse to start in `production` or `staging` when it would use fixed test secrets.
  3. Decide whether `sentinel replay` must run with the `"production"` label, or with `"test"`.
  4. Do the ADR-026 change to Ed25519 before any ingress is added.
  The values are already public. Thus rotation alone does not correct this defect. The correction is to stop the use of fixed values outside tests.
- **Operator ruling (2026-10-30, preliminary)**: The operator accepts this as a pre-deployment security blocker. The operator also ruled that the proposed correction is directionally sound. The ruling records that an attacker who knows the HMAC key can forge authentication, but must still have a path to submit an event. The present lack of network ingress lowers immediate exploitability. It does not make the authentication design acceptable for deployment. Before any production use, these are required:
  1. Secrets for each environment come from protected configuration.
  2. The runtime refuses to start when `production` or `staging` would use test secrets.
  3. Production has no fallback to hardcoded or missing credentials.
  4. Negative tests show that forged producer events are rejected.
  5. The Ed25519 change that ADR-026 requires is verified separately.
- **Authorization**: The correction needs its own narrowly scoped authorization. Any new ingress or deployment waits for that correction. This record does not authorize either.
- **No change made**: This record does not rotate, change, or remove a secret or code.
- **Correction implemented (2026-10-30, unverified)**: The operator authorized a narrowly scoped correction (branch `fix/producer-secrets-from-config`). It does these things:
  1. `src/runtime.ts` no longer holds producer secrets. `SentinelRuntime` takes its producer registrations from the caller, with no default environment and no built-in producers.
  2. `src/spine/producer_secrets.ts` loads secrets for each environment from the file named by `SENTINEL_PRODUCER_SECRETS_FILE`. It refuses a missing variable, an unreadable file, a group- or world-accessible file (POSIX), a file for another environment, and a missing or unknown producer.
  3. The runtime and the loader refuse, in `production` and `staging`: a secret with the published `test-secret-` prefix, a secret shorter than 32 bytes, and one secret shared by two producers. There is no fallback to a hardcoded or missing credential.
  4. The fixed fixture secrets are only in `test/support/producers.ts`. Tests use fresh random secrets and re-sign the committed fixtures.
  5. `test/producer_secrets.test.ts` has the negative tests. Forged producer events are rejected: an event signed with the published secret, and a billing event with a forged signature. A runtime with no producers rejects every event.
  6. `sentinel replay` reads `SENTINEL_ENVIRONMENT` (default `production`). This answers proposed item 3: the label is now set explicitly, and the CLI fails closed without configured secrets. `sentinel watch-cssa` registers no producers.
  7. An independent security review of head `8c7c15d` found no blocking defect. Within the same scope, this correction then also: refuses control characters (a NUL-padded secret is the empty HMAC key) in every environment; refuses non-ASCII, whitespace and low-variety secrets in production and staging; checks every registration in `ProducerRegistry`, not only at runtime construction, keeps a frozen copy of it, and refuses to replace a registered key; opens the secrets file once and refuses a non-regular file and, on POSIX, a symlink and a file owned by another user (Windows follows symlinks and has no permission check); and refuses unknown fields and a shared `key_id`.
  Not in this correction: the ADR-026 change to Ed25519 needs its own verification, by operator ruling. No secret was rotated; the published values stay public and are now refused. Deployment and new ingress stay blocked until this correction is verified.
- **Merged (2026-10-30)**: PR #21 merged as `2669e74156be1f3492c039b6c75d16bd04878630`, on operator authorization. Its tree is identical to the reviewed head `ebcb073542736976cf63f962bb9f23c7b5a6b5f4`. Three independent review rounds found no blocking defect, and Linux CI passed at that head. The residual findings are KI-SENTINEL-20261030-004, -005 and -006.
- **Still required to close**: operational verification, and credential remediation. The operator ruled that merging is not deployment authorization, and that no credential rotation is authorized yet.
- **Status**: Open — the code correction is merged; unresolved until operational verification and credential remediation are complete.

## KI-SENTINEL-20261030-004: Code in the same process can replace the Event Gateway's producer registry — CLOSED 2026-11-02 — security

- **Classification**: Security, in-process only. The operator rated it a high-priority follow-up.
- **Discovery source**: independent security review of forgesentinel PR #21, round 3.
- **Verified at**: `2669e74156be1f3492c039b6c75d16bd04878630` (`origin/master`), by code reading. The reviewer executed it at `ebcb073`, which has the same tree.
- **Evidence**: `src/spine/gateway.ts:51-52`: `EventGateway` receives its registry as `private readonly registry: ProducerRegistry`. A TypeScript `private` is not private at run time, and nothing checks the type of the object.
- **Observed behavior**: Code in the same process sets `runtime.gateway["registry"]` to another object. That object can be another `ProducerRegistry`, or any object with `authenticate` and `allowsEventType` methods. A production runtime then accepts a forged event signed with the published fixture secret.
- **Reachability**: Not reachable through `sentinel replay`, `sentinel watch-cssa`, or any external event path. The gateway has no network ingress (KI-SENTINEL-20261030-001). An attacker must already run code inside the Sentinel process.
- **Proposed correction**: Hold the registry in a true private field (`#registry`). Refuse a registry that is not a `ProducerRegistry` instance. Add a negative test for both cases.
- **Correction implemented (2026-11-01, unverified)**: The operator authorized an isolated correction for this entry and KI-SENTINEL-20261030-005 (branch `fix/registry-integrity-and-prefixes`).
  1. `EventGateway` holds its registry, ledger and dedupe map in true private fields, and freezes its instance. It accepts only an object that the `ProducerRegistry` constructor made (`ProducerRegistry.isRegistry`, a private-field check) whose prototype is exactly `ProducerRegistry.prototype`. It refuses an `Object.create` look-alike, a Proxy, a `Reflect.construct` object, an object from another realm and a subclass. An independent review of the first version (`a341f9d`) showed that a prototype check alone let these through. This version closes that gap.
  2. `ProducerRegistry` freezes its instance, so `authenticate` or `allowsEventType` cannot be shadowed by an own property. `SentinelRuntime` freezes its own fields, so its `registry`, `gateway` and `ledger` cannot be replaced.
  3. `test/registry_integrity.test.ts` checks through the gateway that a forged event stays rejected after each attempt, with a genuine event as a positive control. On unpatched `origin/master`, the tests for this entry fail.
  The operator ruled that this guards against accidental change in the same process, and is not a security boundary against hostile code in the same process. Such code can still change `ProducerRegistry.prototype`.
- **Merged (2026-11-02)**: PR #24 merged as `4d2d9f5165a822eda72a5fcfa3e7f8b8d2c8b556`, on operator authorization. Its tree is identical to the reviewed head `b46f65ef6c0d5c353346bf631ab401fabc3ca226`. Three independent review rounds found one blocking defect in round 1, which was fixed, and no blocking defect at the merged head. Linux CI passed at that head. The operator ruled that this entry stays open until post-merge verification. The accepted boundary is protection against accidental change in the same process, not against hostile code in the same process. Residual notes: KI-SENTINEL-20261102-001, -002 and -003.
- **Post-merge verification (2026-11-02, read-only)**: Run on a fresh detached checkout of `origin/master` at `732a09b3a9f80233b99db4d433237ba890fd680e`. Only `docs/KNOWN_ISSUES.md` changed after the code merge `4d2d9f51`, where Linux CI passed both checks. The full suite ran 390 tests: 388 passed, 1 was skipped (the POSIX-only symlink test), and 1 failed (the existing Windows symlink EPERM in `bounded-local-collector`, which this correction did not touch). An independent probe script, written apart from the PR tests and the reviewer's scripts, ran 46 checks against the shipped build. All 46 passed.
  - The gateway refused, with `TypeError`: an `Object.create` look-alike, a `Reflect.construct` object, a Proxy over a real registry, a Proxy with a prototype trap, an object from another realm, a subclass, a duck-typed object, and `null`. It accepted a real registry.
  - The runtime, the gateway and the registry are frozen. The runtime's `gateway`, `registry` and `ledger` could not be replaced by assignment or `defineProperty`. The gateway's registry, ledger and dedupe map were not reachable. A registry method could not be shadowed, and the registry prototype could not be swapped.
  - After every attempt, a forged event signed with the published fixture secret was rejected, a genuine event was accepted, and de-duplication held.
  - The documented limit is real: code in the same process that patches `ProducerRegistry.prototype.allowsEventType` still changes the result. That is outside the accepted boundary, as `doc/system/03-runtime-boundary.md`, the source comments and this entry state.
- **Status**: CLOSED 2026-11-02 by operator ruling. The correction is merged (`4d2d9f51`) and verified after the merge. The accepted boundary is protection against accidental change in the same process, not against hostile code in the same process.

## KI-SENTINEL-20261030-005: A producer registration with an empty event prefix allows every event type — CLOSED 2026-11-02 — security

- **Classification**: Security, in-process only. The operator rated it a high-priority follow-up.
- **Discovery source**: independent security review of forgesentinel PR #21, round 3.
- **Verified at**: `2669e74156be1f3492c039b6c75d16bd04878630` (`origin/master`), by code reading. The reviewer executed it at `ebcb073`.
- **Evidence**: `src/spine/producers.ts:76-77`: `allowsEventType` returns true when `eventType.startsWith(prefix)`. Every string starts with `""`. `ProducerRegistry.register` (`src/spine/producers.ts:44-60`) does not check `allowed_event_prefixes`.
- **Observed behavior**: A library caller registers a usage producer with `allowed_event_prefixes: [""]`. That producer can then emit `billing.subscription.changed`, and the gateway accepts it.
- **Reachability**: Not reachable through the secrets file. `loadProducerRegistrations` always uses the fixed `STANDARD_PRODUCER_PROFILES` prefixes. A caller that builds registrations in code can reach it.
- **Proposed correction**: In `register()`, refuse an empty prefix list, an empty prefix, and a prefix that does not end in `.`. Add a negative test.
- **Correction implemented (2026-11-01, unverified)**: Same branch as KI-SENTINEL-20261030-004. `ProducerRegistry.register` copies the prefix list once, element by element, into a new frozen plain array. It then refuses, with `ProducerRegistrationError`, a missing or empty list and any prefix that is not lowercase dotted segments ending in `.`. A getter, a custom iterator, an `Array` subclass or `Symbol.species` cannot pass the check with one list and store another. `test/registry_integrity.test.ts` checks the refusals, and checks through the gateway that a producer cannot emit an event outside its prefixes (`event_type_not_allowed`). The tests for the refusals fail on unpatched `origin/master`.
- **Merged (2026-11-02)**: PR #24 merged as `4d2d9f5165a822eda72a5fcfa3e7f8b8d2c8b556`, on operator authorization. Its tree is identical to the reviewed head `b46f65ef6c0d5c353346bf631ab401fabc3ca226`. Three independent review rounds found one blocking defect in round 1, which was fixed, and no blocking defect at the merged head. Linux CI passed at that head. The operator ruled that this entry stays open until post-merge verification. The accepted boundary is protection against accidental change in the same process, not against hostile code in the same process. Residual notes: KI-SENTINEL-20261102-001, -002 and -003.
- **Post-merge verification (2026-11-02, read-only)**: Run on a fresh detached checkout of `origin/master` at `732a09b3a9f80233b99db4d433237ba890fd680e`. Only `docs/KNOWN_ISSUES.md` changed after the code merge `4d2d9f51`, where Linux CI passed both checks. The full suite ran 390 tests: 388 passed, 1 was skipped (the POSIX-only symlink test), and 1 failed (the existing Windows symlink EPERM in `bounded-local-collector`, which this correction did not touch). An independent probe script, written apart from the PR tests and the reviewer's scripts, ran 46 checks against the shipped build. All 46 passed.
  - Registration refused, with `ProducerRegistrationError`: an empty list, an empty prefix, a prefix without a final dot, upper case, a double dot, a leading dot, a wildcard, whitespace, a newline, a non-string element, an array hole, a missing list, and an `Array`-subclass swap. A getter was read once, and the stored list was the checked list, as a frozen plain array. The six standard profiles passed.
  - Through the gateway, these were rejected with `event_type_not_allowed`: usage-metering emitting `billing.subscription.changed` and `license.entitlement.issued`, cssa emitting `identity.login.failed`, and identity-service emitting `usage.tokens.recorded`. An in-scope event was accepted.
- **Status**: CLOSED 2026-11-02 by operator ruling. The correction is merged (`4d2d9f51`) and verified after the merge. The residual notes are tracked separately: KI-SENTINEL-20261102-001 and -002 are open, and -003 is accepted.

## KI-SENTINEL-20261030-006: Low-priority residual items from the PR #21 review — OPEN 2026-10-30

- **Discovery source**: independent security review of forgesentinel PR #21, rounds 1-3. These items were present before PR #21, or are residual assumptions. Each carries the operator's disposition from 2026-10-30.
- **Verified at**: `2669e74156be1f3492c039b6c75d16bd04878630` (`origin/master`), by code reading.
- **Items**:
  1. **Uppercase token acceptance** (low-priority compatibility and security review). `src/spine/producers.ts:69-73`: the token is decoded with `Buffer.from(..., "hex")`, which accepts upper- and lower-case hex. One HMAC therefore has more than one accepted text form. This is malleability, not forgery. Decide whether to require lower-case hex.
  2. **A missing replay credential crashes the replay** (low-priority error-handling correction). `src/spine/replay.ts:33` passes `line.credential` to the gateway with no check. A line with a `null` credential or token throws a `TypeError`, which stops the whole replay instead of rejecting that one line.
  3. **Symlinked parent directories are followed** (document the residual filesystem trust assumption). `src/spine/producer_secrets.ts:117-125`: `O_NOFOLLOW` refuses a symlink only as the last path component. On POSIX, a path whose parent directory is a symlink is followed. The type, mode and owner checks still apply to the file itself. Windows follows symlinks and has no permission check. Document in `doc/system/03-runtime-boundary.md` that the directory path to the secrets file must be trusted.
- **Related**: the fixture generator's Windows path bug is tracked separately as KI-SENTINEL-20261030-003.
- **Correction implemented (2026-11-02, unverified)**: Branch `fix/sentinel-followups`, operator-authorized as one isolated PR with KI-SENTINEL-20261030-003, -006 and KI-SENTINEL-20261102-001, -002.
  1. Item 1: a token or a signature is accepted only as 64 lowercase hex characters (`HMAC_HEX_PATTERN`). An upper-case token is rejected with `producer_auth_failed`, and an upper-case signature with `signature_invalid`.
  2. Item 2: the gateway rejects a missing or malformed credential with `producer_credential_malformed`, instead of throwing. `replayInto` turns a line that parses but is malformed (for example `null`) into a rejection and continues. A rejection stores a non-object input as `{ "malformed_input": ... }`, so the ledger integrity check verifies it. A line that is not valid JSON still stops the replay before anything is ingested, which fails closed. Hostile in-process inputs (throwing getters, Proxies, cyclic objects) can still throw; JSON-parsed lines cannot produce them.
  3. Item 3: `doc/system/03-runtime-boundary.md` states the trust assumption: the directory path to the secrets file must be trusted.
- **Status**: Open — recorded, unresolved until each item is corrected or explicitly accepted.

## KI-SENTINEL-20261102-001: A huge sparse prefix list is copied in full before it is checked — OPEN 2026-11-02 — resource exhaustion — follow-up

- **Classification**: Resource-exhaustion hardening. Not an authorization bypass. The operator deferred it to follow-up work, and asked that it be prioritized if untrusted input can ever reach this path.
- **Discovery source**: independent review of forgesentinel PR #24, round 3 (note N1).
- **Verified at**: `4d2d9f5165a822eda72a5fcfa3e7f8b8d2c8b556` (`origin/master`), by code reading. The reviewer executed it at `b46f65e`, which has the same tree.
- **Evidence**: `src/spine/producers.ts:79-80`: `register()` reads `rawPrefixes.length`, then copies every index into a new array before it checks the first element.
- **Observed behavior**: An array with `length = 5e6` took about 116 ms, then was refused. With `length = 2**32 - 1`, the loop would try about 4.3 billion pushes before the check. That is a hang or an out-of-memory error, which fails safe. A Proxy that reports a huge length behaves the same way.
- **Reachability**: Only a library caller that builds a registration in code. The secrets file always uses the fixed standard profiles.
- **Proposed correction**: Refuse a prefix list longer than a small bound (for example 64) before the copy, or check each element as it is copied. Add a negative test.
- **Correction implemented (2026-11-02, unverified)**: Branch `fix/sentinel-followups`, operator-authorized as one isolated PR with KI-SENTINEL-20261030-003, -006 and KI-SENTINEL-20261102-001, -002. `register()` reads the prefix-list length once and refuses a count that is not an integer from 0 to `MAX_EVENT_PREFIXES` (64), before it reads any element. A test shows that lengths of 65, 5,000,000 and 2^32-1 are refused quickly, and that a Proxy reporting a huge length has no element read.
- **Status**: Open — deferred to follow-up work; unresolved until the correction is verified.

## KI-SENTINEL-20261102-002: The Symbol.species half of a registry test does not show the old bypass — OPEN 2026-11-02 — test quality — follow-up

- **Classification**: Test quality. The operator deferred it to a separate PR.
- **Discovery source**: independent review of forgesentinel PR #24, round 3 (note N2).
- **Verified at**: `4d2d9f5165a822eda72a5fcfa3e7f8b8d2c8b556` (`origin/master`), by code reading. The reviewer executed it at `6bcc336` and `b46f65e`.
- **Evidence**: `test/registry_integrity.test.ts:233-252`, the test "a prefix list cannot be swapped through an Array subclass or Symbol.species". Its species object (`:244`) has `some` and `length`, but no `Symbol.iterator`.
- **Observed behavior**: Against `6bcc336`, before the fix, the species half fails with `TypeError: copy.allowed_event_prefixes is not iterable`. It does not fail by storing a list that differs from the checked list. Its assertions are valid at the merged head. The `Array`-subclass half of the same test does fail for the intended reason.
- **Proposed correction**: Give the species object an iterator that yields `"usage."` and a `some` that returns true. Then confirm that, against `6bcc336`, the test fails because `allowsEventType(..., "billing.subscription.changed")` returns true.
- **Correction implemented (2026-11-02, unverified)**: Branch `fix/sentinel-followups`, operator-authorized as one isolated PR with KI-SENTINEL-20261030-003, -006 and KI-SENTINEL-20261102-001, -002. The species object now has an iterator that yields `"usage."` and a `some` that returns true, and the billing check comes first. Against `6bcc336`, with only the species half kept, the test fails because `allowsEventType(..., "billing.subscription.changed")` returns true. That is the intended reason.
- **Status**: Open — deferred to a separate PR; unresolved until the correction is verified.

## KI-SENTINEL-20261102-003: The public allowsEventType trusts the registration it is given — ACCEPTED 2026-11-02

- **Classification**: Accepted within the documented boundary, by operator ruling.
- **Discovery source**: independent review of forgesentinel PR #24, round 3.
- **Verified at**: `4d2d9f5165a822eda72a5fcfa3e7f8b8d2c8b556` (`origin/master`), by code reading.
- **Evidence**: `src/spine/producers.ts:122`: `ProducerRegistry.allowsEventType(registration, eventType)` is public, and it checks the prefixes of whatever registration object it receives. `allowsEventType({ allowed_event_prefixes: [""] }, ...)` returns true.
- **Why it is accepted**: The gateway passes only the frozen copy that the registry itself returned from `authenticate`. No caller outside the gateway uses the method for an authorization decision. The gateway's contract is that it calls the method with validated input only.
- **Condition**: Reconsider this entry if a caller outside the gateway starts to use `allowsEventType`, or if external callers are added.
- **No change made**: This record changes no code.
- **Status**: Accepted — no correction planned while the condition holds.

## KI-SENTINEL-20261102-004: A wrapped malformed-input rejection has the same body and hash as a rejection of the literal wrapper object — OPEN 2026-11-02 — ledger forensics — non-blocking

- **Classification**: Non-blocking. It affects how rejection records read in an investigation only. It is not an authorization defect.
- **Discovery source**: independent review of forgesentinel PR #27, round 2 (note N5). Confirmed by the post-merge verification at `1d3d8859`.
- **Verified at**: `1d3d8859371206f65648c783d5cafc2501b2692a` (`origin/master`), by execution.
- **Evidence**: `src/spine/gateway.ts:161` stores a rejection whose input is not an object as `{ malformed_input: <input> }`. The ledger hashes the body with `hashPayload` (`src/spine/ledger.ts:74`).
- **Observed behavior**: Ingesting the number `5` and ingesting the object `{ "malformed_input": 5 }` produce rejection records with the same body and the same `source_hash`. `null` and `{ "malformed_input": null }` collide the same way. A reader of the ledger cannot tell which input was received.
- **Bounds**: Only `rejection` records are affected. A wrapper object fails envelope validation, so it can never become an accepted event.
- **Proposed correction**: Mark the wrapper in a way that real input cannot produce, for example a separate record field such as `malformed_input: true` outside `body`, or a wrapper key that the envelope schema forbids. Add a test that the two inputs produce different records.
- **Correction implemented (2026-11-02, unverified)**: Branch `fix/ledger-rejection-fidelity`, operator-authorized as one isolated PR with KI-SENTINEL-20261102-005. `rejectionBody` (`src/spine/gateway.ts`) stores a serializable object without the reserved key as it is, and wraps every other input, including an object that has the `malformed_input` key, as `{ malformed_input, input_type }`. A stored body with that key is therefore always a wrapper, and the encoding is one-to-one inside the hashed body. `test/rejection_fidelity.test.ts` shows that `5` and `{ "malformed_input": 5 }`, and `null` and `{ "malformed_input": null }`, now give different bodies and hashes, that 16 distinct malformed inputs give 16 distinct hashes, and that a normal object rejection keeps its body unchanged.
- **Status**: Open — recorded, unresolved until the correction is verified or the owner accepts it.

## KI-SENTINEL-20261102-005: Function, Symbol and BigInt inputs from a library caller are not recorded faithfully — OPEN 2026-11-02 — library-only input handling — non-blocking

- **Classification**: Non-blocking. A JSON replay file cannot produce these inputs; only a library caller in the same process can. This is inside the accepted in-process boundary.
- **Discovery source**: independent review of forgesentinel PR #27, round 2. Confirmed for all three inputs at `1d3d8859`.
- **Verified at**: `1d3d8859371206f65648c783d5cafc2501b2692a` (`origin/master`), by execution. A function and a Symbol input each gave a rejection whose `source_hash` equals `hashPayload({})`. A BigInt input threw `TypeError`, and the next record took `ledger_seq` 4 after 2, so 3 was skipped.
- **Evidence**: `src/spine/gateway.ts:161` wraps a non-object input. `canonicalJson` (`src/contracts/common.ts:140-154`) uses `JSON.stringify`. `EvidenceLedger.append` increments the sequence number (`src/spine/ledger.ts:72`) before it computes `source_hash` (`:74`).
- **Observed behavior**:
  1. A function or Symbol input is rejected, but `JSON.stringify` drops it, so the record hashes as `{}`. The value is lost.
  2. A BigInt input makes `JSON.stringify` throw, so `gateway.ingest` throws. The sequence number was already incremented, so the ledger skips one `ledger_seq`.
- **Proposed correction**: In `EventGateway.reject`, record the input's `typeof` for a value that JSON cannot represent, instead of the value. In `EvidenceLedger.append`, compute the hash before the sequence number is incremented, so a hashing failure cannot leave a gap. Add tests for function, Symbol and BigInt input.
- **Correction implemented (2026-11-02, unverified)**: Same branch as KI-SENTINEL-20261102-004. A function, a Symbol (with its description), a BigInt (as a decimal string), an unserializable object (for example cyclic, or with a nested BigInt), `undefined`, `null` and NaN are now rejected without throwing, with `input_type` recorded. `EvidenceLedger.append` computes the hash before it increments the sequence number, so a body that cannot be hashed throws without leaving a `ledger_seq` gap. Tests show every such rejection passes the integrity check with consecutive sequence numbers.
- **Status**: Open — recorded, unresolved until the correction is verified or the owner accepts it.
