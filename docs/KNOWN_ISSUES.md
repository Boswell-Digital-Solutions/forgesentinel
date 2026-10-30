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
  Not in this correction: the ADR-026 change to Ed25519 needs its own verification, by operator ruling. No secret was rotated; the published values stay public and are now refused. Deployment and new ingress stay blocked until this correction is verified.
- **Status**: Open — recorded, unresolved until the correction is verified.
