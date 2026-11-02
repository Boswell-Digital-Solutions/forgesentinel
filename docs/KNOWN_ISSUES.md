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

## KI-SENTINEL-20261102-008: The producer credential authenticates only the payload hash, so a signed event can be re-targeted to another tenant, account, actor or subject — OPEN 2026-11-02 — security — P0

- **Classification**: Security, event authentication. P0, by owner ruling of 2026-11-02; high priority when first recorded. The exposure is latent while the gateway runs in shadow mode with no network ingress (KI-SENTINEL-20261030-001). The owner ruled that the gateway stays in shadow mode, without network ingress, until this is corrected and independently verified.
- **Discovery source**: independent review of forgesentinel PR #29, round 2 (finding R3). The author confirmed it independently.
- **Verified at**: `3b17efe` (`origin/master`), by execution, on a production `SentinelRuntime` with strong configured producer secrets.
- **Evidence**:
  - `src/spine/producers.ts:35`: `producerToken(secret, payloadHash)` is HMAC-SHA256 over the payload hash only.
  - `src/spine/build.ts:69`: a producer's credential is built from that token.
  - `src/spine/gateway.ts:92`: the gateway authenticates the credential against `event.integrity.payload_hash` only. The signature that signature-required producers and families add is the same HMAC over the same hash.
  - No other part of the envelope is covered by the credential or the signature.
- **Observed behavior**: A usage event was built and signed for a production runtime. Each field below was then changed in the event alone, and the event was ingested with its original credential:

  | Field changed | Result |
  |---|---|
  | `tenant.tenant_id` (`ten_demo` to `ten_other`) | accepted |
  | `tenant.account_id` | accepted |
  | `actor.actor_id` | accepted |
  | `subject.subject_id` | accepted |
  | `event_id` | accepted |
  | `occurred_at` (moved earlier) | accepted |
  | `observed_at` | accepted |
  | `event_type`, within the producer's prefix (`usage.tokens.recorded` to `usage.retry.recorded`) | accepted |
  | `correlation.trace_id` | accepted |
  | `occurred_at` moved after `observed_at` | rejected, `clock_order` (a contract check, not authentication) |
  | payload field (control) | rejected, `payload_hash_mismatch` |

- **Impact**: Anyone who holds one validly signed event can re-target it to another tenant or account, attribute it to another actor or subject, change its event type within the producer's prefix, change its times, or replay it under a new `event_id`, which also defeats de-duplication. The ledger records the altered event as accepted, authenticated evidence. This breaks the event's claimed identity and authorization context without any payload change, so it is more consequential than KI-SENTINEL-20261102-006. Bounds: there is no network ingress, the pipeline is shadow-only, and the actor must hold a signed event.
- **Remediation requirements** (owner ruling; not authorized by this record):
  1. Authenticate the security-relevant envelope, not only `payload_hash`. At minimum, bind `tenant_id`, `account_id`, `actor_id`, `subject_id`, `event_id`, `event_type`, `occurred_at` and the payload digest.
  2. Use a versioned, deterministic authentication format.
  3. Preserve producer authorization boundaries. Reject altered and cross-tenant events.
  4. Add independent negative tests before any production enforcement.
  - The correction is a separate security remediation track. It must also account for KI-SENTINEL-20261102-006, because a deterministic format cannot rest on the current canonical form, and for the Ed25519 move that ADR-026 requires.
- **Note**: The clean review and green CI of PR #29 do not show that event authentication is secure. PR #29 corrects rejection-record fidelity only.
- **Remediation plan recorded (2026-11-02)**: A design-and-plan document set exists at `docs/plans/Sentinel_Envelope_Authentication_Plan_Set_2026-11-02/` (plan ID `BDS-SNT-ENVELOPE-AUTH-001`). It specifies the canonical byte format `forgesentinel.event_auth.v1` (a fixed, ordered record list plus one record for each control-lineage finding id, explicit byte lengths, an absent-field tag, and a version tag inside the signed bytes; the count was 41 and is superseded — see the R1-A/R1-B/R1-C bullet below), how HMAC-SHA256 covers it now and how Ed25519 covers it under ADR-026, the no-shim compatibility position, the fixture and test-support impact, a negative-test matrix with positive controls, the verification gates, ten owner decisions, twelve risks and eight proposed slices. The plan re-verified this finding by execution at `432337c` and found a wider malleable set than the table above: `actor.actor_type`, `subject.subject_type`, `producer.instance_id`, `producer.version`, `schema_version`, `location.execution_lane`, `data_policy.sensitivity`, `data_policy.retention_class`, `data_policy.cloud_allowed`, `data_policy.content_included`, `integrity.idempotency_key` and `control_lineage` (added or removed) are all accepted with the original credential. Three further facts shape the correction: one credential authenticates every event with the same payload, so a credential is transferable between events; an unknown envelope field passes validation and is stored; and the high-value signature is byte-identical to the credential token, so it proves nothing more. The plan declares a hard dependency on the KI-SENTINEL-20261102-006 correction, because the payload-digest record binds `integrity.payload_hash` and that digest is not one to one today. That record was number 34, and every record **index** in the plan set is superseded with the count — see the R1-A/R1-B/R1-C bullet below.
- **The plan is not an authorization**: The plan document changes no code, no credential, no fixture and no deployment. Each slice needs its own explicit authorization from the owner. The gateway stays in shadow mode, with no network ingress, until the correction is implemented and independently verified.
- **Owner ruling on the plan (2026-11-02)**: The owner approved the architectural direction of `BDS-SNT-ENVELOPE-AUTH-001`, with two amendments, and ruled the correction a **P0 security priority**. The ruling states that the verified cross-tenant event re-targeting is a security-significant authentication failure, and that no exploitation is claimed. All ten plan decisions are ruled: D-1, D-2, D-3, D-4, D-5, D-8, D-9 and D-10 approved with conditions; **D-6 approved with an amendment** (derive independent keys for the producer credential and the high-value signature, not one key with two contexts); **D-7 amended** (define deterministic numeric canonicalization before implementation: refuse non-finite values and negative zero, and align accepted integers with `forge_contract_core`). The ruling adds five implementation gates: no unauthenticated compatibility fallback; the canonical encoding must be injective, proved by property-based and adversarial tests; verify before side effects, so an authentication failure precedes de-duplication, ledger writes, routing and publication; test tenant isolation explicitly, including cross-tenant, cross-account, actor, subject, producer-identity and control-lineage substitution; and preserve operational evidence as protected security telemetry that exposes no credential and no sensitive payload. The plan set is revised to match, `docs/plans/Sentinel_Envelope_Authentication_Plan_Set_2026-11-02/06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` is the authoritative record, and `docs/sentinel/adrs/ADR-027-envelope-authentication-format.md` records the design decision under ruling D-10.
- **Authorization boundaries (owner ruling)**: Three boundaries, in order: design review first, implementation authorization second, production deployment authorization separately. Design approval is not implementation authorization. PR #32 was kept in draft while the plan was revised, and the owner later instructed the merge. The plan registry entry is requested through the authorized `forge` change process; this repository's pull request does not change the `forge` repository.
- **Owner recommendations pending formal ruling (2026-11-02)**: The owner checked PR #32 on GitHub and recorded four recommended rulings. The owner stated that these are recommendations and **not newly recorded owner approvals**, so they are recorded as recommendations and they authorize nothing. (1) Gate 5: approve a payload-excluding rejection record for an authentication failure — the permitted non-payload envelope metadata, a payload digest, a generic external failure code and a restricted internal diagnostic category; the rejected envelope's `data_policy` must not determine storage access, because it is attacker-chosen; the digest is an observed, untrusted value and not proof of authenticity; and no secrets, tokens, authentication bytes or sensitive payload content belong in the record. (2) Slices S3 and S4: one implementation pull request with separate evidence stages — the independent reviewer reproduces the negative-test failures against the pinned vulnerable base before reading the corrected implementation, records the exact commit, command, cases and results, and the combined pull request passes the new negative tests and the positive regression controls before it is merge-eligible, with no skipped security tests. (3) Independent design review is required before proceeding, and must assess canonical-encoding injectivity, HKDF key separation, unknown-field refusal, tenant isolation, rejection-record confidentiality and KI-SENTINEL-20261102-006 dependency closure; a green documentation check is not a substitute. (4) Slice S0 remains a hard prerequisite: the corrected payload digest and its adversarial tests must be independently verified, and merging S0 alone is insufficient. The plan set records all four in `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md`, under a heading that separates them from the rulings.
- **Review state (2026-11-02)**: Independent design review is **requested and not complete**. No pull-request review is submitted on GitHub. The owner's check of PR #32 confirmed that it is a draft, mergeable, unmerged, and that all ten changed files are documentation. The design direction is sound enough to proceed to review; that is not the same as a review having been done.
- **Independent review round 1 (2026-11-02)**: Complete, with the verdict **not safe to proceed to implementation authorization as written**. The reviewer implemented the format from the plan and reproduced its worked example byte for byte before making any claim. It found three blocking defects in the format: `control_lineage.sentinel_finding_ids` type confusion collides, because the spec refused only a bad array element and never a non-array, so `["a","b"]`, `"ab"` and an array-like object encode identically and the validator admits all three; an absent optional parent object and a present empty one encode identically, so `resource` absent and `resource: {}` give one signature for two accepted events; and `integrity.signature` with `integrity.signature_key_id` are admitted, unbound in the credential context, and unverified on an event that needs no signature, so a corrected gateway would still accept a bogus signature. It also found that the matrix case meant to cover that class documented one of the collisions as correct behaviour on a false premise, that the gate-2 property suite would pass against an implementation with no length prefix at all, and that two load-bearing statements of present code behaviour in the plan were false. The plan author re-verified every blocking finding by execution at `5430dea`. The plan set is corrected in place, each defect is marked where it sits, and `docs/plans/Sentinel_Envelope_Authentication_Plan_Set_2026-11-02/07_REVIEW_ROUND_1_FINDINGS.md` is the review of record. No pull-request review is submitted on GitHub, so the owner decides whether that document satisfies recommendation 3.
- **Five current-code defects came out of that review**, each re-verified by execution and recorded separately: KI-SENTINEL-20261102-011 (a rejection record's cloud projection skips every data-policy check), -012 (a rejection's tenant id comes from the unauthenticated envelope), -013 (the authentication-failure message copies unbounded credential text into the ledger and the caller), -014 (an unverified signature is stored as accepted evidence) and -015 (the de-duplication map is not rebuilt, so a verbatim replay is accepted by a fresh process). The first is the most consequential: it needs no attacker and no forged label, and it inverts the repository's stated rule that restricted content can never be cloud eligible.
- **Merged (2026-11-02)**: PR #32 merged as `79698ac`, a squash of head `ea32b32`, on the owner's instruction. The branch was `claude/envelope-auth-plan-47555m`. The merge was documentation only: every one of the eleven changed files sits under `docs/`, and `bash doc/system/BUILD.sh` reproduces `doc/SNTSYSTEM.md` on `master` with no drift. The merge commit credits `e0a4b52`, the owner's own correction of two stale counts in this record.
  **What the merge did not do.** It is not implementation authorization, and the owner's three authorization boundaries are unchanged. It closed none of the review-round-1 findings: at that commit the format defects F1, F2 and F3 were open, their candidate fixes were unruled, and all eight design decisions R1-A to R1-H were open. Five were ruled later the same day; see the bullets below. It closes none of the findings `KI-SENTINEL-20261102-009` through `-015`. The gateway stays shadow-only, with no network ingress.
- **Rulings R1-D and R1-E (2026-11-02)**: The owner ruled two of the eight round-1 decisions. **R1-D**: a separate authorized change, slice SL, carries the `src/spine/ledger.ts` defects — `KI-SENTINEL-20261102-011`, `-012`, `-016` and review finding F34 — sequenced before slice S4, because three of the four are not authentication defects and gate 5 needs an implementable foundation when S4 records the rejection-record shape. **R1-E**: a ledger record of unauthenticated provenance carries no top-level `tenant_id`; the claimed tenant stays in the recommendation-1 metadata as a named observed value that no query filters on; `LedgerRecord` gets no new top-level provenance field. The owner amended R1-E's wording, which named the `rejection` kind and so did not reach `-016`; the rule binds on unauthenticated provenance and extends to the `kind` and `validation` labels. Neither ruling authorizes implementation. `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` is the authoritative record.
- **Rulings R1-A, R1-B and R1-C (2026-11-02)**: The owner ruled the three format decisions, so five of the eight round-1 decisions are ruled and three stay open — R1-F, R1-G and R1-H.
  **R1-A**: refuse `integrity.signature` and `integrity.signature_key_id` on an event whose family requires no signature, **and** bind both where they may legitimately appear. Both, because binding alone leaves `KI-SENTINEL-20261102-014` open.
  **R1-B**: add a presence record for **each** of the three optional parents — `tenant`, `resource` and `control_lineage` — **and** tighten the validator. The reason is that gate 2 requires the encoding itself to be injective, so injectivity must not rest on the validator. An earlier draft exempted `control_lineage`, because `validateEventEnvelope` already refuses a present empty one, and the owner rejected that exemption for contradicting the ruling's own reason.
  **R1-C**: `validateEventEnvelope` type-validates every declared field, and the R-5 drift test compares types as well as names. Measured at `4225489`: a wrong-typed value is admitted in **15 of 17** declared optional fields. An earlier draft said "18 of 18", which conflated 18 probes with the field count; three probes shared one field, two targeted fields that `EventResource` declares required, and the `tenant` and `control_lineage` parents are refused when wrongly typed.
  **Amendment 3**: D-2's bound record count of 41 is **superseded, and no replacement count is stated**. R1-B adds three records and R1-A's binding adds an unsettled number more, so the total is not derivable yet. Slice S1 derives and publishes it, and regenerates the 41-row field table in `01`, the record indices cited across `01`, `02`, `04`, `05` and ADR-027, the worked example and the golden vector.
  No ruling authorizes implementation.
- **Still required to close**: the owner's rulings on the three open decisions R1-F, R1-G and R1-H; a corrected format that is one to one, which is now ruled in design and unimplemented in fact; independent review round 2 against a frozen commit; the verified `KI-SENTINEL-20261102-006` correction, per the D-1 condition; and then an authorized, implemented and independently verified correction for each slice, including slice SL.
- **Status**: Open — the plan is merged and the design is not finished. Independent review round 1 returned blocking defects in the format, so another design round comes before any slice is authorized; unresolved until each implementation slice is authorized, implemented and independently verified.

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
  2. Item 2: the gateway rejects a missing or malformed credential with `producer_credential_malformed`, instead of throwing. `replayInto` turns a line that parses but is malformed (for example `null`) into a rejection and continues. A line that is not valid JSON still stops the replay before anything is ingested, which fails closed. The form of a rejection body is described under KI-SENTINEL-20261102-004 and -005.
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
- **Correction implemented (2026-11-02, unverified)**: Branch `fix/ledger-rejection-fidelity`, operator-authorized as one isolated PR with KI-SENTINEL-20261102-005. `rejectionBody` (`src/spine/gateway.ts`) stores a serializable object without the reserved key as it is, and wraps every other input, including an object that has the `malformed_input` key, as `{ malformed_input, input_type }`. `test/rejection_fidelity.test.ts` shows that `5` and `{ "malformed_input": 5 }`, and `null` and `{ "malformed_input": null }`, now give different bodies and hashes, and that a normal object rejection keeps its body unchanged. A top-level `-0` is recorded as `"-0"`. **Limit:** this closes the collision this entry describes. It is not a one-to-one encoding of every input: inputs that canonical JSON writes alike still collide (a nested `-0` and `0`, a nested out-of-range number and `null`, a dropped `__proto__` key; from a library caller, a `Date`, `Map` or `Set` and `{}`, two functions, two unserializable objects, or an object whose own `toJSON` returns a wrapper shape). The JSON-reachable cases come from the canonical form and are recorded as KI-SENTINEL-20261102-006.
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
- **Correction implemented (2026-11-02, unverified)**: Same branch as KI-SENTINEL-20261102-004. A top-level function, Symbol (with its description), BigInt (as a decimal string), `undefined`, `null` and NaN, and an object that fails envelope validation and cannot be serialized (for example cyclic, or with a nested BigInt), are now rejected without throwing, with `input_type` recorded. `EvidenceLedger.append` computes the hash before it increments the sequence number, so a body that cannot be hashed throws without leaving a `ledger_seq` gap. **Limits:** a BigInt nested inside an event that passes envelope validation still throws, when the payload or the record is hashed (no gap is left). Persistence can still differ from the hash: the WAL writes with `JSON.stringify`, which honours a prototype `toJSON`, while the hash uses the canonical form; this predates the PR and is recorded as KI-SENTINEL-20261102-007.
- **Status**: Open — recorded, unresolved until the correction is verified or the owner accepts it.

## KI-SENTINEL-20261102-006: The canonical JSON form drops `__proto__` keys and normalizes some numbers, so a signed payload can be altered without changing its hash — OPEN 2026-11-02 — security — priority review requested

- **Classification**: Security, payload integrity. Priority review requested. This predates PR #29; its independent review found it, and the author confirmed it end to end. It is recorded here and is not corrected by PR #29.
- **Discovery source**: independent review of forgesentinel PR #29 (finding F1).
- **Verified at**: `1d3d8859371206f65648c783d5cafc2501b2692a` (`origin/master`; the canonical form is unchanged at `3b17efe`), by execution.
- **Evidence**: `canonicalJson` (`src/contracts/common.ts:140-154`) rebuilds each object with `sorted[key] = ...`. For the key `__proto__`, that assignment sets the prototype of the new object instead of creating a key, so the key is dropped from the canonical text. `JSON.stringify` also writes `-0` as `0` and a non-finite number as `null`. The payload hash (`hashPayload`, `:160-162`), the producer token and the producer signature are all computed over this canonical text.
- **Observed behavior**:
  1. `JSON.parse('{"total_tokens":1,"route_class":"general_cloud","__proto__":{"injected":true}}')` has `__proto__` as a real own key, but its payload hash equals the hash of the same object without that key.
  2. End to end: a usage event was signed for a production runtime. A `__proto__` key with arbitrary content was then added to its payload in the replay JSON. The gateway accepted the altered event with the original credential, and the ledger stored the altered body as accepted evidence.
  3. A signed `{"x": null}` and `{"x": 1e400}` (which parses to Infinity) have the same hash, and so do `{"x": 0}` and `{"x": -0}`. A value can therefore change from null to Infinity without breaking the signature.
- **Impact**: An actor who can submit events, and who has one validly signed event, can add a `__proto__` key with arbitrary content to its payload, or change certain numbers, and the event stays authenticated. A consumer that copies the payload with `Object.assign` or a similar setter-based copy would treat the injected `__proto__` content as the copy's prototype. Bounds: the gateway has no network ingress (KI-SENTINEL-20261030-001), the pipeline is shadow-only, and the actor must already hold a signed event. Proposed severity: High once any ingress exists, Medium latent until then. The owner decides.
- **Proposed correction** (not authorized by this record): build canonical objects with `Object.defineProperty` or on a null-prototype object, so every own key, including `__proto__`, appears in the canonical text. Refuse `-0`, NaN and non-finite numbers in envelopes and payloads, or encode them distinctly. Add negative tests that an added `__proto__` key and a null-to-Infinity change both break the signature. Ordinary payloads keep their current canonical text, so committed fixtures and existing hashes for them should not change; confirm this with `npm run fixtures`.
- **Owner ruling (2026-11-02)**: This finding is a **hard prerequisite** for the envelope-authentication correction (`KI-SENTINEL-20261102-008`, plan `BDS-SNT-ENVELOPE-AUTH-001`). Record 34 of the authentication format binds `integrity.payload_hash`, so envelope authentication must not rely on that digest until this correction exists. The owner ruled that this finding **must not be closed on passing tests alone**: the corrected digest semantics and the negative tests for them must be verified. The plan's slice S0 carries this work, and it also carries the D-7 numeric rule (refuse non-finite values and negative zero; align accepted integers with `forge_contract_core`), because payload numbers are event input.
- **Status**: Open — recorded, unresolved until a correction is authorized and verified.

## KI-SENTINEL-20261102-007: The ledger can persist a body differently from the form it hashed — OPEN 2026-11-02 — ledger persistence — non-blocking

- **Classification**: Non-blocking. Library-only: a JSON-parsed replay line cannot produce the inputs below. This predates PR #29.
- **Discovery source**: independent review of forgesentinel PR #29 (finding F3).
- **Verified at**: the review executed it with a temporary WAL at `4e2f5fb` and at base `3b17efe`; base behaves the same.
- **Evidence**: `EvidenceLedger.append` hashes the body with `hashPayload`, which uses the canonical form (`src/contracts/common.ts:140-154`), and `persist` writes it with `JSON.stringify` (`src/spine/ledger.ts`). `JSON.stringify` honours a `toJSON` method, including one on a prototype; the canonical form copies own enumerable keys only.
- **Observed behavior**:
  1. A `Date` body hashes as `{}` but is written to the WAL as an ISO string. After the WAL is reloaded, that record fails `integrityCheck`.
  2. A class instance whose prototype `toJSON` throws, or returns a BigInt, passes hashing and takes a `ledger_seq`. Then `persist` throws: the record is in memory but missing from the WAL, and `append` throws.
- **Proposed correction**: Persist the same canonical text that was hashed, or refuse a body whose `JSON.stringify` and canonical forms differ before a sequence number is taken. Add a WAL round-trip test.
- **Status**: Open — recorded, unresolved until the correction is verified or the owner accepts it.

## KI-SENTINEL-20261102-009: The gateway dedupe key joins caller-controlled strings without length prefixes, so two different events can collide and the second is never recorded — OPEN 2026-11-02 — security-relevant integrity

- **Classification**: Security-relevant integrity, by owner ruling of 2026-11-02; recorded as evidence completeness and de-duplication correctness when first found. Not an authentication defect, but the same injectivity class as KI-SENTINEL-20261102-008. Latent while the gateway has no network ingress (KI-SENTINEL-20261030-001).
- **Discovery source**: the KI-SENTINEL-20261102-008 remediation planning work (`docs/plans/Sentinel_Envelope_Authentication_Plan_Set_2026-11-02/`). The format in that plan must be one to one, which prompted a check of the other place where this repository joins strings before it hashes them.
- **Verified at**: `432337c` (`origin/master`), by execution, with properly signed events from a legitimate producer on a production `SentinelRuntime`. The collision needs no alteration, so it is independent of KI-SENTINEL-20261102-008.
- **Evidence**: `dedupeKey` (`src/spine/gateway.ts:27-39`) hashes seven parts joined with `|`: the producer service, the tenant id, the event id, the event type, the subject as `subject_type` and `subject_id` joined with `:`, the hour bucket, and the payload hash. The join has no escape and no length prefix. `validateEventEnvelope` constrains `event_id` to `/^evt_[A-Za-z0-9_-]+$/` and `event_type` to the canonical registry, but it accepts any non-empty string for `tenant_id`, `subject_type` and `subject_id`. A `|` in one of those three fields moves the segment boundaries.
- **Observed behavior**: Two events were built and signed by `usage-metering`, with the same payload and the same hour bucket.
  - Event A: `tenant_id` `ten_a|evt_zzz|usage.tokens.recorded`, `event_id` `evt_pad`, `event_type` `usage.retry.recorded`, subject `account:acct_2041`.
  - Event B: `tenant_id` `ten_a`, `event_id` `evt_zzz`, `event_type` `usage.tokens.recorded`, `subject_type` `evt_pad|usage.retry.recorded|account`, `subject_id` `acct_2041`.
  - Both give the dedupe key `9d0f5009a79be30132dbec8d6fe3efd9f2affca642b3a80ca7b7d3d9fc774f19`. The gateway accepted A, then returned `status: "duplicate"` for B with A's ledger record. The ledger held one row. B was never recorded.
- **Impact**: A producer, or a tenant whose identifiers reach these fields, can make the gateway drop a different event as a duplicate. The dropped event leaves no ledger row and no rejection row, so the evidence spine loses it silently. The `:` join between `subject_type` and `subject_id` has the same defect, and needs a `:` in the second event's subject.
- **Bounds (verified)**: Both events must authenticate as the same producer service, and must share the hour bucket and the payload hash. The event that is dropped is the one ingested second, and it must carry the separator character. A clean event, with no `|` and no `:` in those fields, cannot be collided with by this route, because the segment count then fixes the split. There is no network ingress and the pipeline is shadow-only.
- **Severity assessment**: Low, latent. The prerequisites are real: an attacker needs the target event's payload, its hour, its producer, and a separator character in the target's own tenant or subject fields. It matters because this is the evidence spine of the security layer, and a silent drop is worse than a rejection.
- **Proposed correction** (not authorized by this record): Build the dedupe key with the one-to-one encoder that `docs/plans/Sentinel_Envelope_Authentication_Plan_Set_2026-11-02/01_CANONICAL_AUTHENTICATION_FORMAT.md` specifies, or give every segment an explicit byte length. Add a test with the two events above. Decision D-8 in that plan set asks the owner whether this correction belongs to that track or to its own.
- **No change made**: This record changes no code.
- **Owner ruling (2026-11-02)**: Accepted as a **separate security-relevant integrity defect, not merely an encoding cleanup**. The ruling states that a collision which silently drops a legitimate event threatens the reliability of the evidence ledger. Remediation is prioritized alongside the authentication rollout where the shared encoding code can safely be reused, and stays separately tracked, immediately after the envelope-authentication correction (plan decision D-8, slice S7). The owner did not authorize the correction in this ruling.
- **Status**: Open — accepted as a security-relevant integrity defect and scheduled after the envelope-authentication correction; unresolved until that correction is authorized and verified.

## KI-SENTINEL-20261102-010: The documented `sentinel replay` command cannot succeed on the committed fixtures in any environment — OPEN 2026-11-02 — documentation and operability

- **Classification**: Documentation drift and operability. Not a security defect. It is a consequence of the KI-SENTINEL-20261030-002 correction that PR #21 merged.
- **Discovery source**: the KI-SENTINEL-20261102-008 remediation planning work, while it listed the verification gates for the proposed slices.
- **Verified at**: `432337c` (`origin/master`), by execution.
- **Evidence**:
  - `doc/system/06-verification.md` and `README.md` both name `node dist/src/cli.js replay fixtures/replay/compound_account_compromise.jsonl` as an operator command.
  - `tools/gen-fixtures.ts:24` signs the committed fixtures with `fixtureProducers("production")`, so every committed envelope carries `producer.environment: "production"`.
  - `src/cli.ts` reads `SENTINEL_ENVIRONMENT` (default `production`) and loads the secrets file for that environment (KI-SENTINEL-20261030-002, correction item 6).
  - `src/spine/producer_secrets.ts` refuses a secret with the published `test-secret-` prefix in `production` and `staging`.
- **Observed behavior**:
  - `SENTINEL_ENVIRONMENT=test` with a secrets file that holds the fixture secrets: the CLI runs and the gateway rejects all 44 lines with `environment_boundary`, because the registry is bound to `test` and each envelope says `production`. The summary reads `0 accepted, 0 duplicate, 44 rejected (of 44)` and the exit code is 0.
  - `SENTINEL_ENVIRONMENT=production` with the same file: the CLI prints `replay refused: the producer secrets file is for "test", not "production"` and exits 2. A production file that held the fixture secrets would be refused as a published test secret.
- **Impact**: An operator who follows the documented command sees either a silent all-rejected run with exit code 0, or a refusal. Neither result says that the committed fixtures and the configured environment do not match. The test suite is unaffected: `test/e2e.replay.test.ts` re-signs the fixtures with fresh random secrets through `resign` (`test/support/producers.ts:53`), so the end-to-end check still works.
- **Severity assessment**: Low. No security impact. It wastes operator time, and the exit code 0 on an all-rejected replay can read as success.
- **Proposed correction** (not authorized by this record): Decide which environment the committed fixtures belong to. Then do one of these: generate the fixtures for the `test` environment; or make the CLI refuse a replay whose envelopes do not match the registry environment, with a clear message; or make a non-zero rejection count give a non-zero exit code; or correct the documented command to name the needed configuration. Update `doc/system/06-verification.md` and `README.md` in the same change, then run `bash doc/system/BUILD.sh`.
- **No change made**: This record changes no code, no fixture and no documentation outside this file.
- **Owner ruling (2026-11-02)**: Accepted as a **documentation and verification-tool defect**. The ruling states that a command which reports success while it rejects every fixture is misleading. The correction must fix the exit-status behaviour and the documentation, **in a separate change** from the envelope-authentication track. So the exit status is not advisory: a replay that rejects every line must not exit 0. The owner did not authorize the correction in this ruling.
- **Status**: Open — accepted as a documentation and verification-tool defect, to be corrected in its own change; unresolved until that change is authorized and verified.

## KI-SENTINEL-20261102-011: A rejection record's cloud projection skips every data-policy check, so a restricted, cloud-denied payload becomes cloud-eligible whenever an event is rejected — OPEN 2026-11-02 — security — high priority

- **Classification**: Security, data boundary. It inverts the doctrine that `CLAUDE.md` and the Wave 0 contract state: restricted content can never be marked cloud eligible. Latent while the gateway has no network ingress (KI-SENTINEL-20261030-001) and no cloud exporter consumes a projection.
- **Discovery source**: the independent design review of the `BDS-SNT-ENVELOPE-AUTH-001` plan set, finding F31. The review was asked to assess rejection-record confidentiality. This author re-verified it by execution.
- **Verified at**: `5430dea` (branch `claude/envelope-auth-plan-47555m`; the code is unchanged from `432337c`, `origin/master`), by execution on a production `SentinelRuntime` with fresh random producer secrets.
- **Evidence**: `EvidenceLedger.cloudProjection` (`src/spine/ledger.ts:138-141`) begins `if (record.kind !== "event") { return { ledger_seq, kind, source_hash, tenant_id, body: record.body }; }`. It returns before every `data_policy` check. The checks that follow it — `cloud_allowed`, `sensitivity`, `content_included` — run only for a record whose `kind` is `event`. `EventGateway.reject` (`src/spine/gateway.ts:213-222`) writes `kind: "rejection"` with `body: rejectionBody(rawEvent)`, and `rejectionBody` returns a serializable object input as it is, so the body is the whole rejected envelope, including its payload.
- **Observed behavior**: An event was built with `data_policy` `{ content_included: true, sensitivity: "restricted", retention_class: "security_365d", cloud_allowed: false }` and a payload holding `SECRET_MANUSCRIPT` and `api_key` values. One payload field was then changed, so the gateway rejected the event with `payload_hash_mismatch`.
  - `cloudProjection` of the rejection record returned a value, not `null`. The returned object contained both the manuscript string and the API-key string.
  - `cloudProjection` of the same event when accepted returned `null`, correctly suppressed by its `data_policy`.
- **Impact**: The classification that suppresses an accepted event is not consulted for a rejected one. So the stricter the event's real policy, the more surprising the result: an honestly labelled `restricted`, `cloud_allowed: false` payload is published in full whenever the event fails any check. Rejection is not a rare path: a clock-order rejection, a payload-hash mismatch, a producer key rotation, or a malformed line all take it. This needs no forged label and no attacker; KI-SENTINEL-20261102-008's forged-label concern is a second, narrower route to the same place.
- **Bounds (verified)**: No code in this repository calls `cloudProjection` on a rejection record today, and no cloud exporter exists. The gateway has no network ingress, and the pipeline is shadow-only. `test/ledger.test.ts:67-77` exercises projections of `kind: "event"` records only, which is why the full suite passes with this open.
- **Severity assessment**: High once any cloud export path exists, medium latent until then. The defect is in the function whose stated job is the cloud data boundary, and its comment claims it never passes payload content that is not cloud eligible.
- **Proposed correction** (not authorized by this record): Apply the data-policy gate to every record kind, or refuse to project a record whose body is not an authenticated envelope. A rejection record's classification is unauthenticated when authentication failed, so the safe form carries no payload and no `data_policy` at all. Add a test for each record kind, not only `event`.
- **Owner disposition (2026-11-02, ruling R1-D)**: A separate authorized change carries this, as slice SL of `BDS-SNT-ENVELOPE-AUTH-001`, sequenced before slice S4. The owner ruled it out of the envelope-authentication track, because it is not an authentication defect and must not wait on the format corrections. Implementation is not yet authorized.
- **No change made**: This record changes no code.
- **Status**: Open — recorded, unresolved until a correction is authorized and verified.

## KI-SENTINEL-20261102-012: A rejection record takes its tenant id from the unauthenticated envelope, so a forged tenant id places an attacker-chosen record inside a victim tenant's evidence view — OPEN 2026-11-02 — security

- **Classification**: Security, tenant isolation. Latent while the gateway has no network ingress (KI-SENTINEL-20261030-001).
- **Discovery source**: the independent design review of the `BDS-SNT-ENVELOPE-AUTH-001` plan set, finding F33. This author re-verified it by execution.
- **Verified at**: `5430dea`, by execution. The code is unchanged from `origin/master`.
- **Evidence**: `EventGateway.ingest` passes `event.tenant?.tenant_id` to `reject` before and after authentication (`src/spine/gateway.ts:147,154,159,163,167,171,183,191`), and `reject` writes it to the record (`:220`). `EvidenceLedger.queryByTenant` filters on exactly that field (`src/spine/ledger.ts:130`). Nothing re-checks the tenant against the authenticated producer, because authentication failed.
- **Observed behavior**: An event naming `tenant_id: "ten_victim"` was rejected for a payload-hash mismatch. `queryByTenant("ten_victim", ...)` then returned one record, of kind `rejection`. The victim tenant's evidence view holds a record whose content the submitter chose.
- **Impact**: An actor who can submit events can write arbitrary rejection records into any tenant's evidence view, with a body they control. A reviewer who reads one tenant's evidence sees material that no authenticated producer sent for that tenant. The forged `tenant_id` also decides retention and access for that record.
- **Bounds (verified)**: The record is marked `validation: "rejected"` and `kind: "rejection"`, and `EvidenceLedger.events()` filters to accepted events (`src/spine/ledger.ts:108`), so a rejection does not reach the detectors or Sentinel Prime. The exposure is to a human or a tool reading tenant evidence, not to the inference pipeline. No network ingress, shadow-only.
- **Severity assessment**: Medium, latent. It is a tenant-isolation defect in the evidence spine, and tenant isolation is a named Wave 1 guarantee.
- **Proposed correction** (not authorized by this record): Do not take an access-control field from an unauthenticated envelope. Either omit `tenant_id` from a record whose authentication failed, or record it inside the body as an observed, untrusted value and keep the record out of every tenant-scoped view. This interacts with the `BDS-SNT-ENVELOPE-AUTH-001` gate-5 record shape, so the two must agree.
- **Owner disposition (2026-11-02, rulings R1-D and R1-E)**: A separate authorized change carries this, as slice SL, before slice S4. R1-E rules the shape: a record of unauthenticated provenance carries no top-level `tenant_id`, the claimed tenant stays in the recommendation-1 metadata as an explicitly named observed value, no query path filters on it, and `LedgerRecord` gets no new top-level provenance field. Implementation is not yet authorized.
- **No change made**: This record changes no code.
- **Status**: Open — recorded, unresolved until a correction is authorized and verified.

## KI-SENTINEL-20261102-013: The producer-authentication failure message copies unbounded attacker-controlled credential text into the evidence ledger and returns it to the caller — OPEN 2026-11-02 — security

- **Classification**: Security, evidence integrity and resource use. Latent while the gateway has no network ingress (KI-SENTINEL-20261030-001).
- **Discovery source**: the independent design review of the `BDS-SNT-ENVELOPE-AUTH-001` plan set, finding F30. This author re-verified it by execution.
- **Verified at**: `5430dea`, by execution. The code is unchanged from `origin/master`.
- **Evidence**: `src/spine/gateway.ts:158` builds the message `producer "<credential.service>" failed authentication for key "<credential.key_id>"`. That `ValidationIssue` goes into `rejection_reasons` on the ledger record (`:218`) and into the `IngestResult` the caller receives (`:227`). `isWellFormedCredential` (`src/spine/producers.ts:29-33`) checks only that `service`, `key_id` and `token` are strings. Neither field has a length bound, a character set, or a registration check at this point, because the lookup already failed.
- **Observed behavior**: A credential with a `key_id` of 200 `A` characters followed by a NUL byte was presented with a valid event. The gateway rejected it with `producer_auth_failed`. The caller's message carried the full 200-byte string and the NUL byte, 259 characters in all, and the ledger record's `rejection_reasons` carried the same text. The presented token did not reach the record.
- **Impact**: Three consequences. An unauthenticated submitter writes chosen text into the evidence ledger, which is the repository's audit surface. A reader or downstream tool that renders a reason message renders attacker text, including control characters. And the record size is attacker-chosen, so each rejected line consumes ledger and write-ahead-log space in proportion to the submitted credential.
- **Related bound**: Contract-validation and payload-hash rejections append before any credential check (`src/spine/gateway.ts:140,147`), so unauthenticated input already consumes the ledger sequence space. The envelope-authentication plan's gate 3 declares the rejection write a deliberate evidence exception, but nothing bounds its size or rate.
- **Severity assessment**: Medium, latent. It is log and evidence injection, with an unbounded size vector, on the trust boundary of the evidence spine.
- **Proposed correction** (not authorized by this record): Do not interpolate unvalidated caller input into a reason message. Report the generic code, and record the credential identity only after a registration lookup succeeds, or record a bounded, character-filtered form marked as observed and untrusted. Bound the stored reason length. This interacts with the `BDS-SNT-ENVELOPE-AUTH-001` D-3 ruling, which requires that the caller's message name no field and no value.
- **No change made**: This record changes no code.
- **Status**: Open — recorded, unresolved until a correction is authorized and verified.

## KI-SENTINEL-20261102-014: An unverified producer signature is stored as accepted evidence on an event that does not require a signature — OPEN 2026-11-02 — security

- **Classification**: Security, evidence trust. Latent while the gateway has no network ingress (KI-SENTINEL-20261030-001).
- **Discovery source**: the independent design review of the `BDS-SNT-ENVELOPE-AUTH-001` plan set, finding F3. This author re-verified it by execution.
- **Verified at**: `5430dea`, by execution. The code is unchanged from `origin/master`.
- **Evidence**: `EventGateway.ingest` evaluates the signature block only when `signatureRequired` (`src/spine/gateway.ts:179-193`), which it derives from the producer registration and the event family, never from the envelope. `validateEventEnvelope` validates `integrity.payload_hash` and `integrity.idempotency_key` and never reads `integrity.signature` or `integrity.signature_key_id` (`src/contracts/envelope.ts:205-209`). So on an event whose family needs no signature, both fields pass through unverified.
- **Observed behavior**: A `usage.tokens.recorded` event was signed and accepted. The same event with `integrity.signature` set to 64 `a` characters and `signature_key_id` set to `key_attacker` was accepted with the original credential, and the ledger stored both values inside the accepted record's `integrity` object. A second event with `signature: "NOT-HEX"` and a numeric `signature_key_id` was also accepted.
- **Impact**: The evidence ledger stores a value that looks like a producer signature and names a key, with no verification behind it. A reader, a detector, or an operator surface that treats the presence of `integrity.signature` as evidence that a high-value producer signed the event is misled. The `signature_key_id` also names a key that need not exist.
- **Bounds (verified)**: For a signature-required producer or family (`billing-service`, `cssa`, and the signature-required families) the gateway does verify the signature and does compare `signature_key_id` with the registration. The defect is confined to events that need no signature. The submitter must already hold a valid credential for the event, so this is not by itself an authentication bypass.
- **Severity assessment**: Medium, latent. It is a defect in what the evidence means, in the record the whole intelligence layer reads.
- **Relation to KI-SENTINEL-20261102-008**: The same class, and not fixed by the plan as written. The `forgesentinel.event_auth.v1` field list binds neither field in the credential context, so a corrected gateway would still accept an added bogus signature. The plan set records this as a blocking review finding.
- **Proposed correction** (not authorized by this record): Refuse `integrity.signature` and `integrity.signature_key_id` on an event that requires no signature, or verify them whenever they are present, and bind both into the authenticated bytes.
- **Owner disposition (2026-11-02, ruling R1-A)**: Ruled, and the ruling takes **both** measures rather than one of them. Refuse both fields on an event whose family requires no signature, and bind both where they may legitimately appear. The owner took both because binding alone leaves this finding open: binding stops a third party adding or altering the fields, but an unverified value is still stored as accepted evidence on a no-signature family. The ruling settles the two measures and not which slice carries each; `05` allocates them. Implementation is not yet authorized.
- **No change made**: This record changes no code.
- **Status**: Open — recorded, unresolved until a correction is authorized and verified.

## KI-SENTINEL-20261102-015: The gateway's de-duplication map is not rebuilt from the ledger, so a verbatim replay is accepted by a fresh process — OPEN 2026-11-02 — evidence integrity

- **Classification**: Evidence integrity, replay. Latent while the gateway has no network ingress (KI-SENTINEL-20261030-001).
- **Discovery source**: the independent design review of the `BDS-SNT-ENVELOPE-AUTH-001` plan set, finding F26. This author re-verified it by execution.
- **Verified at**: `5430dea`, by execution. The code is unchanged from `origin/master`.
- **Evidence**: `EventGateway` holds `#seen` as a fresh `Map` for each instance (`src/spine/gateway.ts:113`) and writes to it only on an accepted event (`:209`). Nothing repopulates it. `EvidenceLedger` does reload its write-ahead log on construction, so the ledger survives a restart and the de-duplication state does not.
- **Observed behavior**: One signed event was ingested twice through one gateway: `accepted`, then `duplicate`. The identical event and credential, ingested through a second gateway instance in the same process, were `accepted`. The ledger then holds two accepted records for one event.
- **Impact**: De-duplication is process-scoped, not durable. A replay file submitted twice across a restart, or the same evidence delivered twice by a future transport, is counted twice. A duplicated event inflates every count a detector derives from the ledger, which is how Sentinel-Cost and the burst detectors reach a finding.
- **Bounds (verified)**: Inside one gateway instance de-duplication works as documented. The repository has no durable deployment and no transport that could redeliver. A replay is an operator action today.
- **Severity assessment**: Low to medium, latent. It is a correctness boundary that the documentation does not state, and the envelope-authentication plan's replay controls assume de-duplication is the backstop.
- **Proposed correction** (not authorized by this record): Rebuild `#seen` from the loaded ledger when the gateway is constructed over a ledger that has records, or state in `doc/system/03-runtime-boundary.md` that de-duplication is process-scoped and is not a replay defence.
- **No change made**: This record changes no code.
- **Status**: Open — recorded, unresolved until a correction is authorized and verified, or the owner accepts it.

## KI-SENTINEL-20261102-016: The cross-tenant denial record is stored as an accepted event under the requested tenant, which stops `runShadow` and discloses the denied principal — OPEN 2026-11-02 — security and availability

- **Classification**: Security (tenant isolation, cross-tenant disclosure) and availability (the shadow pipeline). Latent while no code outside the test suite calls `queryByTenant`, so the pipeline holds no denial record today.
- **Discovery source**: this session, while the author read `src/spine/ledger.ts` in full to ground the owner's open decisions R1-D and R1-E. It is not a finding of independent review round 1, and it is not a variant of KI-SENTINEL-20261102-012, which concerns a rejection record written by the gateway. This record concerns a record the ledger writes about itself. Verified by execution.
- **Verified at**: `79698ac`, `origin/master`, by execution against the compiled `dist/src/spine/ledger.js`.
- **Evidence**: `EvidenceLedger.queryByTenant` appends its own denial telemetry when a tenant-scoped principal requests another tenant (`src/spine/ledger.ts:115-127`). That append sets `kind: "event"`, `validation: "accepted"` and `tenant_id: tenantId`, where `tenantId` is the **requested** tenant and not the principal's own. The body is a four-field diagnostic object, not an `EventEnvelope`. Three readers then trust those two labels. `events()` filters on exactly `kind === "event" && validation === "accepted"` and casts each body to `EventEnvelope` (`:108`). `exportEventsJsonl()` serializes whatever `events()` returns (`:174-176`). `cloudProjection` treats `kind === "event"` as proof that the body carries `integrity` and `data_policy` (`:142-157`).
- **Observed behavior**: one call of `queryByTenant("ten_victim", { principal: "p_attacker", tenant_id: "ten_attacker", role: "tenant" })` threw `CrossTenantAccessDenied` and appended one record, `{ kind: "event", validation: "accepted", tenant_id: "ten_victim" }`. Then:
  - `events()` returned that body with `event_id`, `occurred_at`, `integrity` and `data_policy` all `undefined`.
  - `exportEventsJsonl()` emitted 139 bytes of that non-envelope into the deterministic replay stream.
  - `cloudProjection` and `cloudProjectionContains` both threw `TypeError: Cannot read properties of undefined (reading 'payload_hash')`.
  - With one real accepted event also in the ledger, the expression at `src/runtime.ts:255` threw `RangeError: Invalid time value`, because `Date.parse(undefined)` is `NaN` and `Math.max` propagates it.
  - The legitimate victim tenant then read the record: `queryByTenant("ten_victim", { principal: "p_victim", tenant_id: "ten_victim", role: "tenant" })` returned it, so that tenant saw `denied_principal: "p_attacker"` and `principal_tenant: "ten_attacker"`.
  - `integrityCheck()` reported `ok: true` for the record, so no integrity surface flags it.
- **Impact**: four consequences follow from one mislabelled append. Availability: a single denial record stops `runShadow`, which is the only pipeline mode this repository runs, and it stops it with an unhandled `RangeError` rather than a rejection. Evidence integrity: a diagnostic object enters the accepted-event stream that the features, the baselines and Sentinel Prime read, and it enters the replay export. Cross-tenant disclosure, in the opposite direction to KI-SENTINEL-20261102-012: the record is filed under the **requested** tenant, so the probed tenant learns the identity and the home tenant of a principal it does not own. Cloud boundary: the projection path throws on a record the ledger itself wrote.
- **Bounds (verified)**: `queryByTenant` and `cloudProjection` have no caller in `src/` or `tools/`; only `test/` calls them. So the shipped pipeline creates no denial record and reaches none of these consequences. The gateway has no network ingress (KI-SENTINEL-20261030-001) and the pipeline is shadow-only. The full suite passes with this open, because no test combines a denial record with `events()`, `runShadow` or a projection.
- **Severity assessment**: Medium and latent now. High as soon as any tenant-scoped evidence read path is wired, because that path is what calls `queryByTenant`. The defect sits inside the function whose stated job is tenant isolation, and the telemetry intent is right while the labels are wrong.
- **Proposed correction** (not authorized by this record): Give the denial record a kind that `events()` does not read, and do not file it under the requested tenant. Hold the denied principal and its home tenant in a system-scoped record instead. Make `events()` validate a body rather than cast it, so no future mislabelled record can enter the accepted-event stream. Apply a data-policy gate to every record kind, which KI-SENTINEL-20261102-011 also requires.
- **Owner disposition (2026-11-02, rulings R1-D and R1-E)**: A separate authorized change carries this, as slice SL, before slice S4. R1-E binds on unauthenticated provenance rather than on the `rejection` kind, so it reaches this record, and it extends to the `kind` and `validation` labels. The owner amended R1-E's original wording for that reason. Implementation is not yet authorized.
- **Relation to review finding F34**: the same root cause. `LedgerRecord` carries one `tenant_id`, and that one field means both "the tenant this record is about" and "the tenant that may read it". The owner's open decision R1-E chooses between a provenance field and a rule that such a record carries no `tenant_id`, and either choice must cover this record as well as a rejection record.
- **No change made**: This record changes no code.
- **Status**: Open — recorded, unresolved until a correction is authorized and verified, or the owner accepts it.
