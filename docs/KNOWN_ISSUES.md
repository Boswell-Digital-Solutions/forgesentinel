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
