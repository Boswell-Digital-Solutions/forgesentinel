# Known Issues

This document tracks known issues in the Forge Sentinel repository. Record a
finding here in the same session that you find it. Chat is not durable.

## doc/system layout does not match the audit tool

- **Location**: `doc/system/` — the seven numbered subdirectories
- **Status**: OPEN. Do not change the layout without an operator decision.
- **Impact**: Low. `scripts/audit_doc_system_shape.py` reports `needs_update`
  for this repository.
- **Cause**: BDS Documentation Protocol v2.0 section 5.3 requires flat
  `NN-kebab-case.md` files directly under `doc/system/`. This repository uses
  numbered subdirectories instead.
- **Evidence**: The build markers all pass. `marker_gaps` is empty for
  `_index.md`, `BUILD.sh`, and `validate_snapshots.sh`. `bash doc/system/BUILD.sh`
  runs clean and makes no change to `doc/SNTSYSTEM.md`.

Most Forge repositories use the same subdirectory layout. The tool and the
protocol look stale, not the repositories. A fleet-wide decision must come
first. Do not migrate this repository alone.

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

_Last updated: 2026-09-14_
