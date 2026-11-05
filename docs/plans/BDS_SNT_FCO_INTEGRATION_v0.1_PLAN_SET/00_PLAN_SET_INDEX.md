# 00 — Index, plan identity and read order

This document is section 00 of the plan set. It gives the plan identity and the read order.

| Field | Value |
|---|---|
| Plan ID | BDS-SNT-FCO-v0.1 |
| Title | Forge Sentinel and forge-command Integration |
| Lifecycle | proposed |
| Authority | Planning. The operator directed "build the plan … We then begin implementation" (2026-11-05). Component 09 states the exact work that this direction covers. No other implementation is authorized. |
| Decision owner | Charlie Boswell / Boswell Digital Solutions LLC |
| Prepared | 2026-11-05 America/New_York |
| Parent / extension target | The integration review of 2026-11-05 (forgesentinel PR #52, `docs/sentinel/forge-command-integration-review-2026-11-05.md`). Related: `BDS-SNT-ENVELOPE-AUTH-001` (envelope authentication, S1 to S6); `BDS-FCO-P3-TOKEN-ISSUER-001` (forge-command token issuer). |
| Proposed canonical owner | `Boswell-Digital-Solutions/forgesentinel`, `docs/plans/BDS_SNT_FCO_INTEGRATION_v0.1_PLAN_SET/`. Source lock: each work package pins the revisions it starts from (component 08). |
| Primary candidate consumer | `forgesentinel` (`src/contracts/`, `src/cli.ts`, `docs/`), `forge-command` (`repo.manifest.yaml`, `crates/fc-sources/`, `src/lib/state/workspaces.ts`, `doc/system/`), `forge` (`docs/canonical/`, `CLAUDE.md`) |
| Canonical Drive destination | `/Forge/Plans/BDS_SNT_FCO_INTEGRATION_v0.1_PLAN_SET/` |
| Compilation | Components 00 to 09, in order, compile to `BDS-SNT-FCO-v0.1_COMPILED_PLAN_SET.md`. No build script exists; the compiled file is kept by hand, and an edit to a component is mirrored into it in the same change. |

## Source revisions read

| Repository | Revision |
|---|---|
| `forgesentinel` | `master` `7749737` |
| `forge-command` | `main` `88d783e` |
| `forge` | `main` `b7906c50` |

## Read order

00 Index · 01 Rulings and non-goals · 02 Authority and gaps · 03 Protocol binding and coverage ·
04 Contract and provenance · 05 Mechanism · 06 Decision semantics · 07 QA and acceptance ·
08 Work packages · 09 Operator review packet.
