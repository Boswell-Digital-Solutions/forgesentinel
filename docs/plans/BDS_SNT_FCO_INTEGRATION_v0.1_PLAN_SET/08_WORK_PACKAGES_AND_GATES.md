# 08 — Work packages and gates

This document is section 08. Each work package has the nine-field brief of BDS-PSS-001 §3.6. Shared rules for every package come first, so the briefs do not repeat them.

## Shared rules

- **Starting evidence.** Pin the revision of each repository touched, from its default branch, before the first edit. Recheck it before the PR. The revisions in component 00 are the planning baseline.
- **Write scope.** Work in a new worktree from the default branch. Never switch a shared checkout. Use `git -C` and `gh -R` on every call.
- **Recording.** Each PR records its gate results unpiped, with exit codes. Findings go in the owning repository's `docs/KNOWN_ISSUES.md` in the same change.
- **Hand-off.** Open the PR and hand it to the reviewer and PR manager. Do not merge without the operator's word.
- **Pause.** Stop and report when progress needs an out-of-scope change, an unruled decision, a weaker criterion, or a change to a deployed service.
- **Recovery.** Fix an in-scope failure without weakening a criterion. When an environment is unavailable, mark the criterion blocked and continue independent authorized work.

## WP-00 — Plan set (forgesentinel; forge registry)

| Field | Record |
|---|---|
| Outcome | This plan set exists in forgesentinel and in Drive, conforms to BDS-PSS-001, and is registered. |
| Starting evidence | Component 00 revisions; the review in PR #52. |
| Prerequisites | None. |
| Permitted scope | `docs/plans/BDS_SNT_FCO_INTEGRATION_v0.1_PLAN_SET/` in forgesentinel; new files in `/Forge/Plans/BDS_SNT_FCO_INTEGRATION_v0.1_PLAN_SET/` in Drive; one registry row in `forge` `docs/canonical/plan_registry_v1.json` (separate PR). |
| Boundaries | No code. No change to an existing Drive file. |
| Deliverables | 10 components, the compiled file, 4 siblings, the Drive copy, the registry row. |
| Acceptance criteria | AC-00.1, AC-00.2 |
| Verification | Component 07. |
| Stop conditions | Complete when the plan PR and the registry PR are open and pass their checks. A refused Drive write is reported with the content to paste; the repository copy is still the canonical owner. |

## WP-01 — forge-command declares forgesentinel (forge-command)

| Field | Record |
|---|---|
| Outcome | forge-command declares forgesentinel as an upstream authority, so F-6 can draw the edge (05 §F-6). |
| Starting evidence | `repo.manifest.yaml` `upstream_authorities` has seven entries without forgesentinel; chapter 10.2 has the same seven (`FCO-SENTINEL-NOT-DECLARED-20261105`). |
| Prerequisites | None. |
| Permitted scope | `repo.manifest.yaml`; the four generated agent files and `scripts/repo-context-authority/lock.json`, through `bun run generate:agent-instructions` only; `doc/system/10-ecosystem-integration.md`; `doc/fcoSYSTEM.md` through `BUILD.sh`; `docs/KNOWN_ISSUES.md`. |
| Boundaries | No code. No new connection. The entry says what forgesentinel owns ("security findings, incident briefings and recommendations; never truth"). |
| Deliverables | The manifest entry, the regenerated agent files, the chapter 10.2 row with "Connection today: None", the closed KI entry. |
| Acceptance criteria | AC-01.1 to AC-01.4 |
| Verification | forge-command's gates (component 07). |
| Stop conditions | Complete when the PR is open with green gates. Pause if the generator refuses the entry name. |

## WP-02 — forgesentinel adopts RepoManifest.v1 (forgesentinel) — blocked by D-7

| Field | Record |
|---|---|
| Outcome | forgesentinel declares DataForge and Forge-Agents as upstream authorities in a valid `repo.manifest.yaml`. |
| Starting evidence | No `repo.manifest.yaml`; a hand-written `CLAUDE.md`; the forge-held manifest is empty (`KI-FORGE-20261105-002`). |
| Prerequisites | D-7. A pinned forge_contract_core revision for the schema and generator. |
| Permitted scope | `repo.manifest.yaml`, the four agent files, the generator lock, `doc/system/04-dependencies.md`, `docs/KNOWN_ISSUES.md`. |
| Boundaries | The generated `CLAUDE.md` must keep every rule of the current hand-written one; a rule that the generator cannot carry pauses the work. |
| Deliverables | The manifest, the generated files, the lock. |
| Acceptance criteria | AC-02.1, AC-02.2 |
| Verification | Schema validation; the generator drift check; `npm test`. |
| Stop conditions | Pause on D-7 decline or defer. Pause if a current `CLAUDE.md` rule has no place in the manifest. |

## WP-03 — forge recompiles the map (forge)

| Field | Record |
|---|---|
| Outcome | The canonical map shows forgesentinel's edges. With D-8, the authority table names Forge Sentinel. |
| Starting evidence | 0 of 50 edges touch forgesentinel. **Limit:** the compiler reads `repo.manifest.yaml` at HEAD of each canonical checkout (`committed_manifest`), whatever branch it is on. The forge-command checkout at `ecosystem/forge-command` was on a feature branch on 2026-11-05. |
| Prerequisites | WP-01 merged; the canonical checkouts at their merged default branches. Updating a shared checkout is the operator's action, or a fast-forward that the operator approves. |
| Permitted scope | `docs/canonical/ecosystem_repo_map.v2.json` through the compiler; `docs/KNOWN_ISSUES.md`; `CLAUDE.md` authority table only with D-8. |
| Boundaries | No hand edit of the compiled map. |
| Deliverables | The recompiled map; the KI update; the table row (with D-8). |
| Acceptance criteria | AC-03.1, AC-03.2 |
| Verification | The forge gates. |
| Stop conditions | Pause when a canonical checkout is not at its default branch. Record the limit as a finding in `forge`. |

## WP-04 — Retarget forgesentinel's integration documents (forgesentinel)

| Field | Record |
|---|---|
| Outcome | Every integration document names forge-command and its objects (`KI-SENTINEL-20261105-001`). |
| Starting evidence | Review §6 field map; EAS-04B; implementation status; plan `07`, `09`; ADR-026. |
| Prerequisites | D-1, D-2 and D-5 for the parts that state ownership. The factual renaming needs no decision. |
| Permitted scope | `docs/sentinel/`, `docs/plans/Forge_Sentinel_Integrated_Plan_Set_2026-06-11/` (append a dated retarget note; do not rewrite history), `docs/KNOWN_ISSUES.md`. |
| Boundaries | No code. `src/intel/prime.ts`'s authority string is code and waits for its own change. |
| Deliverables | Retargeted documents; the KI closed or narrowed. |
| Acceptance criteria | Review of each document against the field map; Documentation CI. |
| Verification | `bash doc/system/BUILD.sh && git diff --exit-code -- doc`. |
| Stop conditions | Pause a paragraph whose meaning depends on an unruled decision; retarget the rest. |

## WP-05 — The incident report contract (forgesentinel) — blocked by D-4

| Field | Record |
|---|---|
| Outcome | `forgesentinel.incident_report.v1` exists as a validated contract with a golden fixture (component 04). |
| Starting evidence | `src/contracts/incident.ts`; `fixtures/golden/`; `tools/gen-fixtures.ts`. |
| Prerequisites | D-4. |
| Permitted scope | `src/contracts/incident_report.ts`, `src/contracts/index.ts` (export), `test/incident_report.test.ts`, `tools/gen-fixtures.ts`, `fixtures/golden/`, the contracts validator map in `test/contracts.test.ts`, `doc/system/02-contract-surface.md`, `doc/SNTSYSTEM.md`. |
| Boundaries | No change to `Incident` or to any envelope or authentication module (R-9). |
| Deliverables | Contract, validator, fixture, tests, documentation. |
| Acceptance criteria | AC-05.1 to AC-05.3 |
| Verification | `npm test`; fixture determinism; Documentation CI. |
| Stop conditions | Pause if the projection needs a field that `Incident` does not hold. |

## WP-06 — `sentinel report` (forgesentinel) — after WP-05

| Field | Record |
|---|---|
| Outcome | The CLI writes the report atomically to the component 04 path. |
| Starting evidence | `src/cli.ts` (`replay`, `watch-cssa`); `runShadow` in `src/runtime.ts`. |
| Prerequisites | WP-05 merged. |
| Permitted scope | `src/cli.ts`, a new `src/report/` module, `test/report.test.ts`, `doc/system/03-runtime-boundary.md`, `doc/SNTSYSTEM.md`, `README.md` command list. |
| Boundaries | No network. No change to the gateway, ledger or producer authentication. Producer secrets load exactly as `replay` loads them. |
| Deliverables | The command, tests and documentation. |
| Acceptance criteria | AC-06.1 to AC-06.4 |
| Verification | `npm test`; Documentation CI. |
| Stop conditions | Pause if `runShadow` cannot run without a deployed credential. |

## WP-07 — Systems / Incidents in forge-command (forge-command) — after WP-05

| Field | Record |
|---|---|
| Outcome | The Incidents section reads the report through `incidents_list` and shows `live` or an absence state (05 §F-2). |
| Starting evidence | `workspaces.ts:62` (`built: false`); `crates/fc-sources/` (the DataForge Local and pin-report readers); chapter 10.5. |
| Prerequisites | WP-05 merged, with its schema name and major pinned. The operator's authorization of the slice (R-5: each connection is its own slice). |
| Permitted scope | `crates/fc-authority/src/registry.rs` (one `read` row), `crates/fc-sources/src/sentinel.rs`, `src-tauri/src/lib.rs` (handler), the capability files through the build, `src/lib/ipc/`, `src/lib/state/workspaces.ts`, a new Incidents view under `src/lib/ui/`, tests, `doc/system/07`, `08`, `10`, `15`, `doc/fcoSYSTEM.md`, `docs/KNOWN_ISSUES.md`. |
| Boundaries | No action in the view. No network. No fallback to a fixture. The reader enforces component 04's bounds itself; it does not trust the producer's. |
| Deliverables | The command, the reader, the view, tests, documentation, and the T4 evidence note. |
| Acceptance criteria | AC-07.1 to AC-07.7 |
| Verification | forge-command's gates; the T4 and T5 runs. |
| Stop conditions | Pause if a reviewer finds an authority-boundary defect, or if the desktop T5 run cannot be made. |

## WP-08 to WP-10 — Blocked

| WP | Outcome | Blocked by | Notes |
|---|---|---|---|
| WP-08 | Operator decisions on an incident reach Forge Sentinel, with a receipt | D-1; forge-command `sign`-class work | The brief is written when D-1 is ruled. |
| WP-09 | A governed control directive, signed by its owner with an asymmetric key | D-2, D-3, ADR-026, the envelope-authentication track | `KI-SENTINEL-20261105-004`, `FCO-SENTINEL-DIRECTIVE-SIGNER-20261105` |
| WP-10 | A mission from forge-command, with a verifiable admission | R-4 (execution hold), D-5, `KI-SENTINEL-20261105-002` | AC-10.0 holds until the hold is lifted |

## Gates

| Gate | Passes when |
|---|---|
| GT-1 Declared | WP-01 and WP-03 are merged, with WP-02 when D-7 is accepted |
| GT-2 Readable | WP-05 to WP-07 are merged, and AC-07.7 has a recorded run |
| GT-3 Decidable | WP-08 is merged |
| GT-4 Governed | WP-09 and WP-10 are merged |
