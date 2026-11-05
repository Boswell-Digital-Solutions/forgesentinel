# 07 — QA and verification plan, with acceptance-to-evidence mapping

This document is section 07. It gives each acceptance criterion a stable id, an observable pass condition, a method, and an evidence destination. It applies BDS-QA-001.

## Testing modes and tiers (BDS-QA-001 §2, §5)

| Tier | Applies to | Mode |
|---|---|---|
| T0 pre-flight | Each repository's own gate runs before a work package starts | A |
| T1 unit | Report validator, projection and writer (WP-05, WP-06); the forge-command reader (WP-07) | A |
| T3 contract | The golden report fixture, validated by both sides | A |
| T4 integration | `sentinel report` output read by forge-command's reader | A (both run locally; no external service) |
| T5 E2E | The Incidents view shows a live report and each absence state | A, desktop app, keyboard-driven |
| T6–T8 | Not applicable: no performance target, no packaging change and no new public UI beyond one section. The Incidents view follows the existing accessibility rules of forge-command. | — |

A tier needs every mandatory criterion below; a pass rate does not waive one (BDS-QA-001, mandatory acceptance).

## Repository gates

| Repository | Gate (from its own `CLAUDE.md` or `repo.manifest.yaml`) |
|---|---|
| forgesentinel | `npm test`; `bash doc/system/BUILD.sh && git diff --exit-code -- doc` |
| forge-command | `bun run check`, `bun run test`, `bun run test:repo-context`, `bun run check:agent-instruction-drift`, `bun run check:icons`, `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`, `bun run build`, `bash doc/system/BUILD.sh` |
| forge | `python3 docs/ecosystem/validate_ecosystem_map.py`; `python3 scripts/compile_ecosystem_map_v2.py --check-determinism`; `python3 scripts/check-plan-registry.py` |

Each gate runs unpiped, and its exit code is recorded. A skipped or unavailable check is recorded as such; it does not pass.

## Acceptance criteria

| Id | WP | Pass condition | Method | Evidence |
|---|---|---|---|---|
| AC-00.1 | WP-00 | The plan set conforms to BDS-PSS-001 §5: 10 components, compiled file, 4 siblings, manifest lists exactly the real files | `plan_set_manifest.json` compared with the directory listing; manual §5 review | The plan PR |
| AC-00.2 | WP-00 | The plan is registered in the BDS plan registry and the registry check passes | `python3 scripts/check-plan-registry.py` in `forge` | The registry PR |
| AC-01.1 | WP-01 | forge-command's `repo.manifest.yaml` declares `forgesentinel` under `upstream_authorities` with what it owns | File read at the merged commit | WP-01 PR |
| AC-01.2 | WP-01 | The generated agent files match the manifest | `bun run check:agent-instruction-drift` exits 0 | WP-01 PR checks |
| AC-01.3 | WP-01 | Chapter 10.2 lists forgesentinel, and `doc/fcoSYSTEM.md` is rebuilt | `bash doc/system/BUILD.sh` then `git diff --exit-code -- doc` | WP-01 PR |
| AC-01.4 | WP-01 | `FCO-SENTINEL-NOT-DECLARED-20261105` is closed with a pointer to the change | `docs/KNOWN_ISSUES.md` | WP-01 PR |
| AC-02.1 | WP-02 | forgesentinel has a `repo.manifest.yaml` valid against `RepoManifest.v1`, declaring DataForge and Forge-Agents upstream | Schema validation against forge_contract_core `repo_manifest.v1.schema.json` at a pinned revision | WP-02 PR |
| AC-02.2 | WP-02 | The four agent files are generated, and their hashes match the lock | The pinned generator's drift check exits 0 | WP-02 PR |
| AC-03.1 | WP-03 | The canonical map has an edge `forge-command → forgesentinel`, and with WP-02, edges from forgesentinel | `compile_ecosystem_map_v2.py`, then a query of `spec.edges` | WP-03 PR |
| AC-03.2 | WP-03 | The map validator and the determinism check pass | The `forge` gates above | WP-03 PR |
| AC-05.1 | WP-05 | `validateIncidentReport` accepts the golden fixture and refuses each case in the negative list below | `npm test` with named tests | WP-05 PR |
| AC-05.2 | WP-05 | A report with `mode` other than `shadow`, or with a `status` field instead of `status_as_reported`, is refused | Named negative tests | WP-05 PR |
| AC-05.3 | WP-05 | `npm run fixtures && git diff --exit-code -- fixtures` exits 0 | Fixture determinism (G4 style) | WP-05 PR |
| AC-06.1 | WP-06 | `sentinel report <fixture>` writes a report that validates, with mode 0600, by temporary file and rename | Named test against a temporary directory | WP-06 PR |
| AC-06.2 | WP-06 | The same input at the same commit gives a byte-identical report, except `generated_at` | Named test | WP-06 PR |
| AC-06.3 | WP-06 | A report that would exceed 4 MiB or 500 incidents is truncated or refused as component 04 states; the command exits non-zero on a refused input and writes nothing | Named negative tests | WP-06 PR |
| AC-06.4 | WP-06 | `doc/system/03-runtime-boundary.md` describes the command, the variable and the path; `doc/SNTSYSTEM.md` is rebuilt | Documentation CI | WP-06 PR |
| AC-07.1 | WP-07 | `incidents_list` is in the command table as `read`, granted to `main` only; the ACL test passes | `cargo test --workspace --locked` (`acl.rs`, `registry.rs`) | WP-07 PR |
| AC-07.2 | WP-07 | Each absence state has a test: missing file → `unavailable`; old file → `stale`; bad schema, wrong mode, oversized, integrity mismatch, symlink, other owner → `refused` with its reason | Named Rust tests in `fc-sources` | WP-07 PR |
| AC-07.3 | WP-07 | The view shows "Shadow" and "as reported" labels, the report's age, and no action button | Vitest component test; T5 keyboard check in the desktop app | WP-07 PR; T5 notes |
| AC-07.4 | WP-07 | No path returns fixture incidents or an empty list in place of an absence state | Named tests | WP-07 PR |
| AC-07.5 | WP-07 | No error message contains a path or file content | Named test on each error | WP-07 PR |
| AC-07.6 | WP-07 | Chapters 07, 08, 10 and 15 describe the section and the command; `doc/fcoSYSTEM.md` is rebuilt | `bash doc/system/BUILD.sh` | WP-07 PR |
| AC-07.7 | WP-07 | T4: a report written by `sentinel report` at the WP-06 commit is read as `live` by the WP-07 reader | Recorded run: both commits, the command, the result | WP-07 evidence note |
| AC-10.0 | WP-10 | No mission is dispatched while chapter 16.7's hold is in force | Hold check in code review; no dispatch path exists | WP-10 (blocked) |

Negative list for AC-05.1: a missing field; an unknown top-level field; an unknown major; an incident with a malformed id; a text field over 2000 characters; more than 500 incidents with `truncated: false`; an integrity mismatch.

## Evidence records

A completed record names: the source revision of each repository, the test names or command, the environment (machine, Node, Rust and Bun versions), the observed result and the retained artifact. A planned check is not evidence. The author's own verification is not the independent review that a gate may require.
