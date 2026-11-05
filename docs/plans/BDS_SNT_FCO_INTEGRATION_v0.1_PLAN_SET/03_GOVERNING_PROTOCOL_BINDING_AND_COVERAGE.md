# 03 — Governing-protocol binding, applicability and coverage

This document is section 03. It names each governing source, says whether it binds, and connects each material requirement to a design provision, a work package and an acceptance record.

## Sources

Registry: BDS Protocol Registry v2.11 (`gdrive-file:1jI5roiZc2hRJpqwB0hrOf9OenXQTREjF`), read 2026-11-05.

| Id | Source | Standing | Applies to |
|---|---|---|---|
| BDS-PSS-001 | Plan Set Structure Standard (`gdrive-file:1yWQUGn4yaSPJcQrui3Y5LBcycvCnAHyxhxayk_RiKCY`) | Binding | The form of this plan set |
| BDS-FEI-001 | Forge Ecosystem Integration Protocol v1.0 (`gdrive-file:13oeT0-XbCLgQ-ZR-ts4sk325eUNEiL4I`) | Binding, with recorded conflicts below | Every connection between the two systems |
| BDS-QA-001 | QA Testing Protocol v1.4 (`gdrive-file:177nVV9cB0mXV-uJfIXWSfSYqmqJsd6eF`) | Binding | Component 07, every code work package |
| BDS-DOC-001 | Documentation Protocol v2.0 (`gdrive-file:1tUigvB-A76iIGojmSs-k5KXTbAMeTTY9`) | Binding | `doc/system/` changes in each repository |
| BDS-RR-001 | Repository Review Protocol v1.0 | Binding | The review this plan builds on (PR #52) |
| BDS-HFPC-001 | Human-First Progressive Complexity Protocol v0.1 | Binding | Component 09 decision briefs; the Incidents view |
| BDS-UX-001 | UX/UI System Protocol v1.2, with the workspace `Protocols/` set | Binding | WP-07 (the Incidents view) |
| BDS-RB-001 | Repository Bootstrap and Audit Checklist | Binding | WP-02 (`repo.manifest.yaml`) |
| BDS-PG-001 | Prompt Governance Protocol v1.3 | Supporting | Planning and review templates. **Not read for this plan**; no requirement is taken from it. |
| WS-AUTH | `forge` `CLAUDE.md`: authority hierarchy, deployment status, documentation and findings protocols | Binding | Every work package |
| WS-STE | ASD-STE100 for BDS (`forge` `docs/protocols/BDS_ASD_STE100_v1.md`) | Binding | All prose, commit messages and operator-visible strings |
| FCO-10.5 | forge-command `doc/system` chapter 10.5, connection rule | Binding for forge-command | WP-07 |
| FCO-14 | forge-command chapter 14, authority and security | Binding for forge-command | WP-07, WP-08 |
| FCO-16.7 | forge-command chapter 16.7, execution hold | Binding | WP-10 |

## Conflicts recorded against BDS-FEI-001

BDS-FEI-001 v1.0 (2026-02-17) was written for the predecessor. Where it names `Forge_Command`, R-1 reads it as forge-command, and these conflicts remain:

| FEI clause | What it says | Fact today | Disposition |
|---|---|---|---|
| §2, Law 4, §4.5 | Forge_Command is the token authority on port 9100, with `forge_command_get_token` IPC and an HTTP API | forge-command has no HTTP API (chapter 2.1) and issues no token; its key exists and signs nothing (chapter 15.3) | Unresolved conflict. No work package here depends on token issuance. Recorded for the protocol owner. |
| §4.5 | Applications wait for a READY signal from Forge_Command | forge-command emits no READY signal | Not applicable here: Forge Sentinel is not an application that forge-command supervises. |
| §4.6 | Every Tauri desktop application integrates ForgeHUD | forge-command has its own shell and design system | Out of scope for this plan. Recorded, not decided. |
| §2 invariant | No application runs its own instance of a registered service | forge-command starts DataForge Local itself (chapter 10.6) | Out of scope; recorded. |

## Requirement coverage

| Req | Requirement | Source | Design provision | Work package | Acceptance |
|---|---|---|---|---|---|
| RQ-01 | A connection is one `read` command; `live` only for a fresh read; absence state otherwise; never zero; no fallback | FCO-10.5; FEI Law 5 | 05 §F-2 | WP-07 | AC-07.1–AC-07.4 |
| RQ-02 | No secret crosses IPC; errors hold no secret or path | FCO-14.7 | 05 §F-2 | WP-07 | AC-07.5 |
| RQ-03 | Fail closed on a missing, stale, malformed or oversized report | FEI Law 5; QA-001 core principles | 04 §Bounds | WP-06, WP-07 | AC-06.3, AC-07.2 |
| RQ-04 | A proposer never asserts truth; Sentinel output is labelled shadow and "as reported" | WS-AUTH | 04 §Labels | WP-05, WP-07 | AC-05.2, AC-07.3 |
| RQ-05 | A relationship is declared in `repo.manifest.yaml`, so the Atlas draws it | `forge` map compiler; BDS-RB-001 | 05 §F-6 | WP-01, WP-02, WP-03 | AC-01.1, AC-02.1, AC-03.1 |
| RQ-06 | A `doc/system` part changes in the same change as a new route, command, setting or caller | WS-AUTH documentation protocol; BDS-DOC-001 | 08 deliverables | WP-01, WP-06, WP-07 | AC-01.3, AC-06.4, AC-07.6 |
| RQ-07 | Contract truth lives in `src/contracts/`; golden fixtures stay aligned with validators | forgesentinel `doc/system/02` | 04 | WP-05 | AC-05.1, AC-05.3 |
| RQ-08 | Tests follow the QA tiers; Mode A suffices for T1 to T3 | BDS-QA-001 §2, §5 | 07 | WP-05 to WP-07 | 07 tier table |
| RQ-09 | No execution while the hold is in force | FCO-16.7 | 05 §F-5 | WP-10 | AC-10.0 |
| RQ-10 | Findings go in the owning repository's `docs/KNOWN_ISSUES.md` in the same session | WS-AUTH findings protocol | 08 deliverables | All | Review of each PR |
| RQ-11 | A plan is registered in the BDS plan registry | WS-AUTH; `forge` `scripts/check-plan-registry.py` | 09 handoff | WP-00 | AC-00.2 |

Deferred requirements: FEI §4.5 and §4.6 (see conflicts). Their effect: no work package claims FEI conformance for token, READY or HUD behaviour.
