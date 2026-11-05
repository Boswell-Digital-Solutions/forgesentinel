# BDS-SNT-FCO-v0.1 — Forge Sentinel and forge-command Integration — compiled plan set

This file concatenates components 00 to 09 in order. It is kept by hand: no build script exists, and an edit to a component is mirrored here in the same change (BDS-PSS-001 §3.3).

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

---

# 01 — Binding rulings and non-goals

This document is section 01. It lists the rulings that bind this plan and what the plan does not do.

## Binding rulings already in force

| Id | Ruling | Source |
|---|---|---|
| R-1 | `forge-command` is the Forge Command of concern for every repository that touches it. `Forge_Command` is the predecessor and is reference only. | Operator, 2026-11-04 |
| R-2 | Truth flows one way. A system may propose anything and assert only what it owns. Bypassing an authority is a system fault: fail fast, log it as a security event, do not degrade silently. | `forge` `CLAUDE.md`, authority hierarchy |
| R-3 | Nothing is in production until the operator says so. Write "deployed", never "production". No backwards-compatibility code. | `forge` `CLAUDE.md`, deployment status |
| R-4 | Governed execution stays off until the operator lifts it. The lift needs two enrolled security-key credentials (predecessor R-5). | forge-command chapter 16.7, operator 2026-11-04 |
| R-5 | Each forge-command connection is its own slice: one `read` command, `live` only for a fresh read, an absence state otherwise, never a zero, no fallback. | forge-command chapter 10.5 |
| R-6 | To absorb a surface is to show it in forge-command. It does not move the absorbed system's authority. | forge-command chapter 15.4 |
| R-7 | An operator's signature on their own decision belongs in Forge Command, with their own key. It does not include SMITH verdicts, SMITH keys or the SMITH trust anchor. | Operator, 2026-10-24 |
| R-8 | An authorized slice may amend a contract only within its recorded scope. That authorization does not cover downstream implementation, activation or deployment. | Operator, 2026-10-24 |
| R-9 | The envelope-authentication track keeps its own boundaries. S1 to S6 stay unauthorized until their own rulings. | forgesentinel `06`, owner rulings 2026-11-04 |

## Non-goals

- No live deployment of Forge Sentinel, and no network ingress into it.
- No change to the envelope-authentication track, its formats or its slices.
- No token issuance. forge-command's signing key exists (P3 gate G2), and this plan does not use it.
- No change to the predecessor `Forge_Command`.
- No change to a deployed service's configuration, secrets or environment.
- No Sentinel-originated control reaches CSSA. No mission is dispatched (R-4).
- No incident lifecycle store is built before decision D-1.

---

# 02 — Authority boundary and AUTHORITY_GAP conditions

This document is section 02. It states who owns what across the integration, and which ownership is not yet ruled.

## Ownership

| Subject | Owner | Forge Sentinel | forge-command |
|---|---|---|---|
| Security findings, correlation, incident briefings, recommendations | Forge Sentinel | Owns and proposes | Shows, labelled with source and age |
| CSSA decisions, authorizations and outcomes | CSSA (ForgeAgents), recorded in DataForge | Reads, never rewrites | Does not touch |
| Durable cross-system records | DataForge Cloud | Does not assert | Does not assert (chapter 1.3) |
| The operator's decision on an incident | The operator, in forge-command's approval window | Receives as an input | Records the decision and its receipt |
| Run records, intents, approval receipts, the brake | forge-command | Treats as evidence only | Owns |
| Governance verdicts and SMITH signing | Forge:SMITH | — | — |

## AUTHORITY_GAP conditions

Each gap below blocks the work packages named. A gap is closed only by the operator decision named.

| Gap | What is unruled | Blocks | Closed by |
|---|---|---|---|
| AG-1 | Who owns an incident's lifecycle (open to resolved, dismissed, reopened) | WP-08 | D-1 |
| AG-2 | Who signs a `CloudSecurityControlDirective`, and with which key | WP-09 | D-2 |
| AG-3 | Who signs CSSA policy bundles and entitlement snapshots after the predecessor retires (I-3) | WP-09; the predecessor's retirement | D-3 |
| AG-4 | Whether a Sentinel observation mission is governed execution | WP-10 | D-5 |
| AG-5 | Whether forgesentinel adopts RepoManifest.v1, which makes its agent files generated | WP-02 | D-7 |
| AG-6 | Forge Sentinel's row in the `forge` authority table | WP-03 (row only) | D-8 |

D-4 (the read channel) and D-6 (where the runtime runs) are design decisions, not authority gaps. Component 06 lists all decisions.

## Boundaries that hold for every work package

- Forge Sentinel never writes a lifecycle transition, a run record or a receipt.
- forge-command never rewrites a finding, an evidence record or a CSSA record.
- A forge-command view of Sentinel data is never `live` unless that read came from Sentinel's published output.
- No work package gives forge-command a network listener.

---

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

---

# 04 — Contract and provenance model

This document is section 04. It defines the one new contract the plan proposes: the incident report that Forge Sentinel publishes and forge-command reads. It is a proposal for decision D-4; it is not admitted until WP-05 merges.

## Identity

- Schema: `forgesentinel.incident_report.v1`.
- Owner: forgesentinel, `src/contracts/incident_report.ts`, with a golden fixture in `fixtures/golden/`.
- Consumer: forge-command, `crates/fc-sources/src/sentinel.rs` (WP-07). The consumer pins the schema name and major version. An unknown major fails closed.

## Shape

```json
{
  "schema_version": "forgesentinel.incident_report.v1",
  "generated_at": "2026-11-05T12:00:00.000Z",
  "producer": { "service": "forgesentinel", "version": "0.1.0", "source_commit": "<40 hex>" },
  "mode": "shadow",
  "input": { "kind": "replay", "sha256": "sha256:<64 hex>", "line_count": 0 },
  "coverage": { "gaps": [ { "source": "cssa.outcomes", "reason": "not_configured" } ] },
  "truncated": false,
  "incidents": [
    {
      "incident_id": "inc_…",
      "title": "…",
      "incident_type": "…",
      "status_as_reported": "open",
      "priority": "high",
      "origin": ["sentinel-cost"],
      "subject": { "tenant_id": "…" },
      "risk": { "…": "RiskDimensions" },
      "briefing": { "issue": "…", "where": "…", "recommended_fix": "…", "why_now": "…" },
      "finding_ids": ["…"],
      "evidence_ids": ["…"],
      "independent_signal_count": 2,
      "required_authority": ["forge_command_operator"],
      "recommended_actions": [ { "action_type": "…", "target_id": "…", "scope": "…", "reversible": true, "approval": "single_operator" } ],
      "conflicts": [],
      "missing_telemetry": [],
      "created_at": "…",
      "updated_at": "…"
    }
  ],
  "integrity": { "sha256": "sha256:<64 hex>" }
}
```

Each incident is a projection of `Incident` (`src/contracts/incident.ts`). The projection drops `status_history`, `playbook`, `signals`, `version` and `reopened_from`.

## Labels

- `mode` is the constant `shadow`. A report with any other mode is refused by both sides.
- `status` is renamed `status_as_reported`. It is Forge Sentinel's own view. It is not forge-command's lifecycle, and decision D-1 decides who owns the lifecycle.
- `subject.tenant_id` is metadata as Sentinel holds it. The envelope-authentication rulings (O-1) treat a claimed tenant as untrusted observational metadata, and the view labels it so.
- The report carries no event payload, no secret, no credential and no producer key id.

## Bounds

| Bound | Value | Who enforces it |
|---|---|---|
| File size | 4 MiB | Producer refuses to write more; consumer refuses to read more |
| Incidents | 500 | Producer truncates and sets `truncated: true`; consumer shows "truncated" |
| Text field | 2000 characters at the producer; the consumer cuts to its own display cap (300, as chapter 10.6) | Both |
| Identifier | The existing patterns (`inc_…`) | Producer validator; consumer pattern check |

## Provenance

- `integrity.sha256` is the SHA-256 of the canonical JSON (RFC 8785) of the report with `integrity.sha256` set to `""`. It detects corruption. **It is not authenticity**: a writer with the operator's file access can rewrite the file and the hash. The same limit applies to forge's pin report, which forge-command reads today. A signed report is outside this plan and depends on decision D-2's key work.
- `producer.source_commit` and `input.sha256` let the operator reproduce the report: replay the same input at the same commit and compare.
- forge-command shows the report's age. It flags the report stale after 24 hours (decision D-4 confirms the value).

## Location

- The producer writes `incident_report.v1.json` into the directory named by `SENTINEL_REPORT_DIR`, or by default `$XDG_DATA_HOME/forgesentinel/reports/` (`~/.local/share/forgesentinel/reports/`).
- The write is atomic: a temporary file in the same directory, `fsync`, then `rename`. The file mode is 0600.
- forge-command reads the same default path. `FC_SENTINEL_REPORT` overrides it and must be an absolute path. The reader refuses a symlink, a file that is not regular, and a file owned by another user.

---

# 05 — Core specification of the integration

This document is section 05. It specifies each flow between the two systems and the order in which they connect.

## Principle

Forge Sentinel proposes. forge-command shows and decides. Each authority keeps its truth (R-2, R-6).

## Flows

### F-1 Evidence in (built)

CSSA → DataForge → `sentinel watch-cssa`. This plan does not change it. It stays shadow-only, with no deployed credential.

### F-2 Incidents out (WP-05, WP-06, WP-07)

1. `sentinel report <replay-file>` runs the shadow pipeline (`runShadow`) on a replay file and writes the incident report of component 04. It never reads the network. It reads the producer secrets the way `sentinel replay` does.
2. forge-command reads the report with one new `read` command, `incidents_list`, granted to the main window only.
3. The read returns one of: `live` with the incidents; `unavailable` (no file); `stale` (older than the threshold); `refused` (malformed, oversized, wrong schema, wrong mode, integrity mismatch, symlink, wrong owner). Each non-`live` state carries a reason for the operator. None returns the fixture or zero incidents in its place (R-5).
4. Systems / Incidents changes from `built: false` to a `queue` view. Each row shows priority, title, where, the source, `status_as_reported`, the required authority and the report's age. The inspector shows the briefing, the evidence ids and the recommended actions. It offers **no action**: deciding is WP-08.

### F-3 Decisions back (WP-08, blocked by D-1)

The operator acknowledges, dismisses with a reason, defers, or labels an incident in the approval window, with the security key. The decision is a receipt in forge-command. How Forge Sentinel receives it, and where the durable lifecycle record lives, follows D-1.

### F-4 Governed control (WP-09, blocked by D-2, D-3, ADR-026 and the envelope-authentication track)

A control directive is issued only by the owner that D-2 names, with an asymmetric key. `ControlDirectiveIssuer` in forgesentinel stays a test double until then (`KI-SENTINEL-20261105-004`).

### F-5 Missions (WP-10, blocked by R-4 and D-5)

The EAS-04B adapter is retargeted to forge-command objects (review §6), and its admission carries verifiable evidence (`KI-SENTINEL-20261105-002`). Nothing is dispatched while the hold is in force.

### F-6 Topology (WP-01 to WP-03)

forge-command declares forgesentinel as an upstream authority. forgesentinel declares DataForge and Forge-Agents (D-7). forge recompiles the canonical map, so the Atlas draws the edges.

### F-7 Stop (deferred)

forge-command's brake is not readable outside its process. This plan does not change that. Sentinel's report path does not act, so it needs no stop. WP-09 and WP-10 must define the stop channel before they act.

## Sequence

```
WP-00 plan ─┬─ WP-01 forge-command declares ──┐
            ├─ WP-02 forgesentinel manifest ──┼─ WP-03 forge map (+ D-8 row)
            │   (D-7)                         │
            ├─ WP-04 retarget docs (D-1,D-2,D-5)
            └─ WP-05 report contract (D-4) ── WP-06 sentinel report ── WP-07 Incidents view
                                                                          │
                       WP-08 decisions back (D-1) ── WP-09 controls (D-2, D-3) ── WP-10 missions (R-4, D-5)
```

---

# 06 — Decision semantics

This document is section 06. It says how a decision on this plan is made and what each answer does.

## How a decision works

- The operator answers each decision with **accept**, **accept with change**, **decline** or **defer**.
- **Accept** records the ruling in component 09 and in forgesentinel's `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` style record for this plan. It authorizes only the work packages that component 09 names for it.
- **Accept with change** records the changed text. The work package briefs are amended in the same change.
- **Decline** closes the dependent work packages as `declined`. The plan records why.
- **Defer** leaves the dependent work packages blocked. Independent work continues.
- A recommendation is not a ruling (R-8). Silence is not acceptance.

## Decisions

| Id | Question | Blocks | Recommendation (component 09 gives the brief) |
|---|---|---|---|
| D-1 | Who owns an incident's lifecycle? | WP-08 | The operator decides in forge-command; the durable record lives in DataForge Cloud |
| D-2 | Who signs a control directive, with which key? | WP-09 | The operator's own decision signature in forge-command (R-7) |
| D-3 | Where do the predecessor's cloud-security signatures (I-3) go? | WP-09; predecessor retirement | No recommendation; rule before the predecessor retires |
| D-4 | Which channel carries incidents to forge-command? | WP-05 to WP-07 | The published report of component 04, stale after 24 hours |
| D-5 | Is a Sentinel observation mission governed execution? | WP-10 | Yes |
| D-6 | Where does the Sentinel runtime run? | Any deployment | Decide after WP-07; not needed before it |
| D-7 | Does forgesentinel adopt RepoManifest.v1, making its agent files generated? | WP-02 | Yes |
| D-8 | Does the `forge` authority table get a Forge Sentinel row, and with which text? | WP-03 (row only) | Yes: "security findings, incident briefings, recommendations" — may not assert truth, write lifecycle transitions or issue controls |

---

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

---

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
| Starting evidence | No `repo.manifest.yaml`; a hand-written `CLAUDE.md`; the forge-held manifest is empty (`KI-FORGE-20261105-001`). |
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

---

# 09 — Operator review packet

This document is section 09. It records the authority already given, the decisions still needed, and the next action.

## Authority already given

**Operator direction, 2026-11-05:** "now go to Drive /Forge and build the plan with the protocols there. We then begin implementation."

This plan reads that direction as authorizing the work that needs no open decision:

| Work | Authorized by the direction | Why |
|---|---|---|
| WP-00 plan set and its registry row | Yes | The direction asks for the plan. |
| WP-01 forge-command declares forgesentinel | Yes | No open decision; documentation and a manifest entry only. |
| WP-03 map recompile, without the authority-table row | Yes, once WP-01 merges | No open decision. It still pauses on a shared checkout that is not at its default branch. |
| WP-02, WP-04 to WP-10 | No | Each depends on a decision below, or on the execution hold. |
| Merges | No | Each merge needs the operator's word, as for every PR. |

If the operator meant more or less, the operator corrects this table, and this plan changes to match.

## State

| Result | State |
|---|---|
| Planning | Complete when the plan PR merges. |
| Execution authorization | WP-00, WP-01, WP-03 (above). |
| Implementation | Not started at plan preparation. |
| Verification | None yet. Component 07 defines it. |

## Decisions

Each brief gives the question, the recommendation and its reasons, the alternatives, what follows, and the costs and uncertainty.

### D-1 — Who owns an incident's lifecycle?

- **Question.** When you acknowledge, dismiss or resolve an incident, which system keeps the record that it happened?
- **Recommendation.** You decide in forge-command's approval window, with your key. The durable record lives in DataForge Cloud. Forge Sentinel reads it.
- **Why.** forge-command says it is not canonical memory. DataForge is where durable records live. Sentinel may propose, not assert.
- **Alternatives.** (a) forge-command keeps it locally: simplest, but makes a desktop app the store of security truth, and it is lost with the machine. (b) Sentinel keeps it: the proposer becomes the owner of its own outcome, which breaks R-2.
- **What follows.** WP-08 is written. It needs a DataForge namespace (a DataForge change, its own slice) and forge-command signing.
- **Cost and uncertainty.** It adds a DataForge dependency to WP-08. Deferring blocks only WP-08.

### D-2 — Who signs a control directive?

- **Question.** When you approve a control (for example "hold this executor"), whose key signs the order that CSSA obeys?
- **Recommendation.** Your own decision signature, in forge-command, with an asymmetric key.
- **Why.** The directive is your decision on one incident, which the 2026-10-24 exception places in Forge Command. Today the signer is a test class in Sentinel with a shared HMAC key, so the verifier could also sign.
- **Alternatives.** (a) A separate policy-signer key: more moving parts and a new authority. (b) Forge:SMITH: SMITH signs governance verdicts, not incident responses.
- **What follows.** WP-09 can be written after the envelope-authentication track and ADR-026's Ed25519 change.
- **Cost and uncertainty.** It needs forge-command's first `sign`-class command, which is new authority surface. Deferring blocks WP-09 only.

### D-3 — Where do the predecessor's cloud-security signatures go?

- **Question.** The old Forge_Command signs CSSA policy bundles and entitlement snapshots, and ForgeAgents trusts them. When the old one retires, who signs them?
- **Recommendation.** None from this plan. It must be ruled before the predecessor retires.
- **Options.** forge-command; ForgeCustomer, which owns entitlements; a CSSA-owned signer.
- **What follows.** A plan for the chosen owner. Until then, the predecessor cannot retire without breaking ForgeAgents' trust.
- **Cost and uncertainty.** A wrong owner here would be hard to reverse, because every verifier pins a key.

### D-4 — How do incidents reach forge-command?

- **Question.** Should Sentinel publish a report file that forge-command reads, as forge-command already reads forge's pin report?
- **Recommendation.** Yes, with the contract of component 04, flagged stale after 24 hours.
- **Why.** No server, no port, no credential, and a pattern forge-command already uses.
- **Alternatives.** (a) A loopback HTTP service: needs a running Sentinel service and a credential. (b) Through DataForge: needs a DataForge namespace first.
- **What follows.** WP-05, WP-06, then WP-07 (its own slice authorization).
- **Cost and uncertainty.** A file shows only what the last `sentinel report` run saw; the age label makes that visible. The integrity hash is not authenticity (component 04).

### D-5 — Is a Sentinel mission "governed execution"?

- **Question.** If forge-command sends Sentinel to inspect a repository, does the execution hold forbid it?
- **Recommendation.** Yes.
- **Why.** forge-command would start the work. The hold forbids anything started for an accepted RunIntent.
- **What follows.** WP-10 stays blocked until the hold is lifted. The read path (WP-05 to WP-07) is not affected.

### D-6 — Where does the Sentinel runtime run?

- **Question.** Local worker, started by forge-command as it starts DataForge Local, or a cloud service?
- **Recommendation.** Defer until WP-07 is done. Nothing before it needs a running service.

### D-7 — Does forgesentinel adopt RepoManifest.v1?

- **Question.** The map draws an edge only from a repository's own `repo.manifest.yaml`. The schema makes `AGENTS.md`, `CLAUDE.md`, `CODEX.md` and `GEMINI.md` generated from the manifest. Adopt it?
- **Recommendation.** Yes.
- **Why.** It is the fleet baseline (BDS-RB-001), forge-command already uses it, and it lets the Atlas show what Sentinel depends on.
- **Cost.** The hand-written `CLAUDE.md` becomes generated; every rule in it must move into the manifest. Reversible by removing the files.

### D-8 — A Forge Sentinel row in the forge authority table?

- **Question.** Add Forge Sentinel to the table in `forge` `CLAUDE.md`?
- **Recommendation.** Yes: "Forge Sentinel — owns security findings, incident briefings and recommendations (shadow) — may not assert truth, write lifecycle transitions or issue controls."
- **Why.** Every agent reads that table. Today it gives no rule for what Sentinel may write.

## Next action

1. Open the plan PR (WP-00) and the registry PR.
2. Start WP-01 in forge-command.
3. After WP-01 merges, run WP-03 if the canonical checkouts are at their default branches.
4. Wait for rulings on D-1 to D-8.
