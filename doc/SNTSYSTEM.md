        # Forge Sentinel - Compiled System Reference

        **Designation:** SNT
        **Document role:** Canonical compiled technical reference for the Forge Sentinel security-intelligence fabric
        **Source:** `doc/system/`
        **Build command:** `bash doc/system/BUILD.sh`
        **Document version:** 2.1 (2026-09-20) - flat-layout compliance migration
        **Protocol:** BDS Documentation Protocol v2.0; BDS Repo Documentation System Canonical Compliance Standard

        > **Generated artifact warning:** `doc/SNTSYSTEM.md` is assembled output. Edit
        > the source modules under `doc/system/` and rebuild. Hand edits to the
        > compiled artifact are overwritten by the next build.

        Assembly contract:

        - Command: `bash doc/system/BUILD.sh`
        - Validation: `bash doc/system/validate_snapshots.sh` runs during assembly
        - Primary output: `doc/SNTSYSTEM.md`

        This `doc/system/` tree is the canonical source of truth for Forge Sentinel. It uses
        explicit **truth classes**: canonical facts define repo role, authority
        boundaries, contract behavior, runtime behavior, and verification doctrine;
        snapshot facts are dated, audit-derived counts and current implementation
        inventory that may drift between audits.

        | Part | File | Contents |
        | --- | --- | --- |
        | §1 | `01-overview.md` | 01 Overview |
| §2 | `02-contract-surface.md` | 02 Contract Surface |
| §3 | `03-runtime-boundary.md` | 03 Runtime Boundary |
| §4 | `04-dependencies.md` | 04 Dependencies |
| §5 | `05-governance.md` | 05 Governance |
| §6 | `06-verification.md` | 06 Verification |
| §7 | `90-appendices.md` | 90 Appendices |

        ## Quick Assembly

        ```bash
        bash doc/system/BUILD.sh
        ```

---

            # Overview

            **Document version:** 2.0 (2026-06-22) - canonical compliance migration

            Forge Sentinel is a governed security-intelligence fabric for the Forge ecosystem.

It observes, normalizes, remembers, correlates, predicts, explains, recommends, requests governed enforcement, and learns without becoming an authority itself.

---

            # Contract Surface

            **Document version:** 2.0 (2026-06-22) - canonical compliance migration

            Sentinel contract truth lives under `src/contracts/` and covers event envelopes, evidence, findings, incidents, policy decisions, capability claims, receipts, feedback labels, trust vectors, and CSSA coordination.

Golden fixtures under `fixtures/golden/` are cross-language contract evidence and must stay aligned with validators.

---

            # Runtime Boundary

            **Document version:** 2.0 (2026-06-22) - canonical compliance migration

            The implemented MVP is a TypeScript modular monolith with a shadow-mode intelligence pipeline.

Nodes hold no authority credentials. The pipeline terminates at policy decisions and receipts unless an operator-approved capability is presented to an authority adapter.

## CSSA Watchdog Worker

`src/watchdog/` adds one supervised worker, `sentinel watch-cssa`. It polls all three of DataForge's `cloud-security` record families: decisions, authorizations, and outcomes. It runs four deterministic detectors: denial streak, quota-exceeded burst, approval-pending burst, and execution-failure burst. Outcomes carry no principal or tenant of their own. `AuthorizationIndex` resolves a subject by joining on `authorization_id`. The index is durable and pruned. An outcome with no matching authorization stays unattributed; the worker never guesses a subject. The worker converts each finding through the Forge-Agents §4 `CloudSecurityFinding` contract and feeds it to `SentinelRuntime.ingestSourceFindings`. The worker has no inbound surface. It makes outbound calls only. It requires a live `DATAFORGE_BASE_URL` and `DATAFORGE_CSSA_TOKEN`; no credential is built in. Prime's `promoteSingles()` now promotes all four finding types to a lone-signal incident.

---

            # Dependencies

            **Document version:** 2.0 (2026-06-22) - canonical compliance migration

            Sentinel dependency truth is owned by `package.json`, `package-lock.json`, `tsconfig.json`, and executable test output.

The runtime modules are organized under `src/contracts/`, `src/spine/`, `src/intel/`, `src/authority/`, `src/runtime.ts`, and `src/cli.ts`.

---

            # Governance

            **Document version:** 2.0 (2026-06-22) - canonical compliance migration

            Sentinel separates intelligence from authority. Findings require evidence references, unknown major versions fail safely, restricted content cannot be marked cloud-eligible, and raw incidents are not authority.

CSSA directives must be signed, scoped, expiring, allowlisted, single-use, and rollback-capable.

---

            # Verification

            **Document version:** 2.0 (2026-06-22) - canonical compliance migration

            The README names these operator commands:

```bash
npm install
npm test
npm run fixtures
node dist/src/cli.js replay fixtures/replay/compound_account_compromise.jsonl
node dist/src/cli.js validate event fixtures/golden/event.usage_tokens_recorded.json
```

Update generated docs after changing contracts, fixtures, or shadow-pipeline behavior.

## Which CI runs for which change

A change to documentation runs the Documentation CI and no code CI.
A change to any other file runs the code CI.
A change to both runs both.
No workflow runs on a schedule.

The code workflow `.github/workflows/ci.yml` (job `test`) uses a workflow-level `paths` filter on `push` and on `pull_request`:

```yaml
paths:
  - '**'
  - '!docs/**'
  - '!doc/**'
  - '!**/*.md'
```

The last matching pattern wins.
A change to `.github/workflows/**` is code, so it runs the code CI.
The workflow keeps its `workflow_dispatch` trigger, which qualifies an exact commit and is not affected by the filter.

This repository needs no re-include.
No test, tool or source file reads a Markdown file or a file under `doc/` or `docs/` of this repository.
The tests read JSON fixtures under `fixtures/`.
The bounded local collector and its tests name `doc/system/` and `docs/sentinel/` as safe path prefixes, but the tests run them on a temporary sandbox directory and not on this repository.
If a test or script starts to read a documentation path, add that path as a re-include.

The Documentation CI is `.github/workflows/documentation.yml`.
It runs on a change under `docs/`, under `doc/`, to any `*.md` file, or to its own workflow file.
It runs `bash doc/system/BUILD.sh` and then `git diff --exit-code -- doc`.
`doc/SNTSYSTEM.md` is committed, so the diff step fails when the assembled reference does not match its parts.

This repository is the security layer of the ecosystem.
The code CI is security evidence, and this rule does not weaken it: every change to a non-documentation file runs the full build and the full test run.
This repository has no secret scan workflow today (see `docs/KNOWN_ISSUES.md`).
If a secret scan is added, it must run on every change and must not use a path filter.

Warning: do not add a required status check on a path-filtered workflow.
The check stays pending forever when the filter skips the workflow, and the merge stays blocked.

---

            # Appendices

            **Document version:** 2.0 (2026-06-22) - canonical compliance migration

            The full plan set lives under `docs/plans/Forge_Sentinel_Integrated_Plan_Set_2026-06-11/`.

Implementation status and ADRs live under `docs/sentinel/`.
