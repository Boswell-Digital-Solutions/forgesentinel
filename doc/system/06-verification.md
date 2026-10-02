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
