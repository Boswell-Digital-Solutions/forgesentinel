# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Forge Sentinel is a governed security-intelligence fabric for the Forge ecosystem. It builds behavioral baselines, correlates evidence across time and services, explains its reasoning, and requests the smallest bounded response through the correct authority — without ever becoming an authority itself. This repository is a TypeScript modular monolith implementing the first production MVP slice (Waves 0-3 plus the policy/capability/receipt spine).

## Common Commands

- `npm install` — install dependencies
- `npm test` — build then run the full test suite (`tsc` build + `node --test dist/test/`)
- `npm run build` — compile TypeScript (`tsc -p tsconfig.json`)
- `npm run fixtures` — build then regenerate deterministic fixtures (`dist/tools/gen-fixtures.js`)
- `npm run cli` — run the CLI (`dist/src/cli.js`); supports `replay <fixture.jsonl>` and `validate <event|directive> <file.json>`
- `bash doc/system/BUILD.sh` — rebuild the compiled doc artifact `doc/SNTSYSTEM.md` from its source modules under `doc/system/`

## Architecture

- `src/contracts/` — Wave 0 canonical contract package: event envelope, evidence, finding, incident, policy decision, capability claims, receipt, feedback label, trust vector, model fingerprint, plus CSSA coordination contracts (`cssa.ts`)
- `src/spine/` — Wave 1 evidence spine: producer auth, signature checks, schema/version rejection, tenant isolation, idempotency (`gateway.ts`); append-only evidence ledger with corrections and WAL persistence (`ledger.ts`)
- `src/intel/` — features/baselines, Sentinel-Cost (shadow), Sentinel-Cloud (shadow), and Sentinel Prime (deterministic compound correlation)
- `src/authority/` — policy decision point (`policy.ts`), capability tokens/executor/receipts (`capability.ts`, `executor.ts`, `receipts.ts`), CSSA control issuer/registry (`cssa-control.ts`)
- `src/watchdog/` — the CSSA watchdog: deterministic detectors over all three of DataForge's `cloud-security` record families (`decisions.ts`, `authorizations.ts`, `outcomes.ts`); `outcomes` carry no principal/tenant of their own, so `authorization_index.ts` resolves a subject by joining on `authorization_id`, durable and pruned; durable per-family cursor/detector-state persistence (`worker_state.ts`); the supervised no-inbound poller (`cssa_worker.ts`, run via `sentinel watch-cssa`)
- `src/runtime.ts` — modular-monolith wiring for the shadow pipeline (`runShadow` for fixture replay, `ingestSourceFindings` for a live source like the CSSA watchdog); `src/cli.ts` — replay/validate/watch-cssa CLI
- `fixtures/golden/` — cross-language golden contract fixtures + manifest; `fixtures/replay/` — deterministic end-to-end scenario fixtures (JSONL)
- `test/` — exit-gate tests covering contracts, gateway, ledger, baselines, prime, policy, capability, CSSA, and end-to-end replay
- `docs/plans/` — the integrated plan set (source of truth for design intent); `docs/sentinel/implementation-status.md` — implementation status by wave/epic
- `doc/system/` — canonical source-of-truth doc modules (BDS Documentation Protocol v2.0); `doc/SNTSYSTEM.md` is a generated artifact — edit the sources and rebuild, never hand-edit the compiled file

## Notes

- Everything detection-side runs in **shadow mode** (ADR-011): nodes hold no authority credentials; the pipeline terminates at policy decisions and receipts unless an operator-approved capability is presented to an authority adapter.
- Key doctrine enforced in code: evidence-before-inference (findings without evidence references fail validation), intelligence/authority separation (`GLOBAL_ALWAYS_DENY` blocks license revocation, customer-data deletion, direct code patches, billing mutation), unknown major contract versions fail safely, restricted content can never be marked cloud-eligible, a raw incident is never authority (CSSA registry requires signed/scoped/expiring/allowlisted directives with rollback), and novelty alone never escalates a decision.
