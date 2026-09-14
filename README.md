# Forge Sentinel

A governed security-intelligence fabric for the Forge ecosystem. Sentinel
builds behavioral baselines, correlates evidence across time and services,
explains its reasoning, and requests the smallest bounded response through
the correct authority — without ever becoming an authority itself.

```text
Observe → Normalize → Remember → Correlate → Predict
→ Explain → Recommend → Governed Enforcement → Learn
```

The full plan set lives in
[`docs/plans/Forge_Sentinel_Integrated_Plan_Set_2026-06-11/`](docs/plans/Forge_Sentinel_Integrated_Plan_Set_2026-06-11/00_README.md).
This repository implements its first production MVP slice (Waves 0–3 plus the
policy/capability/receipt spine) as a TypeScript modular monolith.
Implementation status by wave/epic: [`docs/sentinel/implementation-status.md`](docs/sentinel/implementation-status.md).

## What is implemented

| Area | Module | Plan reference |
|---|---|---|
| Canonical contracts: event envelope, evidence, finding, incident, policy decision, capability claims, receipt, feedback label, trust vector, model fingerprint | `src/contracts/` | Wave 0, SNT-000 |
| CSSA coordination contracts: `CloudSecurityFinding.v1` adapter, `CloudSecurityControlDirective.v1`, control lineage | `src/contracts/cssa.ts` | Gates A–D, doc 07 |
| Event Gateway: producer auth, signature checks, schema/major-version rejection, tenant/environment boundary, idempotency, explicit rejections | `src/spine/gateway.ts` | Wave 1, SNT-010 |
| Evidence ledger: append-only with corrections, local/cloud field policy, tenant isolation with recorded denials, WAL persistence, replay | `src/spine/ledger.ts` | Wave 1, SNT-020 |
| Features and baselines: versioned definitions, median/MAD robust statistics, bounded-influence EMA, scope fallback, poisoning protections | `src/intel/features.ts`, `src/intel/baselines.ts` | SNT-030 |
| Sentinel-Cost (shadow): extreme spike, sustained growth, retry storm, cache collapse, billing divergence, quota bypass | `src/intel/cost.ts` | Wave 2, SNT-100 |
| Sentinel-Cloud (shadow): key/region/device novelty, login-failure bursts | `src/intel/cloud.ts` | Wave 3, SNT-110 |
| Sentinel-Agent (shadow): fingerprint-scoped patch-burst/boundary/denial/loop findings | `src/intel/agent.ts` | Wave 5, SNT-120 |
| Sentinel-Provider (shadow): fingerprint registry, alias-change findings, trust reset without inheritance | `src/intel/provider.ts` | Wave 6, SNT-130 |
| Sentinel-License (shadow): Ed25519 entitlement verification (fail closed), shared-entitlement/trial-cycling/churn/Stripe-divergence findings | `src/intel/license.ts`, `src/authority/entitlement.ts` | Wave 7, SNT-140 |
| Sentinel-Data (shadow): egress anomaly, cross-tenant attempts, redaction failures, compound exfiltration | `src/intel/data.ts` | Wave 8, SNT-150 |
| Governed feedback: reviewed labels, explicit training eligibility, per-family calibration with control-effect separation | `src/learning/feedback.ts` | Wave 10, SNT-400/405 |
| Sentinel Prime: deterministic compound correlation (account compromise + agent drift), evidence-independence accounting, feedback-loop exclusion, conflict preservation, duplicate merge, lifecycle | `src/intel/prime.ts` | SNT-200 (deterministic MVP) |
| Policy service: versioned `sentinel_account_compromise@3.1.0` and `sentinel_agent_drift@1.0.0`, always-deny enforcement, cooldown, approval levels | `src/authority/policy.ts` | SNT-210 |
| Capability tokens + executor validation + receipts + rollback (Identity and YellowJacket authorities) | `src/authority/capability.ts`, `executor.ts`, `yellowjacket.ts`, `receipts.ts` | SNT-220 |
| CSSA control issuer/registry: signed scoped expiring directives, raw-incident rejection, replay defense, rollback receipts | `src/authority/cssa-control.ts` | Gate D |
| Replay CLI and shadow pipeline | `src/cli.ts`, `src/runtime.ts` | Wave 1 replay CLI |

Everything detection-side runs in **shadow mode** (ADR-011): nodes hold no
authority credentials, and the pipeline terminates at policy decisions and
receipts unless an operator-approved capability is presented to an authority
adapter.

## Quick start

```bash
npm install
npm test                # build + 182 tests against plan exit gates
npm run fixtures        # regenerate deterministic fixtures

# Replay the end-to-end scenario from the plan (new key + new region +
# usage spike + failed logins -> compound incident -> REQUEST_OPERATOR):
node dist/src/cli.js replay fixtures/replay/compound_account_compromise.jsonl

# A usage spike alone must stay advisory:
node dist/src/cli.js replay fixtures/replay/usage_spike_only.jsonl

# Agent drift: patch burst + denials + boundary violation -> stop run +
# quarantine the exact agent version (re-enable path receipted):
node dist/src/cli.js replay fixtures/replay/agent_drift.jsonl

# Validate documents against contracts:
node dist/src/cli.js validate event fixtures/golden/event.usage_tokens_recorded.json
node dist/src/cli.js validate directive fixtures/golden/directive.cloud_route_hold.json
```

## Layout

```text
src/
  contracts/   Wave 0 contract package (validation, versioning, families)
  spine/       Wave 1 evidence spine (producers, gateway, ledger, replay)
  intel/       features, baselines, all six nodes (Cost, Cloud, Agent,
               Provider, License, Data) and Sentinel Prime
  authority/   policy decision point, capabilities, executors (Identity,
               YellowJacket), receipts, CSSA controls, entitlement verifier
  learning/    governed feedback and calibration (SNT-400/405)
  runtime.ts   modular-monolith wiring (shadow pipeline)
  cli.ts       validate / replay CLI
fixtures/
  golden/      cross-language golden contract fixtures + manifest
  replay/      deterministic end-to-end scenario fixtures (JSONL)
test/          exit-gate tests (contracts, gateway, ledger, baselines,
               prime, policy, capability, CSSA, end-to-end replay)
docs/
  plans/       the integrated plan set (source of truth)
  sentinel/    implementation status and new ADRs (024–026)
```

## Doctrine enforced in code

- **Evidence before inference** — findings without evidence references fail
  contract validation; incidents are reconstructable from the ledger.
- **Intelligence and authority stay separate** — nodes/Prime cannot execute;
  `GLOBAL_ALWAYS_DENY` blocks license revocation, customer-data deletion,
  direct code patches, and billing mutation at the policy layer.
- **Unknown major versions fail safely**; additive minor versions pass.
- **Restricted content cannot be marked cloud-eligible**; cloud projections
  carry metadata and hashes, never excluded content.
- **A raw incident is not authority** — the CSSA registry accepts only
  signed, scoped, expiring, allowlisted control directives (single use,
  rollback required).
- **Policy-generated effects carry lineage** and are excluded from
  independent-evidence counts, so enforcement cannot confirm its own
  hypothesis.
- **Novelty alone never escalates**; a usage spike alone caps confidence and
  yields `RECOMMEND_ONLY`.
- **Invalid entitlement signatures fail closed** (Ed25519); stale cached
  entitlements preserve safe local operation but never paid cloud privilege.
- **No record trains anything automatically** — training eligibility and
  privacy approval are explicit per reviewed label, and calibration excludes
  control-effect-only labels from outcome rates.
