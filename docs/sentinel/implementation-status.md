# Implementation Status

Tracks delivery against `docs/plans/Forge_Sentinel_Integrated_Plan_Set_2026-06-11/11_IMPLEMENTATION_ROADMAP.md`.

Status values: `done (MVP)` — implemented and exit-gate tested at MVP depth in this
repository; `partial` — meaningful subset implemented; `not started`.

## Waves

| Wave | Scope | Status | Notes |
|---|---|---|---|
| 0 | Architecture lock and contracts | done (MVP) | All contracts in `src/contracts/`; golden fixtures + manifest in `fixtures/golden/`; unknown-major rejection and additive-minor acceptance tested. TypeScript is the single contract source; Rust bindings pending (ADR-025). |
| 1 | Evidence spine | done (MVP) | Gateway (auth, signatures, idempotency, explicit rejections), append-only ledger with WAL + corrections, local/cloud field policy, tenant-isolation denials, replay CLI. Centipede import format not yet implemented. |
| 2 | Sentinel-Cost | done (MVP) | Extreme spike, sustained growth, retry storm, **cache-collapse** (robust hit-ratio baseline), **billing/usage-divergence** (metered estimate vs finalized), and **quota-bypass** (feeds Prime correlation) — all shadow/recommend-only, covered by `test/cost.test.ts` and `test/cost-extras.test.ts`. |
| 3 | Sentinel-Cloud | done (MVP) | Key/region/device novelty + login-failure bursts, **implausible-travel** (region-geo speed check), **session-replay** (session-id seen from ≥2 devices), and **service-identity-misuse** (privileged identity op by a service identity) in shadow; reversible key pause/resume + MFA require via capability-validated identity authority adapter. Covered by `test/cloud.test.ts`. |
| 4 | Forge_Command incident surface | not started | Incident/briefing contracts and CLI shadow report exist as the data layer; UI lives in the Forge_Command repository. |
| 5 | Sentinel-Agent | done (MVP) | **patch-burst** (per-agent rolling count), **boundary-violation** (direct `agent.boundary.violated`), and **denied-action-burst** detectors in shadow; feeds `prime.agent_drift_compound` correlation, gated by `sentinel_agent_drift@1.0.0` policy, executed through the capability-validated `YellowJacketAuthority` adapter (stop-run policy-allowed, exact-version quarantine single-operator, receipted re-enable). Never applies or promotes a patch (`AGENT_FORBIDDEN_ACTIONS`). Fingerprint-scoped release boundaries and loop detection are not yet implemented. Covered by `test/agent.test.ts`. |
| 6 | Sentinel-Provider + NeuroForge | partial | Model fingerprint registry with alias-change detection (`SentinelProviderNode`): a material change emits a finding and resets inherited trust to provisional with task performance zeroed, historical identity retained as reduced; sensitive-category eligibility requires a verified normal-state fingerprint. Covered by `test/provider.test.ts`. Routing integration and challenger shadow evaluation pending. |
| 7 | Sentinel-License | done (MVP) | License/billing event families + signature-required ingestion (invalid signature fails closed at the gateway). Detectors: **entitlement-rejected** (surfaces a failed validation), **device-activation-abuse** (per-account daily rate), and **Stripe/entitlement-divergence** (feature granted while subscription canceled/unpaid/past_due). Recommend-only; cannot permanently revoke (`LICENSE_FORBIDDEN_ACTIONS`). Covered by `test/license.test.ts`. A standalone `EntitlementVerifier` (real Ed25519 signatures — unknown key, tampered payload, and expiry all fail closed) is available for the entitlement service; not yet wired into the license detectors above. |
| 8 | Sentinel-Data | done (MVP) | Cross-tenant denial recording + cloud field policy enforced at the ledger (foundations). Detectors: **egress-anomaly** (per-account hourly export rate), **cross-tenant-access** (surfaces `data.cross_tenant.denied`), and **redaction-failure** (`data.redaction.failed`). Feeds `prime.data_exfiltration_compound` correlation, gated by `sentinel_data_exfiltration@1.0.0` policy (exact-destination reversible block, single-operator). Recommend-only; never deletes evidence or exports unredacted (`DATA_FORBIDDEN_ACTIONS`). Covered by `test/data.test.ts`. Export-destination novelty, bulk-export-by-volume, and retention-failure detectors pending (no dedicated event types yet). |
| 9 | Sentinel Prime | partial | Deterministic compound correlation — account compromise, agent drift, and data exfiltration rules all registered — independence accounting, feedback-loop exclusion, conflict preservation, duplicate merge, lifecycle. ML correlation deliberately deferred (ADR-018). |
| 10 | Governed learning | partial | `FeedbackStore` accepts only contract-valid reviewed labels, gates the training set on explicit eligibility plus privacy approval, and emits per-incident-family calibration reports (precision, predicted-vs-observed gap) that count control-effect-only labels separately. Covered by `test/feedback.test.ts`. Dataset registry and champion/challenger pipeline pending. |
| 11 | Production hardening | not started | |

## CSSA integration gates (2026-06-11 addendum)

| Gate | Status | Notes |
|---|---|---|
| A — Contract alignment | done (MVP) | CSSA event mappings, `CloudSecurityFinding.v1`, `CloudSecurityControlDirective.v1`, lineage fields; legacy `SecurityIncident.v1` rejected outside the adapter; Forge_Command is the sole lifecycle owner. |
| B — Evidence flow | partial | CSSA registered as a signing producer; decision/authorization/outcome copies share one evidence root via `run_id`. Full record-family persistence pending. |
| C — Correlation in shadow | partial | Watchdog findings adapt to source findings; shared-root accounting prevents double counting; Prime promotion explicit. |
| D — Signed return controls | done (MVP) | Issuer, registry, validation (issuer/signature/expiry/scope/replay/rollback/unknown-fields), single-use application with receipts, rollback receipts; raw incidents rejected as non-authoritative; lineage flows into downstream events and is excluded from independence. |
| E — Unified operations | not started | Forge_Command UI scope. |

## Epic checklist (13_EPICS)

- SNT-000 Contract Foundation — **done (MVP)** (Rust bindings pending)
- SNT-010 Event Gateway — **done (MVP)**
- SNT-020 Evidence Ledger — **done (MVP)** (DataForge service integration pending)
- SNT-030 Feature/Baseline Service — **done (MVP)**
- SNT-100 Sentinel-Cost — **done (MVP)**
- SNT-110 Sentinel-Cloud — **done (MVP)**
- SNT-115 CSSA Evidence Adapter — **partial**
- SNT-120 Agent + SNT-140 License + SNT-150 Data — **done (MVP)**; SNT-130 (Provider) — **partial** (fingerprint registry + trust reset; NeuroForge routing integration pending)
- SNT-200 Sentinel Prime — **partial (deterministic MVP)**
- SNT-205 CSSA Finding Normalization — **done (MVP)**
- SNT-210 Policy Service — **done (MVP)**
- SNT-215 Signed Cloud Control Directives — **done (MVP)**
- SNT-220 Action/Receipt Service — **done (MVP)**
- SNT-300/305/310 Forge_Command surfaces — **not started**
- SNT-400 Feedback/Calibration — **partial** (reviewed-label store, training eligibility, per-family calibration; dataset registry + challenger pipeline pending)
- SNT-405 Feedback-Loop Calibration — **done (MVP)** (control lineage excluded from independence and tracked separately in calibration)

## Definition-of-done tracking (00_README)

| Criterion | Status |
|---|---|
| Every finding reconstructable from immutable evidence | tested (`e2e.replay.test.ts`) |
| Every action has authority owner, exact scope, rollback, receipt | tested (`capability.test.ts`, `cssa.test.ts`) |
| Every rule/feature/policy versioned | yes (feature/baseline/policy/correlation versions) |
| Local/cloud boundaries enforced and tested | tested (`ledger.test.ts`) |
| Alias change cannot inherit trust | tested (`provider.test.ts`): provisional successor with zeroed task trust |
| Calibration metrics per incident family | partial (`feedback.test.ts`): precision + calibration gap per family with control-effect separation; recall/detection delay pending |
| Compromised node cannot mutate code/billing/license | enforced via `GLOBAL_ALWAYS_DENY` + no authority credentials in nodes; tested |
| Degraded modes preserve hard controls | partially demonstrated (WAL reload); chaos tests pending |
