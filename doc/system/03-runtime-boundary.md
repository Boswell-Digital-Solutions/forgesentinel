            # Runtime Boundary

            **Document version:** 2.0 (2026-06-22) - canonical compliance migration

            The implemented MVP is a TypeScript modular monolith with a shadow-mode intelligence pipeline.

Nodes hold no authority credentials. The pipeline terminates at policy decisions and receipts unless an operator-approved capability is presented to an authority adapter.

## CSSA Watchdog Worker

`src/watchdog/` adds one supervised worker, `sentinel watch-cssa`. It polls all three of DataForge's `cloud-security` record families: decisions, authorizations, and outcomes. It runs four deterministic detectors: denial streak, quota-exceeded burst, approval-pending burst, and execution-failure burst. Outcomes carry no principal or tenant of their own. `AuthorizationIndex` resolves a subject by joining on `authorization_id`. The index is durable and pruned. An outcome with no matching authorization stays unattributed; the worker never guesses a subject. The worker converts each finding through the Forge-Agents §4 `CloudSecurityFinding` contract and feeds it to `SentinelRuntime.ingestSourceFindings`. The worker has no inbound surface. It makes outbound calls only. It requires a live `DATAFORGE_BASE_URL` and `DATAFORGE_CSSA_TOKEN`; no credential is built in. Prime's `promoteSingles()` now promotes all four finding types to a lone-signal incident.
