            # Runtime Boundary

            **Document version:** 2.0 (2026-06-22) - canonical compliance migration

            The implemented MVP is a TypeScript modular monolith with a shadow-mode intelligence pipeline.

Nodes hold no authority credentials. The pipeline terminates at policy decisions and receipts unless an operator-approved capability is presented to an authority adapter.

## CSSA Decision Watchdog Worker

`src/watchdog/` adds one supervised worker, `sentinel watch-cssa`. It polls DataForge's `cloud-security` decisions ledger. It runs two deterministic detectors: denial streak and quota-exceeded burst. It converts each finding through the Forge-Agents §4 `CloudSecurityFinding` contract and feeds it to `SentinelRuntime.ingestSourceFindings`. The worker has no inbound surface. It makes outbound calls only. It requires a live `DATAFORGE_BASE_URL` and `DATAFORGE_CSSA_TOKEN`; no credential is built in. As of this note, no correlation rule references the new finding types, so findings reach the evidence ledger but do not form an incident.
