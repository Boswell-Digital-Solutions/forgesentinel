# EAS-02A Contract and Authority Boundary

Forge Sentinel's TypeScript interfaces are implementation-local runtime
projections. `forge_contract_core` remains the normative owner of shared BDS
contracts.

The replay-only assurance slice uses:

- a local normalized result for deterministic analysis;
- `source_drift_finding.v1` as the named projection for source drift;
- existing BugCheck and DF-RF families as later adapter targets by finding
  class, subject to their own admission and integration gates.

This slice publishes no shared schema and creates no fifth finding family.
Forge_Command retains mission and operator-decision authority. Analyzer results
do not authorize actions, repairs, notifications, merges, deployments or memory
promotion. The existing Forge Sentinel WAL remains a local replay ledger, not
canonical ecosystem truth.

