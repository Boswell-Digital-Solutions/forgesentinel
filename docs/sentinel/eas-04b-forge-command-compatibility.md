# EAS-04B Forge_Command Compatibility Matrix

This document records an adapter-local compatibility lock. It does not publish a shared contract or transfer authority to Forge Sentinel.

| Forge_Command field/owner | Sentinel adapter field | Rule |
| --- | --- | --- |
| accepted intent ID | `intentId` | required; never inferred |
| run ID | `runId` | required; return must match |
| authorization ID/issuer | `authorizationId` / `issuerId` | required; Sentinel never mints either |
| Registry target identity | `target.registryId` | must be `admitted`; local path is not identity |
| target revision | `commitSha` + `treeSha` | exact 40-character lowercase SHA binding |
| operation/mode/scope | procedure + exact three lanes | major 1 only; no widening |
| token lifetime | `issuedAt`, `notBefore`, `expiresAt` | malformed, early, or expired fails closed |
| evidence freshness | `freshnessDeadline` | equality is stale; cannot outlive authority |
| resource bounds | `caps` | values may be lower, never above CP4 ceilings |
| analyzer/verifier separation | `identities` | distinct actor and state-token identities |
| stop authority | `stop` | must be active at admission; later runtime checks are CP4C+ |
| authoritative receipt | Forge_Command-owned | Sentinel return is a hash-bound evidence attachment only |

Unknown fields and unknown major versions fail closed. `COMPLETED` means admitted-scope processing, never repository health. This slice has no collector, runtime entry point, network surface, persistence, scheduler, or target mutation.
