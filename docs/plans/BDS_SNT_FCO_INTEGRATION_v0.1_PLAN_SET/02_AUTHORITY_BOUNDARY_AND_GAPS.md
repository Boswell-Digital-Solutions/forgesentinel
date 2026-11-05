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
