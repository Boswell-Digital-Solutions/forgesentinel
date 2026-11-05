# 01 — Binding rulings and non-goals

This document is section 01. It lists the rulings that bind this plan and what the plan does not do.

## Binding rulings already in force

| Id | Ruling | Source |
|---|---|---|
| R-1 | `forge-command` is the Forge Command of concern for every repository that touches it. `Forge_Command` is the predecessor and is reference only. | Operator, 2026-11-04 |
| R-2 | Truth flows one way. A system may propose anything and assert only what it owns. Bypassing an authority is a system fault: fail fast, log it as a security event, do not degrade silently. | `forge` `CLAUDE.md`, authority hierarchy |
| R-3 | Nothing is in production until the operator says so. Write "deployed", never "production". No backwards-compatibility code. | `forge` `CLAUDE.md`, deployment status |
| R-4 | Governed execution stays off until the operator lifts it. The lift needs two enrolled security-key credentials (predecessor R-5). | forge-command chapter 16.7, operator 2026-11-04 |
| R-5 | Each forge-command connection is its own slice: one `read` command, `live` only for a fresh read, an absence state otherwise, never a zero, no fallback. | forge-command chapter 10.5 |
| R-6 | To absorb a surface is to show it in forge-command. It does not move the absorbed system's authority. | forge-command chapter 15.4 |
| R-7 | An operator's signature on their own decision belongs in Forge Command, with their own key. It does not include SMITH verdicts, SMITH keys or the SMITH trust anchor. | Operator, 2026-10-24 |
| R-8 | An authorized slice may amend a contract only within its recorded scope. That authorization does not cover downstream implementation, activation or deployment. | Operator, 2026-10-24 |
| R-9 | The envelope-authentication track keeps its own boundaries. S1 to S6 stay unauthorized until their own rulings. | forgesentinel `06`, owner rulings 2026-11-04 |

## Non-goals

- No live deployment of Forge Sentinel, and no network ingress into it.
- No change to the envelope-authentication track, its formats or its slices.
- No token issuance. forge-command's signing key exists (P3 gate G2), and this plan does not use it.
- No change to the predecessor `Forge_Command`.
- No change to a deployed service's configuration, secrets or environment.
- No Sentinel-originated control reaches CSSA. No mission is dispatched (R-4).
- No incident lifecycle store is built before decision D-1.
