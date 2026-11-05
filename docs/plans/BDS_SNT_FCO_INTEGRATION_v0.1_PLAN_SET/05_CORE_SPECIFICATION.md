# 05 — Core specification of the integration

This document is section 05. It specifies each flow between the two systems and the order in which they connect.

## Principle

Forge Sentinel proposes. forge-command shows and decides. Each authority keeps its truth (R-2, R-6).

## Flows

### F-1 Evidence in (built)

CSSA → DataForge → `sentinel watch-cssa`. This plan does not change it. It stays shadow-only, with no deployed credential.

### F-2 Incidents out (WP-05, WP-06, WP-07)

1. `sentinel report <replay-file>` runs the shadow pipeline (`runShadow`) on a replay file and writes the incident report of component 04. It never reads the network. It reads the producer secrets the way `sentinel replay` does.
2. forge-command reads the report with one new `read` command, `incidents_list`, granted to the main window only.
3. The read returns one of: `live` with the incidents; `unavailable` (no file); `stale` (older than the threshold); `refused` (malformed, oversized, wrong schema, wrong mode, integrity mismatch, symlink, wrong owner). Each non-`live` state carries a reason for the operator. None returns the fixture or zero incidents in its place (R-5).
4. Systems / Incidents changes from `built: false` to a `queue` view. Each row shows priority, title, where, the source, `status_as_reported`, the required authority and the report's age. The inspector shows the briefing, the evidence ids and the recommended actions. It offers **no action**: deciding is WP-08.

### F-3 Decisions back (WP-08, blocked by D-1)

The operator acknowledges, dismisses with a reason, defers, or labels an incident in the approval window, with the security key. The decision is a receipt in forge-command. How Forge Sentinel receives it, and where the durable lifecycle record lives, follows D-1.

### F-4 Governed control (WP-09, blocked by D-2, D-3, ADR-026 and the envelope-authentication track)

A control directive is issued only by the owner that D-2 names, with an asymmetric key. `ControlDirectiveIssuer` in forgesentinel stays a test double until then (`KI-SENTINEL-20261105-004`).

### F-5 Missions (WP-10, blocked by R-4 and D-5)

The EAS-04B adapter is retargeted to forge-command objects (review §6), and its admission carries verifiable evidence (`KI-SENTINEL-20261105-002`). Nothing is dispatched while the hold is in force.

### F-6 Topology (WP-01 to WP-03)

forge-command declares forgesentinel as an upstream authority. forgesentinel declares DataForge and Forge-Agents (D-7). forge recompiles the canonical map, so the Atlas draws the edges.

### F-7 Stop (deferred)

forge-command's brake is not readable outside its process. This plan does not change that. Sentinel's report path does not act, so it needs no stop. WP-09 and WP-10 must define the stop channel before they act.

## Sequence

```
WP-00 plan ─┬─ WP-01 forge-command declares ──┐
            ├─ WP-02 forgesentinel manifest ──┼─ WP-03 forge map (+ D-8 row)
            │   (D-7)                         │
            ├─ WP-04 retarget docs (D-1,D-2,D-5)
            └─ WP-05 report contract (D-4) ── WP-06 sentinel report ── WP-07 Incidents view
                                                                          │
                       WP-08 decisions back (D-1) ── WP-09 controls (D-2, D-3) ── WP-10 missions (R-4, D-5)
```
