# 06 — Decision semantics

This document is section 06. It says how a decision on this plan is made and what each answer does.

## How a decision works

- The operator answers each decision with **accept**, **accept with change**, **decline** or **defer**.
- **Accept** records the ruling in component 09 and in forgesentinel's `06_OWNER_RULINGS_AND_IMPLEMENTATION_GATES.md` style record for this plan. It authorizes only the work packages that component 09 names for it.
- **Accept with change** records the changed text. The work package briefs are amended in the same change.
- **Decline** closes the dependent work packages as `declined`. The plan records why.
- **Defer** leaves the dependent work packages blocked. Independent work continues.
- A recommendation is not a ruling (R-8). Silence is not acceptance.

## Decisions

| Id | Question | Blocks | Recommendation (component 09 gives the brief) |
|---|---|---|---|
| D-1 | Who owns an incident's lifecycle? | WP-08 | The operator decides in forge-command; the durable record lives in DataForge Cloud |
| D-2 | Who signs a control directive, with which key? | WP-09 | The operator's own decision signature in forge-command (R-7) |
| D-3 | Where do the predecessor's cloud-security signatures (I-3) go? | WP-09; predecessor retirement | No recommendation; rule before the predecessor retires |
| D-4 | Which channel carries incidents to forge-command? | WP-05 to WP-07 | The published report of component 04, stale after 24 hours |
| D-5 | Is a Sentinel observation mission governed execution? | WP-10 | Yes |
| D-6 | Where does the Sentinel runtime run? | Any deployment | Decide after WP-07; not needed before it |
| D-7 | Does forgesentinel adopt RepoManifest.v1, making its agent files generated? | WP-02 | Yes |
| D-8 | Does the `forge` authority table get a Forge Sentinel row, and with which text? | WP-03 (row only) | Yes: "security findings, incident briefings, recommendations" — may not assert truth, write lifecycle transitions or issue controls |
