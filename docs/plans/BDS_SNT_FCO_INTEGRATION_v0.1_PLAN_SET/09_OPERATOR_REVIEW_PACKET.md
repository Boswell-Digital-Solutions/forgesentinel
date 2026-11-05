# 09 — Operator review packet

This document is section 09. It records the authority already given, the decisions still needed, and the next action.

## Authority already given

**Operator direction, 2026-11-05:** "now go to Drive /Forge and build the plan with the protocols there. We then begin implementation."

This plan reads that direction as authorizing the work that needs no open decision:

| Work | Authorized by the direction | Why |
|---|---|---|
| WP-00 plan set and its registry row | Yes | The direction asks for the plan. |
| WP-01 forge-command declares forgesentinel | Yes | No open decision; documentation and a manifest entry only. |
| WP-03 map recompile, without the authority-table row | Yes, once WP-01 merges | No open decision. It still pauses on a shared checkout that is not at its default branch. |
| WP-02, WP-04 to WP-10 | No | Each depends on a decision below, or on the execution hold. |
| Merges | No | Each merge needs the operator's word, as for every PR. |

If the operator meant more or less, the operator corrects this table, and this plan changes to match.

## State

| Result | State |
|---|---|
| Planning | Complete when the plan PR merges. |
| Execution authorization | WP-00, WP-01, WP-03 (above). |
| Implementation | Not started at plan preparation. |
| Verification | None yet. Component 07 defines it. |

## Decisions

Each brief gives the question, the recommendation and its reasons, the alternatives, what follows, and the costs and uncertainty.

### D-1 — Who owns an incident's lifecycle?

- **Question.** When you acknowledge, dismiss or resolve an incident, which system keeps the record that it happened?
- **Recommendation.** You decide in forge-command's approval window, with your key. The durable record lives in DataForge Cloud. Forge Sentinel reads it.
- **Why.** forge-command says it is not canonical memory. DataForge is where durable records live. Sentinel may propose, not assert.
- **Alternatives.** (a) forge-command keeps it locally: simplest, but makes a desktop app the store of security truth, and it is lost with the machine. (b) Sentinel keeps it: the proposer becomes the owner of its own outcome, which breaks R-2.
- **What follows.** WP-08 is written. It needs a DataForge namespace (a DataForge change, its own slice) and forge-command signing.
- **Cost and uncertainty.** It adds a DataForge dependency to WP-08. Deferring blocks only WP-08.

### D-2 — Who signs a control directive?

- **Question.** When you approve a control (for example "hold this executor"), whose key signs the order that CSSA obeys?
- **Recommendation.** Your own decision signature, in forge-command, with an asymmetric key.
- **Why.** The directive is your decision on one incident, which the 2026-10-24 exception places in Forge Command. Today the signer is a test class in Sentinel with a shared HMAC key, so the verifier could also sign.
- **Alternatives.** (a) A separate policy-signer key: more moving parts and a new authority. (b) Forge:SMITH: SMITH signs governance verdicts, not incident responses.
- **What follows.** WP-09 can be written after the envelope-authentication track and ADR-026's Ed25519 change.
- **Cost and uncertainty.** It needs forge-command's first `sign`-class command, which is new authority surface. Deferring blocks WP-09 only.

### D-3 — Where do the predecessor's cloud-security signatures go?

- **Question.** The old Forge_Command signs CSSA policy bundles and entitlement snapshots, and ForgeAgents trusts them. When the old one retires, who signs them?
- **Recommendation.** None from this plan. It must be ruled before the predecessor retires.
- **Options.** forge-command; ForgeCustomer, which owns entitlements; a CSSA-owned signer.
- **What follows.** A plan for the chosen owner. Until then, the predecessor cannot retire without breaking ForgeAgents' trust.
- **Cost and uncertainty.** A wrong owner here would be hard to reverse, because every verifier pins a key.

### D-4 — How do incidents reach forge-command?

- **Question.** Should Sentinel publish a report file that forge-command reads, as forge-command already reads forge's pin report?
- **Recommendation.** Yes, with the contract of component 04, flagged stale after 24 hours.
- **Why.** No server, no port, no credential, and a pattern forge-command already uses.
- **Alternatives.** (a) A loopback HTTP service: needs a running Sentinel service and a credential. (b) Through DataForge: needs a DataForge namespace first.
- **What follows.** WP-05, WP-06, then WP-07 (its own slice authorization).
- **Cost and uncertainty.** A file shows only what the last `sentinel report` run saw; the age label makes that visible. The integrity hash is not authenticity (component 04).

### D-5 — Is a Sentinel mission "governed execution"?

- **Question.** If forge-command sends Sentinel to inspect a repository, does the execution hold forbid it?
- **Recommendation.** Yes.
- **Why.** forge-command would start the work. The hold forbids anything started for an accepted RunIntent.
- **What follows.** WP-10 stays blocked until the hold is lifted. The read path (WP-05 to WP-07) is not affected.

### D-6 — Where does the Sentinel runtime run?

- **Question.** Local worker, started by forge-command as it starts DataForge Local, or a cloud service?
- **Recommendation.** Defer until WP-07 is done. Nothing before it needs a running service.

### D-7 — Does forgesentinel adopt RepoManifest.v1?

- **Question.** The map draws an edge only from a repository's own `repo.manifest.yaml`. The schema makes `AGENTS.md`, `CLAUDE.md`, `CODEX.md` and `GEMINI.md` generated from the manifest. Adopt it?
- **Recommendation.** Yes.
- **Why.** It is the fleet baseline (BDS-RB-001), forge-command already uses it, and it lets the Atlas show what Sentinel depends on.
- **Cost.** The hand-written `CLAUDE.md` becomes generated; every rule in it must move into the manifest. Reversible by removing the files.

### D-8 — A Forge Sentinel row in the forge authority table?

- **Question.** Add Forge Sentinel to the table in `forge` `CLAUDE.md`?
- **Recommendation.** Yes: "Forge Sentinel — owns security findings, incident briefings and recommendations (shadow) — may not assert truth, write lifecycle transitions or issue controls."
- **Why.** Every agent reads that table. Today it gives no rule for what Sentinel may write.

## Next action

1. Open the plan PR (WP-00) and the registry PR.
2. Start WP-01 in forge-command.
3. After WP-01 merges, run WP-03 if the canonical checkouts are at their default branches.
4. Wait for rulings on D-1 to D-8.
