# Forge Sentinel and forge-command — Integration Review (2026-11-05)

- **Status:** a review. It records facts, gaps and the decisions that the operator must make. It
  authorizes no implementation, no connection, no key and no deployment.
- **Question:** how does Forge Sentinel become an important part of the Forge ecosystem through
  `forge-command`, the rebuilt control plane?
- **Rule applied:** `forge-command` is the Forge Command of concern for every repository that
  touches it. `Forge_Command` is the predecessor, and this review uses it only to learn what it did.

## 1. Sources read

Each repository was read from its default branch, through `git archive`, so no shared checkout was
switched.

| Repository | Revision | Parts read |
|---|---|---|
| `forgesentinel` | `master` `7749737` | `doc/system/01`–`06`, `90`; `docs/sentinel/` (EAS-02A, EAS-04B to EAS-04E, implementation status, ADR-026); `docs/plans/Forge_Sentinel_Integrated_Plan_Set_2026-06-11/` `02`, `06`, `07`, `09`; `src/integration/`, `src/authority/cssa-control.ts`, `src/authority/capability.ts`, `src/intel/prime.ts`; `docs/KNOWN_ISSUES.md` |
| `forge-command` | `main` `b6db026` | `doc/system/01`, `02`, `07`, `09`, `10`, `11`, `14`, `15`, `16`; `docs/ROADMAP.md`; `docs/plans/BDS_FCO_P3_TOKEN_ISSUER_v0.1/PLAN.md`; `repo.manifest.yaml`; `src/lib/state/workspaces.ts`; `docs/KNOWN_ISSUES.md` |
| `forge` | `main` `b7906c50` | `CLAUDE.md` (authority table); `docs/ecosystem/ecosystem_map.json`; `docs/canonical/ecosystem_repo_map.v2.json`; `docs/canonical/repo_manifests/forgesentinel.ecosystem-repo-manifest.v1.json`; `docs/canonical/plan_registry_v1.json`; `docs/KNOWN_ISSUES.md` |
| `Forge_Command` (predecessor) | `main` | `api/src/routes/cloud_security.rs` (route list only) |

## 2. Verdict

Forge Sentinel is designed to be the security-intelligence input of the control plane. Its own
plans give Forge Command the operator review, the incident lifecycle, approval and rollback
initiation, and the reviewed outcome. **Today the two systems have no integration at all**, and
every integration artifact in this repository targets the predecessor:

- no edge joins them in the canonical ecosystem map, and neither repository declares the other;
- forge-command shows "Systems / Incidents — absorbs forgesentinel" as not built;
- Forge Sentinel has no read surface that forge-command can call;
- the mission adapter (EAS-04B) admits an unsigned document, so it cannot tell a Forge Command
  mission from a forged one;
- the control-directive signer that the design gives to "Forge_Command policy" is code inside this
  repository, with a symmetric key, and the rebuild has no signer and no plan to own one.

The work to integrate is mostly **rulings first, then small slices**. No slice below is large, but
the order matters, because the authority questions decide the shape of every channel.

## 3. The target picture

Forge Sentinel proposes. forge-command shows and decides. The authorities named in the forge
authority table keep their truth.

| Flow | From → to | What crosses | State today |
|---|---|---|---|
| F-1 Evidence in | CSSA → DataForge → Sentinel | CSSA decisions, authorizations, outcomes | Built: `sentinel watch-cssa` polls the three DataForge families. Shadow only, no live credential. |
| F-2 Incidents out | Sentinel → forge-command, Systems / Incidents | Incident briefings, findings, evidence references, recommendations | **Missing.** No read surface; the section is not built. |
| F-3 Decisions back | forge-command approval window → Sentinel | Acknowledge, dismiss with reason, defer, approve a control, a reviewed label | **Missing.** The approval window and FIDO2 presence exist in forge-command. Sentinel's `FeedbackStore` accepts only reviewed labels, and nothing produces them. |
| F-4 Governed control | approved decision → signed `CloudSecurityControlDirective` → CSSA | One allowlisted, scoped, expiring, single-use control | **Missing in forge-command.** The signer is in this repository (finding G-4). |
| F-5 Missions | forge-command RunIntent and run record → Sentinel assurance mission → observation return | A bounded, read-only repository observation | Adapter contract only (EAS-04B to EAS-04E), test harness, predecessor vocabulary. Blocked by the execution hold (forge-command chapter 16.7). |
| F-6 Topology | Sentinel → forge-command Atlas and Living Topology | The node, its declared edges, its health | **Missing.** The node has no edge, and Sentinel has no `/health`. |
| F-7 Stop | forge-command brake → Sentinel | "Stop" for missions and Sentinel-originated controls | **Missing.** The brake latch lives in forge-command's state directory, and no external system reads it. |

## 4. What exists on each side

| Capability | Forge Sentinel | forge-command |
|---|---|---|
| Process and surface | TypeScript library and CLI (`sentinel replay`, `sentinel watch-cssa`). No HTTP server, no network ingress, no deployment. | One Tauri process. No HTTP API. Reads over loopback HTTP (DataForge Local), files (`~/.nfsc/intents/inbox/`, forge's pin report) and `gh`. |
| Operator decision | None. Policy decisions are shadow-mode and advisory. | Approval window, FIDO2 PIN and touch, receipts with presence evidence. |
| Signing | HMAC-SHA256 for producers, capability tokens and control directives (ADR-026: Ed25519 before any non-shadow deployment). | No signing. No command has the `sign` class (chapter 15.3). P3 plans one new Ed25519 token issuer, `fcn_local`. Gate G2 (key generation) is not authorized. |
| Incident contract | `src/contracts/incident.ts`, briefings, lifecycle in plan `09`. | A not-built Incidents section with the `queue` spine. |
| Run identity | The adapter requires `intentId`, `runId`, `authorizationId`, `issuerId`. | SMITH-signed RunIntent.v1, a nonce ledger, one run record per accepted intent, approval receipts. No token is minted (execution hold). |

## 5. Findings

Each finding is recorded in the repository that owns the fix. This section gives the summary.

| Id | Finding | Owner | Record |
|---|---|---|---|
| G-1 | Every Forge Command integration artifact here targets the predecessor: EAS-04B's compatibility matrix, plan `07` §2 and §8, plan `09`, ADR-026's `forge-command-policy`, Wave 4 and SNT-300 to SNT-310, and Prime's `forge_command_operator` authority. | forgesentinel | `KI-SENTINEL-20261105-001` |
| G-2 | The mission admission (`forgesentinel.forge-command-adapter.mission.v1`) is validated for shape only. `issuerId` and `authorizationId` are strings, and no signature or key binds them. Any caller can write an admission that passes. | forgesentinel | `KI-SENTINEL-20261105-002` |
| G-3 | Forge Sentinel has no read surface that the forge-command connection rule (chapter 10.5) can use: no HTTP route, no published file, no `/health`. | forgesentinel | `KI-SENTINEL-20261105-003` |
| G-4 | `ControlDirectiveIssuer` (`src/authority/cssa-control.ts:26-30`) is "owned by Forge_Command policy" but lives here, signs with HMAC, and so gives every verifier the power to issue. Plan `07` §8 specifies Ed25519. forge-command owns no signer, and its P3 plan puts cloud-security signatures (I-3) out of scope with no named owner. | forgesentinel and forge-command | `KI-SENTINEL-20261105-004`, `FCO-SENTINEL-DIRECTIVE-SIGNER-20261105` |
| G-5 | forge-command absorbs forgesentinel as Systems / Incidents (chapter 15.4, `workspaces.ts:62`), but does not list it in its upstream authorities (chapter 10.2, `repo.manifest.yaml` `upstream_authorities`). | forge-command | `FCO-SENTINEL-NOT-DECLARED-20261105` |
| G-6 | Forge Sentinel's plans give Forge Command the incident lifecycle, approval and denial, rollback initiation and completed stubs (plan `07` §2 and §7). forge-command chapter 15.1 does not claim any of them, and the forge authority table gives Forge Command "run records, lifecycle transitions, run finalization", which is about runs. No document rules who owns an incident's lifecycle. | forge-command (ruling) | `FCO-INCIDENT-LIFECYCLE-OWNER-20261105` |
| G-7 | In the canonical map, `forgesentinel` has no edge (0 of 50), and its forge-held manifest declares no relationship, no authority boundary and posture `unknown`, from `c436411` (2026-09-14). The repository has no `repo.manifest.yaml`, so it cannot declare an edge. The forge authority table does not name Forge Sentinel. | forge | `KI-FORGE-20261105-002` |

## 6. The mission adapter against the rebuild

EAS-04B locked the adapter to predecessor objects. This table maps each field to what forge-command
has today.

| Adapter field | forge-command today | Gap |
|---|---|---|
| `intentId` | RunIntent.v1 `intent_id`, verified against the SMITH roster (`fc-intent`) | None for the identifier. |
| `runId` | One run record per accepted intent | A run record is a record, not a run (chapter 16.7). |
| `authorizationId`, `issuerId` | Approval receipt `apr-…`, with presence evidence on an approve | No verifiable credential reaches Sentinel. No token issuer exists (P3 G2). The receipt digest is unkeyed (`FCO-RECEIPT-DIGEST-UNKEYED-20261103`). |
| `nonce`, `issuedAt`, `notBefore`, `expiresAt` | The RunIntent nonce ledger (`issuer_id:nonce`) and the intent's expiry | The adapter's own nonce is not the intent's nonce. |
| `target.registryId`, `registryState: "admitted"` | The Atlas `bds:repo:` id | The rebuild has no registry admission state. |
| `commitSha`, `treeSha` | Repos and Git reads HEAD, read-only | No tree binding. |
| `procedure`, `lanes`, `caps`, `identities` | None | Sentinel-side concepts. They need a contract both sides pin. |
| `stop.channelId`, `state: "active"` | The emergency brake latch | The latch is not readable outside forge-command. |
| Authoritative receipt, Forge Command-owned | Approval receipts | The Sentinel return is evidence only, which matches. |

**Consequence.** The adapter can map onto the rebuild. It must then verify two signatures that
already exist — the SMITH signature on the RunIntent and the FIDO2 presence evidence on the approve
receipt — or a P3 token, when one exists. It cannot run before the execution hold is lifted,
because a dispatched mission is execution.

## 7. Decisions for the operator

These are the rulings that unblock the work. Each one is a decision, not an implementation.

| # | Decision | Options | Recommendation |
|---|---|---|---|
| D-1 | Who owns an incident's lifecycle (open, acknowledged, contained, resolved, dismissed, reopened)? | (a) forge-command, as Sentinel's plan says; (b) DataForge Cloud as durable truth, with forge-command as the decision surface; (c) Sentinel itself, with forge-command only displaying | (b). forge-command is not canonical memory (chapter 1.3). The operator decides in forge-command, and the durable lifecycle record belongs where durable truth lives. |
| D-2 | Who signs a `CloudSecurityControlDirective`, and with which key? | (a) the operator's own decision signature in forge-command (ruling 2026-10-24); (b) a separate policy-signer key; (c) Forge:SMITH | (a) for operator-approved controls. A directive is the operator's decision on one incident, which the 2026-10-24 exception places in Forge Command. It does not make forge-command a governance-verdict signer. |
| D-3 | Where do the predecessor's cloud-security signatures (I-3: policy bundles, entitlement snapshots, which ForgeAgents CSSA verifies) go when the predecessor retires? | (a) forge-command; (b) ForgeCustomer, which owns entitlements; (c) a CSSA-owned signer | Rule it before the predecessor retires. P3 excludes it, so today it has no successor. This review does not recommend an owner. |
| D-4 | Which channel carries F-2 (incidents to forge-command)? | (a) a file that Sentinel publishes and forge-command reads, as forge-command already does with forge's pin report; (b) a loopback HTTP read, as with DataForge Local; (c) through DataForge | (a) first. It needs no server and no credential, and forge-command already reads published reports with an age label. |
| D-5 | Does a Sentinel observation mission count as governed execution under forge-command chapter 16.7? | Yes / no | Yes. forge-command dispatches it, so the hold applies. Integration up to the read path (F-2, F-6) does not need the hold lifted. |
| D-6 | Where does the Sentinel runtime run? | (a) a local worker that forge-command starts, as it starts DataForge Local; (b) a cloud service | Decide after D-4. Sentinel has no deployment today, and the envelope-authentication track (S1 to S6) must finish before any ingress. |

## 8. Proposed sequence

Each step is its own slice with its own operator authorization. The first three need no code.

1. **Declare the relationship.** Add `forgesentinel` to forge-command's `upstream_authorities` with
   what it owns (findings, briefings and recommendations; never truth). Give forgesentinel a
   `repo.manifest.yaml` that declares DataForge and ForgeAgents (CSSA) upstream. Name Forge
   Sentinel in the forge authority table. The Atlas then draws the edges.
2. **Retarget this repository's integration documents** to forge-command (G-1), and record the
   rulings D-1 to D-5.
3. **Specify F-2 as a published, read-only report** (D-4 option (a)): a versioned schema for
   incident briefings, written by `sentinel`, with its time and source, labelled shadow.
4. **Build Systems / Incidents in forge-command** as a read of that report, following chapter 10.5:
   `source: "live"` only for a fresh read, the absence state otherwise, never zero.
5. **Operator decisions back (F-3).** Acknowledge, dismiss with reason and reviewed labels, decided in
   the approval window with the key, with a signed operator decision once forge-command can sign.
6. **Governed controls (F-4).** Only after D-2, the Ed25519 change of ADR-026, and the
   envelope-authentication track.
7. **Missions (F-5).** Only after the execution hold is lifted, with the adapter verifying the
   RunIntent signature and the approve receipt's presence evidence.

## 9. What this review does not do

It changes no code, no contract and no configuration. It does not rule on D-1 to D-6. It does not
change the envelope-authentication track, whose S1 to S6 boundaries are unchanged. It does not
touch the predecessor.
