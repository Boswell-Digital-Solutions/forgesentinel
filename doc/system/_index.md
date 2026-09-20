        # Forge Sentinel - Compiled System Reference

        **Designation:** SNT
        **Document role:** Canonical compiled technical reference for the Forge Sentinel security-intelligence fabric
        **Source:** `doc/system/`
        **Build command:** `bash doc/system/BUILD.sh`
        **Document version:** 2.1 (2026-09-20) - flat-layout compliance migration
        **Protocol:** BDS Documentation Protocol v2.0; BDS Repo Documentation System Canonical Compliance Standard

        > **Generated artifact warning:** `doc/SNTSYSTEM.md` is assembled output. Edit
        > the source modules under `doc/system/` and rebuild. Hand edits to the
        > compiled artifact are overwritten by the next build.

        Assembly contract:

        - Command: `bash doc/system/BUILD.sh`
        - Validation: `bash doc/system/validate_snapshots.sh` runs during assembly
        - Primary output: `doc/SNTSYSTEM.md`

        This `doc/system/` tree is the canonical source of truth for Forge Sentinel. It uses
        explicit **truth classes**: canonical facts define repo role, authority
        boundaries, contract behavior, runtime behavior, and verification doctrine;
        snapshot facts are dated, audit-derived counts and current implementation
        inventory that may drift between audits.

        | Part | File | Contents |
        | --- | --- | --- |
        | §1 | `01-overview.md` | 01 Overview |
| §2 | `02-contract-surface.md` | 02 Contract Surface |
| §3 | `03-runtime-boundary.md` | 03 Runtime Boundary |
| §4 | `04-dependencies.md` | 04 Dependencies |
| §5 | `05-governance.md` | 05 Governance |
| §6 | `06-verification.md` | 06 Verification |
| §7 | `90-appendices.md` | 90 Appendices |

        ## Quick Assembly

        ```bash
        bash doc/system/BUILD.sh
        ```
