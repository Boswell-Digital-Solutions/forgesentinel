# 04 — Contract and provenance model

This document is section 04. It defines the one new contract the plan proposes: the incident report that Forge Sentinel publishes and forge-command reads. It is a proposal for decision D-4; it is not admitted until WP-05 merges.

## Identity

- Schema: `forgesentinel.incident_report.v1`.
- Owner: forgesentinel, `src/contracts/incident_report.ts`, with a golden fixture in `fixtures/golden/`.
- Consumer: forge-command, `crates/fc-sources/src/sentinel.rs` (WP-07). The consumer pins the schema name and major version. An unknown major fails closed.

## Shape

```json
{
  "schema_version": "forgesentinel.incident_report.v1",
  "generated_at": "2026-11-05T12:00:00.000Z",
  "producer": { "service": "forgesentinel", "version": "0.1.0", "source_commit": "<40 hex>" },
  "mode": "shadow",
  "input": { "kind": "replay", "sha256": "sha256:<64 hex>", "line_count": 0 },
  "coverage": { "gaps": [ { "source": "cssa.outcomes", "reason": "not_configured" } ] },
  "truncated": false,
  "incidents": [
    {
      "incident_id": "inc_…",
      "title": "…",
      "incident_type": "…",
      "status_as_reported": "open",
      "priority": "high",
      "origin": ["sentinel-cost"],
      "subject": { "tenant_id": "…" },
      "risk": { "…": "RiskDimensions" },
      "briefing": { "issue": "…", "where": "…", "recommended_fix": "…", "why_now": "…" },
      "finding_ids": ["…"],
      "evidence_ids": ["…"],
      "independent_signal_count": 2,
      "required_authority": ["forge_command_operator"],
      "recommended_actions": [ { "action_type": "…", "target_id": "…", "scope": "…", "reversible": true, "approval": "single_operator" } ],
      "conflicts": [],
      "missing_telemetry": [],
      "created_at": "…",
      "updated_at": "…"
    }
  ],
  "integrity": { "sha256": "sha256:<64 hex>" }
}
```

Each incident is a projection of `Incident` (`src/contracts/incident.ts`). The projection drops `status_history`, `playbook`, `signals`, `version` and `reopened_from`.

## Labels

- `mode` is the constant `shadow`. A report with any other mode is refused by both sides.
- `status` is renamed `status_as_reported`. It is Forge Sentinel's own view. It is not forge-command's lifecycle, and decision D-1 decides who owns the lifecycle.
- `subject.tenant_id` is metadata as Sentinel holds it. The envelope-authentication rulings (O-1) treat a claimed tenant as untrusted observational metadata, and the view labels it so.
- The report carries no event payload, no secret, no credential and no producer key id.

## Bounds

| Bound | Value | Who enforces it |
|---|---|---|
| File size | 4 MiB | Producer refuses to write more; consumer refuses to read more |
| Incidents | 500 | Producer truncates and sets `truncated: true`; consumer shows "truncated" |
| Text field | 2000 characters at the producer; the consumer cuts to its own display cap (300, as chapter 10.6) | Both |
| Identifier | The existing patterns (`inc_…`) | Producer validator; consumer pattern check |

## Provenance

- `integrity.sha256` is the SHA-256 of the canonical JSON (RFC 8785) of the report with `integrity.sha256` set to `""`. It detects corruption. **It is not authenticity**: a writer with the operator's file access can rewrite the file and the hash. The same limit applies to forge's pin report, which forge-command reads today. A signed report is outside this plan and depends on decision D-2's key work.
- `producer.source_commit` and `input.sha256` let the operator reproduce the report: replay the same input at the same commit and compare.
- forge-command shows the report's age. It flags the report stale after 24 hours (decision D-4 confirms the value).

## Location

- The producer writes `incident_report.v1.json` into the directory named by `SENTINEL_REPORT_DIR`, or by default `$XDG_DATA_HOME/forgesentinel/reports/` (`~/.local/share/forgesentinel/reports/`).
- The write is atomic: a temporary file in the same directory, `fsync`, then `rename`. The file mode is 0600.
- forge-command reads the same default path. `FC_SENTINEL_REPORT` overrides it and must be an absolute path. The reader refuses a symlink, a file that is not regular, and a file owned by another user.
