#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { validateEventEnvelope } from "./contracts/envelope.js";
import { validateFinding } from "./contracts/finding.js";
import { validateIncident } from "./contracts/incident.js";
import { validateActionReceipt } from "./contracts/receipt.js";
import { validateControlDirectiveShape } from "./contracts/cssa.js";
import type { ValidationResult } from "./contracts/common.js";
import { loadReplayFile } from "./spine/replay.js";
import { SentinelRuntime } from "./runtime.js";
import { DataForgeCssaClient } from "./spine/dataforge_cssa_client.js";
import { CssaWatchWorker } from "./watchdog/cssa_worker.js";
import { CssaWorkerStateStore } from "./watchdog/worker_state.js";

const VALIDATORS: Record<string, (value: unknown) => ValidationResult> = {
  event: validateEventEnvelope,
  finding: validateFinding,
  incident: validateIncident,
  receipt: validateActionReceipt,
  directive: validateControlDirectiveShape,
};

function usage(): never {
  console.log(`forge-sentinel CLI (shadow-mode MVP)

Usage:
  sentinel validate <contract> <file.json>   Validate a JSON document against a contract.
                                             Contracts: ${Object.keys(VALIDATORS).join(", ")}
  sentinel replay <fixture.jsonl>            Replay an event fixture through the full
                                             shadow pipeline and print the report.
  sentinel watch-cssa [--once]               Poll DataForge's CSSA decisions ledger and run
                                             the denial-streak/quota-burst detectors, shadow
                                             only. Requires DATAFORGE_BASE_URL and
                                             DATAFORGE_CSSA_TOKEN. --once runs a single poll
                                             cycle, prints status, and exits (exit 1 on error)
                                             instead of looping forever.
`);
  process.exit(2);
}

function pct(value: number): string {
  return `${Math.round(value * 100)}%`;
}

const [, , command, ...args] = process.argv;

if (command === "validate") {
  const [contract, file] = args;
  if (!contract || !file) usage();
  const validator = VALIDATORS[contract];
  if (!validator) usage();
  const result = validator(JSON.parse(readFileSync(file, "utf8")));
  if (result.ok) {
    console.log(`OK: valid ${contract}`);
    process.exit(0);
  }
  console.error(`INVALID ${contract}:`);
  for (const issue of result.issues) {
    console.error(`  - [${issue.code}] ${issue.path}: ${issue.message}`);
  }
  process.exit(1);
} else if (command === "replay") {
  const [file] = args;
  if (!file) usage();
  const runtime = new SentinelRuntime("production");
  const report = runtime.runShadow(loadReplayFile(file));

  console.log("=== Forge Sentinel shadow replay ===");
  console.log(`Ingestion: ${report.replay.accepted} accepted, ${report.replay.duplicates} duplicate, ${report.replay.rejected} rejected (of ${report.replay.total})`);
  console.log(`\nFindings (${report.findings.length}):`);
  for (const finding of report.findings) {
    console.log(`  [${finding.node.name}] ${finding.finding_type} on ${finding.subject.type} ${finding.subject.id}`);
    console.log(`    likelihood ${pct(finding.risk.likelihood)} · impact ${pct(finding.risk.impact)} · confidence ${pct(finding.risk.confidence)} · evidence quality ${pct(finding.risk.evidence_quality)}`);
    console.log(`    ${finding.explanation.summary}`);
  }
  console.log(`\nIncidents (${report.incidents.length}):`);
  for (const incident of report.incidents) {
    console.log(`  ${incident.priority.toUpperCase()} ${incident.incident_id} ${incident.title}`);
    console.log(`    type ${incident.incident_type} · status ${incident.status} · independent signals ${incident.independent_signal_count}`);
    console.log(`    issue: ${incident.briefing.issue}`);
    console.log(`    where: ${incident.briefing.where}`);
    console.log(`    recommended fix: ${incident.briefing.recommended_fix}`);
    console.log(`    authority: ${incident.required_authority.join(" + ")}`);
    for (const action of incident.recommended_actions) {
      console.log(`    action: ${action.action_type} target=${action.target_id} scope=${action.scope} reversible=${action.reversible} approval=${action.approval}`);
    }
    if (incident.conflicts.length > 0) console.log(`    conflicts: ${incident.conflicts.join("; ")}`);
    if (incident.missing_telemetry.length > 0) console.log(`    missing telemetry: ${incident.missing_telemetry.join("; ")}`);
  }
  console.log(`\nPolicy decisions (${report.decisions.length}):`);
  for (const decision of report.decisions) {
    console.log(`  ${decision.policy_decision_id} ${decision.policy_id}@${decision.policy_version} -> ${decision.result}`);
    for (const action of decision.allowed_actions) {
      console.log(`    allow ${action.action_type} (scope ${action.scope}, approval ${action.requires_approval}, reversible ${action.reversible})`);
    }
    for (const deniedAction of decision.denied_actions) {
      console.log(`    deny ${deniedAction.action_type}: ${deniedAction.reason}`);
    }
  }
  console.log("\nSHADOW MODE: no actions were executed; findings and decisions are advisory evidence only.");
} else if (command === "watch-cssa") {
  const baseUrl = process.env["DATAFORGE_BASE_URL"];
  const bearerToken = process.env["DATAFORGE_CSSA_TOKEN"];
  if (!baseUrl || !bearerToken) {
    console.error("watch-cssa requires DATAFORGE_BASE_URL and DATAFORGE_CSSA_TOKEN environment variables (no credential is baked in).");
    process.exit(2);
  }
  const statePath = process.env["CSSA_WORKER_STATE_PATH"] ?? ".forgesentinel/cssa-worker-state.json";
  const worker = new CssaWatchWorker({
    client: new DataForgeCssaClient({ baseUrl, bearerToken }),
    runtime: new SentinelRuntime("production"),
    stateStore: new CssaWorkerStateStore(statePath),
  });
  if (args.includes("--once")) {
    await worker.pollOnce();
    const status = worker.currentStatus();
    console.log(JSON.stringify(status, null, 2));
    process.exit(status.lastError ? 1 : 0);
  } else {
    await worker.run();
  }
} else {
  usage();
}
