/**
 * Deterministic fixture generator. Regenerate with:
 *   npm run build && node dist/tools/gen-fixtures.js
 * Fixtures are committed; replay over them must stay deterministic.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildEvent } from "../src/spine/build.js";
import { standardProducers } from "../src/runtime.js";
import type { ReplayLine } from "../src/spine/replay.js";
import { validateEventEnvelope } from "../src/contracts/envelope.js";
import { validateFinding } from "../src/contracts/finding.js";
import { validateIncident } from "../src/contracts/incident.js";
import { validateActionReceipt } from "../src/contracts/receipt.js";
import { validateControlDirectiveShape } from "../src/contracts/cssa.js";
import { hashPayload } from "../src/contracts/common.js";

const ROOT = new URL("../..", import.meta.url).pathname;
const REPLAY_DIR = join(ROOT, "fixtures", "replay");
const GOLDEN_DIR = join(ROOT, "fixtures", "golden");

const producers = Object.fromEntries(standardProducers("production").map((producer) => [producer.service, producer]));
const TENANT = { tenant_id: "ten_demo", account_id: "acct_2041" };
const NEW_KEY_FP = "sha256:0a1b2c3d4e5f60718293a4b5c6d7e8f9aabbccddeeff00112233445566aa7fa2";

function usageEvent(id: string, occurredAt: string, tokens: number): ReplayLine {
  const producer = producers["usage-metering"]!;
  return buildEvent(producer, {
    event_id: id,
    event_type: "usage.tokens.recorded",
    occurred_at: occurredAt,
    tenant: TENANT,
    actor: { actor_type: "service", actor_id: "neuroforge-gateway" },
    subject: { subject_type: "account", subject_id: TENANT.account_id },
    correlation: { trace_id: `trc_${id}` },
    payload: { total_tokens: tokens, route_class: "general_cloud" },
  });
}

function history(prefix: string): ReplayLine[] {
  const lines: ReplayLine[] = [];
  // 30 days of normal usage, 2026-05-10 .. 2026-06-08, ~100k tokens/day.
  for (let day = 0; day < 30; day++) {
    const date = new Date(Date.parse("2026-05-10T12:00:00.000Z") + day * 24 * 3600 * 1000).toISOString();
    lines.push(usageEvent(`evt_${prefix}_usage_hist_${String(day).padStart(2, "0")}`, date, 100000 + (day % 7) * 1000 - 3000));
  }
  const identity = producers["identity-service"]!;
  lines.push(
    buildEvent(identity, {
      event_id: `evt_${prefix}_key_old`,
      event_type: "identity.api_key.created",
      occurred_at: "2026-05-15T09:00:00.000Z",
      tenant: TENANT,
      actor: { actor_type: "user", actor_id: "usr_owner", api_key_fingerprint: "sha256:knownkey000000000000000000000000000000000000000000000000000000aa" },
      subject: { subject_type: "api_key", subject_id: "key_old" },
      correlation: { trace_id: `trc_${prefix}_key_old` },
      payload: { api_key_fingerprint: "sha256:knownkey000000000000000000000000000000000000000000000000000000aa" },
    }),
    buildEvent(identity, {
      event_id: `evt_${prefix}_session_hist`,
      event_type: "identity.session.created",
      occurred_at: "2026-06-01T08:00:00.000Z",
      tenant: TENANT,
      actor: { actor_type: "user", actor_id: "usr_owner" },
      subject: { subject_type: "session", subject_id: "ses_hist_01" },
      correlation: { trace_id: `trc_${prefix}_ses_hist` },
      location: { execution_lane: "cloud", region: "us-east", country: "US" },
      payload: { region: "us-east", device_fingerprint: "dev_known_macbook" },
    }),
  );
  return lines;
}

function compromiseScenario(): ReplayLine[] {
  const lines = history("cmp");
  const identity = producers["identity-service"]!;
  // 2026-06-09 16:39-16:41 — failed login burst (7 attempts).
  for (let attempt = 0; attempt < 7; attempt++) {
    const at = new Date(Date.parse("2026-06-09T16:39:00.000Z") + attempt * 20 * 1000).toISOString();
    lines.push(
      buildEvent(identity, {
        event_id: `evt_cmp_loginfail_${attempt}`,
        event_type: "identity.login.failed",
        occurred_at: at,
        tenant: TENANT,
        actor: { actor_type: "user", actor_id: "usr_owner" },
        subject: { subject_type: "account", subject_id: TENANT.account_id },
        correlation: { trace_id: `trc_cmp_login_${attempt}` },
        location: { execution_lane: "cloud", region: "eu-central", country: "DE" },
        payload: { reason: "invalid_password", source_ip_hash: "sha256:iphash" },
      }),
    );
  }
  // 16:42 — new API key created.
  lines.push(
    buildEvent(identity, {
      event_id: "evt_cmp_key_new",
      event_type: "identity.api_key.created",
      occurred_at: "2026-06-09T16:42:00.000Z",
      tenant: TENANT,
      actor: { actor_type: "user", actor_id: "usr_owner", api_key_fingerprint: NEW_KEY_FP },
      subject: { subject_type: "api_key", subject_id: "key_new" },
      correlation: { trace_id: "trc_cmp_key_new" },
      location: { execution_lane: "cloud", region: "eu-central", country: "DE" },
      payload: { api_key_fingerprint: NEW_KEY_FP },
    }),
  );
  // 16:43 — session from new region and new device.
  lines.push(
    buildEvent(identity, {
      event_id: "evt_cmp_session_new",
      event_type: "identity.session.created",
      occurred_at: "2026-06-09T16:43:00.000Z",
      tenant: TENANT,
      actor: { actor_type: "user", actor_id: "usr_owner" },
      subject: { subject_type: "session", subject_id: "ses_new_01" },
      correlation: { trace_id: "trc_cmp_ses_new" },
      location: { execution_lane: "cloud", region: "eu-central", country: "DE" },
      payload: { region: "eu-central", device_fingerprint: "dev_new_browser_77" },
    }),
  );
  // 16:45-17:00 — usage acceleration: 15M tokens in the last 24h window.
  lines.push(
    usageEvent("evt_cmp_usage_spike_1", "2026-06-09T16:45:00.000Z", 5000000),
    usageEvent("evt_cmp_usage_spike_2", "2026-06-09T16:52:00.000Z", 5000000),
    usageEvent("evt_cmp_usage_spike_3", "2026-06-09T17:00:00.000Z", 5000000),
  );
  return lines;
}

function spikeOnlyScenario(): ReplayLine[] {
  return [
    ...history("spk"),
    usageEvent("evt_spk_usage_spike_1", "2026-06-09T16:45:00.000Z", 5000000),
    usageEvent("evt_spk_usage_spike_2", "2026-06-09T16:52:00.000Z", 5000000),
    usageEvent("evt_spk_usage_spike_3", "2026-06-09T17:00:00.000Z", 5000000),
  ];
}

const AGENT_FP = "agt_forge-smithy@1.4.2+prompt_3aa1";
const AGENT_RUN = "run_smith_771";

function agentEvent(id: string, eventType: string, occurredAt: string, payload: Record<string, unknown>): ReplayLine {
  return buildEvent(producers["forgeagents"]!, {
    event_id: id,
    event_type: eventType,
    occurred_at: occurredAt,
    tenant: TENANT,
    actor: { actor_type: "agent", actor_id: "forge-smithy" },
    subject: { subject_type: "agent_version", subject_id: AGENT_FP },
    correlation: { trace_id: `trc_${id}`, run_id: AGENT_RUN },
    payload: { agent_fingerprint: AGENT_FP, ...payload },
  });
}

/** 12 core scenario: agent patch burst + denials + boundary violation. */
function agentDriftScenario(): ReplayLine[] {
  const lines: ReplayLine[] = [agentEvent("evt_agt_run_start", "agent.run.started", "2026-06-09T14:00:00.000Z", { task: "refactor_billing_adapter" })];
  for (let patch = 0; patch < 16; patch++) {
    const at = new Date(Date.parse("2026-06-09T14:05:00.000Z") + patch * 60 * 1000).toISOString();
    lines.push(agentEvent(`evt_agt_patch_${String(patch).padStart(2, "0")}`, "agent.patch.applied", at, { files_changed: 3, patch_size_lines: 120 }));
  }
  for (let denial = 0; denial < 6; denial++) {
    const at = new Date(Date.parse("2026-06-09T14:21:00.000Z") + denial * 60 * 1000).toISOString();
    lines.push(agentEvent(`evt_agt_denial_${denial}`, "agent.permission.denied", at, { requested_permission: "fs.write:/etc" }));
  }
  lines.push(agentEvent("evt_agt_boundary", "agent.boundary.violated", "2026-06-09T14:27:30.000Z", { boundary: "repository:authorforge (allowed: forge-smithy)" }));
  return lines;
}

mkdirSync(REPLAY_DIR, { recursive: true });
mkdirSync(GOLDEN_DIR, { recursive: true });

writeFileSync(join(REPLAY_DIR, "compound_account_compromise.jsonl"), compromiseScenario().map((line) => JSON.stringify(line)).join("\n") + "\n");
writeFileSync(join(REPLAY_DIR, "usage_spike_only.jsonl"), spikeOnlyScenario().map((line) => JSON.stringify(line)).join("\n") + "\n");
writeFileSync(join(REPLAY_DIR, "agent_drift.jsonl"), agentDriftScenario().map((line) => JSON.stringify(line)).join("\n") + "\n");

// --- Golden contract fixtures -------------------------------------------

const validEvent = usageEvent("evt_golden_usage", "2026-06-09T12:00:00.000Z", 12345).event;
const invalidMajorEvent = { ...validEvent, schema_version: "2.0.0" };
const restrictedCloudEvent = {
  ...validEvent,
  payload: { raw_prompt: "private manuscript text" },
  data_policy: { content_included: true, sensitivity: "restricted", retention_class: "security_365d", cloud_allowed: true },
  integrity: { ...validEvent.integrity, payload_hash: hashPayload({ raw_prompt: "private manuscript text" }) },
};

const goldenFinding = {
  finding_id: "fnd_golden_001",
  finding_type: "cost.usage_change_extreme",
  node: { name: "sentinel-cost", version: "1.0.0" },
  subject: { type: "account", id: "acct_2041" },
  tenant_id: "ten_demo",
  window: { start: "2026-06-08T17:00:00.000Z", end: "2026-06-09T17:00:00.000Z" },
  risk: { likelihood: 0.74, impact: 0.82, confidence: 0.69, evidence_quality: 0.95 },
  baseline: { baseline_id: "cost.account_daily_usage@1.1.0", expected: 100000, observed: 15000000, change_ratio: 150.0 },
  evidence_ids: ["evd_000001"],
  source_event_roots: ["feature:cost.tokens_per_day@2.0.0:tenant_id=ten_demo|account_id=acct_2041|route_class=general_cloud"],
  explanation: {
    summary: "Daily token usage increased 150x above the account baseline.",
    top_factors: [
      { factor: "usage_change_ratio", contribution: 0.62 },
      { factor: "new_api_key", contribution: 0.21 },
    ],
    uncertainties: ["The account may be running an approved bulk workload."],
  },
  recommendation: { action_class: "REQUEST_OPERATOR", playbook: "PB-COST-COMPROMISE-01" },
  expires_at: "2026-06-10T17:00:00.000Z",
  correlation_hints: { account_id: "acct_2041", route_class: "general_cloud" },
  policy_generated_effect: false,
};

const goldenIncident = {
  incident_id: "inc_0443",
  title: "Possible account compromise with rapid usage growth",
  incident_type: "compound.account_compromise",
  status: "open",
  priority: "high",
  origin: ["sentinel-cost", "sentinel-cloud"],
  subject: { tenant_id: "ten_demo", account_id: "acct_2041" },
  risk: { likelihood: 0.82, impact: 0.88, confidence: 0.81, evidence_quality: 0.94 },
  briefing: {
    issue: "Token usage increased 150x with a new API key, new region/device, and repeated login failures.",
    where: "NeuroForge cloud route / account acct_2041",
    recommended_fix: "Pause only the new key, require MFA, and review the last 24 hours.",
    why_now: "Independent weak signals now form a correlated compromise pattern.",
  },
  finding_ids: ["fnd_golden_001"],
  evidence_ids: ["evd_000001"],
  independent_signal_count: 4,
  signals: ["cost.usage_change_extreme", "cloud.new_api_key", "cloud.new_region", "cloud.login_failure_burst"],
  required_authority: ["identity_service", "forge_command_operator"],
  recommended_actions: [
    { action_type: "identity.api_key.pause", target_id: NEW_KEY_FP, scope: "single_key", reversible: true, approval: "single_operator" },
    { action_type: "identity.mfa.require", target_id: "acct_2041", scope: "account", reversible: true, approval: "policy_allowed" },
  ],
  playbook: "PB-ACCOUNT-COMPROMISE-01",
  conflicts: [],
  missing_telemetry: [],
  version: 1,
  created_at: "2026-06-09T17:04:00.000Z",
  updated_at: "2026-06-09T17:04:00.000Z",
  status_history: [{ status: "open", at: "2026-06-09T17:04:00.000Z" }],
};

const goldenReceiptBody = {
  receipt_id: "rcpt_00001",
  receipt_type: "sentinel.action",
  incident_id: "inc_0443",
  decision: {
    decision_id: "pdec_0001",
    policy_id: "sentinel_account_compromise",
    policy_version: "3.1.0",
    result: "ALLOW_BOUNDED_ACTION",
    approver: { type: "operator", id: "op_17" },
  },
  action: { requested: "identity.api_key.pause", executed: "identity.api_key.pause", target_id: NEW_KEY_FP, scope: "single_key", result: "success" },
  before_state: { key_state: "active" },
  after_state: { key_state: "paused" },
  rollback: { supported: true, action_type: "identity.api_key.resume" },
  control_lineage: { policy_decision_id: "pdec_0001" },
  created_at: "2026-06-09T17:10:00.000Z",
};
const goldenReceipt = { ...goldenReceiptBody, integrity: { hash: hashPayload(goldenReceiptBody) } };

const goldenDirective = {
  schema_version: "cloud_security.control_directive.v1",
  control_id: "ctl_golden_001",
  incident_id: "inc_0443",
  policy_decision_id: "pdec_0001",
  issuer: "forge-command-policy",
  issued_at: "2026-06-09T17:10:00.000Z",
  expires_at: "2026-06-09T17:25:00.000Z",
  action: "cssa.cloud_route.hold",
  target: { tenant_id: "ten_demo", principal_id: "usr_owner", executor_id: "agt_01", cloud_service: "neuroforge", provider: "provider_a" },
  scope: "single_executor_single_route",
  max_uses: 1,
  approval: { level: "single_operator", approval_id: "apr_op17_001" },
  rollback: { required: true, action: "cssa.cloud_route.release" },
  reason_codes: ["SENTINEL_COMPOUND_COMPROMISE"],
  integrity: { algorithm: "hmac-sha256", key_id: "key_fc_policy_01", signature: "0".repeat(64) },
};
const invalidDirective = { ...goldenDirective, control_id: "ctl_golden_002", emergency_override: true };

interface GoldenEntry {
  file: string;
  contract: "event" | "finding" | "incident" | "receipt" | "directive";
  expect_valid: boolean;
  body: unknown;
}

const golden: GoldenEntry[] = [
  { file: "event.usage_tokens_recorded.json", contract: "event", expect_valid: true, body: validEvent },
  { file: "event.invalid_unknown_major_version.json", contract: "event", expect_valid: false, body: invalidMajorEvent },
  { file: "event.invalid_restricted_content_cloud.json", contract: "event", expect_valid: false, body: restrictedCloudEvent },
  { file: "finding.cost_usage_change_extreme.json", contract: "finding", expect_valid: true, body: goldenFinding },
  { file: "incident.compound_account_compromise.json", contract: "incident", expect_valid: true, body: goldenIncident },
  { file: "receipt.api_key_pause.json", contract: "receipt", expect_valid: true, body: goldenReceipt },
  { file: "directive.cloud_route_hold.json", contract: "directive", expect_valid: true, body: goldenDirective },
  { file: "directive.invalid_unknown_field.json", contract: "directive", expect_valid: false, body: invalidDirective },
];

const validators = {
  event: validateEventEnvelope,
  finding: validateFinding,
  incident: validateIncident,
  receipt: validateActionReceipt,
  directive: validateControlDirectiveShape,
} as const;

for (const entry of golden) {
  const result = validators[entry.contract](entry.body);
  if (result.ok !== entry.expect_valid) {
    console.error(`FIXTURE BUG: ${entry.file} expected valid=${entry.expect_valid} but got valid=${result.ok}`);
    for (const issue of result.issues) console.error(`  - [${issue.code}] ${issue.path}: ${issue.message}`);
    process.exit(1);
  }
  writeFileSync(join(GOLDEN_DIR, entry.file), JSON.stringify(entry.body, null, 2) + "\n");
}
writeFileSync(
  join(GOLDEN_DIR, "manifest.json"),
  JSON.stringify(golden.map(({ file, contract, expect_valid }) => ({ file, contract, expect_valid })), null, 2) + "\n",
);

console.log(`wrote ${golden.length} golden fixtures and 3 replay fixtures`);
