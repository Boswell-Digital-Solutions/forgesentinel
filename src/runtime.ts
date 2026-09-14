import type { Environment } from "./contracts/envelope.js";
import type { Finding } from "./contracts/finding.js";
import type { Incident } from "./contracts/incident.js";
import type { PolicyDecision } from "./contracts/policy.js";
import type { EvidenceRecord } from "./contracts/evidence.js";
import { ProducerRegistry, type ProducerRegistration } from "./spine/producers.js";
import { EvidenceLedger } from "./spine/ledger.js";
import { EventGateway } from "./spine/gateway.js";
import { replayInto, type ReplayLine, type ReplaySummary } from "./spine/replay.js";
import { FeatureService } from "./intel/features.js";
import { BaselineService } from "./intel/baselines.js";
import { SentinelCostNode, TOKENS_PER_DAY, RETRIES_PER_HOUR, DAILY_USAGE_BASELINE, CACHE_HITS, CACHE_HIT_RATIO_BASELINE } from "./intel/cost.js";
import { SentinelCloudNode, LOGIN_FAILURES_15M } from "./intel/cloud.js";
import { SentinelAgentNode } from "./intel/agent.js";
import { SentinelProviderNode } from "./intel/provider.js";
import { SentinelLicenseNode } from "./intel/license.js";
import { SentinelDataNode } from "./intel/data.js";
import { SentinelPrime, ACCOUNT_COMPROMISE_COMPOUND, AGENT_DRIFT_COMPOUND, DATA_EXFILTRATION_COMPOUND } from "./intel/prime.js";
import { PolicyService, ACCOUNT_COMPROMISE_POLICY, AGENT_DRIFT_POLICY, DATA_EXFILTRATION_POLICY } from "./authority/policy.js";
import { ReceiptService } from "./authority/receipts.js";

const DAY_MS = 24 * 3600 * 1000;
const HOUR_MS = 3600 * 1000;

export function standardProducers(environment: Environment): ProducerRegistration[] {
  return [
    { service: "identity-service", environment, key_id: "key_identity_01", secret: "test-secret-identity", signature_required: false, allowed_event_prefixes: ["identity."], tenant_scope: "required" },
    { service: "usage-metering", environment, key_id: "key_usage_01", secret: "test-secret-usage", signature_required: false, allowed_event_prefixes: ["usage."], tenant_scope: "required" },
    { service: "neuroforge", environment, key_id: "key_neuroforge_01", secret: "test-secret-neuroforge", signature_required: false, allowed_event_prefixes: ["neuroforge."], tenant_scope: "required" },
    { service: "billing-service", environment, key_id: "key_billing_01", secret: "test-secret-billing", signature_required: true, allowed_event_prefixes: ["billing.", "license."], tenant_scope: "required" },
    { service: "cssa", environment, key_id: "key_cssa_01", secret: "test-secret-cssa", signature_required: true, allowed_event_prefixes: ["cssa."], tenant_scope: "required" },
    { service: "forgeagents", environment, key_id: "key_agents_01", secret: "test-secret-agents", signature_required: false, allowed_event_prefixes: ["agent.", "data."], tenant_scope: "required" },
  ];
}

export interface ShadowReport {
  replay: ReplaySummary;
  findings: Finding[];
  evidence: EvidenceRecord[];
  incidents: Incident[];
  decisions: PolicyDecision[];
  shadow: true;
}

/**
 * Modular-monolith wiring for the MVP slice (ADR-024). Nodes run in shadow:
 * the pipeline ends at policy decisions; nothing here holds authority
 * credentials or executes actions.
 */
export class SentinelRuntime {
  readonly registry = new ProducerRegistry();
  readonly ledger: EvidenceLedger;
  readonly gateway: EventGateway;
  readonly features = new FeatureService();
  readonly baselines = new BaselineService();
  readonly costNode: SentinelCostNode;
  readonly cloudNode: SentinelCloudNode;
  readonly agentNode: SentinelAgentNode;
  readonly providerNode: SentinelProviderNode;
  readonly licenseNode: SentinelLicenseNode;
  readonly dataNode: SentinelDataNode;
  readonly prime: SentinelPrime;
  readonly policy = new PolicyService();
  readonly receipts: ReceiptService;

  constructor(readonly environment: Environment = "production", walPath?: string) {
    this.ledger = new EvidenceLedger(walPath);
    this.gateway = new EventGateway(this.registry, this.ledger);
    this.receipts = new ReceiptService(this.ledger);
    for (const producer of standardProducers(environment)) this.registry.register(producer);

    this.features.register({
      feature_id: "cost.tokens_per_day",
      version: "2.0.0",
      source_events: ["usage.tokens.recorded"],
      scope: ["tenant_id", "account_id", "route_class"],
      window: { type: "rolling", duration_ms: DAY_MS, lateness_allowance_ms: 15 * 60 * 1000 },
      aggregation: { operation: "sum", field: "payload.total_tokens" },
      privacy: { stores_content: false, cloud_allowed: true, retention_class: "security_365d" },
    });
    this.features.register({
      feature_id: "cost.retries_per_hour",
      version: "1.0.0",
      source_events: ["usage.retry.recorded"],
      scope: ["tenant_id", "account_id"],
      window: { type: "rolling", duration_ms: HOUR_MS, lateness_allowance_ms: 5 * 60 * 1000 },
      aggregation: { operation: "count" },
      privacy: { stores_content: false, cloud_allowed: true, retention_class: "security_365d" },
    });
    this.features.register({
      feature_id: "cloud.login_failures_15m",
      version: "1.0.0",
      source_events: ["identity.login.failed"],
      scope: ["tenant_id", "account_id"],
      window: { type: "rolling", duration_ms: 15 * 60 * 1000, lateness_allowance_ms: 60 * 1000 },
      aggregation: { operation: "count" },
      privacy: { stores_content: false, cloud_allowed: true, retention_class: "security_365d" },
    });
    // Sentinel-Cost (Wave 2): cache ratio, billing reconciliation, quota breach.
    this.features.register({
      feature_id: "cost.cache_hits",
      version: "1.0.0",
      source_events: ["usage.tokens.recorded"],
      scope: ["tenant_id", "account_id", "route_class"],
      window: { type: "rolling", duration_ms: DAY_MS, lateness_allowance_ms: 15 * 60 * 1000 },
      aggregation: { operation: "sum", field: "payload.cache_hits" },
      privacy: { stores_content: false, cloud_allowed: true, retention_class: "security_365d" },
    });
    this.features.register({
      feature_id: "cost.cache_misses",
      version: "1.0.0",
      source_events: ["usage.tokens.recorded"],
      scope: ["tenant_id", "account_id", "route_class"],
      window: { type: "rolling", duration_ms: DAY_MS, lateness_allowance_ms: 15 * 60 * 1000 },
      aggregation: { operation: "sum", field: "payload.cache_misses" },
      privacy: { stores_content: false, cloud_allowed: true, retention_class: "security_365d" },
    });
    this.features.register({
      feature_id: "cost.estimated_cents",
      version: "1.0.0",
      source_events: ["usage.cost.estimated"],
      scope: ["tenant_id", "account_id"],
      window: { type: "rolling", duration_ms: DAY_MS, lateness_allowance_ms: 15 * 60 * 1000 },
      aggregation: { operation: "sum", field: "payload.cost_cents" },
      privacy: { stores_content: false, cloud_allowed: true, retention_class: "security_365d" },
    });
    this.features.register({
      feature_id: "cost.finalized_cents",
      version: "1.0.0",
      source_events: ["usage.cost.finalized"],
      scope: ["tenant_id", "account_id"],
      window: { type: "rolling", duration_ms: DAY_MS, lateness_allowance_ms: 15 * 60 * 1000 },
      aggregation: { operation: "sum", field: "payload.cost_cents" },
      privacy: { stores_content: false, cloud_allowed: true, retention_class: "security_365d" },
    });
    this.features.register({
      feature_id: "cost.quota_exceeded_per_day",
      version: "1.0.0",
      source_events: ["usage.quota.exceeded"],
      scope: ["tenant_id", "account_id"],
      window: { type: "rolling", duration_ms: DAY_MS, lateness_allowance_ms: 15 * 60 * 1000 },
      aggregation: { operation: "count" },
      privacy: { stores_content: false, cloud_allowed: true, retention_class: "security_365d" },
    });
    // Sentinel-Agent (Wave 5): patch and denial bursts per agent identity.
    this.features.register({
      feature_id: "agent.patches_per_hour",
      version: "1.0.0",
      source_events: ["agent.patch.applied"],
      scope: ["tenant_id", "actor_id"],
      window: { type: "rolling", duration_ms: HOUR_MS, lateness_allowance_ms: 5 * 60 * 1000 },
      aggregation: { operation: "count" },
      privacy: { stores_content: false, cloud_allowed: true, retention_class: "security_365d" },
    });
    this.features.register({
      feature_id: "agent.denials_per_15m",
      version: "1.0.0",
      source_events: ["agent.permission.denied"],
      scope: ["tenant_id", "actor_id"],
      window: { type: "rolling", duration_ms: 15 * 60 * 1000, lateness_allowance_ms: 60 * 1000 },
      aggregation: { operation: "count" },
      privacy: { stores_content: false, cloud_allowed: true, retention_class: "security_365d" },
    });
    // Sentinel-License (Wave 7): device-activation rate per account.
    this.features.register({
      feature_id: "license.device_activations_per_day",
      version: "1.0.0",
      source_events: ["license.device.activated"],
      scope: ["tenant_id", "account_id"],
      window: { type: "rolling", duration_ms: DAY_MS, lateness_allowance_ms: 15 * 60 * 1000 },
      aggregation: { operation: "count" },
      privacy: { stores_content: false, cloud_allowed: true, retention_class: "security_365d" },
    });
    // Sentinel-Data (Wave 8): export rate per account (egress anomaly).
    this.features.register({
      feature_id: "data.exports_per_hour",
      version: "1.0.0",
      source_events: ["data.object.exported"],
      scope: ["tenant_id", "account_id"],
      window: { type: "rolling", duration_ms: HOUR_MS, lateness_allowance_ms: 5 * 60 * 1000 },
      aggregation: { operation: "count" },
      privacy: { stores_content: false, cloud_allowed: true, retention_class: "security_365d" },
    });

    this.baselines.register({
      baseline_id: DAILY_USAGE_BASELINE,
      version: "1.1.0",
      feature: TOKENS_PER_DAY,
      scope_priority: [
        ["tenant_id", "account_id", "route_class"],
        ["tenant_id", "route_class"],
        ["tenant_id"],
      ],
      method: { type: "robust_seasonal", minimum_samples: 21, center: "median", dispersion: "median_absolute_deviation", ema_alpha: 0.15 },
      protections: { exclude_active_incidents: true, max_single_window_influence: 0.05, freeze_on_confirmed_compromise: true },
    });
    this.baselines.register({
      baseline_id: CACHE_HIT_RATIO_BASELINE,
      version: "1.0.0",
      feature: CACHE_HITS,
      scope_priority: [
        ["tenant_id", "account_id", "route_class"],
        ["tenant_id", "route_class"],
        ["tenant_id"],
      ],
      method: { type: "robust_seasonal", minimum_samples: 14, center: "median", dispersion: "median_absolute_deviation", ema_alpha: 0.15 },
      protections: { exclude_active_incidents: true, max_single_window_influence: 0.05, freeze_on_confirmed_compromise: true },
    });

    this.costNode = new SentinelCostNode(this.features, this.baselines);
    this.cloudNode = new SentinelCloudNode(this.features);
    this.agentNode = new SentinelAgentNode(this.features);
    this.providerNode = new SentinelProviderNode();
    this.licenseNode = new SentinelLicenseNode(this.features);
    this.dataNode = new SentinelDataNode(this.features);
    this.prime = new SentinelPrime([ACCOUNT_COMPROMISE_COMPOUND, AGENT_DRIFT_COMPOUND, DATA_EXFILTRATION_COMPOUND]);
    this.policy.register(ACCOUNT_COMPROMISE_POLICY);
    this.policy.register(AGENT_DRIFT_POLICY);
    this.policy.register(DATA_EXFILTRATION_POLICY);
  }

  /**
   * Ingests a replay fixture, runs every node in shadow at the last observed
   * event time, correlates, and evaluates policy. Deterministic for a given
   * fixture.
   */
  runShadow(lines: ReplayLine[], noveltyLearnedBefore?: string): ShadowReport {
    const replay = replayInto(this.gateway, lines);
    const events = this.ledger.events();
    for (const event of events) this.features.observe(event);
    if (events.length === 0) {
      return { replay, findings: [], evidence: [], incidents: [], decisions: [], shadow: true };
    }
    const lastIso = new Date(Math.max(...events.map((event) => Date.parse(event.occurred_at)))).toISOString();
    const learnCutoff = noveltyLearnedBefore ?? new Date(Date.parse(lastIso) - 6 * HOUR_MS).toISOString();

    const findings: Finding[] = [];
    const evidence: EvidenceRecord[] = [];

    const scopes = new Map<string, { tenant_id: string; account_id: string; route_class: string }>();
    for (const key of this.features.scopeKeys(TOKENS_PER_DAY)) {
      const parts = Object.fromEntries(key.split("|").map((entry) => entry.split("=") as [string, string]));
      if (parts["tenant_id"] && parts["account_id"] && parts["route_class"]) {
        scopes.set(key, { tenant_id: parts["tenant_id"], account_id: parts["account_id"], route_class: parts["route_class"] });
      }
    }
    for (const scope of scopes.values()) {
      const output = this.costNode.evaluate(scope, lastIso);
      findings.push(...output.findings);
      evidence.push(...output.evidence);
    }

    // Account-scoped cost detectors (billing divergence, quota bypass) run once
    // per account so multi-route accounts are not double-flagged.
    const accounts = new Map<string, { tenant_id: string; account_id: string }>();
    for (const event of events) {
      const tenantId = event.tenant?.tenant_id;
      const accountId = event.tenant?.account_id;
      if (tenantId && accountId) accounts.set(`${tenantId}|${accountId}`, { tenant_id: tenantId, account_id: accountId });
    }
    for (const account of accounts.values()) {
      const output = this.costNode.evaluateAccount(account, lastIso);
      findings.push(...output.findings);
      evidence.push(...output.evidence);
    }

    const cloudOutput = this.cloudNode.process(events, learnCutoff);
    findings.push(...cloudOutput.findings);
    evidence.push(...cloudOutput.evidence);

    const agentOutput = this.agentNode.process(events, learnCutoff);
    findings.push(...agentOutput.findings);
    evidence.push(...agentOutput.evidence);

    const providerOutput = this.providerNode.process(events);
    findings.push(...providerOutput.findings);
    evidence.push(...providerOutput.evidence);

    const licenseOutput = this.licenseNode.process(events, learnCutoff);
    findings.push(...licenseOutput.findings);
    evidence.push(...licenseOutput.evidence);

    const dataOutput = this.dataNode.process(events, learnCutoff);
    findings.push(...dataOutput.findings);
    evidence.push(...dataOutput.evidence);

    for (const record of evidence) {
      this.ledger.append({ kind: "evidence", gateway_version: "feature-service.1.0.0", validation: "accepted", transformation_version: "1.0.0", ...(record.scope["tenant_id"] !== undefined ? { tenant_id: record.scope["tenant_id"] } : {}), body: record });
    }
    for (const finding of findings) {
      this.ledger.append({ kind: "finding", gateway_version: "node.1.0.0", validation: "accepted", transformation_version: "1.0.0", tenant_id: finding.tenant_id, body: finding });
    }

    this.prime.submitFindings(findings);
    const incidents = this.prime.correlate(lastIso);
    for (const incident of incidents) {
      this.ledger.append({ kind: "incident", gateway_version: "prime.1.0.0", validation: "accepted", transformation_version: "1.0.0", tenant_id: incident.subject.tenant_id, body: incident });
    }

    const decisions = incidents.map((incident) => this.policy.evaluate(incident, { environment: this.environment }, lastIso));
    for (const decision of decisions) {
      this.ledger.append({ kind: "policy_decision", gateway_version: "policy.1.0.0", validation: "accepted", transformation_version: "1.0.0", body: decision });
    }

    return { replay, findings, evidence, incidents, decisions, shadow: true };
  }
}
