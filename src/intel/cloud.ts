import { clamp01 } from "../contracts/common.js";
import type { EventEnvelope } from "../contracts/envelope.js";
import type { EvidenceRecord } from "../contracts/evidence.js";
import type { Finding } from "../contracts/finding.js";
import { eventEvidence, FeatureService, thresholdBurst } from "./features.js";
import type { NodeOutput } from "./cost.js";

export const LOGIN_FAILURES_15M = "cloud.login_failures_15m@1.0.0";

/**
 * Coarse region centroids for implausible-travel speed checks. Unknown regions
 * are skipped rather than guessed at (04: unknowns stay explicit).
 */
const REGION_GEO: Record<string, { lat: number; lon: number }> = {
  "us-east": { lat: 38.0, lon: -78.5 },
  "us-central": { lat: 41.3, lon: -95.9 },
  "us-west": { lat: 45.6, lon: -121.2 },
  "eu-west": { lat: 53.3, lon: -6.3 },
  "eu-central": { lat: 50.1, lon: 8.7 },
  "ap-south": { lat: 19.1, lon: 72.9 },
  "ap-southeast": { lat: 1.3, lon: 103.8 },
  "ap-northeast": { lat: 35.7, lon: 139.7 },
  "sa-east": { lat: -23.5, lon: -46.6 },
};
/** Above commercial-flight speed: a real person cannot move between regions this fast. */
const MAX_TRAVEL_KMH = 900;
const MIN_TRAVEL_KM = 500;
/** Access events that carry a usable origin region. */
const ACCESS_EVENT_TYPES = new Set(["identity.session.created", "identity.login.succeeded"]);
/** Privileged identity operations a service identity must never perform itself. */
const SERVICE_FORBIDDEN_OPS = new Set(["identity.api_key.created", "identity.privilege.requested"]);

function toRadians(degrees: number): number {
  return (degrees * Math.PI) / 180;
}

function haversineKm(a: { lat: number; lon: number }, b: { lat: number; lon: number }): number {
  const radius = 6371;
  const dLat = toRadians(b.lat - a.lat);
  const dLon = toRadians(b.lon - a.lon);
  const lat1 = toRadians(a.lat);
  const lat2 = toRadians(b.lat);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
  return 2 * radius * Math.asin(Math.min(1, Math.sqrt(h)));
}

/**
 * Sentinel-Cloud (03, SNT-110). Shadow mode. Novelty findings are weak
 * signals: novelty alone never justifies enforcement (05), so their
 * recommendations stay at OBSERVE/RECOMMEND_ONLY and they exist mainly as
 * compound-correlation inputs for Prime.
 */
export class SentinelCloudNode {
  readonly name = "sentinel-cloud";
  readonly version = "1.0.0";
  readonly shadow = true;

  private readonly seenKeys = new Map<string, Set<string>>();
  private readonly seenRegions = new Map<string, Set<string>>();
  private readonly seenDevices = new Map<string, Set<string>>();
  private readonly lastAccess = new Map<string, { region: string; country: string; at_ms: number }>();
  private readonly sessionDevices = new Map<string, Set<string>>();
  private findingCounter = 0;

  constructor(private readonly features: FeatureService) {}

  private nextFindingId(): string {
    this.findingCounter += 1;
    return `fnd_cloud_${String(this.findingCounter).padStart(5, "0")}`;
  }

  /**
   * Processes identity events in time order. Events older than
   * `noveltyLearnedBefore` only train the seen sets (history learning);
   * later events can emit findings.
   */
  process(events: EventEnvelope[], noveltyLearnedBefore: string): NodeOutput {
    const findings: Finding[] = [];
    const evidence: EvidenceRecord[] = [];
    const learnCutoff = Date.parse(noveltyLearnedBefore);
    const sorted = [...events].sort((a, b) => Date.parse(a.occurred_at) - Date.parse(b.occurred_at));

    for (const event of sorted) {
      const tenantId = event.tenant?.tenant_id;
      const accountId = event.tenant?.account_id;
      if (!tenantId || !accountId) continue;
      const accountKey = `${tenantId}/${accountId}`;
      const isLearning = Date.parse(event.occurred_at) < learnCutoff;

      if (event.event_type === "identity.api_key.created") {
        const fingerprint = event.actor.api_key_fingerprint ?? String(event.payload["api_key_fingerprint"] ?? "");
        if (fingerprint) {
          const novel = this.markSeen(this.seenKeys, accountKey, fingerprint);
          if (novel && !isLearning) {
            const record = eventEvidence(event, { tenant_id: tenantId, account_id: accountId });
            evidence.push(record);
            findings.push(this.noveltyFinding("cloud.new_api_key", event, record, 0.3, `New API key ${fingerprint.slice(-8)} created; account has no prior history with this key.`, fingerprint));
          }
        }
      }

      if (event.event_type === "identity.session.created" || event.event_type === "identity.api_key.used") {
        const region = typeof event.payload["region"] === "string" ? (event.payload["region"] as string) : event.location.region;
        const device = typeof event.payload["device_fingerprint"] === "string" ? (event.payload["device_fingerprint"] as string) : undefined;
        if (region) {
          const novel = this.markSeen(this.seenRegions, accountKey, region);
          if (novel && !isLearning) {
            const record = eventEvidence(event, { tenant_id: tenantId, account_id: accountId });
            evidence.push(record);
            findings.push(this.noveltyFinding("cloud.new_region", event, record, 0.3, `First observed access from region "${region}" for this account.`));
          }
        }
        if (device) {
          const novel = this.markSeen(this.seenDevices, accountKey, device);
          if (novel && !isLearning) {
            const record = eventEvidence(event, { tenant_id: tenantId, account_id: accountId });
            evidence.push(record);
            findings.push(this.noveltyFinding("cloud.new_device", event, record, 0.25, `First observed access from device ${device.slice(-8)} for this account.`));
          }
        }
      }

      this.detectImplausibleTravel(event, accountKey, tenantId, accountId, isLearning, findings, evidence);
      this.detectSessionReplay(event, tenantId, accountId, isLearning, findings, evidence);
      this.detectServiceIdentityMisuse(event, tenantId, accountId, isLearning, findings, evidence);
    }

    const burstFindings = this.loginFailureBursts(sorted, learnCutoff);
    findings.push(...burstFindings.findings);
    evidence.push(...burstFindings.evidence);
    return { findings, evidence };
  }

  private loginFailureBursts(events: EventEnvelope[], learnCutoff: number): NodeOutput {
    return thresholdBurst(this.features, {
      events,
      learnCutoff,
      eventType: "identity.login.failed",
      featureRef: LOGIN_FAILURES_15M,
      threshold: 5,
      groupField: "account_id",
      unit: "failures/15m",
      nextFindingId: () => this.nextFindingId(),
      node: { name: this.name, version: this.version },
      findingType: "cloud.login_failure_burst",
      actionClass: "RECOMMEND_ONLY",
      likelihood: (count) => clamp01(0.4 + 0.03 * count),
      impact: 0.5,
      confidence: 0.7,
      summarize: (count) => `${count} failed logins within 15 minutes for this account.`,
      subject: (_tenantId, accountId) => ({ type: "account", id: accountId }),
      correlationHints: (_tenantId, accountId) => ({ account_id: accountId }),
    });
  }

  /**
   * Implausible travel (03): two account accesses whose distance over elapsed
   * time exceeds physical travel speed. Weak alone (VPN/proxy), strong as a
   * compound-correlation input — so it stays RECOMMEND_ONLY.
   */
  private detectImplausibleTravel(
    event: EventEnvelope,
    accountKey: string,
    tenantId: string,
    accountId: string,
    isLearning: boolean,
    findings: Finding[],
    evidence: EvidenceRecord[],
  ): void {
    if (!ACCESS_EVENT_TYPES.has(event.event_type)) return;
    const region = event.location.region ?? (typeof event.payload["region"] === "string" ? (event.payload["region"] as string) : undefined);
    if (!region || !REGION_GEO[region]) return;
    const atMs = Date.parse(event.occurred_at);
    const prior = this.lastAccess.get(accountKey);
    if (prior && !isLearning && prior.region !== region && REGION_GEO[prior.region]) {
      const distanceKm = haversineKm(REGION_GEO[prior.region]!, REGION_GEO[region]!);
      const hours = Math.max((atMs - prior.at_ms) / 3_600_000, 1 / 60);
      const speedKmh = distanceKm / hours;
      if (distanceKm >= MIN_TRAVEL_KM && speedKmh > MAX_TRAVEL_KMH) {
        const record = eventEvidence(event, { tenant_id: tenantId, account_id: accountId });
        evidence.push(record);
        findings.push({
          finding_id: this.nextFindingId(),
          finding_type: "cloud.implausible_travel",
          node: { name: this.name, version: this.version },
          subject: { type: "account", id: accountId },
          tenant_id: tenantId,
          window: { start: new Date(prior.at_ms).toISOString(), end: event.occurred_at },
          risk: { likelihood: clamp01(0.45 + 0.15 * Math.min(1, speedKmh / 5000)), impact: 0.55, confidence: 0.65, evidence_quality: record.quality.score },
          evidence_ids: [record.evidence_id],
          source_event_roots: [record.source_event_root],
          explanation: {
            summary: `Account access moved ${Math.round(distanceKm)} km (${prior.region} -> ${region}) in ${hours.toFixed(1)}h, implying ${Math.round(speedKmh)} km/h — faster than physical travel.`,
            top_factors: [{ factor: "implausible_travel_speed", contribution: 1 }],
            uncertainties: ["A VPN, proxy, or corporate egress can produce implausible travel without compromise."],
          },
          recommendation: { action_class: "RECOMMEND_ONLY" },
          expires_at: new Date(atMs + 24 * 3600 * 1000).toISOString(),
          correlation_hints: { account_id: accountId },
          policy_generated_effect: event.control_lineage?.policy_generated_effect === true,
        });
      }
    }
    this.lastAccess.set(accountKey, { region, country: event.location.country ?? "", at_ms: atMs });
  }

  /** Session replay (03): one session id observed from more than one device. */
  private detectSessionReplay(
    event: EventEnvelope,
    tenantId: string,
    accountId: string,
    isLearning: boolean,
    findings: Finding[],
    evidence: EvidenceRecord[],
  ): void {
    const sessionId = event.actor.session_id;
    const device = typeof event.payload["device_fingerprint"] === "string" ? (event.payload["device_fingerprint"] as string) : undefined;
    if (!sessionId || !device) return;
    const devices = this.sessionDevices.get(sessionId) ?? new Set<string>();
    if (!devices.has(device) && devices.size >= 1 && !isLearning) {
      const record = eventEvidence(event, { tenant_id: tenantId, account_id: accountId });
      evidence.push(record);
      findings.push({
        finding_id: this.nextFindingId(),
        finding_type: "cloud.session_replay",
        node: { name: this.name, version: this.version },
        subject: { type: "account", id: accountId },
        tenant_id: tenantId,
        window: { start: event.occurred_at, end: event.occurred_at },
        risk: { likelihood: 0.6, impact: 0.6, confidence: 0.7, evidence_quality: record.quality.score },
        evidence_ids: [record.evidence_id],
        source_event_roots: [record.source_event_root],
        explanation: {
          summary: `Session ${sessionId.slice(-8)} was used from a new device ${device.slice(-8)} after ${devices.size} prior device(s) — possible session token replay.`,
          top_factors: [{ factor: "session_device_mismatch", contribution: 1 }],
          uncertainties: ["A user switching devices mid-session or a shared session can resemble replay."],
        },
        recommendation: { action_class: "REQUEST_OPERATOR", playbook: "PB-CLOUD-SESSION-01" },
        expires_at: new Date(Date.parse(event.occurred_at) + 24 * 3600 * 1000).toISOString(),
        correlation_hints: { account_id: accountId, actor_id: event.actor.actor_id },
        policy_generated_effect: event.control_lineage?.policy_generated_effect === true,
      });
    }
    devices.add(device);
    this.sessionDevices.set(sessionId, devices);
  }

  /**
   * Service identity misuse (03): a service identity performing a privileged
   * identity operation outside its service-to-service role.
   */
  private detectServiceIdentityMisuse(
    event: EventEnvelope,
    tenantId: string,
    accountId: string,
    isLearning: boolean,
    findings: Finding[],
    evidence: EvidenceRecord[],
  ): void {
    if (isLearning) return;
    if (event.actor.actor_type !== "service" || !SERVICE_FORBIDDEN_OPS.has(event.event_type)) return;
    const record = eventEvidence(event, { tenant_id: tenantId, account_id: accountId });
    evidence.push(record);
    findings.push({
      finding_id: this.nextFindingId(),
      finding_type: "cloud.service_identity_misuse",
      node: { name: this.name, version: this.version },
      subject: { type: "account", id: accountId },
      tenant_id: tenantId,
      window: { start: event.occurred_at, end: event.occurred_at },
      risk: { likelihood: 0.55, impact: 0.6, confidence: 0.7, evidence_quality: record.quality.score },
      evidence_ids: [record.evidence_id],
      source_event_roots: [record.source_event_root],
      explanation: {
        summary: `Service identity "${event.actor.actor_id}" performed a privileged identity operation (${event.event_type}) outside its service role.`,
        top_factors: [{ factor: "service_identity_privileged_op", contribution: 1 }],
        uncertainties: ["A legitimate automation change can introduce a new service operation; verify the change."],
      },
      recommendation: { action_class: "REQUEST_OPERATOR", playbook: "PB-CLOUD-SVCID-01" },
      expires_at: new Date(Date.parse(event.occurred_at) + 24 * 3600 * 1000).toISOString(),
      correlation_hints: { account_id: accountId, actor_id: event.actor.actor_id },
      policy_generated_effect: event.control_lineage?.policy_generated_effect === true,
    });
  }

  private markSeen(map: Map<string, Set<string>>, accountKey: string, value: string): boolean {
    const set = map.get(accountKey) ?? new Set<string>();
    const novel = !set.has(value);
    set.add(value);
    map.set(accountKey, set);
    return novel;
  }

  private noveltyFinding(type: string, event: EventEnvelope, record: EvidenceRecord, likelihood: number, summary: string, keyFingerprint?: string): Finding {
    const tenantId = event.tenant?.tenant_id ?? "unknown";
    const accountId = event.tenant?.account_id ?? "unknown";
    return {
      finding_id: this.nextFindingId(),
      finding_type: type,
      node: { name: this.name, version: this.version },
      subject: { type: "account", id: accountId },
      tenant_id: tenantId,
      window: { start: event.occurred_at, end: event.occurred_at },
      risk: { likelihood, impact: 0.5, confidence: 0.6, evidence_quality: record.quality.score },
      evidence_ids: [record.evidence_id],
      source_event_roots: [record.source_event_root],
      explanation: {
        summary,
        top_factors: [{ factor: type, contribution: 1 }],
        uncertainties: ["Novelty alone is a weak signal; it rarely justifies enforcement by itself."],
      },
      recommendation: { action_class: "OBSERVE" },
      expires_at: new Date(Date.parse(event.occurred_at) + 24 * 3600 * 1000).toISOString(),
      correlation_hints: {
        account_id: accountId,
        ...(keyFingerprint !== undefined ? { api_key_fingerprint: keyFingerprint } : {}),
      },
      policy_generated_effect: event.control_lineage?.policy_generated_effect === true,
    };
  }
}
