import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CrossTenantAccessDenied, EvidenceLedger, buildEvent } from "../src/index.js";
import { byService, testProducers } from "./support/producers.js";

const PRODUCERS = testProducers("production");
const producers = byService(PRODUCERS);

function appendEvent(ledger: EvidenceLedger, overrides: { sensitivity?: "internal" | "confidential" | "restricted"; content?: boolean; cloudAllowed?: boolean; lane?: "local" | "cloud"; payload?: Record<string, unknown>; tenant?: string }) {
  const { event } = buildEvent(producers["forgeagents"]!, {
    event_id: `evt_l_${Math.random().toString(36).slice(2, 10)}`,
    event_type: "data.object.read",
    occurred_at: "2026-06-09T12:00:00.000Z",
    tenant: { tenant_id: overrides.tenant ?? "ten_a" },
    actor: { actor_type: "agent", actor_id: "forge-smithy" },
    subject: { subject_type: "data_object", subject_id: "obj_1" },
    correlation: { trace_id: "trc_l1" },
    location: { execution_lane: overrides.lane ?? "local" },
    payload: overrides.payload ?? { object_path_hash: "sha256:abc" },
    data_policy: {
      content_included: overrides.content ?? false,
      sensitivity: overrides.sensitivity ?? "internal",
      retention_class: "security_365d",
      cloud_allowed: overrides.cloudAllowed ?? true,
    },
  });
  return ledger.append({
    kind: "event",
    gateway_version: "test",
    validation: "accepted",
    transformation_version: "1.0.0",
    tenant_id: event.tenant!.tenant_id,
    body: event,
  });
}

test("originals are immutable: corrections append with a supersedes link", () => {
  const ledger = new EvidenceLedger();
  const original = appendEvent(ledger, {});
  const corrected = ledger.appendCorrection(original.ledger_seq, { ...(original.body as object), corrected: true }, "correction.1.0.0");
  assert.equal(corrected.supersedes, original.ledger_seq);
  assert.ok(ledger.bySeq(original.ledger_seq), "original remains readable");
  assert.equal(ledger.all().length, 2);
});

test("cross-tenant query is denied and the denial is recorded (10 tenant isolation)", () => {
  const ledger = new EvidenceLedger();
  appendEvent(ledger, { tenant: "ten_a" });
  assert.throws(
    () => ledger.queryByTenant("ten_a", { principal: "svc_other", tenant_id: "ten_b", role: "tenant" }),
    CrossTenantAccessDenied,
  );
  assert.equal(ledger.denials.length, 1);
  const denialEvents = ledger.all().filter((record) => (record.body as Record<string, unknown>)["event_type"] === "data.cross_tenant.denied");
  assert.equal(denialEvents.length, 1);
  const own = ledger.queryByTenant("ten_a", { principal: "svc_a", tenant_id: "ten_a", role: "tenant" });
  assert.ok(own.length >= 1);
});

test("protected content is absent from the default cloud projection (Wave 8 exit gate, enforced early)", () => {
  const ledger = new EvidenceLedger();
  const secretText = "SECRET-MANUSCRIPT-CONTENT";
  const localOnly = appendEvent(ledger, { sensitivity: "restricted", content: true, cloudAllowed: false, payload: { excerpt: secretText } });
  assert.equal(ledger.cloudProjection(localOnly), null, "cloud-ineligible events do not project at all");

  const confidentialContent = appendEvent(ledger, { sensitivity: "confidential", content: true, cloudAllowed: true, payload: { excerpt: secretText } });
  const projection = ledger.cloudProjection(confidentialContent);
  assert.ok(projection, "metadata projection exists");
  assert.equal(ledger.cloudProjectionContains(confidentialContent, secretText), false, "content never crosses the boundary");
  assert.equal(projection!["payload_omitted"], "content_excluded_by_field_policy");
  assert.ok(projection!["payload_hash"], "hash reference is preserved");

  const metadataOnly = appendEvent(ledger, { sensitivity: "internal", content: false, cloudAllowed: true });
  const metaProjection = ledger.cloudProjection(metadataOnly);
  assert.ok(metaProjection && metaProjection["payload"], "cloud-eligible metadata payloads project normally");
});

test("WAL persistence reloads deterministically (DataForge outage path)", () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-wal-"));
  const walPath = join(dir, "ledger.jsonl");
  try {
    const ledger = new EvidenceLedger(walPath);
    appendEvent(ledger, {});
    appendEvent(ledger, { tenant: "ten_b" });
    const reloaded = new EvidenceLedger(walPath);
    assert.equal(reloaded.all().length, 2);
    assert.deepEqual(reloaded.all().map((record) => record.ledger_seq), [1, 2]);
    const next = appendEvent(reloaded, {});
    assert.equal(next.ledger_seq, 3, "sequence continues after reload");
    assert.ok(reloaded.integrityCheck().every((check) => check.ok), "hashes verify after reload");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
