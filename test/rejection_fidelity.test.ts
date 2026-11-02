import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EvidenceLedger,
  MALFORMED_INPUT_KEY,
  SentinelRuntime,
  buildEvent,
  rejectionBody,
  type LedgerRecord,
  type ProducerCredential,
} from "../src/index.js";
import { byService, testProducers } from "./support/producers.js";

/**
 * KI-SENTINEL-20261102-004: two different inputs never give the same
 * rejection body or hash. KI-SENTINEL-20261102-005: function, Symbol, BigInt
 * and unserializable inputs are recorded faithfully, and a body that cannot
 * be hashed leaves no ledger_seq gap.
 */

function runtime(): SentinelRuntime {
  return new SentinelRuntime("production", { producers: testProducers("production") });
}

function rejectionOf(rt: SentinelRuntime, input: unknown): LedgerRecord {
  const result = rt.gateway.ingest(input, undefined as unknown as ProducerCredential);
  assert.equal(result.status, "rejected");
  return result.record!;
}

test("a wrapped input and the literal wrapper object give different bodies and hashes", () => {
  const rt = runtime();
  const pairs: [unknown, unknown][] = [
    [5, { [MALFORMED_INPUT_KEY]: 5 }],
    [null, { [MALFORMED_INPUT_KEY]: null }],
    ["text", { [MALFORMED_INPUT_KEY]: "text" }],
    [5, { [MALFORMED_INPUT_KEY]: 5, input_type: "number" }],
  ];
  for (const [primitive, literal] of pairs) {
    const a = rejectionOf(rt, primitive);
    const b = rejectionOf(rt, literal);
    assert.notDeepEqual(a.body, b.body, JSON.stringify(literal));
    assert.notEqual(a.source_hash, b.source_hash, JSON.stringify(literal));
  }
});

test("distinct malformed inputs give distinct rejection hashes", () => {
  const rt = runtime();
  const inputs: unknown[] = [undefined, null, 0, 5, "5", true, false, NaN, Infinity, -Infinity, 10n, Symbol("s"), () => 1, [], {}, { [MALFORMED_INPUT_KEY]: 5 }];
  const hashes = inputs.map((input) => rejectionOf(rt, input).source_hash);
  // A function and a Symbol with no description cannot keep their value; every other pair must differ.
  assert.equal(new Set(hashes).size, inputs.length, "every input above has its own hash");
});

test("a normal object rejection keeps its body unchanged", () => {
  const rt = runtime();
  const producer = byService(testProducers("production"))["usage-metering"]!;
  const { event } = buildEvent(producer, {
    event_id: "evt_fidelity_object",
    event_type: "usage.tokens.recorded",
    occurred_at: "2026-06-09T12:00:00.000Z",
    tenant: { tenant_id: "ten_demo", account_id: "acct_1" },
    actor: { actor_type: "service", actor_id: "x" },
    subject: { subject_type: "account", subject_id: "acct_1" },
    correlation: { trace_id: "trc_fidelity_object" },
    payload: { total_tokens: 1, route_class: "general_cloud" },
  });
  const record = rejectionOf(rt, event);
  assert.equal(record.body, event, "an envelope-shaped object is stored as itself");
  assert.equal(rejectionBody(event), event);
});

test("function, Symbol, BigInt and unserializable inputs are rejected with their type recorded", () => {
  const rt = runtime();
  const cyclic: Record<string, unknown> = {};
  cyclic["self"] = cyclic;
  const cases: [unknown, unknown, string][] = [
    [() => 1, null, "function"],
    [Symbol("tag"), "tag", "symbol"],
    [12345678901234567890n, "12345678901234567890", "bigint"],
    [{ amount: 10n }, null, "unserializable"],
    [cyclic, null, "unserializable"],
    [undefined, null, "undefined"],
    [null, null, "null"],
    [NaN, "NaN", "number"],
  ];
  for (const [input, value, type] of cases) {
    let record: LedgerRecord | undefined;
    assert.doesNotThrow(() => {
      record = rejectionOf(rt, input);
    }, type);
    assert.deepEqual(record!.body, { [MALFORMED_INPUT_KEY]: value, input_type: type }, type);
  }
  const checks = rt.ledger.integrityCheck();
  assert.ok(checks.every((check) => check.ok), "every rejection passes the integrity check");
  assert.deepEqual(checks.map((check) => check.seq), checks.map((_, index) => index + 1), "no ledger_seq gap");
});

test("a body that cannot be hashed throws before a ledger_seq is taken", () => {
  const ledger = new EvidenceLedger();
  const base = { kind: "rejection" as const, gateway_version: "test", validation: "rejected" as const, transformation_version: "test" };
  ledger.append({ ...base, body: { n: 1 } });
  assert.throws(() => ledger.append({ ...base, body: { n: 10n } }), TypeError);
  const next = ledger.append({ ...base, body: { n: 2 } });
  assert.equal(next.ledger_seq, 2, "the failed append did not consume a sequence number");
  assert.ok(ledger.integrityCheck().every((check) => check.ok));
});
