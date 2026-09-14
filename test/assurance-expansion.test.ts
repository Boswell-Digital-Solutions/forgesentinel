import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  containsRestrictedCanary,
  EXPANSION_VERIFIER_ID,
  redactGeneralOutput,
  verifyCandidate,
} from "../src/intel/assurance-verifier.js";
import {
  createFinding,
  stableFindingId,
  updateFinding,
  type FindingIdentity,
} from "../src/intel/finding-lineage.js";
import { calculateMetrics, type QualificationObservation } from "../src/intel/qualification-metrics.js";
import {
  evaluateAssurance,
  EXPANSION_ANALYZER_ID,
  type ExpansionCandidate,
  type ExpansionInput,
  type ExpansionLane,
  type ExpansionSeverity,
} from "../src/intel/security-assurance.js";

interface PairedCase {
  readonly id: string;
  readonly ruleId: string;
  readonly severity: ExpansionSeverity;
  readonly expected: string;
  readonly fault: string;
  readonly clean: string;
}

interface ComparisonCase {
  readonly id: string;
  readonly ruleId: string;
  readonly expected: string;
  readonly observed: string;
}

function fixture<T>(name: string): T {
  return JSON.parse(readFileSync(`fixtures/assurance-expansion/${name}`, "utf8")) as T;
}

function candidate(
  lane: ExpansionLane = "security",
  expected = "safe",
  observed = "unsafe",
  overrides: Partial<ExpansionInput> = {},
): ExpansionCandidate {
  return evaluateAssurance({
    fixtureId: "syn_fixture",
    lane,
    ruleId: "syn_rule",
    targetId: "syn_repo_alpha",
    surface: "syn_surface",
    severity: "S1",
    expected,
    observed,
    evidenceRefs: ["sha256:syn_evidence"],
    analyzerStateToken: "syn_state_analyzer",
    ...overrides,
  });
}

function verify(
  item: ExpansionCandidate,
  overrides: Partial<Parameters<typeof verifyCandidate>[0]> = {},
) {
  return verifyCandidate({
    candidate: item,
    verifierId: EXPANSION_VERIFIER_ID,
    verifierStateToken: "syn_state_verifier",
    oracleRuleId: "syn_oracle_v1",
    expectedClassification: item.classification,
    evidenceAvailable: true,
    verifierAvailable: true,
    candidateSource: "deterministic",
    ...overrides,
  });
}

const security = fixture<{ cases: PairedCase[] }>("SEC-FOUNDATION-001.json").cases;
const truth = fixture<{ cases: ComparisonCase[] }>("TRU-FOUNDATION-001.json").cases;
const accuracy = fixture<{ cases: ComparisonCase[] }>("ACC-FOUNDATION-001.json").cases;

for (const [index, item] of security.entries()) {
  test(`${item.id} detects ${item.ruleId} and accepts its clean control`, () => {
    const fault = candidate("security", item.expected, item.fault, {
      fixtureId: item.id,
      ruleId: item.ruleId,
      severity: item.severity,
    });
    const clean = candidate("security", item.expected, item.clean, {
      fixtureId: `${item.id}-CONTROL`,
      ruleId: item.ruleId,
      severity: item.severity,
    });
    assert.equal(fault.classification, "FINDING");
    assert.equal(clean.classification, "SUPPORTED");
    assert.equal(fault.acceptedEffects, 0);
    assert.notEqual(fault.candidateId, clean.candidateId);
    assert.equal(index >= 0, true);
  });
}

for (const item of truth) {
  test(`${item.id} classifies ${item.ruleId} without intent inference`, () => {
    const result = candidate("truthfulness", item.expected, item.observed, {
      fixtureId: item.id,
      ruleId: item.ruleId,
      severity: "S2",
    });
    assert.equal(result.classification, item.expected === item.observed ? "SUPPORTED" : "FINDING");
    assert.equal(/intent|dishonest|deception/i.test(result.summary), false);
  });
}

for (const item of accuracy) {
  test(`${item.id} classifies ${item.ruleId} against its exact control`, () => {
    const result = candidate("accuracy", item.expected, item.observed, {
      fixtureId: item.id,
      ruleId: item.ruleId,
      severity: "S2",
    });
    assert.equal(result.classification, item.expected === item.observed ? "SUPPORTED" : "FINDING");
    assert.equal(result.evidenceRefs.length, 1);
  });
}

test("VER-001 independent registered rule confirms matching candidate", () => {
  assert.equal(verify(candidate()).state, "CONFIRMED");
});

test("VER-002 independent rule rejects a mismatching candidate without deleting it", () => {
  const item = candidate();
  const result = verify(item, { expectedClassification: "SUPPORTED" });
  assert.equal(result.state, "NOT_CONFIRMED");
  assert.equal(result.candidateId, item.candidateId);
  assert.equal(result.disagreementVisible, true);
});

test("VER-003 unavailable evidence remains inconclusive", () => {
  assert.equal(verify(candidate(), { evidenceAvailable: false }).state, "INCONCLUSIVE");
});

test("VER-004 unavailable verifier blocks without self-verification fallback", () => {
  assert.equal(verify(candidate(), { verifierAvailable: false }).state, "BLOCKED");
});

test("VER-005 shared analyzer and verifier identity fails independence", () => {
  const result = verify(candidate(), { verifierId: EXPANSION_ANALYZER_ID });
  assert.equal(result.state, "INDEPENDENCE_VIOLATION");
});

test("VER-006 model-shaped disagreement remains visible", () => {
  const result = verify(candidate(), { expectedClassification: "SUPPORTED", candidateSource: "model-shaped" });
  assert.equal(result.state, "NOT_CONFIRMED");
  assert.equal(result.disagreementVisible, true);
});

test("VER-007 supported completion with missing required evidence is rejected", () => {
  const result = verify(candidate("truthfulness", "complete", "complete"), { requiredEvidenceMissing: true });
  assert.equal(result.state, "NOT_CONFIRMED");
  assert.equal(result.reason, "false_completion_rejected");
});

const lineageIdentity: FindingIdentity = fixture<{ identity: FindingIdentity }>("LIN-FOUNDATION-001.json").identity;

test("LIN-001 same key with new evidence updates one lineage", () => {
  const first = createFinding(lineageIdentity, ["sha256:syn_a"], "S2");
  const next = updateFinding(first, { identity: lineageIdentity, evidenceRefs: ["sha256:syn_b"], severity: "S2" });
  assert.equal(next.findingId, first.findingId);
  assert.deepEqual(next.evidenceRefs, ["sha256:syn_a", "sha256:syn_b"]);
});

test("LIN-002 material surface change creates a new finding identity", () => {
  const first = createFinding(lineageIdentity, ["sha256:syn_a"], "S2");
  const changed = { ...lineageIdentity, surface: "syn_surface_other" };
  const next = updateFinding(first, { identity: changed, evidenceRefs: ["sha256:syn_b"], severity: "S2" });
  assert.notEqual(next.findingId, first.findingId);
  assert.equal(next.priorFindingId, first.findingId);
});

test("LIN-003 resolved fault returning is marked reopened", () => {
  const open = createFinding(lineageIdentity, ["sha256:syn_a"], "S2");
  const resolved = { ...open, state: "RESOLVED" as const };
  const next = updateFinding(resolved, { identity: lineageIdentity, evidenceRefs: ["sha256:syn_b"], severity: "S2", reopen: true });
  assert.equal(next.state, "REOPENED");
});

test("LIN-004 procedure-major change is superseded with reconciliation link", () => {
  const first = createFinding(lineageIdentity, ["sha256:syn_a"], "S2");
  const changed = { ...lineageIdentity, procedureMajor: 2 };
  const next = updateFinding(first, { identity: changed, evidenceRefs: ["sha256:syn_b"], severity: "S2" });
  assert.equal(next.state, "SUPERSEDED");
  assert.equal(next.priorFindingId, first.findingId);
});

test("LIN-005 duplicate delivery keeps one version and exposes duplicate count", () => {
  const first = createFinding(lineageIdentity, ["sha256:syn_a"], "S2");
  const next = updateFinding(first, { identity: lineageIdentity, evidenceRefs: ["sha256:syn_a"], severity: "S2", duplicate: true });
  assert.equal(next.version, first.version);
  assert.equal(next.duplicateDeliveries, 1);
});

test("LIN-006 severity increase remains in the same visible lineage", () => {
  const first = createFinding(lineageIdentity, ["sha256:syn_a"], "S2");
  const next = updateFinding(first, { identity: lineageIdentity, evidenceRefs: ["sha256:syn_b"], severity: "S1" });
  assert.equal(next.findingId, first.findingId);
  assert.equal(next.severity, "S1");
  assert.equal(stableFindingId(next), first.findingId);
});

const redaction = fixture<{ canaries: string[]; cleanText: string }>("RED-MET-FOUNDATION-001.json");

test("RED-001 canaries are removed across nested general outputs", () => {
  const output = redactGeneralOutput({ source: redaction.canaries[0], nested: [redaction.canaries[1]] });
  assert.equal(containsRestrictedCanary(output), false);
});

test("RED-002 redaction preserves a non-reversible digest marker", () => {
  const output = String(redactGeneralOutput(redaction.canaries[2]));
  assert.match(output, /^\[REDACTED:sha256:[0-9a-f]{16}\]$/);
});

test("RED-003 error-shaped text cannot leak a restricted canary", () => {
  const output = redactGeneralOutput({ error: `failed on ${redaction.canaries[3]}` });
  assert.equal(containsRestrictedCanary(output), false);
});

test("RED-004 ordinary evidence remains readable", () => {
  assert.equal(redactGeneralOutput(redaction.cleanText), redaction.cleanText);
});

function metricInput(overrides: Partial<QualificationObservation> = {}): QualificationObservation {
  return { fixtureId: "syn_metric", lane: "security", severity: "S1", expectedFinding: true, observedFinding: true, ...overrides };
}

test("MET-001 confusion counts remain separate per lane and severity", () => {
  const metrics = calculateMetrics([
    metricInput(),
    metricInput({ fixtureId: "syn_clean", expectedFinding: false, observedFinding: false }),
    metricInput({ fixtureId: "syn_fp", lane: "accuracy", severity: "S2", expectedFinding: false, observedFinding: true }),
  ]);
  assert.equal(metrics.strata.length, 2);
  assert.deepEqual(metrics.strata.map((item) => [item.lane, item.tp, item.tn, item.fp, item.fn]), [["accuracy", 0, 0, 1, 0], ["security", 1, 1, 0, 0]]);
});

test("MET-002 synthetic S0 and S1 recall is explicit", () => {
  const metrics = calculateMetrics([metricInput({ severity: "S0" }), metricInput({ severity: "S1" })]);
  assert.equal(metrics.s0s1Recall, 1);
});

test("MET-003 every introduced analyzer verifier disagreement is visible", () => {
  const metrics = calculateMetrics([metricInput({ disagreementIntroduced: true, disagreementVisible: true })]);
  assert.equal(metrics.disagreementVisibility, 1);
});

test("MET-004 failed strata cannot be hidden by aggregate successes", () => {
  const metrics = calculateMetrics([metricInput(), metricInput({ fixtureId: "syn_miss", lane: "truthfulness", observedFinding: false })]);
  assert.deepEqual(metrics.hiddenFailedStrata, ["truthfulness|S1"]);
});

test("XLANE-001 provenance mismatch produces separate security and accuracy candidates", () => {
  const securityCandidate = candidate("security", "syn_digest_a", "syn_digest_b", { ruleId: "artifact_provenance" });
  const accuracyCandidate = candidate("accuracy", "syn_digest_a", "syn_digest_b", { ruleId: "source_artifact" });
  assert.equal(securityCandidate.classification, "FINDING");
  assert.equal(accuracyCandidate.classification, "FINDING");
  assert.notEqual(securityCandidate.candidateId, accuracyCandidate.candidateId);
});

test("REPLAY-001 identical analyzer and verifier tuples replay deterministically", () => {
  const firstCandidate = candidate();
  const secondCandidate = candidate();
  assert.deepEqual(secondCandidate, firstCandidate);
  assert.deepEqual(verify(secondCandidate), verify(firstCandidate));
});
