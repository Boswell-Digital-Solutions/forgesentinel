import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  ASSURANCE_ANALYZER_ID,
  analyzeAccuracy,
  analyzeCoverage,
  analyzeTruthfulness,
  type AccuracyInput,
  type AssuranceResult,
  type CoverageInput,
  type TruthfulnessInput,
} from "../src/intel/assurance.js";

const VERIFIER_ID = "forgesentinel.assurance-fixture-verifier.v0.1";

interface Fixture<T> {
  readonly fixtureId: string;
  readonly input: T;
  readonly expected: {
    readonly classification: string;
    readonly requiredPhrases: readonly string[];
    readonly forbiddenPhrases: readonly string[];
  };
}

function loadFixture<T>(name: string): Fixture<T> {
  return JSON.parse(readFileSync(`fixtures/assurance/${name}`, "utf8")) as Fixture<T>;
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stable(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "undefined";
}

function verify<T>(fixture: Fixture<T>, result: AssuranceResult): void {
  assert.notEqual(VERIFIER_ID, ASSURANCE_ANALYZER_ID);
  assert.equal(result.fixtureId, fixture.fixtureId);
  assert.equal(result.classification, fixture.expected.classification);
  for (const phrase of fixture.expected.requiredPhrases) {
    assert.ok(result.summary.includes(phrase), `summary must include '${phrase}'`);
  }
  const assertedText = result.summary.toLowerCase();
  for (const phrase of fixture.expected.forbiddenPhrases) {
    assert.ok(!assertedText.includes(phrase.toLowerCase()), `analyzer must not assert '${phrase}'`);
  }
  assert.ok(result.prohibitedInferences.length >= 3);
}

test("EAS-COV-001 reports a source-labeled coverage gap without absence inference", () => {
  const fixture = loadFixture<CoverageInput>("EAS-COV-001.json");
  const first = analyzeCoverage(fixture.input);
  const second = analyzeCoverage(fixture.input);
  verify(fixture, first);
  assert.equal(stable(first), stable(second));
});

test("EAS-TRU-001 reports a scoped contradiction without intent inference", () => {
  const fixture = loadFixture<TruthfulnessInput>("EAS-TRU-001.json");
  const first = analyzeTruthfulness(fixture.input);
  const second = analyzeTruthfulness(fixture.input);
  verify(fixture, first);
  assert.equal(stable(first), stable(second));
});

test("EAS-ACC-001 reports source drift without substantive-invalidity inference", () => {
  const fixture = loadFixture<AccuracyInput>("EAS-ACC-001.json");
  const first = analyzeAccuracy(fixture.input);
  const second = analyzeAccuracy(fixture.input);
  verify(fixture, first);
  assert.equal(stable(first), stable(second));
  assert.equal(first.contractProjection, "source_drift_finding.v1");
});

test("missing evidence and observations fail closed", () => {
  const truth = analyzeTruthfulness({
    fixtureId: "negative-truth",
    subject: "claim",
    claim: { statement: "x", assertedState: "operational", evidenceRef: "claim-ref" },
    implementationEvidence: [],
  });
  const accuracy = analyzeAccuracy({
    fixtureId: "negative-accuracy",
    subject: "pin",
    pinnedCommit: null,
    observedCommit: null,
    planEvidenceRef: "plan-ref",
    observationEvidenceRef: "observation-ref",
  });
  const coverage = analyzeCoverage({
    fixtureId: "negative-coverage",
    subject: "estate",
    admittedTargets: ["repo-x"],
    observations: [],
  });
  assert.equal(truth.classification, "INSUFFICIENT_EVIDENCE");
  assert.equal(accuracy.classification, "UNVERIFIABLE");
  assert.equal(coverage.classification, "COVERAGE_GAP");
});
