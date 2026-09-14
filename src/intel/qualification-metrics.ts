import type { ExpansionLane, ExpansionSeverity } from "./security-assurance.js";

export interface QualificationObservation {
  readonly fixtureId: string;
  readonly lane: ExpansionLane;
  readonly severity: ExpansionSeverity;
  readonly expectedFinding: boolean;
  readonly observedFinding: boolean;
  readonly disagreementIntroduced?: boolean;
  readonly disagreementVisible?: boolean;
}

export interface MetricStratum {
  readonly lane: ExpansionLane;
  readonly severity: ExpansionSeverity;
  readonly tp: number;
  readonly tn: number;
  readonly fp: number;
  readonly fn: number;
}

export interface QualificationMetrics {
  readonly strata: readonly MetricStratum[];
  readonly s0s1Recall: number;
  readonly disagreementVisibility: number;
  readonly hiddenFailedStrata: readonly string[];
}

export function calculateMetrics(observations: readonly QualificationObservation[]): QualificationMetrics {
  const groups = new Map<string, QualificationObservation[]>();
  for (const item of observations) {
    const key = `${item.lane}|${item.severity}`;
    groups.set(key, [...(groups.get(key) ?? []), item]);
  }
  const strata = [...groups.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, items]) => {
    const [lane, severity] = key.split("|") as [ExpansionLane, ExpansionSeverity];
    return {
      lane,
      severity,
      tp: items.filter((item) => item.expectedFinding && item.observedFinding).length,
      tn: items.filter((item) => !item.expectedFinding && !item.observedFinding).length,
      fp: items.filter((item) => !item.expectedFinding && item.observedFinding).length,
      fn: items.filter((item) => item.expectedFinding && !item.observedFinding).length,
    };
  });
  const critical = observations.filter((item) => item.expectedFinding && (item.severity === "S0" || item.severity === "S1"));
  const visible = observations.filter((item) => item.disagreementIntroduced === true);
  return {
    strata,
    s0s1Recall: critical.length === 0 ? 1 : critical.filter((item) => item.observedFinding).length / critical.length,
    disagreementVisibility: visible.length === 0 ? 1 : visible.filter((item) => item.disagreementVisible === true).length / visible.length,
    hiddenFailedStrata: strata.filter((item) => item.fn > 0).map((item) => `${item.lane}|${item.severity}`),
  };
}
