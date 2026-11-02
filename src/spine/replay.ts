import { readFileSync } from "node:fs";
import type { EventEnvelope } from "../contracts/envelope.js";
import type { EventGateway, IngestResult } from "./gateway.js";
import type { ProducerCredential } from "./producers.js";

export interface ReplayLine {
  event: EventEnvelope;
  credential: ProducerCredential;
}

export interface ReplaySummary {
  total: number;
  accepted: number;
  duplicates: number;
  rejected: number;
  results: IngestResult[];
}

export function parseReplayJsonl(content: string): ReplayLine[] {
  return content
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as ReplayLine);
}

export function loadReplayFile(path: string): ReplayLine[] {
  return parseReplayJsonl(readFileSync(path, "utf8"));
}

/**
 * Deterministic replay: identical input fixtures produce identical ledgers.
 * A line that parses but is malformed (for example `null`, or one with no
 * credential) becomes a rejection of that line; it does not stop the replay.
 * A line that is not valid JSON fails earlier, in parseReplayJsonl
 * (KI-SENTINEL-20261030-006 item 2).
 */
export function replayInto(gateway: EventGateway, lines: ReplayLine[]): ReplaySummary {
  const results = lines.map((line) => {
    const entry = (typeof line === "object" && line !== null ? line : {}) as Partial<ReplayLine>;
    return gateway.ingest(entry.event, entry.credential as ProducerCredential);
  });
  return {
    total: results.length,
    accepted: results.filter((result) => result.status === "accepted").length,
    duplicates: results.filter((result) => result.status === "duplicate").length,
    rejected: results.filter((result) => result.status === "rejected").length,
    results,
  };
}
