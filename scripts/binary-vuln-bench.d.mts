// Types for the binary-vuln benchmark's pure exports (consumed by the vitest test).
// Runnable logic lives in the sibling .mjs (scripts run under bare `node`, no build step).
export interface BinaryRule {
  id: string;
  desc: string;
  test: (c: string) => boolean;
}
export interface BinaryFixture {
  id: string;
  desc: string;
  clean: boolean;
  expect: string[];
  content: string;
}
export interface BinaryCorpus {
  fixtures: BinaryFixture[];
}
export interface BinaryScore {
  detection: { hits: number; total: number; rate: number };
  discrimination: { clean: number; falsePositives: number };
  perFixture: Array<{ id: string; clean: boolean; ok: boolean; expected?: string[]; detected: string[] }>;
}
export const RULES: BinaryRule[];
export function loadCorpus(): BinaryCorpus;
export function detect(content: string): Set<string>;
export function scoreCorpus(corpus: BinaryCorpus, detectFn?: (content: string) => Set<string>): BinaryScore;
