// Types for the cloud-misconfig benchmark's pure exports (consumed by the vitest test).
// The runnable logic lives in the sibling .mjs (scripts run under bare `node`, no build step).
export interface CloudFixture {
  id: string;
  desc: string;
  clean: boolean;
  expect: string[];
  hcl: string;
}
export interface CloudCorpus {
  target_checks: string[];
  fixtures: CloudFixture[];
}
export interface CloudScore {
  detection: { hits: number; total: number; rate: number };
  discrimination: { clean: number; falsePositives: number };
  perFixture: Array<{
    id: string;
    clean: boolean;
    ok: boolean;
    expected?: string[];
    detected?: string[];
    falsePos?: string[];
  }>;
}
export function loadCorpus(): CloudCorpus;
export function parseCheckov(json: unknown): Record<string, Set<string>>;
export function scoreCorpus(corpus: CloudCorpus, byFixture: Record<string, Set<string>>): CloudScore;
