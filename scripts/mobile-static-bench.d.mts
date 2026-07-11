// Types for the mobile-static benchmark's pure exports (consumed by the vitest test).
// Runnable logic lives in the sibling .mjs (scripts run under bare `node`, no build step).
export interface MobileRule {
  id: string;
  kind: 'manifest' | 'code';
  desc: string;
  test: (c: string) => boolean;
}
export interface MobileFixture {
  id: string;
  kind: 'manifest' | 'code';
  desc: string;
  clean: boolean;
  expect: string[];
  content: string;
}
export interface MobileCorpus {
  fixtures: MobileFixture[];
}
export interface MobileScore {
  detection: { hits: number; total: number; rate: number };
  discrimination: { clean: number; falsePositives: number };
  perFixture: Array<{ id: string; clean: boolean; ok: boolean; expected?: string[]; detected: string[] }>;
}
export const RULES: MobileRule[];
export function loadCorpus(): MobileCorpus;
export function detect(content: string, kind?: 'manifest' | 'code'): Set<string>;
export function scoreCorpus(corpus: MobileCorpus, detectFn?: (content: string, kind?: 'manifest' | 'code') => Set<string>): MobileScore;
