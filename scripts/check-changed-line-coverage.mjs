#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

export function changedLines(diff) {
  const files = new Map();
  let current;
  for (const line of String(diff).split('\n')) {
    if (line.startsWith('+++ b/')) {
      current = line.slice(6);
      if (!files.has(current)) files.set(current, new Set());
      continue;
    }
    const match = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
    if (!match || !current) continue;
    const start = Number(match[1]);
    const count = match[2] === undefined ? 1 : Number(match[2]);
    for (let n = start; n < start + count; n += 1) files.get(current).add(n);
  }
  return files;
}

export function assessChangedCoverage(coverage, changes) {
  let coverable = 0;
  let covered = 0;
  const uncovered = [];
  for (const [file, lines] of changes) {
    if (!file.startsWith('src/') || file.endsWith('.test.ts') || file.includes('/__tests__/')) continue;
    const entry = Object.values(coverage).find((item) => String(item.path || '').replaceAll('\\', '/').endsWith(`/${file}`));
    if (!entry) continue;
    for (const line of lines) {
      const statementIds = Object.entries(entry.statementMap || {})
        .filter(([, span]) => line >= span.start.line && line <= span.end.line)
        .map(([id]) => id);
      if (!statementIds.length) continue;
      coverable += 1;
      if (statementIds.some((id) => Number(entry.s?.[id] || 0) > 0)) covered += 1;
      else uncovered.push(`${file}:${line}`);
    }
  }
  return { coverable, covered, percent: coverable ? (covered / coverable) * 100 : 100, uncovered };
}

function selfTest() {
  const changes = changedLines('+++ b/src/a.ts\n@@ -1 +1,3 @@\n+x\n+y\n+z');
  const coverage = { '/repo/src/a.ts': { path: '/repo/src/a.ts', statementMap: { 0: { start: { line: 1 }, end: { line: 1 } }, 1: { start: { line: 2 }, end: { line: 3 } } }, s: { 0: 1, 1: 0 } } };
  const result = assessChangedCoverage(coverage, changes);
  if (result.coverable !== 3 || result.covered !== 1 || Math.round(result.percent) !== 33) throw new Error('changed-line coverage self-test failed');
  console.log('changed-line coverage self-test passed');
}

if (process.argv.includes('--self-test')) {
  selfTest();
} else {
  const base = process.argv[2] || process.env.COVERAGE_BASE;
  const minimum = Number(process.argv[3] || process.env.PR_CHANGED_LINE_COVERAGE || 50);
  if (!base) throw new Error('base revision required as argv[2] or COVERAGE_BASE');
  const diff = execFileSync('git', ['diff', '--unified=0', '--no-ext-diff', `${base}...HEAD`, '--', 'src'], { encoding: 'utf8' });
  const coverage = JSON.parse(readFileSync('coverage-pr/coverage-final.json', 'utf8'));
  const result = assessChangedCoverage(coverage, changedLines(diff));
  console.log(`Changed executable lines: ${result.covered}/${result.coverable} (${result.percent.toFixed(1)}%; required ${minimum}%)`);
  if (result.uncovered.length) console.log(`Uncovered changed lines:\n${result.uncovered.slice(0, 100).join('\n')}`);
  if (result.percent < minimum) process.exitCode = 1;
}
