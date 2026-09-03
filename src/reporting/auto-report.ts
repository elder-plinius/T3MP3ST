/**
 * Auto-report generator — writes a markdown engagement report to reports/
 * when a mission completes. No-op when the reports dir can't be written
 * (best-effort, never breaks the mission).
 */

import { mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import type { Finding, Target, Mission } from '../types/index.js';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function esc(text: string): string {
  return String(text ?? '').replace(/[\\`*_{}[\]()#+\-.!|>]/g, (c) => '\\' + c);
}

function findingLine(f: Finding): string[] {
  const lines: string[] = [];
  const verified = f.verifyGate?.passed ? '✅ verified' : `⚠️ unverified (${f.verifyGate?.provenance ?? 'none'})`;
  const asserted = f.assertedSeverity && f.assertedSeverity !== f.severity ? ` (asserted: ${f.assertedSeverity})` : '';
  lines.push(`- **[${f.severity.toUpperCase()}] ${esc(f.title)}** — ${verified}${asserted}`);
  if (f.description) lines.push(`  - Описание: ${esc(f.description)}`);
  if (f.cve?.length) lines.push(`  - CVE: ${f.cve.join(', ')}`);
  if (f.cwe?.length) lines.push(`  - CWE: ${f.cwe.join(', ')}`);
  if (f.remediation) lines.push(`  - Ремедиация: ${esc(f.remediation)}`);
  for (const ev of f.evidence?.slice(0, 3) ?? []) {
    const snippet = String(ev.content || '').replace(/\s+/g, ' ').slice(0, 180);
    if (snippet) lines.push(`  - Evidence (${ev.type}): \`${esc(snippet)}\``);
  }
  return lines;
}

export function buildMissionReport(mission: Mission, findings: Finding[], targets: Target[]): string {
  const out: string[] = [];
  out.push(`# Отчёт по миссии: ${mission.name}`);
  out.push('');
  out.push(`- **Статус**: ${mission.status}`);
  out.push(`- **Финальная фаза**: ${mission.currentPhase}`);
  out.push(`- **Начало**: ${mission.startedAt ? new Date(mission.startedAt).toISOString() : '—'}`);
  if (mission.completedAt) out.push(`- **Завершение**: ${new Date(mission.completedAt).toISOString()}`);
  out.push('');

  out.push('## Цели');
  out.push('');
  if (targets.length === 0) out.push('_нет целей_');
  for (const t of targets) {
    out.push(`- ${t.address} (${t.type}, zone: ${t.zone}, status: ${t.status})`);
  }
  out.push('');

  const bySeverity = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = f.severity;
    if (!bySeverity.has(key)) bySeverity.set(key, []);
    bySeverity.get(key)!.push(f);
  }

  out.push(`## Находки (${findings.length})`);
  out.push('');
  if (findings.length === 0) {
    out.push('_уязвимостей не обнаружено_');
  }
  for (const sev of SEVERITY_ORDER) {
    const group = bySeverity.get(sev);
    if (!group?.length) continue;
    out.push(`### ${sev.toUpperCase()} (${group.length})`);
    out.push('');
    for (const f of group) out.push(...findingLine(f));
    out.push('');
  }

  out.push('---');
  out.push('*Сгенерировано автоматически T3MP3ST после завершения миссии.*');
  return out.join('\n');
}

export function writeMissionReport(reportsDir: string, mission: Mission, findings: Finding[], targets: Target[]): string | null {
  try {
    mkdirSync(reportsDir, { recursive: true });
    const safeName = mission.name.replace(/[^a-zA-Z0-9-_]+/g, '_').slice(0, 60) || 'mission';
    const file = join(reportsDir, `${safeName}-${Date.now()}.md`);
    writeFileSync(file, buildMissionReport(mission, findings, targets), 'utf8');
    return file;
  } catch {
    return null;
  }
}
