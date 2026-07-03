#!/usr/bin/env node
/**
 * arsenal-doctor.mjs — arsenal readiness report.
 *
 * Answers "which of our specialist tools are actually installed, and exactly how do I install
 * the rest?" — the executable companion to docs/INSTALL_MATRIX.md. Server-first (like
 * scripts/doctor.mjs): it reads GET /api/arsenal/status, which carries per-tool
 * available/status/installHint/category. Groups missing command-ready tools by category and
 * prints the install command for each, so closing the gap is copy-paste.
 *
 * Usage:
 *   node scripts/arsenal-doctor.mjs            human-readable report
 *   node scripts/arsenal-doctor.mjs --json     machine-readable
 *   node scripts/arsenal-doctor.mjs --fix      print only the install commands for missing tools
 *   node scripts/arsenal-doctor.mjs --strict   exit 1 unless every command-ready tool is installed
 */
import process from 'node:process';

const baseUrl = (process.env.T3MP3ST_API_URL || 'http://127.0.0.1:3333').replace(/\/$/, '');
const jsonMode = process.argv.includes('--json');
const fixMode = process.argv.includes('--fix');
const strict = process.argv.includes('--strict');

async function apiGet(path) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    const res = await fetch(`${baseUrl}${path}`, { signal: controller.signal });
    const text = await res.text();
    return { ok: res.ok, status: res.status, data: text ? JSON.parse(text) : {} };
  } finally {
    clearTimeout(timer);
  }
}

function main(status) {
  const tools = Array.isArray(status.tools) ? status.tools : [];
  // command-ready = the agent can actually execute it (safe_command | receipt_required)
  const ready = tools.filter(t => t.execution === 'safe_command' || t.execution === 'receipt_required');
  const installed = ready.filter(t => t.status === 'installed');
  const missing = ready.filter(t => t.status !== 'installed');

  if (fixMode) {
    // de-dupe install hints (several tools share one, e.g. foundry forge/cast)
    const seen = new Set();
    for (const t of missing) {
      const hint = (t.installHint || '').trim();
      if (hint && !seen.has(hint)) { seen.add(hint); console.log(hint); }
    }
    process.exitCode = 0;
    return;
  }

  if (jsonMode) {
    console.log(JSON.stringify({
      baseUrl,
      total: tools.length,
      commandReady: ready.length,
      installed: installed.length,
      missing: missing.map(t => ({ id: t.id, binary: t.binary, category: t.category, installHint: t.installHint })),
      pct: ready.length ? Math.round((installed.length / ready.length) * 100) : 0,
    }, null, 2));
    process.exitCode = strict && missing.length ? 1 : 0;
    return;
  }

  const pct = ready.length ? Math.round((installed.length / ready.length) * 100) : 0;
  console.log(`\n⚔️  T3MP3ST ARSENAL READINESS  —  ${installed.length}/${ready.length} command-ready tools installed (${pct}%)\n`);

  // group by category for the "group of experts" view
  const byCat = {};
  for (const t of ready) (byCat[t.category] = byCat[t.category] || []).push(t);
  for (const cat of Object.keys(byCat).sort()) {
    const list = byCat[cat];
    const marks = list.map(t => (t.status === 'installed' ? `✓${t.id}` : `✗${t.id}`)).join('  ');
    console.log(`  ${cat.padEnd(18)} ${marks}`);
  }

  if (missing.length) {
    console.log(`\n  ── ${missing.length} missing — install commands (or: npm run arsenal:doctor -- --fix) ──`);
    const seen = new Set();
    for (const t of missing) {
      const hint = (t.installHint || 'see docs/INSTALL_MATRIX.md').trim();
      const key = `${t.category}:${hint}`;
      if (seen.has(key)) continue;
      seen.add(key);
      console.log(`    ${t.binary.padEnd(14)} ${hint}`);
    }
    console.log(`\n  Reproducible alternative — the full Kali+ image:  npm run tools:build  (then --tools-image cybench-tools:latest)`);
  } else {
    console.log('\n  ✅ every command-ready tool is installed — full arsenal armed.');
  }
  console.log('');
  process.exitCode = strict && missing.length ? 1 : 0;
}

(async () => {
  try {
    const res = await apiGet('/api/arsenal/status');
    if (!res.ok) throw new Error(`status ${res.status}`);
    main(res.data);
  } catch (e) {
    console.error(`arsenal-doctor: API offline at ${baseUrl} (${e.message}). Start it with \`npm run server\` for live readiness.`);
    console.error('Install reference: docs/INSTALL_MATRIX.md  ·  quick host setup: bash scripts/install-tools.sh --web');
    process.exitCode = 1;
  }
})();
