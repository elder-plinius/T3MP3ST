#!/usr/bin/env node
/**
 * T3MP3ST → Obsidian vault sync.
 *
 * Reads live t3mp3st ledgers + CVE-bench JSON results, writes a folder of
 * markdown notes with frontmatter + wikilinks into the chosen vault.
 * Idempotent: re-running updates existing notes by ID.
 *
 * Usage:
 *   node scripts/obsidian-sync.mjs                          # default vault, one-shot
 *   node scripts/obsidian-sync.mjs --vault ~/MyVault        # explicit vault
 *   node scripts/obsidian-sync.mjs --watch                  # poll every 10s
 *   node scripts/obsidian-sync.mjs --bench-only             # skip live ledgers
 *   node scripts/obsidian-sync.mjs --no-bench               # skip CVE bench
 *   node scripts/obsidian-sync.mjs --api http://127.0.0.1:3333
 *   node scripts/obsidian-sync.mjs --interval 5             # watch interval (sec)
 */

import fs   from 'node:fs';
import path from 'node:path';
import os   from 'node:os';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const REPO       = path.resolve(__dirname, '..');

// ----- args --------------------------------------------------------------

function parseArgs(argv) {
  const a = {
    vault: process.env.OBSIDIAN_VAULT_PATH
        || path.join(os.homedir(), 'Desktop', 'younger_plinius', 'PliniVault'),
    api: process.env.T3MP3ST_API_URL || 'http://127.0.0.1:3333',
    watch: false,
    interval: 10,
    benchOnly: false,
    noBench: false,
    verbose: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if      (k === '--vault')      a.vault = argv[++i];
    else if (k === '--api')        a.api = argv[++i];
    else if (k === '--watch')      a.watch = true;
    else if (k === '--once')       a.watch = false;
    else if (k === '--interval')   a.interval = parseInt(argv[++i], 10);
    else if (k === '--bench-only') a.benchOnly = true;
    else if (k === '--no-bench')   a.noBench = true;
    else if (k === '-v' || k === '--verbose') a.verbose = true;
    else if (k === '-h' || k === '--help')    { help(); process.exit(0); }
  }
  return a;
}

function help() {
  console.log(`T3MP3ST → Obsidian vault sync

Options:
  --vault <path>        Vault root (default: ~/Desktop/younger_plinius/PliniVault)
                        T3MP3ST notes land under <vault>/T3MP3ST/
  --api <url>           t3mp3st base URL (default: http://127.0.0.1:3333)
  --watch               Re-sync on a timer
  --once                One-shot sync (default)
  --interval <sec>      Watch interval (default 10)
  --bench-only          Only sync CVE-bench results, skip live ledgers
  --no-bench            Skip CVE-bench, only live ledgers
  -v, --verbose
  -h, --help
`);
}

// ----- io helpers ---------------------------------------------------------

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function safeName(s) {
  return String(s).replace(/[^a-zA-Z0-9._-]+/g, '-').slice(0, 80);
}

function writeNote(file, content) {
  ensureDir(path.dirname(file));
  // Only rewrite if changed — preserves vault mtime semantics + Obsidian cache
  let prev = '';
  try { prev = fs.readFileSync(file, 'utf8'); } catch {}
  if (prev === content) return false;
  fs.writeFileSync(file, content);
  return true;
}

function fm(obj) {
  // tiny YAML-ish frontmatter writer (we control the input)
  const lines = ['---'];
  const emit = (k, v) => {
    if (v === undefined || v === null) return;
    if (Array.isArray(v)) {
      if (v.length === 0) { lines.push(`${k}: []`); return; }
      lines.push(`${k}:`);
      for (const item of v) lines.push(`  - ${formatScalar(item)}`);
    } else if (typeof v === 'object') {
      lines.push(`${k}:`);
      for (const [kk, vv] of Object.entries(v)) lines.push(`  ${kk}: ${formatScalar(vv)}`);
    } else {
      lines.push(`${k}: ${formatScalar(v)}`);
    }
  };
  for (const [k, v] of Object.entries(obj)) emit(k, v);
  lines.push('---');
  return lines.join('\n');
}

function formatScalar(v) {
  if (v === null || v === undefined) return '';
  if (typeof v === 'string') {
    // quote if it contains YAML-meta chars
    if (/[:#&*!|>'"%@`,\[\]{}]/.test(v) || /^\s|\s$/.test(v) || v === '') {
      return JSON.stringify(v);
    }
    return v;
  }
  return String(v);
}

function wikilink(id, alias) {
  if (!id) return '';
  return alias ? `[[${id}|${alias}]]` : `[[${id}]]`;
}

async function tryGet(url) {
  try {
    const r = await fetch(url);
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

// ----- note builders ------------------------------------------------------

function buildMissionNote(mission, related) {
  const id = mission.id || 'unknown';
  const noteId = `M-${safeName(id).replace(/^M-/, '')}`;
  const findings = related.findings.filter(f => f.missionId === id).map(f => `F-${safeName(f.id || '')}`);
  const evidence = related.evidence.filter(e => e.missionId === id).map(e => `E-${safeName(e.id || '')}`);
  const front = fm({
    type: 't3mp3st-mission',
    id: noteId,
    name: mission.name || mission.codename || id,
    family: mission.family || mission.missionFamily || 'unspecified',
    status: mission.status || 'unknown',
    opsec: mission.opsecLevel || mission.opsec || '',
    started: mission.startedAt || mission.createdAt || '',
    updated: mission.updatedAt || '',
    gate_score: mission.gateScore || mission.score || '',
    gate_status: mission.gateStatus || '',
    findings,
    evidence,
    tags: ['t3mp3st', 'mission', mission.family || 'mission'].filter(Boolean),
  });
  const body = [
    `# Mission: ${mission.name || mission.codename || id}`,
    '',
    `**Family:** ${mission.family || '—'}  `,
    `**Status:** ${mission.status || '—'}  `,
    `**Started:** ${mission.startedAt || mission.createdAt || '—'}`,
    '',
    '## Findings',
    findings.length ? findings.map(f => `- ${wikilink(f)}`).join('\n') : '_none yet_',
    '',
    '## Evidence',
    evidence.length ? evidence.map(e => `- ${wikilink(e)}`).join('\n') : '_none yet_',
    '',
    '## Raw',
    '```json',
    JSON.stringify(mission, null, 2),
    '```',
    '',
  ].join('\n');
  return { id: noteId, content: front + '\n\n' + body };
}

function buildFindingNote(finding) {
  const id = finding.id || 'unknown';
  const noteId = `F-${safeName(id).replace(/^F-/, '')}`;
  const mLink = finding.missionId ? `M-${safeName(finding.missionId).replace(/^M-/, '')}` : null;
  const evidenceLinks = (finding.evidenceIds || []).map(e => `E-${safeName(e).replace(/^E-/, '')}`);
  const cwe = (finding.claim + ' ' + finding.impact + ' ' + finding.title).match(/CWE-\d+/i)?.[0] || '';
  const front = fm({
    type: 't3mp3st-finding',
    id: noteId,
    mission: mLink || '',
    target: finding.target || '',
    severity: finding.severity || 'info',
    confidence: typeof finding.confidence === 'number' ? finding.confidence : null,
    status: finding.status || '',
    created: finding.createdAt || '',
    updated: finding.updatedAt || '',
    cwe: cwe.toUpperCase(),
    evidence: evidenceLinks,
    tags: ['t3mp3st', 'finding', `severity-${finding.severity || 'info'}`],
  });
  const body = [
    `# Finding: ${finding.title || '(untitled)'}`,
    '',
    `**Severity:** ${finding.severity || '—'}  `,
    `**Confidence:** ${finding.confidence ?? '—'}  `,
    `**Status:** ${finding.status || '—'}  `,
    mLink ? `**Mission:** ${wikilink(mLink)}` : '',
    `**Target:** ${finding.target || '—'}`,
    cwe ? `**CWE:** ${cwe}` : '',
    '',
    '## Claim',
    '',
    finding.claim || '_no claim_',
    '',
    '## Impact',
    '',
    finding.impact || '_no impact stated_',
    '',
    '## Evidence',
    evidenceLinks.length ? evidenceLinks.map(e => `- ${wikilink(e)}`).join('\n') : '_none linked_',
    '',
    '## Recommended Fix',
    '',
    finding.recommendedFix || '_n/a_',
    '',
    '## Acceptance Criteria',
    (finding.acceptanceCriteria || []).map(c => `- [ ] ${c}`).join('\n') || '_none_',
    '',
  ].filter(Boolean).join('\n');
  return { id: noteId, content: front + '\n\n' + body };
}

function buildEvidenceNote(evidence) {
  const id = evidence.id || 'unknown';
  const noteId = `E-${safeName(id).replace(/^E-/, '')}`;
  const findingLink = evidence.findingId ? `F-${safeName(evidence.findingId).replace(/^F-/, '')}` : null;
  const missionLink = evidence.missionId ? `M-${safeName(evidence.missionId).replace(/^M-/, '')}` : null;
  const front = fm({
    type: 't3mp3st-evidence',
    id: noteId,
    mission: missionLink || '',
    finding: findingLink || '',
    operation: evidence.operationId || '',
    provenance: evidence.provenance || 'weak',
    source: evidence.source || '',
    created: evidence.createdAt || '',
    tags: ['t3mp3st', 'evidence', `prov-${evidence.provenance || 'weak'}`],
  });
  const body = [
    `# Evidence: ${evidence.title || '(untitled)'}`,
    '',
    `**Provenance:** ${evidence.provenance || 'weak'}  `,
    `**Source:** ${evidence.source || '—'}  `,
    missionLink ? `**Mission:** ${wikilink(missionLink)}` : '',
    findingLink ? `**Finding:** ${wikilink(findingLink)}` : '',
    '',
    '## Summary',
    '',
    evidence.summary || '_no summary_',
    '',
    evidence.command ? '## Command\n\n```bash\n' + evidence.command + '\n```\n' : '',
    evidence.output  ? '## Output\n\n```\n' + String(evidence.output).slice(0, 3000) + '\n```\n' : '',
  ].filter(Boolean).join('\n');
  return { id: noteId, content: front + '\n\n' + body };
}

function buildHypothesisNote(h) {
  const id = h.id || 'unknown';
  const noteId = `H-${safeName(id).replace(/^H-/, '')}`;
  const front = fm({
    type: 't3mp3st-hypothesis',
    id: noteId,
    mission: h.missionId ? `M-${safeName(h.missionId)}` : '',
    status: h.status || '',
    confidence: typeof h.confidence === 'number' ? h.confidence : null,
    created: h.createdAt || '',
    tags: ['t3mp3st', 'hypothesis'],
  });
  return { id: noteId, content: front + '\n\n# Hypothesis: ' + (h.title || '') + '\n\n' + (h.statement || '') };
}

function buildRetestNote(r) {
  const id = r.id || 'unknown';
  const noteId = `R-${safeName(id).replace(/^R-/, '')}`;
  const findingLink = r.findingId ? `F-${safeName(r.findingId)}` : null;
  const front = fm({
    type: 't3mp3st-retest',
    id: noteId,
    finding: findingLink || '',
    status: r.status || r.result || '',
    created: r.createdAt || '',
    tags: ['t3mp3st', 'retest', r.status || r.result || 'pending'],
  });
  return { id: noteId, content: front + '\n\n# Retest: ' + (r.title || id) + (findingLink ? '\n\nLinked finding: ' + wikilink(findingLink) : '') };
}

function buildSitrepNote(s, idx) {
  const ts = s.timestamp || s.createdAt || new Date().toISOString();
  const noteId = `S-${ts.replace(/[:.]/g, '-')}-${idx}`;
  const front = fm({
    type: 't3mp3st-sitrep',
    id: noteId,
    mission: s.missionId ? `M-${safeName(s.missionId)}` : '',
    phase: s.phase || '',
    timestamp: ts,
    tags: ['t3mp3st', 'sitrep'],
  });
  return { id: noteId, content: front + '\n\n# Sitrep ' + ts + '\n\n' + (s.summary || JSON.stringify(s, null, 2)) };
}

function buildMemoryNote(m, idx) {
  const noteId = `MEM-${safeName(m.id || 'mem-' + idx)}`;
  const front = fm({
    type: 't3mp3st-memory',
    id: noteId,
    kind: m.kind || m.type || '',
    confidence: typeof m.confidence === 'number' ? m.confidence : null,
    accepted: !!m.accepted,
    created: m.createdAt || '',
    tags: ['t3mp3st', 'memory', m.kind || 'note'],
  });
  return { id: noteId, content: front + '\n\n# Memory: ' + (m.title || m.id || 'entry') + '\n\n' + (m.body || m.statement || JSON.stringify(m, null, 2)) };
}

// ----- CVE-bench corpus + runs --------------------------------------------

function loadBenchCorpus() {
  const corpusDir = path.join(REPO, 'bench', 'cve-hunt', 'samples');
  if (!fs.existsSync(corpusDir)) return [];
  const entries = [];
  for (const id of fs.readdirSync(corpusDir)) {
    const gtPath = path.join(corpusDir, id, 'ground-truth.yaml');
    if (!fs.existsSync(gtPath)) continue;
    const raw = fs.readFileSync(gtPath, 'utf8');
    entries.push({ id, gtPath, raw });
  }
  return entries;
}

function buildCorpusNote(entry) {
  // minimal frontmatter extraction from the YAML by regex
  const cve = (entry.raw.match(/^cve:\s*(.+)$/m) || [])[1] || entry.id;
  const alias = (entry.raw.match(/^alias:\s*(.+)$/m) || [])[1] || '';
  const cwe = (entry.raw.match(/^cwe_primary:\s*(.+)$/m) || [])[1] || '';
  const severity = (entry.raw.match(/^severity:\s*(.+)$/m) || [])[1] || '';
  const vc = (entry.raw.match(/^vuln_class:\s*(.+)$/m) || [])[1] || '';
  const lang = (entry.raw.match(/^# Language:.*$/m) || [])[1] || '';
  const front = fm({
    type: 'cve-bench-corpus',
    id: entry.id,
    cve, alias, cwe, severity, vuln_class: vc,
    tags: ['cve-bench', 'corpus', (cwe || '').toLowerCase()].filter(Boolean),
  });
  // try to locate source file in sample dir
  const sampleDir = path.join(REPO, 'bench', 'cve-hunt', 'samples', entry.id);
  const files = fs.existsSync(sampleDir) ? fs.readdirSync(sampleDir) : [];
  const sourceFile = files.find(f => /^source\./.test(f));
  const source = sourceFile ? fs.readFileSync(path.join(sampleDir, sourceFile), 'utf8') : '';
  const ext = sourceFile ? sourceFile.split('.').pop() : '';
  const body = [
    `# ${cve} — ${alias}`,
    '',
    `**CWE**: ${cwe}  `,
    `**Severity**: ${severity}  `,
    `**Class**: ${vc}`,
    '',
    '## Ground truth',
    '',
    '```yaml',
    entry.raw,
    '```',
    '',
    sourceFile ? '## Vulnerable source\n\n```' + ext + '\n' + source + '\n```\n' : '',
    '',
    '## Bench history',
    '',
    '```dataview',
    'TABLE timestamp as run, mode, score_percent as score, detected, decoys_caught',
    'FROM "T3MP3ST/CVE-Bench/Runs"',
    `WHERE contains(detected_list, "${entry.id}")`,
    'SORT timestamp DESC',
    '```',
  ].filter(Boolean).join('\n');
  return { id: entry.id, content: front + '\n\n' + body };
}

function buildBenchRunNote(report, fileName) {
  const id = path.basename(fileName, '.json');
  const ts = report.timestamp || new Date().toISOString();
  const agg = report.aggregate || {};
  const samples = report.samples || [];
  const detected = samples.filter(s => s.detected).map(s => s.sample_id);
  const missed   = samples.filter(s => !s.is_decoy && !s.detected).map(s => s.sample_id);
  const decoyHit = samples.filter(s => s.is_decoy && s.findings_count > 0).map(s => s.sample_id);
  const front = fm({
    type: 'cve-bench-run',
    id,
    mode: report.mode || 'unknown',
    model: report.model || '',
    timestamp: ts,
    score_percent: agg.score_percent,
    detected_count: agg.detected,
    missed_count: agg.missed,
    fp_count: agg.decoy_false_positives,
    net_score: agg.net_score,
    f1: agg.f1_score,
    precision: agg.precision,
    recall: agg.recall,
    detected_list: detected,
    missed_list: missed,
    decoys_caught: decoyHit,
    tags: ['cve-bench', 'run', `mode-${report.mode || 'unknown'}`],
  });
  const table = [
    '| Sample | Mode | Detect | Gates | Pts | Judge |',
    '| --- | --- | --- | --- | --- | --- |',
    ...samples.map(s => {
      const sid = s.is_decoy ? s.sample_id : wikilink(s.sample_id);
      const verdict = s.is_decoy
        ? (s.findings_count === 0 ? '✓ clean' : '✗ FP')
        : (s.detected ? '✓' : '✗');
      const gates = s.best_gates ? [
        s.best_gates.file_match      ? 'F' : '·',
        s.best_gates.cwe_match       ? 'C' : '·',
        s.best_gates.line_proximity  ? 'L' : '·',
        s.best_gates.keyword_match   ? 'K' : '·',
        s.best_gates.exploit_pattern ? 'P' : '·',
      ].join('') : '—';
      const pts = s.points_awarded !== undefined ? `${s.points_awarded}/${s.points_possible || 0}` : '—';
      const judge = s.best_judge
        ? `${s.best_judge.valid_vulnerability ? '✓' : '✗'}/eq=${s.best_judge.evidence_quality ?? '?'}`
        : '—';
      return `| ${sid} | ${report.mode} | ${verdict} | ${gates} | ${pts} | ${judge} |`;
    }),
  ].join('\n');
  const body = [
    `# CVE-Bench Run — ${ts}`,
    '',
    `**Mode:** ${report.mode}  `,
    `**Model:** ${report.model || 'stub'}  `,
    `**Score:** ${agg.score_percent}% (net ${agg.net_score}/${agg.points_possible})  `,
    `**Detect:** ${agg.detected}/${agg.real_cves} • **FP:** ${agg.decoy_false_positives} • **F1:** ${agg.f1_score}`,
    '',
    '## Per-sample',
    '',
    table,
    '',
    '## Raw aggregate',
    '',
    '```json',
    JSON.stringify(agg, null, 2),
    '```',
  ].join('\n');
  return { id, content: front + '\n\n' + body };
}

// ----- index page --------------------------------------------------------

function buildIndex() {
  return [
    '---',
    'type: t3mp3st-index',
    'tags: [t3mp3st, index]',
    '---',
    '',
    '# T3MP3ST Operations Hub',
    '',
    'Live mirror of t3mp3st\'s ledgers and CVE-bench runs, auto-synced by',
    '`scripts/obsidian-sync.mjs`.',
    '',
    '## Active missions',
    '',
    '```dataview',
    'TABLE status, family, gate_status, gate_score',
    'FROM "T3MP3ST/Missions"',
    'WHERE status != "completed" AND status != "closed"',
    'SORT updated DESC',
    '```',
    '',
    '## Recent critical findings',
    '',
    '```dataview',
    'TABLE severity, confidence, mission, target',
    'FROM "T3MP3ST/Findings"',
    'WHERE severity = "critical" OR severity = "high"',
    'SORT confidence DESC',
    'LIMIT 20',
    '```',
    '',
    '## CVE-Bench leaderboard (last 25 runs)',
    '',
    '```dataview',
    'TABLE mode, score_percent as "score %", detected_count as detect, fp_count as FP, net_score, f1',
    'FROM "T3MP3ST/CVE-Bench/Runs"',
    'SORT timestamp DESC',
    'LIMIT 25',
    '```',
    '',
    '## CVE-Bench corpus coverage',
    '',
    '```dataview',
    'TABLE cve, alias, cwe, severity, vuln_class',
    'FROM "T3MP3ST/CVE-Bench/Corpus"',
    'SORT cve ASC',
    '```',
    '',
    '## Evidence by provenance (last 50)',
    '',
    '```dataview',
    'TABLE provenance, source, finding',
    'FROM "T3MP3ST/Evidence"',
    'SORT created DESC',
    'LIMIT 50',
    '```',
    '',
    '## Hypotheses awaiting promotion',
    '',
    '```dataview',
    'TABLE status, confidence, mission',
    'FROM "T3MP3ST/Hypotheses"',
    'WHERE status = "open" OR status = "pending"',
    'SORT confidence DESC',
    '```',
    '',
    '## Memory entries',
    '',
    '```dataview',
    'TABLE kind, accepted, confidence',
    'FROM "T3MP3ST/Memory"',
    'SORT created DESC',
    'LIMIT 25',
    '```',
    '',
    '---',
    '',
    '_Re-sync: `npm run obsidian` from the t3mp3st repo. Live-watch: `npm run obsidian:watch`._',
  ].join('\n');
}

// ----- top-level sync ----------------------------------------------------

async function syncOnce(args) {
  const root = path.join(args.vault, 'T3MP3ST');
  ensureDir(root);
  ensureDir(path.join(root, 'Missions'));
  ensureDir(path.join(root, 'Findings'));
  ensureDir(path.join(root, 'Evidence'));
  ensureDir(path.join(root, 'Hypotheses'));
  ensureDir(path.join(root, 'Retests'));
  ensureDir(path.join(root, 'Sitreps'));
  ensureDir(path.join(root, 'Memory'));
  ensureDir(path.join(root, 'Inbox'));
  ensureDir(path.join(root, 'CVE-Bench', 'Corpus'));
  ensureDir(path.join(root, 'CVE-Bench', 'Runs'));

  const stats = {
    missions: 0, findings: 0, evidence: 0, hypotheses: 0,
    retests: 0, sitreps: 0, memory: 0,
    corpus: 0, runs: 0,
  };

  // Live ledgers (best effort — silent if server offline)
  if (!args.benchOnly) {
    const [
      findingsResp, evidenceResp, hypothesesResp, retestsResp,
      sitrepsResp, memoryResp,
    ] = await Promise.all([
      tryGet(`${args.api}/api/findings`),
      tryGet(`${args.api}/api/evidence`),
      tryGet(`${args.api}/api/hypotheses`),
      tryGet(`${args.api}/api/retests`),
      tryGet(`${args.api}/api/general/sitreps`),
      tryGet(`${args.api}/api/memory/capsule`),
    ]);

    const findings   = findingsResp?.findings   || [];
    const evidence   = evidenceResp?.evidence   || [];
    const hypotheses = hypothesesResp?.hypotheses || [];
    const retests    = retestsResp?.retests    || [];
    const sitreps    = sitrepsResp?.sitreps    || [];
    const memory     = memoryResp?.entries     || memoryResp?.memory || [];

    // synthesise missions from finding+evidence (no /api/missions endpoint).
    const missionIds = new Set();
    for (const x of [...findings, ...evidence]) if (x.missionId) missionIds.add(x.missionId);
    const missions = [...missionIds].map(id => ({ id, name: id, status: 'active' }));

    const related = { findings, evidence };
    for (const m of missions) {
      const n = buildMissionNote(m, related);
      writeNote(path.join(root, 'Missions', `${n.id}.md`), n.content);
      stats.missions++;
    }
    for (const f of findings)   { const n = buildFindingNote(f);    writeNote(path.join(root, 'Findings', `${n.id}.md`), n.content); stats.findings++; }
    for (const e of evidence)   { const n = buildEvidenceNote(e);   writeNote(path.join(root, 'Evidence', `${n.id}.md`), n.content); stats.evidence++; }
    for (const h of hypotheses) { const n = buildHypothesisNote(h); writeNote(path.join(root, 'Hypotheses', `${n.id}.md`), n.content); stats.hypotheses++; }
    for (const r of retests)    { const n = buildRetestNote(r);     writeNote(path.join(root, 'Retests', `${n.id}.md`), n.content); stats.retests++; }
    sitreps.forEach((s, i)  => { const n = buildSitrepNote(s, i);   writeNote(path.join(root, 'Sitreps', `${n.id}.md`), n.content); stats.sitreps++; });
    memory.forEach((m, i)   => { const n = buildMemoryNote(m, i);   writeNote(path.join(root, 'Memory', `${n.id}.md`), n.content); stats.memory++; });
  }

  // CVE-bench corpus + runs
  if (!args.noBench) {
    const corpus = loadBenchCorpus();
    for (const entry of corpus) {
      const n = buildCorpusNote(entry);
      writeNote(path.join(root, 'CVE-Bench', 'Corpus', `${n.id}.md`), n.content);
      stats.corpus++;
    }
    const resultsDir = path.join(REPO, 'bench', 'cve-hunt', 'results');
    if (fs.existsSync(resultsDir)) {
      for (const f of fs.readdirSync(resultsDir)) {
        if (!f.endsWith('.json')) continue;
        try {
          const report = JSON.parse(fs.readFileSync(path.join(resultsDir, f), 'utf8'));
          const n = buildBenchRunNote(report, f);
          writeNote(path.join(root, 'CVE-Bench', 'Runs', `${n.id}.md`), n.content);
          stats.runs++;
        } catch (e) {
          if (args.verbose) console.error(`skip ${f}: ${e.message}`);
        }
      }
    }
  }

  // Always-refresh index
  writeNote(path.join(root, '_Index.md'), buildIndex());

  return stats;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.verbose) console.log('args:', args);

  const run = async () => {
    const t0 = Date.now();
    try {
      const s = await syncOnce(args);
      const dur = ((Date.now() - t0) / 1000).toFixed(2);
      const ts = new Date().toISOString().slice(11, 19);
      console.log(`[${ts}] sync ok (${dur}s)  missions=${s.missions} findings=${s.findings} evidence=${s.evidence} hypotheses=${s.hypotheses} retests=${s.retests} sitreps=${s.sitreps} memory=${s.memory} corpus=${s.corpus} runs=${s.runs}  → ${args.vault}/T3MP3ST/`);
    } catch (e) {
      console.error('sync error:', e.message);
    }
  };

  await run();
  if (!args.watch) return;
  console.log(`watching every ${args.interval}s — ctrl-c to stop`);
  setInterval(run, args.interval * 1000);
}

main().catch(e => { console.error('FATAL:', e); process.exit(1); });
