#!/usr/bin/env node
/**
 * model-matrix — build and verify an apples-to-apples model comparison from
 * committed benchmark artifacts. This command never runs models or targets.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_MANIFEST = 'bench/model-matrix/cybench-opus-pass1.manifest.json';
const OUTCOMES = ['success', 'failure', 'abstention', 'infrastructure_error', 'skipped'];

const readJson = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const rel = (file) => path.relative(REPO, file).split(path.sep).join('/');

export function classifyResult(result = {}) {
  const verdict = result.verdict || {};
  const text = `${result.error || ''} ${verdict.reason || ''} ${verdict.disposition || ''}`.toLowerCase();
  if (result.error || verdict.disposition === 'ERROR' || /timeout|connection|infrastructure|spawn|api error|judge error/.test(text)) {
    return 'infrastructure_error';
  }
  if (verdict.detected === true || verdict.score === 1) return 'success';
  if (/refus|abstain|declin|no[- ]action|skipp/.test(text)) return 'abstention';
  return 'failure';
}

export function validateManifest(manifest) {
  if (manifest?.schema !== 't3mp3st.bench.model-matrix-manifest/v1') throw new Error('unsupported manifest schema');
  if (!manifest.id || !manifest.corpus || !manifest.attempt_policy || !manifest.scoring_policy) {
    throw new Error('manifest requires id, corpus, attempt_policy, and scoring_policy');
  }
  if (!Array.isArray(manifest.tasks) || manifest.tasks.length === 0 || new Set(manifest.tasks).size !== manifest.tasks.length) {
    throw new Error('manifest tasks must be a non-empty unique array');
  }
  if (!Array.isArray(manifest.subjects) || manifest.subjects.length < 2) throw new Error('manifest requires at least two subjects');
  const subjectIds = new Set();
  for (const subject of manifest.subjects) {
    for (const field of ['id', 'model', 'provider', 'model_version_or_date', 'harness', 'agent_runtime', 'tool_access', 'target_class', 'run_mode', 'source_dir']) {
      if (!subject[field]) throw new Error(`subject missing ${field}`);
    }
    if (subjectIds.has(subject.id)) throw new Error(`duplicate subject id: ${subject.id}`);
    subjectIds.add(subject.id);
  }
}

function loadTask(subject, taskId, root = REPO) {
  const artifact = path.resolve(root, subject.source_dir, `${subject.file_prefix || ''}${taskId}.json`);
  if (!fs.existsSync(artifact)) {
    return { task_id: taskId, outcome: 'skipped', source_artifact: rel(artifact), reason: 'artifact missing' };
  }
  const data = readJson(artifact);
  if (data.model !== subject.model) throw new Error(`${rel(artifact)} model ${data.model} != ${subject.model}`);
  if (data.hunter !== subject.harness) throw new Error(`${rel(artifact)} harness ${data.hunter} != ${subject.harness}`);
  if (data.schema !== subject.artifact_schema) throw new Error(`${rel(artifact)} schema ${data.schema} != ${subject.artifact_schema}`);
  const result = (data.results || []).find((entry) => entry.id === taskId);
  if (!result) throw new Error(`${rel(artifact)} does not contain task ${taskId}`);
  const outcome = classifyResult(result);
  return {
    task_id: taskId,
    outcome,
    source_artifact: rel(artifact),
    artifact_timestamp: data.timestamp,
    category: result.category || 'unknown',
    duration_sec: typeof result.duration_sec === 'number' ? result.duration_sec : null,
    reason: String(result.error || result.verdict?.reason || ''),
  };
}

export function buildReport(manifestOrPath = DEFAULT_MANIFEST, root = REPO) {
  const manifestPath = typeof manifestOrPath === 'string'
    ? path.resolve(REPO, manifestOrPath)
    : null;
  const manifest = manifestPath ? readJson(manifestPath) : manifestOrPath;
  validateManifest(manifest);
  const rows = manifest.subjects.map((subject) => {
    const tasks = manifest.tasks.map((taskId) => loadTask(subject, taskId, root));
    const outcomes = Object.fromEntries(OUTCOMES.map((outcome) => [outcome, tasks.filter((task) => task.outcome === outcome).length]));
    const attempted = tasks.length - outcomes.skipped;
    return {
      id: subject.id,
      model: subject.model,
      provider: subject.provider,
      model_version_or_date: subject.model_version_or_date,
      harness: subject.harness,
      agent_runtime: subject.agent_runtime,
      tool_access: subject.tool_access,
      target_class: subject.target_class,
      run_mode: subject.run_mode,
      attempt_policy: manifest.attempt_policy,
      scoring_policy: manifest.scoring_policy,
      outcomes,
      attempted,
      success_rate: attempted ? outcomes.success / attempted : 0,
      tasks,
    };
  });
  return {
    schema: 't3mp3st.bench.model-matrix/v1',
    id: manifest.id,
    generated_at: manifest.generated_at,
    source_manifest: manifestPath ? rel(manifestPath) : null,
    corpus: manifest.corpus,
    corpus_size: manifest.tasks.length,
    task_ids: manifest.tasks,
    attempt_policy: manifest.attempt_policy,
    scoring_policy: manifest.scoring_policy,
    comparison_limits: manifest.comparison_limits,
    rows,
  };
}

const pct = (value) => `${(value * 100).toFixed(1)}%`;
const symbol = (outcome) => ({
  success: '✅',
  failure: '❌',
  abstention: '⏸️',
  infrastructure_error: '⚠️',
  skipped: '⏭️',
}[outcome]);

export function renderMarkdown(report) {
  const lines = [
    '# Model / harness benchmark matrix',
    '',
    `Corpus: **${report.corpus}** (${report.corpus_size} tasks) · attempt policy: **${report.attempt_policy}** · scoring: **${report.scoring_policy}**.`,
    '',
    '> This is a system comparison: model + provider + harness + tool access. It does not isolate model capability.',
    '',
    '| model | provider | harness | runtime | tool access | success | failure | abstention | infra error | skipped | rate |',
    '|---|---|---|---|---|---:|---:|---:|---:|---:|---:|',
  ];
  for (const row of report.rows) {
    const o = row.outcomes;
    lines.push(`| ${row.model} | ${row.provider} | ${row.harness} | ${row.agent_runtime} | ${row.tool_access} | ${o.success} | ${o.failure} | ${o.abstention} | ${o.infrastructure_error} | ${o.skipped} | ${pct(row.success_rate)} |`);
  }
  lines.push('', '## Task outcomes', '');
  lines.push(`| task | ${report.rows.map((row) => row.model).join(' | ')} |`);
  lines.push(`|---|${report.rows.map(() => '---').join('|')}|`);
  for (const taskId of report.task_ids) {
    lines.push(`| ${taskId} | ${report.rows.map((row) => {
      const task = row.tasks.find((entry) => entry.task_id === taskId);
      return `[${symbol(task.outcome)} ${task.outcome}](../../${task.source_artifact})`;
    }).join(' | ')} |`);
  }
  lines.push('', '## Limits', '', report.comparison_limits, '',
    'Outcome classes: ✅ success · ❌ benchmark failure · ⏸️ refusal/abstention · ⚠️ infrastructure error · ⏭️ skipped/unavailable.');
  return `${lines.join('\n')}\n`;
}

export function verifyCommitted(manifestPath = DEFAULT_MANIFEST) {
  const manifest = readJson(path.resolve(REPO, manifestPath));
  const report = buildReport(manifestPath);
  const jsonPath = path.resolve(REPO, manifest.output_json);
  const mdPath = path.resolve(REPO, manifest.output_markdown);
  const expectedJson = `${JSON.stringify(report, null, 2)}\n`;
  const expectedMarkdown = renderMarkdown(report);
  return {
    ok: fs.existsSync(jsonPath) && fs.existsSync(mdPath)
      && fs.readFileSync(jsonPath, 'utf8') === expectedJson
      && fs.readFileSync(mdPath, 'utf8') === expectedMarkdown,
    report,
    jsonPath,
    mdPath,
    expectedJson,
    expectedMarkdown,
  };
}

function selfTest() {
  const cases = [
    ['success', classifyResult({ verdict: { detected: true, score: 1 } })],
    ['failure', classifyResult({ verdict: { detected: false, reason: 'mismatch' } })],
    ['abstention', classifyResult({ verdict: { detected: false, reason: 'model refusal' } })],
    ['infrastructure_error', classifyResult({ error: 'request timeout' })],
  ];
  let failed = 0;
  for (const [expected, actual] of cases) {
    const ok = expected === actual;
    console.log(`  ${ok ? '✅' : '❌'} classify ${expected}`);
    if (!ok) failed++;
  }
  try {
    validateManifest({ schema: 'wrong' });
    failed++;
    console.log('  ❌ malformed manifest rejected');
  } catch {
    console.log('  ✅ malformed manifest rejected');
  }
  console.log(`\n${failed ? `❌ ${failed} FAILED` : '✅ ALL PASS'} — model-matrix self-test\n`);
  return failed === 0;
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    args[key] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args['self-test']) process.exit(selfTest() ? 0 : 1);
  const manifestPath = String(args.manifest || DEFAULT_MANIFEST);
  if (args.verify) {
    const result = verifyCommitted(manifestPath);
    console.log(result.ok ? '✅ model matrix verified from committed artifacts' : '❌ model matrix differs from committed artifacts');
    process.exit(result.ok ? 0 : 1);
  }
  const manifest = readJson(path.resolve(REPO, manifestPath));
  const report = buildReport(manifestPath);
  fs.writeFileSync(path.resolve(REPO, manifest.output_json), `${JSON.stringify(report, null, 2)}\n`);
  fs.writeFileSync(path.resolve(REPO, manifest.output_markdown), renderMarkdown(report));
  console.log(`generated ${manifest.output_json} and ${manifest.output_markdown}`);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
