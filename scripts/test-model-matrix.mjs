#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildReport, classifyResult, validateManifest } from './model-matrix.mjs';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 't3mp3st-model-matrix-'));
const write = (relative, value) => {
  const file = path.join(root, relative);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value));
};
const artifact = (model, task, verdict, error = null) => ({
  schema: 'fixture/v1',
  timestamp: '2026-07-20T00:00:00.000Z',
  model,
  hunter: 'fixture-harness',
  results: [{ id: task, category: 'fixture', verdict, error, duration_sec: 1 }],
});
const subject = (id, model, dir) => ({
  id,
  model,
  provider: 'fixture-provider',
  model_version_or_date: 'fixture',
  harness: 'fixture-harness',
  artifact_schema: 'fixture/v1',
  agent_runtime: 'fixture-runtime',
  tool_access: 'mocked',
  target_class: 'static_fixture',
  run_mode: 'single_agent',
  source_dir: dir,
});
const manifest = {
  schema: 't3mp3st.bench.model-matrix-manifest/v1',
  id: 'fixture',
  generated_at: '2026-07-20T00:00:00.000Z',
  corpus: 'fixture corpus',
  attempt_policy: 'pass@1',
  scoring_policy: 'fixture strict',
  comparison_limits: 'offline fixture only',
  tasks: ['task-a', 'task-b'],
  subjects: [subject('a', 'model-a', 'a'), subject('b', 'model-b', 'b')],
};

try {
  write('a/task-a.json', artifact('model-a', 'task-a', { detected: true, score: 1 }));
  write('a/task-b.json', artifact('model-a', 'task-b', { detected: false, reason: 'model refusal' }));
  write('b/task-a.json', artifact('model-b', 'task-a', { detected: false, reason: 'mismatch' }));
  // b/task-b intentionally missing: proves unavailable artifacts remain "skipped".
  const report = buildReport(manifest, root);
  assert.equal(report.rows.length, 2);
  assert.deepEqual(report.rows[0].outcomes, {
    success: 1, failure: 0, abstention: 1, infrastructure_error: 0, skipped: 0,
  });
  assert.deepEqual(report.rows[1].outcomes, {
    success: 0, failure: 1, abstention: 0, infrastructure_error: 0, skipped: 1,
  });
  assert.equal(classifyResult({ error: 'spawn failed' }), 'infrastructure_error');
  assert.throws(() => validateManifest({ schema: 'invalid' }), /unsupported manifest schema/);

  write('b/task-a.json', artifact('wrong-model', 'task-a', { detected: true }));
  assert.throws(() => buildReport(manifest, root), /model wrong-model != model-b/);
  console.log('✅ model-matrix fixture aggregation, incomplete artifacts, and malformed receipts pass');
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
