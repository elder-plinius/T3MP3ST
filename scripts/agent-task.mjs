#!/usr/bin/env node
/**
 * T3MP3ST Agent Task CLI — run committed agent tasks and grade them.
 *
 * A task directory (bench/tasks/<id>/) pins the prompt, allowed tools, grader
 * (success AND failure criteria), and optionally a deterministic stub script.
 * Every run produces a self-contained bundle: events.jsonl (ordered event
 * stream — every tool call, every gate denial) + verdict.json (named checks).
 *
 * Backends:
 *   stub    replay the committed script (deterministic, zero network) — default
 *
 * Usage:
 *   node scripts/agent-task.mjs --list
 *   node scripts/agent-task.mjs --task egress-receipt-check [--out DIR]
 *   node scripts/agent-task.mjs --self-test        # all tasks + negative fixtures
 *
 * Requires a build first (harness modules load from dist/): npm run build
 */
import process from 'node:process';
import fs from 'node:fs';
import path from 'node:path';

const TASKS_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', 'bench', 'tasks');

async function loadHarness() {
  try {
    const contract = await import('../dist/benchmark/task-contract.js');
    const runner = await import('../dist/benchmark/task-runner.js');
    return { parseAgentTask: contract.parseAgentTask, loadAgentTask: runner.loadAgentTask, runAgentTask: runner.runAgentTask, StubBackend: runner.StubBackend };
  } catch (e) {
    console.error(`agent-task: could not load harness from dist/ (build first: npm run build). ${e.message}`);
    process.exit(2);
  }
}

function listTaskDirs() {
  return fs.readdirSync(TASKS_DIR, { withFileTypes: true })
    .filter(d => d.isDirectory() && fs.existsSync(path.join(TASKS_DIR, d.name, 'task.json')))
    .map(d => d.name);
}

function negativeFiles(taskId) {
  const dir = path.join(TASKS_DIR, taskId, 'negatives');
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter(f => f.endsWith('.json')).map(f => path.join(dir, f));
}

/** Negative fixture: { note, expectedOutcome, expectFailingCheck, steps }. Steps are validated by re-parsing a synthetic task. */
function loadNegative(taskJson, negativePath) {
  const raw = JSON.parse(fs.readFileSync(negativePath, 'utf8'));
  if (!Array.isArray(raw.steps)) throw new Error(`${negativePath}: missing steps`);
  return { note: raw.note ?? '', expectedOutcome: raw.expectedOutcome, expectFailingCheck: raw.expectFailingCheck, steps: raw.steps, taskJson };
}

async function runSteps({ steps, taskJson, outDir, label }) {
  const { parseAgentTask, runAgentTask, StubBackend } = await loadHarness();
  const task = parseAgentTask({ ...taskJson, stub: { steps }, expectedOutcome: undefined });
  if (!task) throw new Error(`${label}: steps failed task-contract validation`);
  const run = await runAgentTask(task, new StubBackend(task.stub), outDir ? { workspaceDir: outDir } : {});
  return run;
}

function printVerdict(run, label) {
  const icon = run.verdict.outcome === 'pass' ? '✅' : run.verdict.outcome === 'fail' ? '❌' : '⚠️';
  console.log(`  ${icon} ${label} → ${run.verdict.outcome} (${run.verdict.eventCount} events, bundle: ${run.workspaceDir})`);
  for (const c of run.verdict.checks) {
    if (!c.passed) console.log(`     FAILED check ${c.name}: ${c.detail}`);
  }
}

async function main() {
  const args = process.argv.slice(2);
  const flag = name => {
    const i = args.indexOf(`--${name}`);
    return i === -1 ? undefined : args[i + 1];
  };

  if (args.includes('--self-test')) {
    const dirs = listTaskDirs();
    let bad = 0;
    for (const id of dirs) {
      const taskJson = JSON.parse(fs.readFileSync(path.join(TASKS_DIR, id, 'task.json'), 'utf8'));
      // Positive: committed stub must produce the committed expectedOutcome.
      if (taskJson.stub) {
        const run = await runSteps({ steps: taskJson.stub.steps, taskJson, label: id });
        printVerdict(run, `${id} (stub)`);
        if (run.verdict.outcome !== (taskJson.expectedOutcome ?? 'pass')) { console.error(`     expected ${taskJson.expectedOutcome ?? 'pass'}`); bad++; }
      }
      // Negatives: each must fail on its named check — failure criteria bite.
      for (const negPath of negativeFiles(id)) {
        const neg = loadNegative(taskJson, negPath);
        const run = await runSteps({ steps: neg.steps, taskJson, label: path.basename(negPath) });
        printVerdict(run, `${id}/${path.basename(negPath)}`);
        if (run.verdict.outcome !== neg.expectedOutcome) { console.error(`     expected ${neg.expectedOutcome}`); bad++; }
        if (neg.expectFailingCheck && !run.verdict.checks.some(c => !c.passed && c.name === neg.expectFailingCheck)) {
          console.error(`     expected failing check ${neg.expectFailingCheck}`);
          bad++;
        }
      }
    }
    console.log(bad === 0 ? 'agent-task self-test: all committed tasks and negative fixtures graded as pinned' : `agent-task self-test: ${bad} mismatch(es)`);
    process.exit(bad === 0 ? 0 : 1);
  }

  if (args.includes('--list')) {
    for (const id of listTaskDirs()) {
      const { loadAgentTask } = await loadHarness();
      const task = loadAgentTask(path.join(TASKS_DIR, id, 'task.json'));
      console.log(`${id}  [${task.family}] ${task.title} — grader: ${task.grader.kind}${task.stub ? ', stub: yes' : ''}`);
    }
    return;
  }

  const taskId = flag('task');
  if (!taskId) {
    console.error('usage: node scripts/agent-task.mjs --list | --task <id> [--out DIR] | --self-test');
    process.exit(2);
  }
  const { loadAgentTask, runAgentTask, StubBackend } = await loadHarness();
  const task = loadAgentTask(path.join(TASKS_DIR, taskId, 'task.json'));
  if (!task.stub) {
    console.error(`agent-task: task ${taskId} has no committed stub script (live backends: see bench/tasks/README.md)`);
    process.exit(2);
  }
  const outDir = flag('out');
  const run = await runAgentTask(task, new StubBackend(task.stub), outDir ? { workspaceDir: outDir } : {});
  printVerdict(run, `${taskId} (stub)`);
  process.exit(run.verdict.outcome === 'pass' ? 0 : 1);
}

main().catch(e => { console.error(`agent-task: ${e.message}`); process.exit(2); });
