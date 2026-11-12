/**
 * Agent task contract — reproducible tasks, ordered tool-call event streams, explicit grading.
 * Pins: strict task validation (fail closed), event-log invariants (seq order, logical clock,
 * JSONL round-trip), grader criteria (event-policy incl. denied-call budget and
 * artifact hashes), stub-run determinism (byte-identical bundles), negative fixtures (failure
 * criteria actually bite), and Arsenal tap observability (args on executed calls, scope denials).
 */
import { describe, it, expect } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  AGENT_TASK_SCHEMA,
  parseAgentTask,
  type AgentTaskSpec,
  type StubStep,
} from '../benchmark/task-contract.js';
import { classifyDenial, preview, TaskEventLog } from '../benchmark/task-events.js';
import { gradeAgentTask } from '../benchmark/task-grader.js';
import { runAgentTask, StubBackend, tapArsenal, loadAgentTask, type TaskBackend } from '../benchmark/task-runner.js';
import { Arsenal, BUILTIN_TOOLS, EXTERNAL_TOOLS } from '../arsenal/index.js';
import type { ArsenalScope } from '../arsenal/index.js';
import { buildAdapterTools } from '../arsenal/adapter-tools.js';
import { TOOL_ADAPTERS } from '../arsenal/catalog.js';
import type { CustomTool } from '../types/index.js';

const TASKS_DIR = join(import.meta.dirname, '..', '..', 'bench', 'tasks');

function loadCommittedTask(id: string): AgentTaskSpec {
  const task = parseAgentTask(JSON.parse(readFileSync(join(TASKS_DIR, id, 'task.json'), 'utf8')));
  if (!task) throw new Error(`committed task ${id} failed validation`);
  return task;
}

function loadNegativeSteps(id: string, name: string): { expectedOutcome: string; expectFailingCheck?: string; steps: StubStep[] } {
  const raw = JSON.parse(readFileSync(join(TASKS_DIR, id, 'negatives', `${name}.json`), 'utf8'));
  return { expectedOutcome: raw.expectedOutcome, expectFailingCheck: raw.expectFailingCheck, steps: raw.steps };
}

/** Re-validate negative steps through the contract (malformed negatives must not silently pass). */
function taskWithSteps(task: AgentTaskSpec, steps: StubStep[]): AgentTaskSpec {
  const reparsed = parseAgentTask({ ...task, schemaVersion: AGENT_TASK_SCHEMA, stub: { steps } });
  if (!reparsed) throw new Error('negative fixture steps failed contract validation');
  return reparsed;
}

/** Minimal event-policy task: passes when `tool` was called successfully once. */
function oneCallTask(tool: string): AgentTaskSpec {
  const base = loadCommittedTask('egress-receipt-check');
  return { ...base, grader: { kind: 'event-policy', requiredCalls: [{ tool, minCount: 1 }], forbidDeniedCalls: true } };
}

describe('agent task contract validation (fail closed)', () => {
  it('accepts the committed fixtures', () => {
    expect(loadCommittedTask('egress-receipt-check').grader.kind).toBe('event-policy');
  });

  it('rejects malformed specs', () => {
    const good = JSON.parse(readFileSync(join(TASKS_DIR, 'egress-receipt-check', 'task.json'), 'utf8'));
    expect(parseAgentTask({ ...good, schemaVersion: 'other/v9' })).toBeUndefined();
    expect(parseAgentTask({ ...good, id: 'Bad_Id' })).toBeUndefined();
    expect(parseAgentTask({ ...good, timeoutMs: 10 })).toBeUndefined();
    expect(parseAgentTask({ ...good, grader: { kind: 'vibes' } })).toBeUndefined();
    expect(parseAgentTask({ ...good, grader: { kind: 'event-policy', requiredCalls: [] } })).toBeUndefined();
    expect(parseAgentTask({ ...good, stub: { steps: [{ kind: 'rm_rf', tool: 'x' }] } })).toBeUndefined();
  });

  it('rejects traversal and non-hex artifact pins', () => {
    const good = JSON.parse(readFileSync(join(TASKS_DIR, 'egress-receipt-check', 'task.json'), 'utf8'));
    const withTraversal = structuredClone(good);
    withTraversal.grader.artifacts[0].path = '../../etc/passwd';
    expect(parseAgentTask(withTraversal)).toBeUndefined();
    const badHash = structuredClone(good);
    badHash.grader.artifacts[0].sha256 = 'not-a-hash';
    expect(parseAgentTask(badHash)).toBeUndefined();
  });

  it('loadAgentTask loads committed files and fails closed on malformed ones', () => {
    const task = loadAgentTask(join(TASKS_DIR, 'egress-receipt-check', 'task.json'));
    expect(task.id).toBe('egress-receipt-check');
    const bogus = join(tmpdir(), 't3mp3st-bad-task.json');
    writeFileSync(bogus, JSON.stringify({ schemaVersion: 'nope' }));
    expect(() => loadAgentTask(bogus)).toThrow(/not a valid/);
  });
});

describe('agent task event log', () => {
  it('assigns monotonic seq and logical ts, freezes events, and round-trips JSONL', () => {
    const log = new TaskEventLog('demo-task', 'stub');
    log.append({ kind: 'task_started', detail: 'agent-task/v1' });
    log.append({ kind: 'tool_call', tool: 'http_get', parameters: { url: 'https://target.example.com/' }, success: true, durationMs: 12, resultPreview: '200 OK' });
    log.append({ kind: 'task_finished', answer: 'done' });
    expect(log.all.map(e => e.seq)).toEqual([1, 2, 3]);
    expect(log.all.map(e => e.ts)).toEqual([1, 2, 3]);
    expect(Object.isFrozen(log.all[0])).toBe(true);

    const restored = TaskEventLog.fromJsonl(log.toJsonl(), 'demo-task', 'stub');
    expect(restored.all).toEqual(log.all);
  });

  it('rejects corrupt streams: bad JSON, unknown kind, non-continuous seq, foreign task', () => {
    expect(() => TaskEventLog.fromJsonl('not json', 'demo-task', 'stub')).toThrow();
    expect(() => TaskEventLog.fromJsonl(JSON.stringify({ schemaVersion: 't3mp3st_agent_task_event/v1', seq: 1, ts: 1, kind: 'spark', taskId: 'demo-task', backend: 'stub' }), 'demo-task', 'stub')).toThrow();
    const line2 = JSON.stringify({ schemaVersion: 't3mp3st_agent_task_event/v1', seq: 7, ts: 7, kind: 'note', taskId: 'demo-task', backend: 'stub', text: 'x' });
    expect(() => TaskEventLog.fromJsonl(line2, 'demo-task', 'stub')).toThrow(/seq/);
    const foreign = JSON.stringify({ schemaVersion: 't3mp3st_agent_task_event/v1', seq: 1, ts: 1, kind: 'note', taskId: 'other-task', backend: 'stub', text: 'x' });
    expect(() => TaskEventLog.fromJsonl(foreign, 'demo-task', 'stub')).toThrow(/mismatch/);
  });

  it('classifies gate denials and truncates previews', () => {
    expect(classifyDenial('SCOPE DENIED: target ...')).toBe('scope');
    expect(classifyDenial('APPROVAL REQUIRED: ...')).toBe('approval');
    expect(classifyDenial('Validation failed')).toBe('other');
    expect(preview('x'.repeat(600))?.startsWith('x'.repeat(512))).toBe(true);
    expect(preview('x'.repeat(600))?.length).toBeGreaterThan(512);
  });
});

describe('agent task grader', () => {
  const policyTask = loadCommittedTask('egress-receipt-check');

  it('abstention and infrastructure errors are graded as their own outcomes, not failures', async () => {
    const abstain = await runAgentTask(policyTask, new StubBackend({ steps: [{ kind: 'finish', abstain: true }] }));
    expect(abstain.verdict.outcome).toBe('abstain');
    const infra = await runAgentTask(policyTask, new StubBackend({ steps: [{ kind: 'finish', infrastructureError: 'backend crashed' }] }));
    expect(infra.verdict.outcome).toBe('infrastructure_error');
  });

  it('a stream with no task_finished is an infrastructure_error, never a silent pass', async () => {
    const truncated = await runAgentTask(policyTask, new StubBackend({ steps: [{ kind: 'note', text: 'backend hung' }] }));
    expect(truncated.verdict.outcome).toBe('infrastructure_error');
    expect(truncated.verdict.checks.find(c => c.name === 'task_completed')?.passed).toBe(false);
  });
});

describe('agent task runner — committed event-policy task', () => {
  const task = loadCommittedTask('egress-receipt-check');
  const taskStub = task.stub;
  if (!taskStub) throw new Error('egress-receipt-check must carry a stub script');

  it('passes the committed stub run with every check green', async () => {
    const run = await runAgentTask(task, new StubBackend(taskStub));
    expect(run.verdict.outcome).toBe('pass');
    expect(run.verdict.checks.every(c => c.passed)).toBe(true);
    expect(run.verdict.checks.map(c => c.name)).toEqual([
      'no_dropped_events',
      'task_completed',
      'required_call:http_request(url)',
      'required_call:header_analysis(url)',
      'denied_calls_within_budget',
      'artifact:summary.md',
    ]);
    // The bundle is in the workspace: ordered events + verdict.
    const events = readFileSync(run.eventsPath, 'utf8');
    expect(events.split('\n').filter(Boolean)).toHaveLength(run.log.length);
    expect(events).toContain('"kind":"tool_call"');
  });

  it('is byte-reproducible: two runs produce identical events.jsonl and verdict.json', async () => {
    const a = await runAgentTask(task, new StubBackend(taskStub));
    const b = await runAgentTask(task, new StubBackend(taskStub));
    expect(readFileSync(a.eventsPath, 'utf8')).toBe(readFileSync(b.eventsPath, 'utf8'));
    expect(readFileSync(a.verdictPath, 'utf8')).toBe(readFileSync(b.verdictPath, 'utf8'));
  });

  it('required-call matching is argument-aware (url must contain the scoped host)', async () => {
    const steps: StubStep[] = [
      { kind: 'tool_call', tool: 'http_request', parameters: { url: 'https://elsewhere.example.org/' }, durationMs: 10, result: '200' },
      { kind: 'tool_call', tool: 'http_request', parameters: { url: 'https://target.example.com/' }, durationMs: 10, result: '200' },
      { kind: 'tool_call', tool: 'header_analysis', parameters: { url: 'https://target.example.com/' }, durationMs: 5, result: 'ok' },
      { kind: 'write_artifact', path: 'summary.md', content: committedSummary() },
      { kind: 'finish', answer: 'x' },
    ];
    const run = await runAgentTask(task, new StubBackend({ steps }));
    // only ONE of two http_request calls matches the scoped-host arg constraint → required count unmet
    expect(run.verdict.outcome).toBe('fail');
    expect(run.verdict.checks.find(c => c.name === 'required_call:http_request(url)')?.passed).toBe(false);
  });

  it('committed negative fixtures fail on exactly their pinned check', async () => {
    for (const name of ['scope-denial', 'missing-call', 'wrong-artifact']) {
      const neg = loadNegativeSteps('egress-receipt-check', name);
      const run = await runAgentTask(taskWithSteps(task, neg.steps), new StubBackend({ steps: neg.steps }));
      expect(run.verdict.outcome).toBe(neg.expectedOutcome);
      const failed = run.verdict.checks.filter(c => !c.passed).map(c => c.name);
      expect(failed).toContain(neg.expectFailingCheck);
    }
  });
});

function committedSummary(): string {
  const taskJson = JSON.parse(readFileSync(join(TASKS_DIR, 'egress-receipt-check', 'task.json'), 'utf8'));
  const step = (taskJson.stub.steps as { kind: string; path?: string; content?: string }[]).find(s => s.kind === 'write_artifact' && s.path === 'summary.md');
  if (!step?.content) throw new Error('committed summary.md content missing');
  return step.content;
}

describe('review fixes — workspace freshness, crash persistence, lifecycle, reserved names, phantom tools', () => {
  const task = loadCommittedTask('egress-receipt-check');
  const taskStub = task.stub;
  if (!taskStub) throw new Error('egress-receipt-check must carry a stub script');

  it('refuses a contaminated workspace — a stale artifact can never re-pass', async () => {
    const stale = mkdtempSync(join(tmpdir(), 't3mp3st-stale-ws-'));
    writeFileSync(join(stale, 'summary.md'), 'leftover from an earlier run');
    await expect(runAgentTask(task, new StubBackend(taskStub), { workspaceDir: stale }))
      .rejects.toThrow(/not empty/);
    // and a completed run's own bundle directory is non-empty, so a rerun into it refuses too
    const run = await runAgentTask(task, new StubBackend(taskStub));
    await expect(runAgentTask(task, new StubBackend({ steps: taskStub.steps.filter(s => s.kind !== 'write_artifact') }), { workspaceDir: run.workspaceDir }))
      .rejects.toThrow(/not empty/);
  });

  it('a backend exception still persists the partial log and an infrastructure verdict', async () => {
    const exploding: TaskBackend = {
      id: 'boom',
      run: async (_t, log) => {
        log.append({ kind: 'note', text: 'about to explode' });
        throw new Error('backend exploded');
      },
    };
    const run = await runAgentTask(task, exploding);
    expect(run.verdict.outcome).toBe('infrastructure_error');
    expect(run.verdict.checks.find(c => c.name === 'no_infrastructure_error')?.detail).toContain('backend exploded');
    expect(existsSync(run.eventsPath)).toBe(true);
    expect(existsSync(run.verdictPath)).toBe(true);
    expect(run.log.all.some(e => e.kind === 'note')).toBe(true);
    expect(run.log.all.at(-1)).toMatchObject({ kind: 'task_finished', infrastructureError: 'backend exploded' });
  });

  it('a backend that finishes and then throws keeps its verdict — the post-finish throw becomes a note', async () => {
    const late: TaskBackend = {
      id: 'late-boom',
      run: async (_t, log) => {
        log.append({ kind: 'tool_call', tool: 'jwt_decode', parameters: { token: 'x' }, success: true, durationMs: 1, resultPreview: 'payload' });
        log.append({ kind: 'task_finished', answer: 'decoded' });
        throw new Error('cleanup exploded');
      },
    };
    const run = await runAgentTask(oneCallTask('jwt_decode'), late);
    expect(run.verdict.outcome).toBe('pass'); // the finish stands; the throw is not a second finish
    expect(run.log.all.filter(e => e.kind === 'task_finished')).toHaveLength(1);
    expect(run.log.all.at(-1)?.text).toContain('cleanup exploded');
    expect(existsSync(run.eventsPath)).toBe(true);
    expect(existsSync(run.verdictPath)).toBe(true);
  });

  it('exactly one task_started (first) and one task_finished per stream', () => {
    const log = new TaskEventLog('lifecycle-task', 'stub');
    log.append({ kind: 'task_started', detail: 'x' });
    expect(() => log.append({ kind: 'task_started', detail: 'again' })).toThrow(/first event/);
    log.append({ kind: 'task_finished', answer: 'done' });
    expect(() => log.append({ kind: 'task_finished', answer: 'twice' })).toThrow(/once/);
    // mid-stream task_started is also rejected
    const log2 = new TaskEventLog('lifecycle-task', 'stub');
    log2.append({ kind: 'task_started', detail: 'x' });
    expect(() => TaskEventLog.fromJsonl([JSON.stringify({ schemaVersion: 't3mp3st_agent_task_event/v1', seq: 2, ts: 2, kind: 'task_started', taskId: 'lifecycle-task', backend: 'stub', detail: 'x' }), JSON.stringify({ schemaVersion: 't3mp3st_agent_task_event/v1', seq: 1, ts: 1, kind: 'task_started', taskId: 'lifecycle-task', backend: 'stub', detail: 'x' })].join('\n'), 'lifecycle-task', 'stub')).toThrow();
  });

  it('empty answers/results flow end-to-end instead of crashing the logger', async () => {
    const empty: StubStep[] = [
      { kind: 'tool_call', tool: 'jwt_decode', parameters: { token: 'abc' }, durationMs: 1, result: '' },
      { kind: 'finish', answer: '' },
    ];
    const run = await runAgentTask(oneCallTask('jwt_decode'), new StubBackend({ steps: empty }));
    expect(run.verdict.outcome).toBe('pass'); // an empty result/answer is a valid event, not a logger crash
    expect(run.log.all[1]).toMatchObject({ kind: 'tool_call', resultPreview: '' });
  });

  it('stub/grader paths may not shadow the run bundle (events.jsonl / verdict.json)', () => {
    const good = JSON.parse(readFileSync(join(TASKS_DIR, 'egress-receipt-check', 'task.json'), 'utf8'));
    const shadowStub = structuredClone(good);
    (shadowStub.stub.steps as { kind: string; path?: string }[]).find(s => s.kind === 'write_artifact')!.path = 'events.jsonl';
    expect(parseAgentTask(shadowStub)).toBeUndefined();
    const shadowGrader = structuredClone(good);
    shadowGrader.grader.artifacts[0].path = 'verdict.json';
    expect(parseAgentTask(shadowGrader)).toBeUndefined();
  });

  it('every tool named by a committed task is registered or mintable (no phantom tools in tasks)', () => {
    const registered = new Set([...BUILTIN_TOOLS, ...EXTERNAL_TOOLS].map(t => t.name));
    const minted = new Set(
      buildAdapterTools(TOOL_ADAPTERS, {
        runSubprocess: async () => ({ stdout: '', stderr: '', exitCode: 0 }),
        isToolAvailable: async () => true,
        scopeOk: () => true,
        createReportWorkspace: async () => ({ reportBase: '', cleanup: () => Promise.resolve() }),
        readToolReport: async () => '',
      }, new Set()).map(t => t.name),
    );
    const phantoms: string[] = [];
    for (const id of readdirSync(TASKS_DIR)) {
      const taskJson = join(TASKS_DIR, id, 'task.json');
      if (!existsSync(taskJson)) continue;
      const spec = loadAgentTask(taskJson);
      for (const tool of spec.allowedTools ?? []) {
        if (!registered.has(tool) && !minted.has(tool)) phantoms.push(`${id}: allowedTools → ${tool}`);
      }
      if (spec.grader.kind === 'event-policy') {
        for (const req of spec.grader.requiredCalls) {
          if (!registered.has(req.tool) && !minted.has(req.tool)) phantoms.push(`${id}: requiredCalls → ${req.tool}`);
        }
      }
    }
    expect(phantoms, `bench/tasks reference phantom tools: ${phantoms.join(', ')}`).toEqual([]);
  });
});

describe('arsenal tap — observable tool calls from the live gate path', () => {
  const scope: ArsenalScope = { allowedHosts: ['target.example.com'], allowLoopback: true, allowPrivate: true };
  const probe: CustomTool = {
    name: 'probe', description: 'x', category: 'web', parameters: [],
    handler: async () => ({ success: true, output: 'hit' }),
  };

  it('records executed calls with arguments and out-of-scope calls as tool_denied', async () => {
    const ars = new Arsenal();
    ars.register(probe);
    ars.setScope(scope);
    const log = new TaskEventLog('tap-test', 'stub');
    const untap = tapArsenal(ars, log);
    try {
      await ars.execute('probe', { parameters: { url: 'https://target.example.com/x' } });
      await ars.execute('probe', { parameters: { url: 'https://evil.com/x' } });
      await expect(ars.execute('nope', { parameters: {} })).rejects.toThrow();
    } finally {
      untap();
    }
    const events = log.all;
    expect(events[0]).toMatchObject({ kind: 'tool_call', tool: 'probe', success: true, parameters: { url: 'https://target.example.com/x' } });
    expect(events[1]).toMatchObject({ kind: 'tool_denied', tool: 'probe', reason: 'scope' });
    expect(events[1]?.detail).toMatch(/SCOPE DENIED/);
    expect(events[2]).toMatchObject({ kind: 'tool_call', tool: 'nope', success: false });
    // after untap, no further events are recorded (clean teardown)
    await ars.execute('probe', { parameters: { url: 'https://target.example.com/y' } });
    expect(log.all).toHaveLength(3);
  });

  it('the tapped stream grades: an off-scope attempt fails an event-policy run', async () => {
    const ars = new Arsenal();
    ars.register(probe);
    ars.setScope(scope);
    const log = new TaskEventLog('egress-receipt-check', 'stub');
    const untap = tapArsenal(ars, log);
    log.append({ kind: 'task_started', detail: 'agent-task/v1' });
    await ars.execute('probe', { parameters: { url: 'https://target.example.com/' } });
    await ars.execute('probe', { parameters: { url: 'https://evil.com/' } });
    log.append({ kind: 'task_finished', answer: 'done' });
    untap();
    const task = loadCommittedTask('egress-receipt-check');
    const verdict = gradeAgentTask({ ...task, grader: { kind: 'event-policy', requiredCalls: [{ tool: 'probe', minCount: 1 }] } }, log);
    expect(verdict.outcome).toBe('fail');
    expect(verdict.checks.find(c => c.name === 'denied_calls_within_budget')?.passed).toBe(false);
  });

  it('a successful tool with EMPTY output stays a success — instrumentation never flips the result', async () => {
    const ars = new Arsenal();
    const silent: CustomTool = {
      name: 'silent_ok', description: 'succeeds with no output', category: 'web', parameters: [],
      handler: async () => ({ success: true, output: '' }),
    };
    ars.register(silent);
    const log = new TaskEventLog('empty-output-task', 'stub');
    const untap = tapArsenal(ars, log);
    let result;
    try {
      result = await ars.execute('silent_ok', { parameters: { url: 'https://target.example.com/' } });
    } finally {
      untap();
    }
    expect(result.success).toBe(true); // execute() result untouched by the logging subscriber
    const evt = log.all.find(e => e.kind === 'tool_call');
    expect(evt).toMatchObject({ tool: 'silent_ok', success: true, resultPreview: '' });
  });

  it('an over-long (unrecordable) tool name cannot break execute() — and the drop is counted', async () => {
    const ars = new Arsenal();
    const longName = 'x'.repeat(80); // > 64-char tool names are rejected by the event schema
    const log = new TaskEventLog('long-name-task', 'stub');
    const untap = tapArsenal(ars, log);
    try {
      await expect(ars.execute(longName, { parameters: {} })).rejects.toThrow(/not found/i);
    } finally {
      untap();
    }
    // the tap dropped the unrecordable event instead of throwing out of execute()
    expect(log.all.filter(e => e.tool === longName)).toEqual([]);
    // the drop is COUNTED — the stream is known-incomplete, never silently shorter
    expect(log.dropped).toBe(1);
  });

  it('a dropped scope denial grades infrastructure_error — an unloggable denial can never pass', async () => {
    // Register a tool whose name exceeds the event schema limit, so its denial event is
    // unrecordable: the off-scope attempt MUST still fail the run instead of vanishing.
    const ars = new Arsenal();
    const longProbe: CustomTool = {
      name: 'x'.repeat(80), description: 'unrecordable name', category: 'web', parameters: [],
      handler: async () => ({ success: true, output: 'never runs' }),
    };
    ars.register(longProbe);
    ars.setScope({ allowedHosts: ['target.example.com'], allowLoopback: true, allowPrivate: true });
    const backend: TaskBackend = {
      id: 'stub',
      run: async (_task, log) => {
        const untap = tapArsenal(ars, log);
        try {
          await ars.execute(longProbe.name, { parameters: { url: 'https://evil.com/' } }); // scope-denied
          await ars.execute(longProbe.name, { parameters: { url: 'https://target.example.com/' } }); // ok
        } finally {
          untap();
        }
        log.append({ kind: 'task_finished', answer: 'looks complete' });
      },
    };
    const task = loadCommittedTask('egress-receipt-check');
    const permissive = { ...task, grader: { kind: 'event-policy' as const, requiredCalls: [{ tool: longProbe.name, minCount: 1 }] } };
    const run = await runAgentTask(permissive, backend);
    expect(run.verdict.outcome).toBe('infrastructure_error');
    // BOTH long-named-tool events were unrecordable (the denial AND the success)
    expect(run.verdict.droppedEvents).toBe(2);
    expect(run.log.dropped).toBe(2);
    expect(run.verdict.checks.find(c => c.name === 'no_dropped_events')?.passed).toBe(false);
    expect(run.log.all.some(e => e.kind === 'note' && e.text?.includes('dropped 2'))).toBe(true);
  });
});
