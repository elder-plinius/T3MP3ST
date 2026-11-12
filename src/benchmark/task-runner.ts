/**
 * Agent Task Runner — executes a task against a backend, producing a graded,
 * self-contained run bundle (events.jsonl + verdict.json) in a workspace dir.
 *
 * Backends implement `TaskBackend`. The stub backend replays a committed script
 * (deterministic, zero network, zero tool execution — CI-safe); live backends
 * wrap a real agent and record observable tool calls into the same event log via
 * `tapArsenal`, so graded streams are comparable across backends.
 */

import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { dirname, join } from 'path';
import type { Arsenal } from '../arsenal/index.js';
import type { AgentTaskSpec, StubScript, StubStep } from './task-contract.js';
import { AGENT_TASK_SCHEMA, parseAgentTask } from './task-contract.js';
import { classifyDenial, preview, TaskEventLog, type TaskEvent } from './task-events.js';
import { gradeAgentTask, type TaskVerdict } from './task-grader.js';

export const AGENT_TASK_RUNNER_VERSION = 'agent-task/v1';

export interface TaskBackend {
  /** Backend label recorded on every event (e.g. "stub", "t3mp3st-server"). */
  readonly id: string;
  /**
   * Drive the task. Must append tool_call/tool_denied/note events to the log
   * and end by appending exactly one task_finished event.
   */
  run(task: AgentTaskSpec, log: TaskEventLog, workspaceDir: string): Promise<void>;
}

export interface RunAgentTaskOptions {
  /** Reuse a directory as the run workspace (created if missing). Default: fresh temp dir. */
  workspaceDir?: string;
  /** Logical clock for the event log. Default: ts === seq (fully deterministic). */
  now?: (seq: number) => number;
}

export interface AgentTaskRun {
  verdict: TaskVerdict;
  log: TaskEventLog;
  workspaceDir: string;
  eventsPath: string;
  verdictPath: string;
}

/** Deterministic scripted backend — the reproducible CI/self-test path. */
export class StubBackend implements TaskBackend {
  readonly id = 'stub';
  constructor(private readonly script: StubScript) {}

  async run(_task: AgentTaskSpec, log: TaskEventLog, workspaceDir: string): Promise<void> {
    for (const step of this.script.steps) {
      stubStep(step, log, workspaceDir);
    }
  }
}

function stubStep(step: StubStep, log: TaskEventLog, workspaceDir: string): void {
  switch (step.kind) {
    case 'tool_call':
      log.append({
        kind: 'tool_call',
        tool: step.tool,
        ...(step.parameters ? { parameters: step.parameters } : {}),
        ...(step.success !== undefined ? { success: step.success } : {}),
        ...(step.durationMs !== undefined ? { durationMs: step.durationMs } : {}),
        ...(step.result !== undefined ? { resultPreview: preview(step.result) } : {}),
      });
      break;
    case 'tool_denied':
      log.append({
        kind: 'tool_denied',
        tool: step.tool,
        ...(step.parameters ? { parameters: step.parameters } : {}),
        reason: step.reason,
        ...(step.detail ? { detail: preview(step.detail) } : {}),
      });
      break;
    case 'write_artifact': {
      const target = join(workspaceDir, step.path);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, step.content);
      break;
    }
    case 'note':
      log.append({ kind: 'note', text: step.text });
      break;
    case 'finish':
      log.append({
        kind: 'task_finished',
        ...(step.answer !== undefined ? { answer: step.answer } : {}),
        ...(step.abstain !== undefined ? { abstained: step.abstain } : {}),
        ...(step.infrastructureError !== undefined ? { infrastructureError: step.infrastructureError } : {}),
      });
      break;
  }
}

/**
 * Run a task to a graded verdict. The workspace directory always receives the
 * full run bundle: events.jsonl (ordered event stream) and verdict.json (named
 * pass/fail checks + outcome).
 *
 * A provided workspaceDir must be EMPTY (or nonexistent): a leftover artifact from an
 * earlier run could satisfy an artifact check and produce a false pass.
 *
 * A backend that throws still gets a persisted bundle — the runner appends a
 * task_finished(infrastructureError) event, grades, and returns an
 * infrastructure_error verdict so the partial evidence is diagnosable.
 */
export async function runAgentTask(
  task: AgentTaskSpec,
  backend: TaskBackend,
  opts: RunAgentTaskOptions = {},
): Promise<AgentTaskRun> {
  const workspaceDir = opts.workspaceDir ?? mkdtempSync(join(tmpdir(), `t3mp3st-agent-task-${task.id}-`));
  if (existsSync(workspaceDir)) {
    const existing = readdirSync(workspaceDir);
    if (existing.length > 0) {
      throw new Error(`agent-task: workspace '${workspaceDir}' is not empty — refusing to grade into a possibly contaminated directory (use a fresh directory)`);
    }
  }
  mkdirSync(workspaceDir, { recursive: true });
  const log = new TaskEventLog(task.id, backend.id, opts.now);
  log.append({ kind: 'task_started', detail: AGENT_TASK_RUNNER_VERSION });

  try {
    await backend.run(task, log, workspaceDir);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // If the backend already finished, the finish stands (the run completed per contract);
    // the post-finish throw is preserved as a note instead of a second, illegal finish.
    if (!log.all.some(e => e.kind === 'task_finished')) {
      log.append({ kind: 'task_finished', infrastructureError: message.slice(0, 512) || 'backend threw' });
    } else {
      log.append({ kind: 'note', text: `backend threw after task_finished: ${message.slice(0, 400)}` });
    }
  }
  if (log.dropped > 0) {
    log.append({ kind: 'note', text: `instrumentation dropped ${log.dropped} event(s) — evidence incomplete` });
  }

  const eventsPath = join(workspaceDir, 'events.jsonl');
  const verdictPath = join(workspaceDir, 'verdict.json');
  writeFileSync(eventsPath, log.toJsonl());
  const verdict = gradeAgentTask(task, log, workspaceDir);
  writeFileSync(verdictPath, JSON.stringify(verdict, null, 2) + '\n');
  return { verdict, log, workspaceDir, eventsPath, verdictPath };
}

/** Load + strictly validate a task.json from disk (fail closed on malformed files). */
export function loadAgentTask(path: string): AgentTaskSpec {
  const task = parseAgentTask(JSON.parse(readFileSync(path, 'utf8')));
  if (!task) throw new Error(`agent-task: ${path} is not a valid ${AGENT_TASK_SCHEMA} task`);
  return task;
}

/**
 * Mirror every Arsenal tool call into the task event log: executed calls become
 * tool_call events (tool, parameters, success, durationMs, result preview) and
 * pre-execution refusals become tool_denied events with the gate that refused
 * (scope/approval). Returns an unsubscribe function.
 */
export function tapArsenal(arsenal: Arsenal, log: TaskEventLog): () => void {
  // Instrumentation MUST NOT change what execute() returns: a throwing subscriber inside
  // Arsenal's 'tool:executed' emit would flip a success into an ExecutionError, and inside a
  // denial emit would replace the SCOPE DENIED result with an exception. Swallow logging
  // faults here (the event is dropped, the tool result is untouched).
  const guarded = (record: () => void): void => {
    try {
      record();
    } catch {
      /* drop the event, never the tool result — but never grade a run with holes */
      log.noteDropped();
    }
  };
  const onExecuted = (e: { tool: { name: string }; result: { success: boolean; output?: string; error?: string }; durationMs: number; parameters?: Record<string, unknown> }): void => {
    guarded(() => log.append({
      kind: 'tool_call',
      tool: e.tool.name,
      ...(e.parameters ? { parameters: e.parameters } : {}),
      success: e.result.success,
      durationMs: e.durationMs,
      ...(e.result.output !== undefined ? { resultPreview: preview(e.result.output) } : {}),
      ...(e.result.error !== undefined ? { errorPreview: preview(e.result.error) } : {}),
    }));
  };
  const onError = (e: { tool: { name: string }; error: Error; parameters?: Record<string, unknown> }): void => {
    guarded(() => {
      const reason = classifyDenial(e.error.message);
      const shared = {
        tool: e.tool.name,
        ...(e.parameters ? { parameters: e.parameters } : {}),
      };
      if (reason === 'other') {
        log.append({ kind: 'tool_call', ...shared, success: false, errorPreview: preview(e.error.message) });
      } else {
        log.append({ kind: 'tool_denied', ...shared, reason, detail: preview(e.error.message) });
      }
    });
  };
  arsenal.on('tool:executed', onExecuted);
  arsenal.on('tool:error', onError);
  return () => {
    arsenal.off('tool:executed', onExecuted);
    arsenal.off('tool:error', onError);
  };
}

export type { TaskEvent };
