/**
 * Agent Task Grader — turns an event stream into an explicit pass/fail verdict.
 *
 * Success AND failure criteria are named checks, so a red verdict says exactly
 * which criterion bit (missing required call, denied call over budget, artifact
 * hash mismatch, wrong flag, abstention, infrastructure error). Outcome taxonomy
 * matches the model-matrix convention: pass | fail | abstain | infrastructure_error.
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import type { AgentTaskSpec, TaskOutcome } from './task-contract.js';
import { sha256Hex } from './task-contract.js';
import type { TaskEvent } from './task-events.js';

export const AGENT_TASK_VERDICT_SCHEMA = 't3mp3st_agent_task_verdict/v1';

export interface GraderCheck {
  name: string;
  passed: boolean;
  detail: string;
}

export interface TaskVerdict {
  schemaVersion: typeof AGENT_TASK_VERDICT_SCHEMA;
  taskId: string;
  backend: string;
  outcome: TaskOutcome;
  checks: GraderCheck[];
  eventCount: number;
  /** Events instrumentation dropped (unloggable). Any drop makes the evidence incomplete. */
  droppedEvents: number;
}

function requiredCallName(tool: string, args?: { key: string }[]): string {
  return args?.length ? `required_call:${tool}(${args.map(a => a.key).join(',')})` : `required_call:${tool}`;
}

function callMatches(event: TaskEvent, tool: string, args?: { key: string; contains: string }[]): boolean {
  if (event.kind !== 'tool_call' || event.tool !== tool || event.success === false) return false;
  if (!args?.length) return true;
  return args.every(({ key, contains }) => {
    const value = event.parameters?.[key];
    return value !== undefined && String(value).includes(contains);
  });
}

/**
 * Grade a finished run. `workspaceDir` (optional) is where the backend wrote
 * artifacts; artifact checks read files from it and compare pinned sha256s.
 * `droppedEvents` (default 0) is the count of events instrumentation could not
 * log: a run with dropped events has incomplete evidence and grades
 * infrastructure_error no matter what the visible stream says (fail closed —
 * e.g. a dropped scope denial must never let an off-scope run pass).
 */
export function gradeAgentTask(task: AgentTaskSpec, events: readonly TaskEvent[], workspaceDir?: string, droppedEvents = 0): TaskVerdict {
  const checks: GraderCheck[] = [];
  if (droppedEvents > 0) {
    checks.push({ name: 'no_dropped_events', passed: false, detail: `instrumentation dropped ${droppedEvents} event(s) — evidence incomplete, refusing to grade` });
    return verdict(task, events, 'infrastructure_error', checks, droppedEvents);
  }
  checks.push({ name: 'no_dropped_events', passed: true, detail: '0 dropped events' });
  const finished = [...events].reverse().find(e => e.kind === 'task_finished');
  const denied = events.filter(e => e.kind === 'tool_denied');

  // A backend that never finished is an infrastructure failure, not a capability miss.
  if (!finished) {
    checks.push({ name: 'task_completed', passed: false, detail: 'no task_finished event in stream' });
    return verdict(task, events, 'infrastructure_error', checks, droppedEvents);
  }
  checks.push({ name: 'task_completed', passed: true, detail: 'task_finished present' });

  if (finished.infrastructureError) {
    checks.push({ name: 'no_infrastructure_error', passed: false, detail: finished.infrastructureError });
    return verdict(task, events, 'infrastructure_error', checks, droppedEvents);
  }

  if (finished.abstained) {
    // Abstention is graded SEPARATELY from failure (model-matrix convention).
    checks.push({ name: 'completed_without_abstention', passed: false, detail: 'agent abstained' });
    return verdict(task, events, 'abstain', checks, droppedEvents);
  }

  const g = task.grader;
  if (g.kind === 'flag-exact') {
    const answer = (finished.answer ?? '').trim();
    checks.push({
      name: 'flag',
      passed: answer === g.flag.trim() && answer.length > 0,
      detail: answer === g.flag.trim() && answer.length > 0 ? 'exact flag match' : 'final answer does not match the committed flag',
    });
  } else {
    for (const req of g.requiredCalls) {
      const count = events.filter(e => callMatches(e, req.tool, req.args)).length;
      checks.push({
        name: requiredCallName(req.tool, req.args),
        passed: count >= req.minCount,
        detail: `${count} matching successful call(s), require >= ${req.minCount}`,
      });
    }
    const budget = g.forbidDeniedCalls === false ? (g.maxDeniedCalls ?? 0) : 0;
    checks.push({
      name: 'denied_calls_within_budget',
      passed: denied.length <= budget,
      detail: `${denied.length} denied call(s), budget ${budget} (${denied.map(d => `${d.tool}:${d.reason}`).join(', ') || 'none'})`,
    });
    for (const art of g.artifacts ?? []) {
      if (!workspaceDir) {
        checks.push({ name: `artifact:${art.path}`, passed: false, detail: 'no workspace directory provided to grader' });
        continue;
      }
      try {
        const actual = sha256Hex(readFileSync(join(workspaceDir, art.path)));
        checks.push({
          name: `artifact:${art.path}`,
          passed: actual === art.sha256,
          detail: actual === art.sha256 ? 'sha256 match' : `sha256 mismatch (got ${actual.slice(0, 12)}…)`,
        });
      } catch {
        checks.push({ name: `artifact:${art.path}`, passed: false, detail: 'artifact file missing from workspace' });
      }
    }
  }

  const passed = checks.every(c => c.passed);
  return verdict(task, events, passed ? 'pass' : 'fail', checks, droppedEvents);
}

function verdict(task: AgentTaskSpec, events: readonly TaskEvent[], outcome: TaskOutcome, checks: GraderCheck[], droppedEvents: number): TaskVerdict {
  return {
    schemaVersion: AGENT_TASK_VERDICT_SCHEMA,
    taskId: task.id,
    backend: events[0]?.backend ?? 'unknown',
    outcome,
    checks,
    eventCount: events.length,
    droppedEvents,
  };
}
