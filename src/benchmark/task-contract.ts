/**
 * Agent Task Contract — reproducible agent tasks with graders (schema v1).
 *
 * A task is a committed, self-contained directory (bench/tasks/<id>/) that pins:
 *   - the prompt and allowed tools handed to the agent,
 *   - the grader: what counts as PASS and what counts as FAIL, and
 *   - (optionally) a deterministic stub script that replays a scripted run.
 *
 * Everything is validated strictly (fail-closed, same style as mission recovery
 * snapshots): a malformed task never silently grades. Combined with the logical
 * event clock in task-events.ts, a stub run is byte-reproducible: same task in,
 * same events.jsonl and verdict.json out, on any machine.
 */

import { createHash } from 'crypto';

export const AGENT_TASK_SCHEMA = 't3mp3st_agent_task/v1';

export const TASK_OUTCOMES = ['pass', 'fail', 'abstain', 'infrastructure_error'] as const;
export type TaskOutcome = (typeof TASK_OUTCOMES)[number];

// ── Graders ──────────────────────────────────────────────────────────────────

/** CTF-shaped grading: the agent's final answer must exactly match the flag. */
export interface FlagExactGrader {
  kind: 'flag-exact';
  /** Canonical flag; compared after trim() against the task_finished answer. */
  flag: string;
}

/** One required tool-call shape the event stream must contain. */
export interface RequiredCallSpec {
  tool: string;
  /** Minimum number of matching successful calls (default 1). */
  minCount: number;
  /** Every entry must match: String(parameters[key]).includes(contains). */
  args?: { key: string; contains: string }[];
}

/** A file the agent must have produced in the run workspace, pinned by hash. */
export interface ArtifactSpec {
  path: string;
  sha256: string;
}

/**
 * Process-shaped grading: the ordered tool-call event log IS the deliverable.
 * PASS requires every requiredCall to be satisfied by in-scope successful
 * calls, denied calls within budget, and every artifact byte-identical.
 */
export interface EventPolicyGrader {
  kind: 'event-policy';
  requiredCalls: RequiredCallSpec[];
  /** Default true: any tool_denied event fails the run. */
  forbidDeniedCalls?: boolean;
  /** Allowed number of tool_denied events when forbidDeniedCalls is false (default 0). */
  maxDeniedCalls?: number;
  artifacts?: ArtifactSpec[];
}

export type TaskGraderSpec = FlagExactGrader | EventPolicyGrader;

// ── Deterministic stub backend script ────────────────────────────────────────

export type StubStep =
  | {
      kind: 'tool_call';
      tool: string;
      parameters?: Record<string, unknown>;
      success?: boolean;
      durationMs?: number;
      result?: string;
    }
  | {
      /** A call the egress/approval gate refused — replayed as a tool_denied event. */
      kind: 'tool_denied';
      tool: string;
      parameters?: Record<string, unknown>;
      reason: 'scope' | 'approval';
      detail?: string;
    }
  | { kind: 'write_artifact'; path: string; content: string }
  | { kind: 'note'; text: string }
  | { kind: 'finish'; answer?: string; abstain?: boolean; infrastructureError?: string };

export interface StubScript {
  steps: StubStep[];
}

// ── Task spec ────────────────────────────────────────────────────────────────

export interface AgentTaskSpec {
  schemaVersion: typeof AGENT_TASK_SCHEMA;
  id: string;
  title: string;
  /** Mission family label (web_api, ctf, code_supply_chain, ...) for grouping. */
  family: string;
  prompt: string;
  /** Tool names the agent may call. Empty/omitted = unrestricted (documented). */
  allowedTools?: string[];
  /** Hard wall-clock budget for a live run. */
  timeoutMs: number;
  /**
   * Outcome a correct harness must produce for the committed stub script.
   * Used by tests and `agent-task --self-test` to pin BOTH success and failure
   * criteria — a negative fixture carries expectedOutcome: "fail".
   */
  expectedOutcome?: TaskOutcome;
  grader: TaskGraderSpec;
  stub?: StubScript;
}

// ── Validation helpers ───────────────────────────────────────────────────────

const idPattern = /^[a-z0-9][a-z0-9-]{1,63}$/;
const toolPattern = /^[a-z0-9_]{1,64}$/;
const argKeyPattern = /^[a-zA-Z0-9_.-]{1,64}$/;
const sha256Pattern = /^[0-9a-f]{64}$/;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function str(v: unknown, min: number, max: number): string | undefined {
  if (typeof v !== 'string' || v.length < min || v.length > max) return undefined;
  return v;
}

/** Relative, traversal-free path inside the run workspace. */
export function isSafeRelPath(p: unknown): p is string {
  if (typeof p !== 'string' || p.length < 1 || p.length > 200) return false;
  if (p.includes('\\') || p.includes('\0')) return false;
  if (p.startsWith('/') || /^[a-zA-Z]:/.test(p)) return false;
  const parts = p.split('/');
  return parts.every(part => part.length >= 1 && part !== '.' && part !== '..');
}

function parseArgsChecks(v: unknown): { key: string; contains: string }[] | undefined {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > 8) return undefined;
  const out: { key: string; contains: string }[] = [];
  for (const raw of v) {
    if (!isRecord(raw)) return undefined;
    const key = str(raw.key, 1, 64);
    const contains = str(raw.contains, 1, 256);
    if (!key || !argKeyPattern.test(key) || !contains) return undefined;
    out.push({ key, contains });
  }
  return out;
}

function parseGrader(v: unknown): TaskGraderSpec | undefined {
  if (!isRecord(v)) return undefined;
  if (v.kind === 'flag-exact') {
    const flag = str(v.flag, 1, 512);
    if (!flag) return undefined;
    return { kind: 'flag-exact', flag };
  }
  if (v.kind === 'event-policy') {
    if (!Array.isArray(v.requiredCalls) || v.requiredCalls.length < 1 || v.requiredCalls.length > 16) return undefined;
    const requiredCalls: RequiredCallSpec[] = [];
    for (const raw of v.requiredCalls) {
      if (!isRecord(raw)) return undefined;
      const tool = str(raw.tool, 1, 64);
      if (!tool || !toolPattern.test(tool)) return undefined;
      const minCount = raw.minCount === undefined ? 1 : raw.minCount;
      if (typeof minCount !== 'number' || !Number.isInteger(minCount) || minCount < 1 || minCount > 1000) return undefined;
      const args = parseArgsChecks(raw.args);
      if (args === undefined) return undefined;
      requiredCalls.push(args.length ? { tool, minCount, args } : { tool, minCount });
    }
    let forbidDeniedCalls = true;
    if (v.forbidDeniedCalls !== undefined) {
      if (typeof v.forbidDeniedCalls !== 'boolean') return undefined;
      forbidDeniedCalls = v.forbidDeniedCalls;
    }
    let maxDeniedCalls = 0;
    if (v.maxDeniedCalls !== undefined) {
      if (typeof v.maxDeniedCalls !== 'number' || !Number.isInteger(v.maxDeniedCalls) || v.maxDeniedCalls < 0 || v.maxDeniedCalls > 100) return undefined;
      maxDeniedCalls = v.maxDeniedCalls;
    }
    let artifacts: ArtifactSpec[] | undefined;
    if (v.artifacts !== undefined) {
      if (!Array.isArray(v.artifacts) || v.artifacts.length > 16) return undefined;
      artifacts = [];
      for (const raw of v.artifacts) {
        if (!isRecord(raw) || !isSafeRelPath(raw.path)) return undefined;
        if (typeof raw.sha256 !== 'string' || !sha256Pattern.test(raw.sha256)) return undefined;
        artifacts.push({ path: raw.path, sha256: raw.sha256 });
      }
    }
    const grader: EventPolicyGrader = { kind: 'event-policy', requiredCalls, forbidDeniedCalls };
    if (!forbidDeniedCalls) grader.maxDeniedCalls = maxDeniedCalls;
    if (artifacts) grader.artifacts = artifacts;
    return grader;
  }
  return undefined;
}

function parseStub(v: unknown): StubScript | undefined {
  if (!isRecord(v) || !Array.isArray(v.steps) || v.steps.length < 1 || v.steps.length > 1000) return undefined;
  const steps: StubStep[] = [];
  for (const raw of v.steps) {
    if (!isRecord(raw)) return undefined;
    switch (raw.kind) {
      case 'tool_call': {
        const tool = str(raw.tool, 1, 64);
        if (!tool || !toolPattern.test(tool)) return undefined;
        if (raw.parameters !== undefined && !isRecord(raw.parameters)) return undefined;
        if (raw.success !== undefined && typeof raw.success !== 'boolean') return undefined;
        const durationMs = raw.durationMs;
        if (durationMs !== undefined && (typeof durationMs !== 'number' || !Number.isInteger(durationMs) || durationMs < 0 || durationMs > 3_600_000)) return undefined;
        if (raw.result !== undefined && str(raw.result, 0, 4096) === undefined) return undefined;
        steps.push({
          kind: 'tool_call',
          tool,
          ...(raw.parameters ? { parameters: raw.parameters as Record<string, unknown> } : {}),
          ...(raw.success !== undefined ? { success: raw.success } : {}),
          ...(durationMs !== undefined ? { durationMs } : {}),
          ...(raw.result !== undefined ? { result: raw.result as string } : {}),
        });
        break;
      }
      case 'tool_denied': {
        const tool = str(raw.tool, 1, 64);
        if (!tool || !toolPattern.test(tool)) return undefined;
        if (raw.reason !== 'scope' && raw.reason !== 'approval') return undefined;
        if (raw.parameters !== undefined && !isRecord(raw.parameters)) return undefined;
        if (raw.detail !== undefined && str(raw.detail, 0, 512) === undefined) return undefined;
        steps.push({
          kind: 'tool_denied',
          tool,
          reason: raw.reason,
          ...(raw.parameters ? { parameters: raw.parameters as Record<string, unknown> } : {}),
          ...(raw.detail !== undefined ? { detail: raw.detail as string } : {}),
        });
        break;
      }
      case 'write_artifact': {
        if (!isSafeRelPath(raw.path)) return undefined;
        const content = str(raw.content, 0, 65_536);
        if (content === undefined) return undefined;
        steps.push({ kind: 'write_artifact', path: raw.path, content });
        break;
      }
      case 'note': {
        const text = str(raw.text, 1, 4096);
        if (!text) return undefined;
        steps.push({ kind: 'note', text });
        break;
      }
      case 'finish': {
        if (raw.answer !== undefined && str(raw.answer, 0, 4096) === undefined) return undefined;
        if (raw.abstain !== undefined && typeof raw.abstain !== 'boolean') return undefined;
        if (raw.infrastructureError !== undefined && str(raw.infrastructureError, 1, 512) === undefined) return undefined;
        steps.push({
          kind: 'finish',
          ...(raw.answer !== undefined ? { answer: raw.answer as string } : {}),
          ...(raw.abstain !== undefined ? { abstain: raw.abstain } : {}),
          ...(raw.infrastructureError !== undefined ? { infrastructureError: raw.infrastructureError as string } : {}),
        });
        break;
      }
      default:
        return undefined;
    }
  }
  return { steps };
}

/**
 * Strictly validate an agent task spec. Returns undefined (never throws) on any
 * malformed field so callers can fail closed on untrusted task files.
 */
export function parseAgentTask(value: unknown): AgentTaskSpec | undefined {
  if (!isRecord(value) || value.schemaVersion !== AGENT_TASK_SCHEMA) return undefined;
  const id = str(value.id, 3, 64);
  if (!id || !idPattern.test(id)) return undefined;
  const title = str(value.title, 1, 200);
  if (!title) return undefined;
  const family = str(value.family, 1, 64);
  if (!family) return undefined;
  const prompt = str(value.prompt, 1, 8000);
  if (!prompt) return undefined;
  if (value.allowedTools !== undefined) {
    if (!Array.isArray(value.allowedTools) || value.allowedTools.length > 64) return undefined;
    for (const t of value.allowedTools) {
      if (typeof t !== 'string' || !toolPattern.test(t)) return undefined;
    }
  }
  const timeoutMs = value.timeoutMs === undefined ? 600_000 : value.timeoutMs;
  if (typeof timeoutMs !== 'number' || !Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 36_000_000) return undefined;
  let expectedOutcome: TaskOutcome | undefined;
  if (value.expectedOutcome !== undefined) {
    if (!TASK_OUTCOMES.includes(value.expectedOutcome as TaskOutcome)) return undefined;
    expectedOutcome = value.expectedOutcome as TaskOutcome;
  }
  const grader = parseGrader(value.grader);
  if (!grader) return undefined;
  let stub: StubScript | undefined;
  if (value.stub !== undefined) {
    stub = parseStub(value.stub);
    if (!stub) return undefined;
  }
  return {
    schemaVersion: AGENT_TASK_SCHEMA,
    id,
    title,
    family,
    prompt,
    ...(value.allowedTools ? { allowedTools: value.allowedTools as string[] } : {}),
    timeoutMs,
    ...(expectedOutcome ? { expectedOutcome } : {}),
    grader,
    ...(stub ? { stub } : {}),
  };
}

export function sha256Hex(content: string | Buffer): string {
  return createHash('sha256').update(content).digest('hex');
}
