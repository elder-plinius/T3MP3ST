// =============================================================================
// Cairn engine — drives the blackboard through bootstrap / reason / explore
// rounds against an injected LLM. Techniques reimplemented from oritera/Cairn
// (AGPL-3.0); prompts are native rewrites of the documented contracts, no
// upstream code vendored.
//
// The `chat` dependency is injected (same pattern as the OSINT LLM lanes), so
// tests drive the whole engine with a scripted model and the server wires it
// to the operator's configured backbone.
// =============================================================================

import {
  CairnBoard,
  validateBootstrapPayload,
  validateExplorePayload,
  validateReasonPayload,
  type BoardConfig,
  type Completion,
  type Fact,
  type Intent,
  DEFAULT_BOARD_CONFIG,
} from './cairn-board.js';

export type ChatFn = (system: string, user: string) => Promise<string>;

export interface CairnSearchConfig extends BoardConfig {
  /** Wall-clock budget for the whole search. */
  budgetMs: number;
  /** Per-task LLM budget. A task that exceeds it is discarded, nothing written. */
  taskTimeoutMs: number;
  /** Explorers claimed per wave — bounded by BoardConfig.maxProjectWorkers. */
  workerName: string;
}

export const DEFAULT_SEARCH_CONFIG: CairnSearchConfig = {
  ...DEFAULT_BOARD_CONFIG,
  budgetMs: 6 * 60_000,
  taskTimeoutMs: 120_000,
  workerName: 't3mp3st-cairn',
};

export interface JournalEntry {
  task: 'bootstrap' | 'bootstrap_conclude' | 'reason' | 'explore';
  intentId?: string;
  at: number;
  ms: number;
  outcome: string;
  detail?: string;
}

export interface CairnSearchResult {
  id: string;
  origin: string;
  goal: string;
  state: 'complete' | 'stalled' | 'budget_exhausted' | 'failed';
  completion: Completion | null;
  facts: Fact[];
  intents: Intent[];
  hints: string[];
  journal: JournalEntry[];
  ms: number;
}

// -----------------------------------------------------------------------------
// output extraction — models decorate JSON with prose and fences; the contract
// needs the one balanced object.
// -----------------------------------------------------------------------------

export function extractJsonObject(text: string): Record<string, unknown> | null {
  if (!text) return null;
  const start = text.indexOf('{');
  if (start < 0) return null;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) {
        try {
          const parsed = JSON.parse(text.slice(start, i + 1));
          return typeof parsed === 'object' && parsed !== null ? parsed as Record<string, unknown> : null;
        } catch {
          return null;
        }
      }
    }
  }
  return null;
}

// -----------------------------------------------------------------------------
// prompts — native rewrites of the three task contracts.
// -----------------------------------------------------------------------------

const REASON_SYSTEM = [
  'You are the reasoner of a state-space search. You will be given a YAML snapshot of a task graph:',
  'facts are confirmed objective findings, intents are exploration directions. The graph grows from ORIGIN toward GOAL',
  'by proposing intents that explore from known facts and conclude into new facts. You judge exactly two things:',
  '(1) whether the current facts already satisfy GOAL, and (2) if not, which high-value exploration directions to propose now.',
  '',
  'Return ONLY one raw JSON object — no prose, no markdown fences:',
  '  {"accepted": true, "data": {"complete": {"from": ["f001"], "description": "why the confirmed facts prove GOAL"}}}',
  '  {"accepted": true, "data": {"intents": [{"from": ["f003"], "description": "direction"}, {"from": ["f002", "f005"], "description": "another"}]}}',
  '  {"accepted": true, "data": {}}',
  '',
  'Rules:',
  '- complete.from must cite valid fact ids, and the description must argue why those facts suffice to prove GOAL. Do not declare completion on hope.',
  '- If GOAL is not met, reflect on why: has the search drifted? Is a course-correcting intent needed?',
  '- When open intents already exist and no more valuable direction has appeared, return empty data — do not pad.',
  '- When the open-intents list is empty you MUST propose at least one intent.',
  '- Propose at most {MAX_INTENTS} intents. Each must be an independent, parallelizable, non-overlapping direction with a clear core insight — not a broad wish and not a step-by-step plan.',
  '- An intent may grow from several facts; its from[] must cite valid fact ids.',
].join('\n');

const EXPLORE_SYSTEM = [
  'You are an explorer in a state-space search. You receive a graph snapshot and ONE assigned intent; explore ONLY that direction',
  'and try to move the search toward GOAL. The direction may dead-end — that is a normal outcome, not a failure of yours,',
  'but before ending, make sure the intent was genuinely explored.',
  '',
  'Return ONLY one raw JSON object — no prose, no markdown fences:',
  '  {"accepted": true, "data": {"description": "<the objective conclusion of this exploration>"}}',
  '',
  'Rules:',
  '- data.description must state confirmed objective results, and must be INCREMENTAL: never repeat what the graph snapshot already shows.',
  '- A clean negative is a valid fact: "tested X for Y, no exploitable Z found" advances the search by closing a direction.',
  '- Keep the description to the key finding(s); point at long evidence instead of pasting it.',
  '- Refuse with {"accepted": false, "reason": "policy_refusal"} ONLY when the intent itself requires something you must refuse — never as a way to skip work.',
].join('\n');

const BOOTSTRAP_SYSTEM = [
  'You are opening a state-space search with an unusually direct attempt: given ORIGIN and GOAL, try to achieve GOAL right now',
  'with what you can do immediately. If — and only if — you achieve it, return:',
  '  {"accepted": true, "data": {"fact": {"description": "objective result"}, "complete": {"description": "why GOAL is satisfied"}}}',
  'You will be cut off at the time limit if you have not solved it; there is no partial credit in this phase. Do not pad the',
  'fact with process narration; state the confirmed result. Refuse only with {"accepted": false, "reason": "policy_refusal"}.',
].join('\n');

const BOOTSTRAP_CONCLUDE_SYSTEM = [
  'The direct attempt is over — do NOT continue pursuing the goal, do not wait, do not plan further actions.',
  'Summarize the single most important confirmed objective fact established so far, even when it is only a precise restatement',
  'of what was attempted and ruled out. Return ONLY:',
  '  {"accepted": true, "data": {"fact": {"description": "..."}}}',
].join('\n');

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`task exceeded ${ms}ms`)), ms);
    p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
  });
}

export interface CairnSearchOptions {
  origin: string;
  goal: string;
  hints?: string[];
  chat: ChatFn;
  config?: Partial<CairnSearchConfig>;
  searchId?: string;
  /** Called with the live board before the first round — the Hint primitive's
   *  injection point: hints added mid-search are a new situation and re-reason. */
  onBoardReady?: (board: CairnBoard) => void;
}

/**
 * Run one search to completion, budget, or stall. Faithful to the upstream
 * scheduling order: bootstrap on an initial search, then a due Reason, then
 * concurrent Explores up to the worker cap. Every task's invalid output is
 * DISCARDED — nothing unwritable ever reaches the graph.
 */
export async function runCairnSearch(opts: CairnSearchOptions): Promise<CairnSearchResult> {
  const config: CairnSearchConfig = { ...DEFAULT_SEARCH_CONFIG, ...(opts.config || {}) };
  const configWithIntents: BoardConfig = { maxIntents: config.maxIntents, bootstrapEnabled: config.bootstrapEnabled, maxProjectWorkers: config.maxProjectWorkers };
  const board = new CairnBoard(opts.origin, opts.goal, configWithIntents);
  board.addOriginAndGoal();
  for (const hint of opts.hints || []) board.addHint(hint);
  opts.onBoardReady?.(board);

  const startedAt = Date.now();
  const deadline = startedAt + config.budgetMs;
  const journal: JournalEntry[] = [];
  const id = opts.searchId ?? `cairn_${startedAt.toString(36)}`;
  let state: CairnSearchResult['state'] = 'stalled';
  let consecutiveNoProgress = 0;

  // The budget is a wall-clock CONTRACT, not a between-rounds suggestion: a task that
  // starts 1s before the deadline is cut at the deadline, not allowed to burn its full
  // taskTimeout past it (measured live: a 60s budget ran 222s because waves checked the
  // clock only between rounds while in-flight tasks kept their whole timeout).
  const taskBudget = () => Math.max(5_000, Math.min(config.taskTimeoutMs, deadline - Date.now()));

  const chatOrThrow: ChatFn = async (system, user) => {
    const raw = await opts.chat(system, user);
    if (!raw || !raw.trim()) throw new Error('model returned an empty reply');
    return raw;
  };

  while (Date.now() < deadline && !board.completion) {
    const task = board.nextTask();
    if (!task) {
      // No dispatchable task: explores only exist mid-wave (each wave runs to
      // its conclusions before the next round), reason is not due, and the
      // frontier is empty. The model has said its last word — end the search
      // honestly. Clearing the reason checkpoint here to force more rounds
      // would livelock: a legal noop would reset progress, forever.
      break;
    }

    if (task === 'bootstrap') {
      board.bootstrapRunning = true;
      const t0 = Date.now();
      let outcome = 'discarded';
      let detail: string | undefined;
      try {
        const raw = await withTimeout(chatOrThrow(BOOTSTRAP_SYSTEM, bootstrapPrompt(board, board.hints.map((h) => h.text))), taskBudget());
        const payload = extractJsonObject(raw);
        const verdict = payload ? validateBootstrapPayload(payload, 'execute') : { kind: 'invalid' as const, error: 'no JSON object in output' };
        if (verdict.kind === 'complete') {
          const fact = board.addFact(verdict.factDescription, config.workerName);
          board.complete([fact.id], verdict.completeDescription);
          outcome = 'complete';
        } else if (verdict.kind === 'invalid') {
          detail = verdict.error;
        } else if (verdict.kind === 'rejected') {
          detail = verdict.reason;
        } else {
          detail = 'main phase returned a fact without a completion — contract requires both';
        }
      } catch (e) {
        detail = e instanceof Error ? e.message : String(e);
      }
      board.bootstrapRunning = false;
      // The main phase only returns on success — anything else falls to the
      // conclude phase, which banks one fact and leaves the initial state.
      if (outcome !== 'complete') {
        const ct0 = Date.now();
        let cOutcome = 'discarded';
        detail = undefined; // the conclude entry reports on the conclude phase, not the failed main phase
        try {
          const raw = await withTimeout(chatOrThrow(BOOTSTRAP_CONCLUDE_SYSTEM, bootstrapConcludePrompt(board)), taskBudget());
          const payload = extractJsonObject(raw);
          const verdict = payload ? validateBootstrapPayload(payload, 'conclude') : { kind: 'invalid' as const, error: 'no JSON object in output' };
          if (verdict.kind === 'fact') {
            board.addFact(verdict.factDescription, config.workerName);
            cOutcome = 'fact';
          } else if (verdict.kind === 'invalid') {
            detail = `${detail ?? ''}; conclude: ${verdict.error}`.trim();
          } else if (verdict.kind === 'rejected') {
            detail = `${detail ?? ''}; conclude: ${verdict.reason}`.trim();
          } else {
            detail = `${detail ?? ''}; conclude returned a completion, which the phase forbids`.trim();
          }
        } catch (e) {
          detail = `${detail ?? ''}; conclude: ${e instanceof Error ? e.message : String(e)}`.trim();
        }
        journal.push({ task: 'bootstrap_conclude', at: ct0, ms: Date.now() - ct0, outcome: cOutcome, detail });
      }
      board.bootstrapAttempted = true;
      journal.push({ task: 'bootstrap', at: t0, ms: Date.now() - t0, outcome, detail });
      continue;
    }

    if (task === 'reason') {
      board.reasonRunning = true;
      const t0 = Date.now();
      let outcome = 'noop';
      let detail: string | undefined;
      try {
        const openIntents = board.openIntents.map((i) => ({ id: i.id, description: i.description }));
        const user = reasonPrompt(board, openIntents, config.maxIntents);
        const raw = await withTimeout(chatOrThrow(REASON_SYSTEM, user), taskBudget());
        const payload = extractJsonObject(raw);
        const verdict = payload
          ? validateReasonPayload(payload, board.openIntentsEmpty, config.maxIntents)
          : ({ kind: 'invalid' as const, error: 'no JSON object in output' });
        if (verdict.kind === 'complete') {
          board.complete(verdict.complete.from, verdict.complete.description);
          outcome = 'complete';
        } else if (verdict.kind === 'intents') {
          const proposed: string[] = [];
          let deduped = 0;
          for (const intent of verdict.intents) {
            const created = board.proposeIntent(intent.description, intent.from, config.workerName);
            if (created) proposed.push(created.id);
            else deduped += 1;
          }
          outcome = proposed.length ? `intents ${proposed.join(',')}` : `noop (all ${deduped} duplicated existing intents)`;
          if (!proposed.length) outcome = 'noop';
          if (deduped) detail = `${deduped} proposal(s) duplicated existing intents and were dropped`;
        } else if (verdict.kind === 'noop') {
          outcome = 'noop';
        } else if (verdict.kind === 'rejected') {
          outcome = 'rejected';
          detail = verdict.reason;
        } else {
          outcome = 'invalid';
          detail = verdict.error;
        }
      } catch (e) {
        outcome = 'discarded';
        detail = e instanceof Error ? e.message : String(e);
      }
      // Only a VALID reason outcome moves the situation checkpoint — upstream
      // records the last successfully completed reason. A timeout/invalid/
      // refused round is discarded whole: the new situation that triggered it
      // stays un-acknowledged, so the next round re-reasons instead of the
      // checkpoint swallowing the event.
      const reasonValid = outcome === 'complete' || outcome === 'noop' || outcome.startsWith('intents');
      if (reasonValid) board.checkpointReason();
      board.reasonRunning = false;
      journal.push({ task: 'reason', at: t0, ms: Date.now() - t0, outcome, detail });
      if (reasonValid) {
        consecutiveNoProgress = 0;
      } else {
        consecutiveNoProgress += 1;
        if (consecutiveNoProgress >= 3 && board.openIntentsEmpty) { state = 'stalled'; break; }
      }
      continue;
    }

    // explore wave: claim up to the remaining worker capacity and run concurrently.
    // nextTask only routes here with spare capacity, so capacity >= 1.
    const capacity = Math.max(0, config.maxProjectWorkers - board.runningTaskCount);
    if (capacity < 1) break;
    const claimable = board.claimableIntents.slice(0, capacity);
    for (const intent of claimable) board.claimIntent(intent.id, config.workerName);
    const t0 = Date.now();
    const results = await Promise.all(claimable.map(async (intent) => {
      const iT0 = Date.now();
      let outcome = 'discarded';
      let detail: string | undefined;
      try {
        const raw = await withTimeout(chatOrThrow(EXPLORE_SYSTEM, explorePrompt(board, intent)), taskBudget());
        const payload = extractJsonObject(raw);
        const verdict = payload ? validateExplorePayload(payload) : { kind: 'invalid' as const, error: 'no JSON object in output' };
        if (verdict.kind === 'fact') {
          board.concludeIntent(intent.id, verdict.description, config.workerName);
          outcome = 'fact';
        } else if (verdict.kind === 'rejected') {
          outcome = 'rejected';
          detail = verdict.reason;
          board.releaseIntent(intent.id);
        } else {
          outcome = 'invalid';
          detail = verdict.error;
          board.releaseIntent(intent.id);
        }
      } catch (e) {
        outcome = 'discarded';
        detail = e instanceof Error ? e.message : String(e);
        board.releaseIntent(intent.id);
      }
      journal.push({ task: 'explore', intentId: intent.id, at: iT0, ms: Date.now() - iT0, outcome, detail });
      return outcome;
    }));
    journal.push({ task: 'explore', at: t0, ms: Date.now() - t0, outcome: `wave: ${results.join(',')}` });
    consecutiveNoProgress = 0;
  }

  if (board.completion) state = 'complete';
  else if (Date.now() >= deadline) state = 'budget_exhausted';
  else state = 'stalled';

  return {
    id,
    origin: board.origin,
    goal: board.goal,
    state,
    completion: board.completion,
    facts: [...board.facts.values()],
    intents: [...board.intents.values()],
    hints: board.hints.map((h) => h.text),
    journal,
    ms: Date.now() - startedAt,
  };
}

function reasonPrompt(board: CairnBoard, openIntents: Array<{ id: string; description: string }>, maxIntents: number): string {
  return [
    `# Goal\n${board.goal}`,
    '',
    '# Graph',
    '```',
    board.snapshotYaml(),
    '```',
    '',
    '# Valid facts',
    JSON.stringify(board.factIds),
    '',
    '# Open Intents',
    JSON.stringify(openIntents),
    '',
    `Propose at most ${maxIntents} intent(s).`,
  ].join('\n');
}

function explorePrompt(board: CairnBoard, intent: Intent): string {
  return [
    `# Goal\n${board.goal}`,
    '',
    '# Graph',
    '```',
    board.snapshotYaml(),
    '```',
    '',
    '# Current Intent',
    intent.id,
    '',
    '# Current Intent Description',
    intent.description,
  ].join('\n');
}

function bootstrapPrompt(board: CairnBoard, hints: string[]): string {
  return [
    `# Origin\n${board.origin}`,
    '',
    `# Goal\n${board.goal}`,
    '',
    '# Hints',
    JSON.stringify(hints),
  ].join('\n');
}

function bootstrapConcludePrompt(board: CairnBoard): string {
  return [
    `# Origin\n${board.origin}`,
    '',
    `# Goal\n${board.goal}`,
    '',
    'Summarize the most important confirmed fact established by the attempt that just ended.',
  ].join('\n');
}
