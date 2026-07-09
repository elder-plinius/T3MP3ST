/**
 * whitebox — glue that wires the large-repo analysis pipeline end to end:
 *
 *     code-ingest (SELECT)  ->  context-pack (BUDGET)  ->  DecompositionOrchestrator (REASON)
 *
 * This is the WHITE-BOX path: it reads LOCAL source you own off disk (no network
 * target, no probing). The only outbound calls are the LLM calls the orchestrator
 * itself makes (worker + orchestrator models). It is otherwise pure of network
 * side effects.
 *
 * SCOPE CAVEAT (inherited from code-ingest): the ingest layer is a PYTHON-ONLY,
 * regex "AST-lite" prototype — see recon/code-ingest.ts. It selects which Python
 * blocks to analyze first by security exposure; anything non-`.py` or imported
 * from outside the scan scope is invisible. Do NOT describe this as "any repo".
 */

import { config } from '../config/index.js';
import {
  ingestRepository,
  createPythonIngestConfig,
  packAnalysisUnits,
} from './code-ingest.js';
import { DecompositionOrchestrator } from '../orchestration/index.js';
import type { DecompositionConfig } from '../orchestration/index.js';
import type { LLMProvider } from '../types/index.js';
import { realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, relative, resolve, sep } from 'node:path';

/**
 * Default worker-source token budget when building a source blob directly from a
 * repo for a one-off analysis. Generous so the orchestrator's own view is rich;
 * it re-packs internally per-worker under its own tighter budget.
 */
const DEFAULT_ANALYSIS_SOURCE_BUDGET = 40000;

/** Result of turning a repo into a packed, security-ordered source blob. */
export interface RepoSourceContext {
  /** The packed, LLM-facing source text (security-priority order preserved). */
  sourceContext: string;
  /** The raw ingest stats (files/blocks + per-exposure counts). */
  stats: unknown;
  /** How many analysis units made it into the budget. */
  includedUnits: number;
  /** How many analysis units were dropped for budget. */
  droppedUnits: number;
}

/**
 * Thrown when a caller-supplied repoPath fails the containment check. The API
 * layer maps this to a 400 (bad request), never a 500 or a silent read.
 */
export class RepoPathError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RepoPathError';
  }
}

/**
 * B-03 — path containment for the caller-supplied repoPath.
 *
 * The white-box path reads source off disk from an operator-supplied path. On a
 * localhost tool the operator legitimately analyzes any repo THEY own, but an
 * unbounded path is an arbitrary-directory read primitive (repoPath=/etc, another
 * user's home, ~/.ssh) reachable by anything that can reach the API. We therefore:
 *   1. canonicalize with realpath — collapses '..' AND resolves symlinks, so
 *      neither traversal nor a symlink planted inside the root can escape after
 *      the check (we validate the resolved target, not the string),
 *   2. require it to exist AND be a directory,
 *   3. confine it to an allowed ROOT — the operator's home by default, overridable
 *      with T3MP3ST_REPO_ROOT for repos kept elsewhere (/opt, /srv, a volume).
 * Returns the canonical, contained absolute path to hand to the reader.
 */
export function resolveContainedRepoPath(input: unknown): string {
  if (typeof input !== 'string' || !input.trim()) {
    throw new RepoPathError('repoPath is required and must be a non-empty string');
  }
  let root: string;
  try {
    root = realpathSync(resolve(process.env.T3MP3ST_REPO_ROOT || homedir()));
  } catch {
    throw new RepoPathError('configured T3MP3ST_REPO_ROOT does not resolve to an existing path');
  }
  let real: string;
  try {
    real = realpathSync(resolve(input));
  } catch {
    throw new RepoPathError('repoPath does not resolve to an existing path');
  }
  try {
    if (!statSync(real).isDirectory()) {
      throw new RepoPathError('repoPath must be a directory');
    }
  } catch (e) {
    if (e instanceof RepoPathError) throw e;
    // statSync can throw (e.g. a TOCTOU deletion between realpath and here) — normalize
    // to RepoPathError so the API layer returns a clean 400, never an unhandled rejection.
    throw new RepoPathError('repoPath is not accessible');
  }
  // relative(root, real) is '' when equal, starts with '..' (as a whole segment)
  // when real is outside root, or is absolute when they share no root (Windows).
  const rel = relative(root, real);
  if (rel !== '' && (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel))) {
    throw new RepoPathError(
      `repoPath resolves outside the allowed root (${root}). Set T3MP3ST_REPO_ROOT to analyze a repo kept elsewhere.`,
    );
  }
  return real;
}

/**
 * Ingest a local repo and pack it into a single security-ordered source blob
 * suitable for handing to `TempestCommand.setWhiteboxSource` (or any consumer
 * that wants the highest-priority code first).
 *
 * @param repoPath  Absolute path to a LOCAL repo you own.
 * @param tokenBudget  Packing budget in tokens (default 24000).
 */
export function ingestRepoToSourceContext(
  repoPath: string,
  tokenBudget = 24000,
): RepoSourceContext {
  const safePath = resolveContainedRepoPath(repoPath);
  const result = ingestRepository(createPythonIngestConfig(safePath));
  const packed = packAnalysisUnits(result.analysisUnits, tokenBudget);
  return {
    sourceContext: packed.text,
    stats: result.stats,
    includedUnits: packed.includedUnits.length,
    droppedUnits: packed.droppedUnits.length,
  };
}

/** Options for a full white-box decomposition analysis run. */
export interface WhiteboxAnalysisOptions {
  /** Absolute path to a LOCAL repo you own. */
  repoPath: string;
  /** The offensive objective — only the orchestrator model sees this. */
  objective: string;
  /** Max decomposition rounds. Default 5 (orchestrator's own default). */
  maxRounds?: number;
}

/** Result of a full white-box decomposition analysis run. */
export interface WhiteboxAnalysisResult {
  /** Raw ingest stats (files/blocks + per-exposure counts). */
  ingestStats: unknown;
  /** ids of blocks detected as entry points. */
  entryPoints: string[];
  /** Total analysis units the ingest produced (before packing). */
  unitCount: number;
  /** The orchestrator's DecompositionResult. */
  decomposition: unknown;
}

/**
 * Build the DecompositionOrchestrator config the same way scripts/decompose.mjs
 * does: an orchestrator model (opus) that holds the objective + a worker model
 * (fable-5) that answers benign analytical sub-queries. Model/provider selection
 * flows through the shared ConfigManager (env keys, fallback chain, etc.) exactly
 * like the rest of the server.
 *
 * Env overrides (optional, mirroring the CLI flags):
 *   TEMPEST_ORCHESTRATOR_PROVIDER / TEMPEST_ORCHESTRATOR_MODEL
 *   TEMPEST_WORKER_PROVIDER       / TEMPEST_WORKER_MODEL
 */
function buildDecompositionConfig(): DecompositionConfig {
  const orchestratorProvider =
    (process.env.TEMPEST_ORCHESTRATOR_PROVIDER as LLMProvider) || 'openrouter';
  const workerProvider =
    (process.env.TEMPEST_WORKER_PROVIDER as LLMProvider) || 'openrouter';
  const orchestratorModel = config.getLLMConfig(
    orchestratorProvider,
    process.env.TEMPEST_ORCHESTRATOR_MODEL || 'anthropic/claude-opus-4.8',
  );
  const workerModel = config.getLLMConfig(
    workerProvider,
    process.env.TEMPEST_WORKER_MODEL || 'anthropic/claude-fable-5',
  );
  return {
    orchestratorModel,
    workerModel,
    maxQueriesPerRound: 8,
    parallelWorkers: true,
  };
}

/**
 * Full white-box analysis: ingest a LOCAL repo, build a generous security-ordered
 * source view, then run the multi-model DecompositionOrchestrator against the
 * objective. LLM-HEAVY — this may take a while (multiple orchestrator +
 * worker round-trips). Reads LOCAL source only; the only network calls are the
 * orchestrator's own LLM calls.
 *
 * @returns ingest telemetry + the orchestrator's DecompositionResult.
 */
export async function runWhiteboxAnalysis(
  opts: WhiteboxAnalysisOptions,
): Promise<WhiteboxAnalysisResult> {
  const { repoPath, objective, maxRounds } = opts;
  const safePath = resolveContainedRepoPath(repoPath);

  // 1) ingest LOCAL source, security-rank the blocks
  const result = ingestRepository(createPythonIngestConfig(safePath));

  // 2) pack into a generous source view (orchestrator re-packs per-worker itself)
  const packed = packAnalysisUnits(result.analysisUnits, DEFAULT_ANALYSIS_SOURCE_BUDGET);
  const sourceContext = packed.text;

  // Fail loud ONLY when there is genuinely NO source to analyze: 0 ingestable source files
  // (non-Python or empty repo). A valid Python repo that has files but no def/class (a
  // module-level-only script) yields 0 blocks -> empty packed text; that used to run the
  // orchestrator, so we do NOT regress it into a 500 — gate the throw on the file count, not
  // on empty packed text, and let a files>0 repo proceed as before.
  if (result.stats.files === 0) {
    throw new Error(
      'white-box analysis has no analyzable source: the repo has 0 ingestable source files ' +
      '(non-Python, or empty). Point repoPath at a Python codebase.',
    );
  }

  // 3) construct the orchestrator with a sane default config (mirrors decompose.mjs)
  const decompConfig = buildDecompositionConfig();
  if (typeof maxRounds === 'number' && maxRounds > 0) {
    decompConfig.maxRounds = maxRounds;
  }
  const orch = new DecompositionOrchestrator(decompConfig);

  // 4) run the decomposition loop (LLM calls happen HERE)
  const decomposition = await orch.run(objective, sourceContext);

  return {
    ingestStats: result.stats,
    entryPoints: result.entryPoints,
    unitCount: result.analysisUnits.length,
    decomposition,
  };
}
