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
 * SCOPE CAVEAT (inherited from code-ingest): the ingest layer extracts blocks via
 * web-tree-sitter for Python/JS/TS/Go/Java/C/C++ (fail-open to the Python regex
 * "AST-lite" path) — see recon/code-ingest.ts + recon/ts-parse.ts. It selects which
 * blocks to analyze first by security exposure; a language without a bundled grammar,
 * or code imported from outside the scan scope, is invisible. Do NOT describe this as
 * "any repo" or "any language".
 *
 * KNOWN v1 EXTRACTION LIMITS (fail-safe — these shapes are silently NOT extracted or
 * under-linked, never mis-extracted; all strictly better than the prior Python-only
 * ingest, and tracked as follow-ups):
 *   - JS/TS: only `function`/`method`/`class` declarations are captured. Arrow-function
 *     and function-expression definitions (`const f = () => …`) are not — idiomatic in
 *     modern TS, so their sinks may go unranked.
 *   - C++: only free functions are captured. In-class and out-of-line (`Class::method`)
 *     member methods are not — a materially narrower C++ story than "full support".
 *   - Entry-point elevation for non-Python code relies on name heuristics only; no
 *     language emits `decorators`, so annotation-based routes (Spring `@GetMapping`,
 *     TS `@Get()`, Express `app.get(...)`) are not elevated to `exposed_externally`.
 *   - Call-graph/reachability: buildCallGraph strips a block's signature line before
 *     scanning for callees (kept unchanged for Python-benchmark stability), so a
 *     SINGLE-LINE non-Python definition (`func F(u) { return G(u) }`) misses the call
 *     on that line — the block is still extracted and sink-classified, only the edge
 *     is lost.
 */

import { config } from '../config/index.js';
import {
  ingestRepository,
  createMultiLangIngestConfig,
  packAnalysisUnits,
} from './code-ingest.js';
import { DecompositionOrchestrator } from '../orchestration/index.js';
import type { DecompositionConfig } from '../orchestration/index.js';
import type { LLMProvider } from '../types/index.js';
import { mkdtempSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { homedir, tmpdir } from 'node:os';
import { join as joinPath, isAbsolute, relative, resolve, sep } from 'node:path';

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

export class RepoCloneError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RepoCloneError';
  }
}

export interface ResolvedRepoSource {
  repoPath: string;
  source: 'local' | 'github';
  cleanup(): void;
}

function isGitHubHttpsRepoUrl(input: string): boolean {
  try {
    const url = new URL(input);
    return url.protocol === 'https:' &&
      url.hostname.toLowerCase() === 'github.com' &&
      /^\/[^/]+\/[^/]+(?:\.git)?\/?$/.test(url.pathname);
  } catch {
    return false;
  }
}

function getGitHubRepoToken(): string | undefined {
  return process.env.T3MP3ST_GITHUB_TOKEN?.trim() || process.env.GITHUB_TOKEN?.trim();
}

export function cloneGitHubRepoForAnalysis(repoUrl: string): ResolvedRepoSource {
  if (!isGitHubHttpsRepoUrl(repoUrl)) {
    throw new RepoCloneError('repoUrl must be an https://github.com/<owner>/<repo> URL');
  }

  const token = getGitHubRepoToken();
  if (!token) {
    throw new RepoCloneError('private GitHub repo scans require T3MP3ST_GITHUB_TOKEN or GITHUB_TOKEN');
  }

  const tempRoot = mkdtempSync(joinPath(tmpdir(), 't3mp3st-repo-'));
  const cloneDir = joinPath(tempRoot, 'repo');
  const askPassPath = joinPath(tempRoot, 'git-askpass.sh');
  try {
    writeFileSync(
      askPassPath,
      [
        '#!/bin/sh',
        'case "$1" in',
        "*Username*) printf '%s\\n' 'x-access-token' ;;",
        '*) printf "%s\\n" "$T3MP3ST_GIT_TOKEN" ;;',
        'esac',
        '',
      ].join('\n'),
      { mode: 0o700 },
    );
    execFileSync('git', [
      '-c', 'credential.helper=',
      'clone',
      '--depth', '1',
      '--filter=blob:none',
      repoUrl,
      cloneDir,
    ], {
      stdio: ['ignore', 'ignore', 'pipe'],
      env: {
        ...process.env,
        GIT_ASKPASS: askPassPath,
        GIT_TERMINAL_PROMPT: '0',
        T3MP3ST_GIT_TOKEN: token,
      },
    });

    return {
      repoPath: realpathSync(cloneDir),
      source: 'github',
      cleanup: () => { rmSync(tempRoot, { recursive: true, force: true }); },
    };
  } catch (error) {
    rmSync(tempRoot, { recursive: true, force: true });
    const message = error instanceof Error ? error.message.replaceAll(token, '[REDACTED]') : 'git clone failed';
    throw new RepoCloneError(`GitHub repo clone failed: ${message}`);
  }
}

export function resolveRepoSourceForAnalysis(input: unknown): ResolvedRepoSource {
  if (typeof input === 'string' && isGitHubHttpsRepoUrl(input.trim())) {
    return cloneGitHubRepoForAnalysis(input.trim());
  }
  return {
    repoPath: resolveContainedRepoPath(input),
    source: 'local',
    cleanup: () => { /* local repos are caller-owned; nothing to remove */ },
  };
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
 * @param repoPath  Absolute path to a LOCAL repo you own, or a GitHub HTTPS repo URL with token auth.
 * @param tokenBudget  Packing budget in tokens (default 24000).
 */
export function ingestRepoToSourceContext(
  repoPath: string,
  tokenBudget = 24000,
): RepoSourceContext {
  const source = resolveRepoSourceForAnalysis(repoPath);
  try {
    const result = ingestRepository(createMultiLangIngestConfig(source.repoPath));
    const packed = packAnalysisUnits(result.analysisUnits, tokenBudget);
    return {
      sourceContext: packed.text,
      stats: result.stats,
      includedUnits: packed.includedUnits.length,
      droppedUnits: packed.droppedUnits.length,
    };
  } finally {
    source.cleanup();
  }
}

/** Options for a full white-box decomposition analysis run. */
export interface WhiteboxAnalysisOptions {
  /** Absolute path to a LOCAL repo you own, or a GitHub HTTPS repo URL with token auth. */
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
  const source = resolveRepoSourceForAnalysis(repoPath);

  // 1) ingest source, security-rank the blocks
  try {
    const result = ingestRepository(createMultiLangIngestConfig(source.repoPath));

    // 2) pack into a generous source view (orchestrator re-packs per-worker itself)
    const packed = packAnalysisUnits(result.analysisUnits, DEFAULT_ANALYSIS_SOURCE_BUDGET);
    const sourceContext = packed.text;

  // Fail loud ONLY when there is genuinely NO source to analyze: 0 ingestable source files
  // (no supported-language files, or empty repo). A valid repo that has files but no
  // def/class/func (a module-level-only script) yields 0 blocks -> empty packed text; that
  // used to run the orchestrator, so we do NOT regress it into a 500 — gate the throw on the
  // file count, not on empty packed text, and let a files>0 repo proceed as before.
    if (result.stats.files === 0) {
      throw new Error(
      'white-box analysis has no analyzable source: the repo has 0 ingestable source files ' +
        '(no supported-language source, or empty). Point repoPath at a code repository.',
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
  } finally {
    source.cleanup();
  }
}
