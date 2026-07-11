/**
 * code-ingest — security-aware static code SELECTION layer.
 *
 * ⚠️ HONEST SCOPING (read this before trusting the output):
 *
 *   This is a PYTHON-ONLY, regex-based "AST-lite" PROTOTYPE — it is NOT a real
 *   parser. It scans `.py` files with line-oriented regexes to find `def`/`class`
 *   blocks, guesses where each block ends from indentation, and resolves calls by
 *   matching bare names against other blocks it happened to find. Consequently it
 *   WILL mis-parse real code:
 *     - a def whose parens never balance (truncated / malformed file) is skipped
 *     - deeply nested defs / closures — a nested inner def is labeled a "method"
 *     - `def`/`class` keywords appearing inside strings, comments, or docstrings
 *     - dynamic dispatch, imports, aliasing — none of it is understood
 *   Call resolution is INTRA-REPO ONLY (by name). Anything imported from outside
 *   the scan scope is invisible — that is the honest limit of a name-matcher.
 *
 *   The real version is tree-sitter (or a language server) + multi-language.
 *   Do NOT describe this as handling "any repo" or being "repository-scale"
 *   without the Python/prototype caveat above.
 *
 * WHAT IT DOES DO: it decides which Python code blocks a downstream security
 * analysis should look at FIRST — ranking by exposure (entry points, attack
 * surface, security controls), reachability from externally-triggered handlers,
 * and dangerous-sink / SSRF-IDOR risk signals. It is the SELECTION layer that
 * sits UPSTREAM of the token-budgeting packer (orchestration/context-pack).
 *
 * PURITY: pure + deterministic static analysis. No LLM calls, no network. The
 * only side effect is reading files off disk during `crawl`.
 *
 * COMPOSITION: it does NOT reimplement token counting. It imports
 * `estimateTokens` and the `SourceFile`/`SourceBundle` types from
 * orchestration/context-pack and reuses them. context-pack ranks files by
 * lexical relevance to an objective; code-ingest ranks blocks by SECURITY
 * priority. `packAnalysisUnits` preserves the security ordering while reusing
 * the shared token estimator.
 */

import { readdirSync, readFileSync, statSync } from 'fs';
import { join, sep } from 'path';
import {
  estimateTokens,
  type SourceFile,
  type SourceBundle,
} from '../orchestration/context-pack.js';
import { redactString } from '../redact.js';

// =============================================================================
// TYPES
// =============================================================================

export interface IngestConfig {
  /** Root directory to crawl. */
  repoRoot: string;
  /** File extensions to keep (e.g. [".py"]). Includes the leading dot. */
  includeExts: string[];
  /** Path substrings/globs to skip (matched loosely against the full path). */
  excludeGlobs: string[];
  /** Skip files larger than this many bytes (undefined = no limit). */
  maxFileBytes?: number;
  /** Stop crawling after this many files (undefined = no limit). A generous ceiling that
   *  bounds a pathological/runaway repo; a normal repo never reaches it. */
  maxFiles?: number;
  /** Stop reading once cumulative source bytes exceed this (undefined = no limit). Bounds
   *  total ingest memory regardless of file count; a normal repo never reaches it. */
  maxTotalBytes?: number;
}

export interface CodeBlock {
  /** Stable id: path + "::" + name + "@" + lineStart. */
  id: string;
  /** Repo-relative-ish path (as returned by crawl). */
  path: string;
  /** Function / method / class name. */
  name: string;
  kind: 'function' | 'method' | 'class';
  /** 1-indexed line of the def/class keyword. */
  lineStart: number;
  /** 1-indexed last line of the block (inclusive). */
  lineEnd: number;
  /** Bare parameter names (self/cls dropped, defaults/annotations stripped). */
  params: string[];
  /** Decorator lines immediately preceding the def/class (with the leading @). */
  decorators: string[];
  /** The source text of the block (lineStart..lineEnd inclusive). */
  body: string;
}

export type Exposure =
  | 'exposed_externally'
  | 'exposed_internally'
  | 'attack_surface'
  | 'security_control'
  | 'neutral';

export interface AnalysisUnit {
  block: CodeBlock;
  exposure: Exposure;
  /** ids of blocks that call this block (intra-repo, by name). */
  callers: string[];
  /** ids of blocks this block calls (intra-repo, by name). */
  callees: string[];
  /** Reachable from an entry point via the call graph? */
  reachable: boolean;
  /** Shortest hop count from an entry point (0 = is an entry point). */
  reachDepth: number;
  /** Representative reachability path(s): id chains from an entry point. */
  reachabilityPaths: string[][];
  /** Human-readable evidence: the sink/param patterns that matched. */
  riskSignals: string[];
  /** Security priority score (>= 0). Higher = look at it sooner. */
  priority: number;
}

export interface IngestResult {
  analysisUnits: AnalysisUnit[];
  /** ids of blocks detected as entry points. */
  entryPoints: string[];
  stats: {
    files: number;
    blocks: number;
    /** Present + true only when crawl/ingest stopped early at a maxFiles/maxTotalBytes
     *  ceiling (omitted otherwise, so a normal ingest's stats shape is unchanged). */
    truncated?: boolean;
  } & Record<Exposure, number>;
}

// =============================================================================
// PATTERNS
// =============================================================================

// Default directory/path fragments we never descend into or analyze.
const DEFAULT_EXCLUDES = [
  'node_modules',
  '.git',
  'dist',
  'build',
  'venv',
  '.venv',
  '__pycache__',
  'site-packages',
  // test dirs
  'test',
  'tests',
  '__tests__',
  'testing',
];

// def / class detectors (line-anchored; capture the leading indent).
const DEF_RE = /^(\s*)(async\s+)?def\s+(\w+)\s*\(([^)]*)\)/;
// A def whose `(` may not close on the same line — used to recover multiline signatures.
const DEF_START_RE = /^(\s*)(async\s+)?def\s+(\w+)\s*\(/;
const CLASS_RE = /^(\s*)class\s+(\w+)/;
const DECORATOR_RE = /^\s*@/;

// Entry-point signals.
const ENTRY_DECORATOR_RES: RegExp[] = [
  /@(app|router|bp|blueprint)\.(route|get|post|put|delete|patch)/i,
  /@.*\.route/i,
  /grpc|servicer|rpc/i,
  /webhook|@app\.(get|post)/i,
];
const ENTRY_NAME_RES: RegExp[] = [
  /^(handle|on|process|serve|do_|post_|get_)/i,
  /_handler$|_view$|_endpoint$/i,
];

// Classification signals.
const SECURITY_CONTROL_NAME_RE =
  /valid|verif|auth|authoriz|authentic|permission|sanitiz|escap|csrf|check_|require_|is_allowed/i;

// Dangerous sinks that make a block part of the attack surface.
const DANGEROUS_SINK_RE =
  /requests\.(get|post|put)|urllib|urlopen|httpx|socket\.|subprocess|os\.system|\beval\(|\bexec\(|pickle\.loads|yaml\.load|cursor\.execute|\.raw\(|open\(/;

// Outbound-request sinks specifically (subset of the above) — used for the
// SSRF/IDOR "identifier param + outbound request" signal.
const OUTBOUND_REQUEST_RE =
  /requests\.(get|post|put)|urllib|urlopen|httpx|socket\./;

// URL/identifier-shaped param names.
const RISKY_PARAM_RE = /url|uri|endpoint|host|addr|id$|_id|path|file|name/i;

// Individual sink patterns, for evidence reporting (riskSignals[]).
const SINK_EVIDENCE_RES: Array<{ label: string; re: RegExp }> = [
  { label: 'requests.get/post/put', re: /requests\.(get|post|put)/ },
  { label: 'urllib', re: /urllib/ },
  { label: 'urlopen', re: /urlopen/ },
  { label: 'httpx', re: /httpx/ },
  { label: 'socket', re: /socket\./ },
  { label: 'subprocess', re: /subprocess/ },
  { label: 'os.system', re: /os\.system/ },
  { label: 'eval()', re: /\beval\(/ },
  { label: 'exec()', re: /\bexec\(/ },
  { label: 'pickle.loads', re: /pickle\.loads/ },
  { label: 'yaml.load', re: /yaml\.load/ },
  { label: 'cursor.execute', re: /cursor\.execute/ },
  { label: '.raw()', re: /\.raw\(/ },
  { label: 'open()', re: /open\(/ },
];

// Base priority score per exposure class.
const EXPOSURE_BASE: Record<Exposure, number> = {
  exposed_externally: 100,
  attack_surface: 80,
  exposed_internally: 50,
  security_control: 40,
  neutral: 10,
};

// =============================================================================
// STAGE 1 — CRAWL
// =============================================================================

function isExcluded(path: string, excludeGlobs: string[]): boolean {
  // Bare fragments match a path SEGMENT only; glob (`*`) entries match as a
  // substring.
  const segments = path.split(sep);
  for (const ex of excludeGlobs) {
    if (!ex) continue;
    if (segments.includes(ex)) return true;
    if (ex.includes('*') && path.includes(ex.replace(/\*/g, ''))) return true;
  }
  return false;
}

function hasIncludedExt(name: string, includeExts: string[]): boolean {
  return includeExts.some((ext) => name.endsWith(ext));
}

/**
 * Recursively walk `config.repoRoot`, returning the paths of files whose
 * extension is in `includeExts`, skipping anything matching `excludeGlobs`
 * (plus the built-in default excludes) and files larger than `maxFileBytes`.
 *
 * Deterministic: directory entries are sorted before descent.
 */
export function crawl(config: IngestConfig): string[] {
  const out: string[] = [];
  const excludes = [...DEFAULT_EXCLUDES, ...(config.excludeGlobs ?? [])];
  const maxFiles = config.maxFiles;

  const walk = (dir: string): void => {
    if (maxFiles !== undefined && out.length >= maxFiles) return; // ceiling hit — stop descending
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // unreadable dir — skip, stay pure/deterministic
    }
    // sort for deterministic ordering
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

    for (const entry of entries) {
      if (maxFiles !== undefined && out.length >= maxFiles) return; // ceiling hit — stop
      const full = join(dir, entry.name);
      if (isExcluded(full, excludes)) continue;

      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile()) {
        if (!hasIncludedExt(entry.name, config.includeExts)) continue;
        if (config.maxFileBytes !== undefined) {
          try {
            if (statSync(full).size > config.maxFileBytes) continue;
          } catch {
            continue;
          }
        }
        out.push(full);
      }
    }
  };

  walk(config.repoRoot);
  if (maxFiles !== undefined && out.length >= maxFiles) {
    console.warn(`[code-ingest] crawl reached maxFiles ceiling (${maxFiles}); repo may be truncated — raise IngestConfig.maxFiles to analyze more.`);
  }
  return out;
}

// =============================================================================
// STAGE 2 — PARSE (regex "AST-lite")
// =============================================================================

/** Track the enclosing-class indent stack so we can label methods vs functions. */
interface ClassFrame {
  indent: number;
}

/**
 * Is a line "significant" for indentation-based block-end detection?
 * Blank lines and comment-only lines do NOT end a block.
 */
function isBlankOrComment(line: string): boolean {
  const trimmed = line.trim();
  return trimmed === '' || trimmed.startsWith('#');
}

/** Find the 1-indexed lineEnd of a block that starts at `startIdx` (0-indexed). */
function findBlockEnd(lines: string[], startIdx: number, defIndent: number): number {
  for (let i = startIdx + 1; i < lines.length; i++) {
    const line = lines[i];
    if (isBlankOrComment(line)) continue;
    const indent = leadingIndent(line);
    if (indent <= defIndent) {
      // block ended on the previous significant line; walk back over trailing blanks
      let end = i - 1;
      while (end > startIdx && isBlankOrComment(lines[end])) end--;
      return end + 1; // convert to 1-indexed
    }
  }
  // ran to EOF — block extends to the last line
  return lines.length;
}

function leadingIndent(line: string): number {
  let n = 0;
  for (const ch of line) {
    if (ch === ' ') n += 1;
    else if (ch === '\t') n += 1; // treat a tab as one indent unit (prototype)
    else break;
  }
  return n;
}

/** Split a Python signature arg list into bare parameter names. */
function parseParams(rawArgs: string): string[] {
  if (!rawArgs.trim()) return [];
  const out: string[] = [];
  for (const rawPart of rawArgs.split(',')) {
    let part = rawPart.trim();
    if (!part) continue;
    // drop default value  (a=1)  and annotation  (a: int)
    part = part.split('=')[0];
    part = part.split(':')[0];
    part = part.trim();
    // strip *args / **kwargs markers to the bare name
    part = part.replace(/^\*+/, '').trim();
    if (!part) continue; // bare "*" positional-only marker
    if (part === '/') continue; // positional-only separator
    if (part === 'self' || part === 'cls') continue;
    out.push(part);
  }
  return out;
}

/**
 * Recover a def signature that may span multiple lines. Balances parens (so a
 * nested call/bracket in a default value doesn't end it early) and returns the
 * bare arg substring plus the index of the line holding the matching ')'.
 * Returns null if the parens never balance within a sane window (truncated /
 * malformed) — the caller then skips it rather than mis-parsing.
 */
function readDefSignature(
  lines: string[],
  startIdx: number,
): { name: string; rawArgs: string; endIdx: number } | null {
  const m = lines[startIdx].match(DEF_START_RE);
  if (!m) return null;
  const name = m[3];
  const openPos = m[0].length - 1; // index of the '(' on the first line
  let depth = 0;
  let started = false;
  let args = '';
  const cap = Math.min(lines.length, startIdx + 60); // bound the scan
  for (let i = startIdx; i < cap; i++) {
    const line = lines[i];
    const from = i === startIdx ? openPos : 0;
    for (let c = from; c < line.length; c++) {
      const ch = line[c];
      if (ch === '(') {
        depth += 1;
        started = true;
        if (depth === 1) continue; // don't record the outer '('
      } else if (ch === ')') {
        depth -= 1;
        if (depth === 0) return { name, rawArgs: args, endIdx: i };
      }
      if (started && depth >= 1) args += ch;
    }
    if (started) args += '\n'; // separator between wrapped lines (parseParams trims)
  }
  return null;
}

/** Collect decorator lines immediately preceding line index `startIdx`. */
function collectDecorators(lines: string[], startIdx: number): string[] {
  const decos: string[] = [];
  for (let i = startIdx - 1; i >= 0; i--) {
    const line = lines[i];
    if (line.trim() === '') continue; // allow blank lines between decorators
    if (DECORATOR_RE.test(line)) {
      decos.unshift(line.trim());
    } else {
      break;
    }
  }
  return decos;
}

/**
 * Parse one file's content into CodeBlocks using line-oriented regexes.
 *
 * PROTOTYPE CAVEAT (see file header): multiline def signatures are recovered by
 * paren-balancing (readDefSignature), but `def`/`class` inside a string/docstring
 * is still falsely matched, and a nested inner def is labeled a "method".
 */
export function parseFile(path: string, content: string): CodeBlock[] {
  const lines = content.split('\n');
  const blocks: CodeBlock[] = [];
  const classStack: ClassFrame[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    const classMatch = line.match(CLASS_RE);
    // def: single-line fast path, then multiline-signature recovery.
    let defName: string | null = null;
    let defArgs = '';
    let sigEndIdx = i;
    const singleDef = line.match(DEF_RE);
    if (singleDef) {
      defName = singleDef[3];
      defArgs = singleDef[4];
    } else if (!classMatch && DEF_START_RE.test(line)) {
      const sig = readDefSignature(lines, i);
      if (sig) {
        defName = sig.name;
        defArgs = sig.rawArgs;
        sigEndIdx = sig.endIdx;
      }
    }

    if (!classMatch && !defName) continue;

    const indent = leadingIndent(line);

    // Pop any class frames we've dedented out of.
    while (classStack.length && indent <= classStack[classStack.length - 1].indent) {
      classStack.pop();
    }

    const lineStart = i + 1;
    // Measure a def's body from AFTER its (possibly multiline) signature, so a
    // ")"-on-its-own-line at def indent isn't mistaken for the block end.
    const lineEnd = findBlockEnd(lines, classMatch ? i : sigEndIdx, indent);
    const body = lines.slice(i, lineEnd).join('\n');
    const decorators = collectDecorators(lines, i);

    if (classMatch) {
      const name = classMatch[2];
      blocks.push({
        id: `${path}::${name}@${lineStart}`,
        path,
        name,
        kind: 'class',
        lineStart,
        lineEnd,
        params: [],
        decorators,
        body,
      });
      // this class becomes an enclosing frame for subsequent nested defs
      classStack.push({ indent });
    } else if (defName) {
      const nestedInClass =
        classStack.length > 0 && indent > classStack[classStack.length - 1].indent;
      blocks.push({
        id: `${path}::${defName}@${lineStart}`,
        path,
        name: defName,
        kind: nestedInClass ? 'method' : 'function',
        lineStart,
        lineEnd,
        params: parseParams(defArgs),
        decorators,
        body,
      });
    }

    // Skip past multiline-signature continuation lines so they aren't re-scanned.
    if (sigEndIdx > i) i = sigEndIdx;
  }

  return blocks;
}

// =============================================================================
// STAGE 3 — CALL GRAPH
// =============================================================================

export interface CallGraphEntry {
  callees: string[];
  callers: string[];
}

/**
 * Resolve intra-repo calls BY NAME. For each block, scan its body for `name(`
 * occurrences of OTHER known block names and record them as callees; callers are
 * the inverse. Keyed by block id.
 *
 * PROTOTYPE CAVEAT: name collisions across files are not disambiguated — every
 * block sharing that name is treated as a callee. This is the honest limit of a
 * name-matcher without a real symbol table.
 */
export function buildCallGraph(blocks: CodeBlock[]): Record<string, CallGraphEntry> {
  const graph: Record<string, CallGraphEntry> = {};
  for (const b of blocks) graph[b.id] = { callees: [], callers: [] };

  // name -> ids (multiple blocks can share a name)
  const byName = new Map<string, string[]>();
  for (const b of blocks) {
    const arr = byName.get(b.name) ?? [];
    arr.push(b.id);
    byName.set(b.name, arr);
  }

  // Precompile a call-detector per distinct name.
  const nameRes = new Map<string, RegExp>();
  for (const name of byName.keys()) {
    nameRes.set(name, new RegExp(`\\b${escapeRe(name)}\\s*\\(`));
  }

  for (const b of blocks) {
    // A block should not count as calling itself just by its own def line; strip
    // the first line (the def) before scanning so `def foo(` doesn't self-match.
    const bodyAfterSignature = b.body.split('\n').slice(1).join('\n');
    for (const [name, ids] of byName) {
      if (name === b.name && ids.length === 1) continue; // pure self, skip
      const re = nameRes.get(name)!;
      if (re.test(bodyAfterSignature)) {
        for (const targetId of ids) {
          if (targetId === b.id) continue; // no self-edge
          if (!graph[b.id].callees.includes(targetId)) {
            graph[b.id].callees.push(targetId);
          }
          if (!graph[targetId].callers.includes(b.id)) {
            graph[targetId].callers.push(b.id);
          }
        }
      }
    }
  }

  return graph;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// =============================================================================
// STAGE 4 — ENTRY POINTS
// =============================================================================

/**
 * A block is an entry point if any decorator matches an externally-triggered
 * handler pattern OR its name matches a handler-shaped pattern. Returns ids.
 */
export function findEntryPoints(blocks: CodeBlock[]): string[] {
  const ids: string[] = [];
  for (const b of blocks) {
    if (isEntryPoint(b)) ids.push(b.id);
  }
  return ids;
}

function isEntryPoint(b: CodeBlock): boolean {
  const decoText = b.decorators.join('\n');
  if (decoText && ENTRY_DECORATOR_RES.some((re) => re.test(decoText))) return true;
  if (ENTRY_NAME_RES.some((re) => re.test(b.name))) return true;
  return false;
}

// =============================================================================
// STAGE 5 — REACHABILITY
// =============================================================================

export interface Reachability {
  reachable: boolean;
  reachDepth: number;
  paths: string[][];
}

/**
 * BFS from entry points through callees. Sets reachable + shortest reachDepth,
 * and records ONE representative id-chain path per reached block.
 */
export function reachability(
  callGraph: Record<string, CallGraphEntry>,
  entryPointIds: string[],
): Record<string, Reachability> {
  const result: Record<string, Reachability> = {};
  for (const id of Object.keys(callGraph)) {
    result[id] = { reachable: false, reachDepth: Infinity, paths: [] };
  }

  interface QItem {
    id: string;
    depth: number;
    path: string[];
  }
  const queue: QItem[] = [];

  for (const id of entryPointIds) {
    if (!(id in result)) continue;
    result[id] = { reachable: true, reachDepth: 0, paths: [[id]] };
    queue.push({ id, depth: 0, path: [id] });
  }

  while (queue.length) {
    const { id, depth, path } = queue.shift()!;
    const entry = callGraph[id];
    if (!entry) continue;
    for (const callee of entry.callees) {
      const cur = result[callee];
      if (!cur) continue;
      if (!cur.reachable) {
        const newPath = [...path, callee];
        result[callee] = {
          reachable: true,
          reachDepth: depth + 1,
          paths: [newPath],
        };
        queue.push({ id: callee, depth: depth + 1, path: newPath });
      }
      // shortest-path only (BFS visits shortest first); deeper re-discoveries
      // are ignored so reachDepth stays the minimum hop count.
    }
  }

  // Normalize unreachable Infinity depths to a sentinel that survives JSON.
  for (const id of Object.keys(result)) {
    if (!result[id].reachable) {
      result[id].reachDepth = -1;
    }
  }

  return result;
}

// =============================================================================
// STAGE 6 — CLASSIFY
// =============================================================================

export interface ClassifyContext {
  isEntryPoint: boolean;
  reachable: boolean;
}

/** Compute the risk-signal evidence list for a block (sinks + risky-param combo). */
function computeRiskSignals(block: CodeBlock): string[] {
  const signals: string[] = [];
  const body = block.body;

  for (const { label, re } of SINK_EVIDENCE_RES) {
    if (re.test(body)) signals.push(`sink:${label}`);
  }

  const riskyParam = block.params.find((p) => RISKY_PARAM_RE.test(p));
  if (riskyParam && OUTBOUND_REQUEST_RE.test(body)) {
    signals.push(`ssrf-idor:param(${riskyParam})+outbound-request`);
  }

  return signals;
}

/** Does this block accept an identifier-shaped param AND make an outbound request? */
function hasSsrfIdorShape(block: CodeBlock): boolean {
  const riskyParam = block.params.some((p) => RISKY_PARAM_RE.test(p));
  return riskyParam && OUTBOUND_REQUEST_RE.test(block.body);
}

/**
 * Assign exactly ONE Exposure with fixed precedence:
 *   exposed_externally > security_control (by NAME) > attack_surface (by BODY/param)
 *     > exposed_internally (reachable) > neutral.
 *
 * NOTE: attack_surface fires EVEN IF the block is unreachable — in a monorepo the
 * real callers may be outside the scan scope, so an outbound-request sink is a
 * real surface regardless of intra-repo reachability.
 */
export function classify(
  block: CodeBlock,
  ctx: ClassifyContext,
): { exposure: Exposure; riskSignals: string[] } {
  const riskSignals = computeRiskSignals(block);

  if (ctx.isEntryPoint) {
    return { exposure: 'exposed_externally', riskSignals };
  }

  if (SECURITY_CONTROL_NAME_RE.test(block.name)) {
    return { exposure: 'security_control', riskSignals };
  }

  const hasDangerousSink = DANGEROUS_SINK_RE.test(block.body);
  if (hasDangerousSink || hasSsrfIdorShape(block)) {
    return { exposure: 'attack_surface', riskSignals };
  }

  if (ctx.reachable) {
    return { exposure: 'exposed_internally', riskSignals };
  }

  return { exposure: 'neutral', riskSignals };
}

// =============================================================================
// STAGE 7 — PRIORITIZE
// =============================================================================

/**
 * priority =
 *   base-by-exposure
 * + 10 per riskSignal
 * + reachability bonus (reachable ? max(0, 30 - reachDepth*5) : 0)
 * + SSRF/IDOR bonus (+20 when identifier-param AND outbound request)
 * clamped to a minimum of 0. Unreachable blocks simply miss the reachability
 * bonus — they are never pushed negative / buried.
 */
export function prioritize(unit: {
  block: CodeBlock;
  exposure: Exposure;
  reachable: boolean;
  reachDepth: number;
  riskSignals: string[];
}): number {
  let score = EXPOSURE_BASE[unit.exposure];
  score += 10 * unit.riskSignals.length;
  if (unit.reachable) {
    score += Math.max(0, 30 - unit.reachDepth * 5);
  }
  if (hasSsrfIdorShape(unit.block)) {
    score += 20;
  }
  return Math.max(0, score);
}

// =============================================================================
// PUBLIC API — ingestRepository
// =============================================================================

/**
 * Run the full pipeline: crawl → parse → call graph → entry points →
 * reachability → classify → prioritize → emit (sorted by priority desc).
 */
export function ingestRepository(config: IngestConfig): IngestResult {
  const files = crawl(config);
  const maxTotalBytes = config.maxTotalBytes;
  let totalBytes = 0;
  // truncated if crawl already hit the file ceiling, or the byte ceiling trips below.
  let truncated = config.maxFiles !== undefined && files.length >= config.maxFiles;

  const allBlocks: CodeBlock[] = [];
  let processedFiles = 0;
  for (const path of files) {
    let content: string;
    try {
      content = readFileSync(path, 'utf8');
    } catch {
      continue;
    }
    processedFiles += 1;
    totalBytes += content.length;
    allBlocks.push(...parseFile(path, content));
    if (maxTotalBytes !== undefined && totalBytes >= maxTotalBytes) {
      truncated = true;
      console.warn(`[code-ingest] ingest reached maxTotalBytes ceiling (${maxTotalBytes}) after ${totalBytes} bytes; remaining files skipped — raise IngestConfig.maxTotalBytes to analyze more.`);
      break;
    }
  }

  const callGraph = buildCallGraph(allBlocks);
  const entryPoints = findEntryPoints(allBlocks);
  const entrySet = new Set(entryPoints);
  const reach = reachability(callGraph, entryPoints);

  const stats: IngestResult['stats'] = {
    files: processedFiles,
    blocks: allBlocks.length,
    exposed_externally: 0,
    exposed_internally: 0,
    attack_surface: 0,
    security_control: 0,
    neutral: 0,
  };
  // Only surface `truncated` when it actually fired — keeps a normal ingest's stats shape
  // byte-identical (existing toEqual tests unaffected).
  if (truncated) stats.truncated = true;

  const units: AnalysisUnit[] = [];
  for (const block of allBlocks) {
    const r = reach[block.id] ?? { reachable: false, reachDepth: -1, paths: [] };
    const ctx: ClassifyContext = {
      isEntryPoint: entrySet.has(block.id),
      reachable: r.reachable,
    };
    const { exposure, riskSignals } = classify(block, ctx);
    const priority = prioritize({
      block,
      exposure,
      reachable: r.reachable,
      reachDepth: r.reachDepth,
      riskSignals,
    });

    stats[exposure] += 1;

    units.push({
      block,
      exposure,
      callers: callGraph[block.id]?.callers ?? [],
      callees: callGraph[block.id]?.callees ?? [],
      reachable: r.reachable,
      reachDepth: r.reachDepth,
      reachabilityPaths: r.paths,
      riskSignals,
      priority,
    });
  }

  // STAGE 8 — emit sorted by priority desc; stable tiebreak on id for determinism.
  units.sort((a, b) => b.priority - a.priority || (a.block.id < b.block.id ? -1 : a.block.id > b.block.id ? 1 : 0));

  return { analysisUnits: units, entryPoints, stats };
}

/**
 * Sensible default config for a Python repo. Python-only by design (see header).
 */
export function createPythonIngestConfig(repoRoot: string): IngestConfig {
  return {
    repoRoot,
    includeExts: ['.py'],
    excludeGlobs: [...DEFAULT_EXCLUDES],
    maxFileBytes: 1_000_000,
    maxFiles: 50_000,             // generous ceiling — a normal repo is far below this
    maxTotalBytes: 1_000_000_000, // 1 GB cumulative — bounds ingest memory on a runaway repo
  };
}

// =============================================================================
// COMPOSITION WITH context-pack — rendering & security-ordered packing
// =============================================================================

/** Render one AnalysisUnit into an LLM-facing block of text. */
export function formatUnitForLLM(unit: AnalysisUnit): string {
  const b = unit.block;
  const lines: string[] = [];
  lines.push(`# ${b.path}:${b.lineStart}-${b.lineEnd}  ${b.name} (${b.kind})`);
  lines.push(`exposure: ${unit.exposure}   priority: ${unit.priority}`);
  lines.push(
    `reachable: ${unit.reachable}${unit.reachable ? ` (depth ${unit.reachDepth})` : ''}`,
  );
  lines.push(`callers: ${unit.callers.length ? unit.callers.join(', ') : '(none)'}`);
  lines.push(`callees: ${unit.callees.length ? unit.callees.join(', ') : '(none)'}`);
  if (unit.reachabilityPaths.length) {
    const path = unit.reachabilityPaths[0];
    lines.push(`reachability path: ${path.join(' -> ')}`);
  }
  lines.push(
    `risk signals: ${unit.riskSignals.length ? unit.riskSignals.join(', ') : '(none)'}`,
  );
  lines.push('---');
  lines.push(redactString(b.body));
  return lines.join('\n');
}

/** Turn analysis units into a context-pack SourceBundle (one file per unit). */
export function analysisUnitsToBundle(units: AnalysisUnit[]): SourceBundle {
  return units.map<SourceFile>((unit) => ({
    path: `${unit.block.path}::${unit.block.name}`,
    content: formatUnitForLLM(unit),
  }));
}

export interface PackedAnalysis {
  text: string;
  includedUnits: AnalysisUnit[];
  droppedUnits: AnalysisUnit[];
  tokensUsed: number;
}

/**
 * Pack analysis units into a token budget, PRESERVING the security priority
 * order the units already arrive in (do NOT re-rank by lexical relevance — that
 * is context-pack's job). Reuses the shared `estimateTokens` estimator; it does
 * NOT reimplement token counting or add a char-count batcher.
 *
 * Units are added in order until the next unit would push the running estimate
 * over `tokenBudget`; that unit and every remaining unit are dropped. (Because
 * units are already sorted by priority desc, this drops the lowest-priority
 * units, exactly as intended.)
 */
export function packAnalysisUnits(
  units: AnalysisUnit[],
  tokenBudget: number,
): PackedAnalysis {
  const budget = Math.max(0, Math.floor(tokenBudget));
  const sections: string[] = [];
  const includedUnits: AnalysisUnit[] = [];
  const droppedUnits: AnalysisUnit[] = [];
  let tokensUsed = 0;

  for (const unit of units) {
    const rendered = formatUnitForLLM(unit);
    // cost of appending this section (join with a newline between sections)
    const candidateText = sections.length
      ? `${sections.join('\n')}\n${rendered}`
      : rendered;
    const candidateTokens = estimateTokens(candidateText);

    if (candidateTokens > budget && includedUnits.length > 0) {
      droppedUnits.push(unit);
      continue;
    }
    if (candidateTokens > budget && includedUnits.length === 0) {
      // even the first (highest-priority) unit overflows the budget — drop it
      // rather than silently exceeding the budget.
      droppedUnits.push(unit);
      continue;
    }

    sections.push(rendered);
    includedUnits.push(unit);
    tokensUsed = candidateTokens;
  }

  return {
    text: sections.join('\n'),
    includedUnits,
    droppedUnits,
    tokensUsed,
  };
}
