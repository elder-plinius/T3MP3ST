/**
 * T3MP3ST Arsenal — Kali+ adapter → CustomTool factory (Phase-1)
 *
 * Turns the catalogued Kali+ `ToolAdapter`s (src/arsenal/catalog.ts) into real, arg-templated,
 * scope-checked, gracefully-degrading `CustomTool`s (src/types/index.ts) that the engine's Arsenal
 * can register and an operator can call.
 *
 * Design constraints (from the pack-hunt design HT-1):
 *  - Dangerous adapters stay off the callable surface: `execution === 'catalog_only'` (metasploit,
 *    hydra) and `execution === 'import_only'` (bloodhound) are NEVER minted — `adapterToCustomTool`
 *    returns `null` for them, so a keyless pack agent cannot invoke them through generic execution.
 *  - Missing binary DEGRADES, never throws: the handler returns `{ success:false, error: installHint }`
 *    exactly like the hand-written `EXTERNAL_TOOLS` (nmap_scan/nuclei_scan) do, so the model can pick
 *    another tool instead of crashing the loop.
 *  - Scope is enforced BEFORE the subprocess runs. The Arsenal already has a hard egress gate in
 *    `execute()` (scopeViolation), but that only fires when a mission has set a scope. This factory
 *    accepts an OPTIONAL `scopeOk(target)` predicate as a second, in-handler belt-and-braces check on
 *    the resolved target for THIS specific adapter; when provided and it returns false the handler
 *    returns a `SCOPE DENIED` result without spawning anything.
 *
 * Everything is done through INJECTED dependencies (`runSubprocess` / `isToolAvailable` from
 * src/arsenal/index.ts, an optional `scopeOk`) so this module stays self-contained and unit-testable
 * with fakes — it spawns no real binaries of its own and imports no server code.
 */

import type { ToolAdapter } from './catalog.js';
import type { CustomTool, ToolContext, ToolResult } from '../types/index.js';

// =============================================================================
// INJECTED DEPENDENCIES
// =============================================================================

/** Result shape of the real `runSubprocess` in src/arsenal/index.ts. */
export interface SubprocessResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * The (fakeable) dependencies the factory needs. `runSubprocess` / `isToolAvailable` are the real
 * functions exported from src/arsenal/index.ts; `scopeOk` is an optional in-handler target gate.
 */
export interface AdapterToolDeps {
  /** Same signature as `runSubprocess` in src/arsenal/index.ts. */
  runSubprocess: (
    command: string,
    args: string[],
    options?: { timeout?: number; maxOutput?: number }
  ) => Promise<SubprocessResult>;
  /** Same signature as `isToolAvailable` in src/arsenal/index.ts. */
  isToolAvailable: (command: string) => Promise<boolean>;
  /**
   * Optional per-target scope predicate. Receives the resolved target host/url the adapter would hit;
   * return false to refuse the call. When omitted, the in-handler scope check is skipped (the
   * Arsenal-level egress gate in execute() still applies at the engine boundary).
   */
  scopeOk?: (target: string) => boolean;
}

// =============================================================================
// ARG TEMPLATES
// =============================================================================

/**
 * How a given adapter's binary consumes its target + which context parameter carries that target.
 *
 * `build(target, params)` returns the full argv for the subprocess. `targetParam` names the
 * ToolContext parameter the target is read from (falling back to `context.target.address`).
 * `defaultTimeoutMs` is the per-adapter subprocess timeout (scanners get longer budgets).
 */
interface ArgTemplate {
  targetParam: string;
  defaultTimeoutMs: number;
  build: (target: string, params: Record<string, unknown>) => string[];
}

const str = (v: unknown): string | undefined =>
  typeof v === 'string' && v.trim() ? v.trim() : undefined;

/**
 * Resolve the filesystem PATH a source/supply-chain scanner should run against (semgrep, gitleaks,
 * trivy, …). These adapters are non-networked and operate on a directory, defaulting to the working
 * dir (`.`). The subcommand + output flags in each template are HARDCODED — only this path is
 * tunable, and it is sanitised so it cannot smuggle a flag or an inherited URL past the gate:
 *   - a leading `-` would be reparsed as a scanner flag (arg injection) → fall back to `.`,
 *   - an http(s) URL (e.g. a networked mission target inherited via context.target.address) is not a
 *     scan path → fall back to `.`.
 */
const scanPath = (target: string, params: Record<string, unknown>): string => {
  const p = str(params.path) ?? str(params.target) ?? (target || undefined);
  if (!p || /^-/.test(p) || /^https?:\/\//i.test(p)) return '.';
  return p;
};

/**
 * Resolve the local FILE/artifact a reverse-engineering or mobile analyser runs against (objdump,
 * readelf, r2, myth, apkleaks, …). Unlike a directory scanner, a binary tool has no sensible cwd
 * default — a bare `objdump .` is meaningless — so instead of silently degrading this REFUSES an
 * absent or non-local path by throwing, which the factory handler turns into a clean
 * `{ success:false }` result (never an unhandled rejection). The two rejected shapes:
 *   - no path at all → the tool would spawn `<binary> ''` / `<binary>` and produce nothing,
 *   - an http(s) URL (e.g. a networked mission target inherited via context.target.address) → not a
 *     local artifact. (A leading `-` is already refused upstream by the factory's option-looking-
 *     target guard, since these templates read the artifact from their `targetParam`.)
 */
const artifactPath = (target: string, params: Record<string, unknown>): string => {
  const p = str(params.file) ?? str(params.path) ?? str(params.artifact) ?? (target || undefined);
  if (!p) throw new Error('requires a file/artifact path (none was provided).');
  if (/^https?:\/\//i.test(p)) throw new Error(`'${p}' is a URL, not a local artifact path.`);
  return p;
};

/**
 * Per-binary arg templates for the common command-ready adapters. Keyed by `adapter.binary` (the
 * process name), with `adapter.id` also accepted as a fallback key so callers can template by either.
 * Anything not listed here falls back to `DEFAULT_TEMPLATE` (pass the target as a positional arg).
 *
 * Templates are intentionally conservative — no intrusive flags are auto-added; risk stays where the
 * catalog put it and the Arsenal egress gate + optional scopeOk fence the target.
 */
const ARG_TEMPLATES: Record<string, ArgTemplate> = {
  nmap: {
    targetParam: 'target',
    defaultTimeoutMs: 120_000,
    // Scan flags are HARDCODED — never taken from an LLM-supplied string. A free-form `flags` param
    // word-split into argv is arbitrary-nmap-flag injection: `-oN`/`-oX` write attacker-chosen files,
    // `--script` runs arbitrary NSE, `-iL` reads an arbitrary file — none of which the scope gate
    // inspects. `ports` is the only tunable, accepted ONLY if it is a pure port spec (digits, commas,
    // dashes); anything else (spaces, letters, an injected flag) is dropped, not passed through.
    build: (target, params) => {
      const args = ['-sV', '-T4'];
      const ports = str(params.ports);
      if (ports && /^[0-9,-]+$/.test(ports)) args.push('-p', ports);
      args.push(target);
      return args;
    },
  },
  nuclei: {
    targetParam: 'url',
    defaultTimeoutMs: 300_000,
    build: (target, params) => {
      const severity = str(params.severity) ?? 'medium,high,critical';
      const tags = str(params.tags);
      const args = ['-target', target, '-severity', severity, '-silent', '-jsonl'];
      if (tags) args.push('-tags', tags);
      return args;
    },
  },
  ffuf: {
    targetParam: 'url',
    defaultTimeoutMs: 120_000,
    build: (target, params) => {
      const wordlist = str(params.wordlist) ?? '/usr/share/wordlists/dirb/common.txt';
      const mc = str(params.mc) ?? '200,301,302,403';
      return ['-u', target, '-w', wordlist, '-mc', mc, '-o', '/dev/stdout', '-of', 'json', '-s'];
    },
  },
  sqlmap: {
    targetParam: 'url',
    defaultTimeoutMs: 300_000,
    // Keep level/risk low unless the mission receipt explicitly permits intrusive testing.
    build: (target, params) => {
      const level = str(params.level) ?? '1';
      const risk = str(params.risk) ?? '1';
      return ['-u', target, '--batch', `--level=${level}`, `--risk=${risk}`];
    },
  },
  gobuster: {
    targetParam: 'url',
    defaultTimeoutMs: 120_000,
    build: (target, params) => {
      const mode = str(params.mode) ?? 'dir';
      const wordlist = str(params.wordlist) ?? '/usr/share/wordlists/dirb/common.txt';
      return [mode, '-u', target, '-w', wordlist, '-q'];
    },
  },
  nikto: {
    targetParam: 'url',
    defaultTimeoutMs: 300_000,
    build: (target) => ['-h', target],
  },
  httpx: {
    targetParam: 'url',
    defaultTimeoutMs: 60_000,
    build: (target) => ['-u', target, '-status-code', '-title', '-tech-detect', '-json', '-silent'],
  },
  naabu: {
    targetParam: 'host',
    defaultTimeoutMs: 120_000,
    build: (target, params) => {
      const topPorts = str(params.top_ports) ?? '100';
      return ['-host', target, '-top-ports', topPorts, '-silent'];
    },
  },
  katana: {
    targetParam: 'url',
    defaultTimeoutMs: 120_000,
    build: (target) => ['-u', target, '-jsonl', '-silent'],
  },
  subfinder: {
    targetParam: 'domain',
    defaultTimeoutMs: 120_000,
    build: (target) => ['-d', target, '-silent'],
  },
  dalfox: {
    targetParam: 'url',
    defaultTimeoutMs: 180_000,
    build: (target) => ['url', target, '--format', 'json', '--silence'],
  },
  dig: {
    targetParam: 'domain',
    defaultTimeoutMs: 30_000,
    build: (target, params) => {
      const type = str(params.type);
      const args = [target];
      if (type) args.push(type);
      args.push('+short');
      return args;
    },
  },
  host: {
    targetParam: 'domain',
    defaultTimeoutMs: 30_000,
    build: (target) => [target],
  },
  whois: {
    targetParam: 'domain',
    defaultTimeoutMs: 30_000,
    build: (target) => [target],
  },
  curl: {
    targetParam: 'url',
    defaultTimeoutMs: 30_000,
    build: (target, params) => {
      const method = str(params.method) ?? 'GET';
      const args = ['-s', '-i', '-X', method];
      const data = str(params.data);
      if (data) {
        // A `-d`/`--data` value whose first char is `@` (read a local file) or `<` (read stdin) turns
        // curl into a local-file-disclosure / exfil primitive — `-d @/etc/passwd` POSTs that file's
        // contents. `--data-raw` sends the body verbatim and disables @/< interpretation entirely; the
        // explicit reject is belt-and-braces so a caller can never smuggle a file read past the gates.
        if (/^[@<]/.test(data)) {
          throw new Error(`curl: refusing a data value starting with '${data[0]}' (would read a local file/stdin).`);
        }
        args.push('--data-raw', data);
      }
      args.push(target);
      return args;
    },
  },

  // ── Source / supply-chain scanners (non-networked, operate on a PATH) ───────────────────────────
  // Without these, each falls through to DEFAULT_TEMPLATE and spawns `<binary> <target>` — which for
  // a subcommand-driven scanner is a broken invocation (e.g. `semgrep .` never runs a scan, and with
  // no path it is `semgrep ''`). Templates mirror the catalog `commandHint` and hardcode the
  // subcommand + machine-readable output flags; the only tunable is the scan path (see scanPath).
  semgrep: {
    targetParam: 'path',
    defaultTimeoutMs: 300_000,
    build: (target, params) => ['scan', '--config', 'auto', '--json', scanPath(target, params)],
  },
  gitleaks: {
    targetParam: 'path',
    defaultTimeoutMs: 180_000,
    build: (target, params) => ['detect', '--source', scanPath(target, params), '--report-format', 'json', '--redact', '--no-banner'],
  },
  trufflehog: {
    targetParam: 'path',
    defaultTimeoutMs: 300_000,
    build: (target, params) => ['filesystem', scanPath(target, params), '--json', '--no-update'],
  },
  trivy: {
    targetParam: 'path',
    defaultTimeoutMs: 300_000,
    build: (target, params) => ['fs', '--format', 'json', scanPath(target, params)],
  },
  syft: {
    targetParam: 'path',
    defaultTimeoutMs: 180_000,
    build: (target, params) => ['dir:' + scanPath(target, params), '-o', 'cyclonedx-json'],
  },
  grype: {
    targetParam: 'path',
    defaultTimeoutMs: 180_000,
    build: (target, params) => ['dir:' + scanPath(target, params), '-o', 'json'],
  },
  checkov: {
    targetParam: 'path',
    defaultTimeoutMs: 180_000,
    build: (target, params) => ['-d', scanPath(target, params), '-o', 'json'],
  },

  // ── Reverse-engineering / mobile / smart-contract static analysis (local_read, operate on a FILE) ─
  // Without these each falls through to DEFAULT_TEMPLATE and spawns `<binary> <file>` — which for a
  // subcommand- or flag-driven analyser is a broken (or, for r2, an INTERACTIVE-shell-hanging)
  // invocation. Templates mirror the catalog `commandHint` and hardcode the READ-ONLY subcommand +
  // machine-readable output flags; the only tunable is the artifact/scan path (see artifactPath /
  // scanPath). None add an intrusive or code-executing flag — risk stays where the catalog put it.
  objdump: {
    // `objdump <file>` errors ("no options given"); disassembly needs an action flag.
    targetParam: 'file',
    defaultTimeoutMs: 60_000,
    build: (target, params) => ['-d', '-M', 'intel', artifactPath(target, params)],
  },
  readelf: {
    // `readelf <file>` errors ("Warning: Nothing to do"); `-a` dumps all ELF headers.
    targetParam: 'file',
    defaultTimeoutMs: 60_000,
    build: (target, params) => ['-a', artifactPath(target, params)],
  },
  checksec: {
    // checksec takes its subject as `--file=<path>`, not a bare positional.
    targetParam: 'file',
    defaultTimeoutMs: 30_000,
    build: (target, params) => ['--file=' + artifactPath(target, params)],
  },
  r2: {
    // A bare `r2 <file>` drops into an INTERACTIVE prompt and blocks the agent loop until the
    // per-adapter timeout burns out. `-q -c ij` runs ONE read-only info command as JSON, then quits;
    // `scr.color=0` keeps the JSON free of ANSI escapes. No `w`/`!`/analysis-write commands are used.
    targetParam: 'file',
    defaultTimeoutMs: 60_000,
    build: (target, params) => ['-q', '-e', 'scr.color=0', '-c', 'ij', artifactPath(target, params)],
  },
  exiftool: {
    // `exiftool <file>` works but prints human text; `-json` gives a structured, parseable channel.
    targetParam: 'file',
    defaultTimeoutMs: 30_000,
    build: (target, params) => ['-json', artifactPath(target, params)],
  },
  myth: {
    // `myth <file>` errors; Mythril needs the `analyze` subcommand. `-o json` emits machine output.
    targetParam: 'file',
    defaultTimeoutMs: 300_000,
    build: (target, params) => ['analyze', artifactPath(target, params), '-o', 'json'],
  },
  apkleaks: {
    // `apkleaks <file>` errors; the APK is supplied via `-f`. Results print to stdout.
    targetParam: 'file',
    defaultTimeoutMs: 180_000,
    build: (target, params) => ['-f', artifactPath(target, params)],
  },
  slither: {
    // Slither accepts a positional target, but a bare run prints human text; `--json -` streams the
    // findings as JSON to stdout. Directory-oriented, so it may default to the working dir.
    targetParam: 'path',
    defaultTimeoutMs: 300_000,
    build: (target, params) => [scanPath(target, params), '--json', '-'],
  },
  mobsfscan: {
    // Directory-oriented static scanner; `--json` gives a structured channel over the default text.
    targetParam: 'path',
    defaultTimeoutMs: 180_000,
    build: (target, params) => ['--json', scanPath(target, params)],
  },
};

/** Fallback for any mintable adapter without a bespoke template: pass the target as a positional arg. */
const DEFAULT_TEMPLATE: ArgTemplate = {
  targetParam: 'target',
  defaultTimeoutMs: 120_000,
  build: (target) => [target],
};

/** The parameter keys a target may arrive under, mirroring the Arsenal's SCOPE_TARGET_KEYS surface. */
const TARGET_PARAM_KEYS = ['url', 'target', 'host', 'hostname', 'domain', 'address', 'endpoint', 'base_url'];

function resolveTemplate(adapter: ToolAdapter): ArgTemplate {
  return ARG_TEMPLATES[adapter.binary] ?? ARG_TEMPLATES[adapter.id] ?? DEFAULT_TEMPLATE;
}

/**
 * True when the adapter has a bespoke `ARG_TEMPLATE` (a real, hardcoded invocation) rather than
 * falling through to `DEFAULT_TEMPLATE`'s bare `<binary> <target>`. Exported so the invocation-honesty
 * guard test can assert that every mintable adapter's invocation correctness is explicitly classified
 * — and that a newly-catalogued subcommand tool cannot silently ship a broken positional invocation.
 */
export function hasArgTemplate(adapter: ToolAdapter): boolean {
  return Boolean(ARG_TEMPLATES[adapter.binary] ?? ARG_TEMPLATES[adapter.id]);
}

/**
 * Resolve the target string for an adapter call: the template's preferred param first, then the other
 * common target keys, then `context.target.address`. Returns undefined if none is present.
 */
function resolveTarget(template: ArgTemplate, context: ToolContext): string | undefined {
  const params = context.parameters || {};
  const preferred = str(params[template.targetParam]);
  if (preferred) return preferred;
  for (const k of TARGET_PARAM_KEYS) {
    const v = str(params[k]);
    if (v) return v;
  }
  return str(context.target?.address);
}

// =============================================================================
// FACTORY
// =============================================================================

/** True only for adapters that may be minted as callable tools (safe_command / receipt_required). */
export function isMintable(adapter: ToolAdapter): boolean {
  return adapter.execution === 'safe_command' || adapter.execution === 'receipt_required';
}

/**
 * Turn one catalogued adapter into a callable `CustomTool`.
 *
 * Returns `null` for `execution === 'catalog_only'` (metasploit, hydra) and `execution ===
 * 'import_only'` (bloodhound) — those are NEVER minted, so they cannot be reached through generic
 * command execution.
 */
export function adapterToCustomTool(adapter: ToolAdapter, deps: AdapterToolDeps): CustomTool | null {
  if (!isMintable(adapter)) return null; // catalog_only / import_only are never callable

  const template = resolveTemplate(adapter);

  const handler = async (context: ToolContext): Promise<ToolResult> => {
    // 1) Degrade (never throw) when the binary is absent — the model picks another tool.
    if (!(await deps.isToolAvailable(adapter.binary))) {
      return {
        success: false,
        error: `${adapter.name} (${adapter.binary}) is not installed. ${adapter.installHint}`,
      };
    }

    // 2) Resolve the target this call would hit.
    const target = resolveTarget(template, context);
    if (adapter.networked && !target) {
      return { success: false, error: `${adapter.name} requires a target (${template.targetParam}).` };
    }

    // 2b) Refuse an option-looking target: a value starting with '-' gets reparsed by the tool as a
    //     FLAG rather than a target (curl `-K`/`-o`, nikto/whois/host positional, the default
    //     positional template) — argument injection that slips past the scope gate, which only
    //     inspects hosts. Reject it at this single choke point, before any argv is built or spawned.
    if (target && /^-/.test(target)) {
      return {
        success: false,
        error: `${adapter.name}: refusing option-looking target '${target}' (leading '-' is not a valid host/URL).`,
      };
    }

    // 3) In-handler scope belt-and-braces: refuse an out-of-scope target BEFORE spawning anything.
    if (target && deps.scopeOk && !deps.scopeOk(target)) {
      return {
        success: false,
        error: `SCOPE DENIED: target '${target}' is not in the authorized scope — ${adapter.binary} refused before execution.`,
      };
    }

    // 4) Build argv from the per-adapter template and run the subprocess with a per-adapter timeout.
    //    A template may REFUSE a dangerous param (e.g. curl `-d @file` local-file read) by throwing —
    //    convert that into a clean failure result, never an unhandled rejection.
    let argv: string[];
    try {
      argv = template.build(target ?? '', context.parameters || {});
    } catch (err) {
      return { success: false, error: `${adapter.name}: ${err instanceof Error ? err.message : String(err)}` };
    }
    const result = await deps.runSubprocess(adapter.binary, argv, { timeout: template.defaultTimeoutMs });

    if (result.exitCode !== 0) {
      return {
        success: false,
        error: `${adapter.binary} exited ${result.exitCode}: ${result.stderr || result.stdout || 'no output'}`,
        output: result.stdout || undefined,
      };
    }

    return { success: true, output: result.stdout };
  };

  return {
    name: toolNameFor(adapter),
    description: `${adapter.name}: ${adapter.notes} (Kali+ adapter; ${adapter.execution}, risk=${adapter.risk})`,
    category: adapter.category,
    // Carry the catalog risk onto the tool so Arsenal.execute()'s approval gate can see it: an
    // intrusive/credential/dangerous adapter is inert until approved, and warns on the hottest calls.
    riskTier: adapter.risk,
    parameters: [
      {
        name: template.targetParam,
        type: 'string',
        description: `Target for ${adapter.name} (${adapter.evidenceKinds.join(', ') || 'evidence'}).`,
        required: adapter.networked,
      },
    ],
    handler,
  };
}

/** The stable tool-name a given adapter mints as (used for de-dup against already-registered tools). */
export function toolNameFor(adapter: ToolAdapter): string {
  return `${adapter.id.replace(/[^a-z0-9]+/gi, '_')}_tool`;
}

/**
 * Map a list of adapters to callable `CustomTool`s, skipping:
 *  - non-mintable adapters (catalog_only / import_only → dropped),
 *  - any adapter whose minted tool-name is already present in `alreadyRegistered` (so the bespoke
 *    hand-written EXTERNAL_TOOLS like nmap_scan / nuclei_scan win and we don't double-register).
 */
export function buildAdapterTools(
  adapters: ToolAdapter[],
  deps: AdapterToolDeps,
  alreadyRegistered: ReadonlySet<string> = new Set()
): CustomTool[] {
  const tools: CustomTool[] = [];
  for (const adapter of adapters) {
    const tool = adapterToCustomTool(adapter, deps);
    if (!tool) continue; // catalog_only / import_only
    if (alreadyRegistered.has(tool.name)) continue; // don't shadow an existing registration
    tools.push(tool);
  }
  return tools;
}
