/**
 * T3MP3ST Arsenal — purpose-built post-exploitation drivers (metasploit, hydra).
 *
 * The catalog withholds these from the GENERIC adapter factory (`execution: catalog_only`) because
 * the generic "one-shot CLI + a target arg" shape can't drive them: msfconsole is a command REPL, not
 * `msfconsole <host>`. So they get real, hand-written drivers here instead — structured module/option
 * invocation with parseable output — and each carries its `riskTier` so Arsenal.execute()'s approval
 * gate fences it: a `dangerous`/`credential` tool is inert until the operator has approved it, and the
 * hottest actions fire a loud audited warning.
 *
 * SAFETY (these run live exploitation / real auth traffic):
 *  - the target is scope-checked (the injected `scopeOk`) AND rejected if it looks like a flag.
 *  - metasploit values are sanitized against msf-command injection into the `-x` command string
 *    (a `;` or newline in a module/option would inject extra console commands).
 *  - a missing binary DEGRADES (returns an error result) instead of throwing.
 *
 * Dependencies are INJECTED (same `AdapterToolDeps` the adapter factory uses) so this module spawns no
 * real binaries of its own and is unit-testable with fakes.
 */

import type { AdapterToolDeps } from './adapter-tools.js';
import type { CustomTool, ToolContext, ToolResult } from '../types/index.js';
import { isSensitiveFilePath } from './path-guard.js';

const str = (v: unknown): string | undefined =>
  typeof v === 'string' && v.trim() ? v.trim() : undefined;

/** Resolve the target for a post-ex call: an explicit `target`/`rhosts` param, else the context target. */
function resolveTarget(context: ToolContext): string | undefined {
  const p = context.parameters || {};
  return str(p.target) ?? str(p.rhosts) ?? str(context.target?.address);
}

/** Reject an option-looking value (leading '-') a tool would reparse as its own flag. */
function optionLooking(v: string): boolean {
  return /^-/.test(v);
}

/** A target a tool would misparse or that defeats the scope gate: leading '-' (a flag), leading '/'
 *  or a scheme `x://` (host-normalizes to empty → fail-open), or an `@` (user@host — the scope gate
 *  checks the host AFTER the @, but msf/hydra would receive the raw value, a checked≠emitted mismatch).
 *  Bare hosts / IPs / CIDRs (10.0.0.0/24) pass — CIDR RANGE is validated by the scope gate. */
function unsafeTarget(v: string): boolean {
  return /^[-/]/.test(v) || /:\/\//.test(v) || v.includes('@');
}

/** msf option keys that set the TARGET host — must not be settable via `options` (that would override
 *  the scope-checked `target`/RHOSTS with an unauthorized host). The target comes only from `target`. */
const MSF_TARGET_OPT_KEYS: ReadonlySet<string> = new Set(['rhosts', 'rhost', 'vhost']);

// =============================================================================
// METASPLOIT — resource-command driver via `msfconsole -q -x "<commands>"`
// =============================================================================

// Chars that would break out of an msf command in the `-x` string and inject extra console commands
// (`;` = command separator, CR/LF = new line, quotes/backtick = string breakout). A value containing
// any of these is refused rather than sanitized-and-run — fail closed.
const MSF_UNSAFE = /[;\r\n"'`]/;

/** Build a Metasploit driver tool: `use <module>; set RHOSTS <target>; [set …]; run; exit`. */
export function createMetasploitTool(deps: AdapterToolDeps): CustomTool {
  const handler = async (context: ToolContext): Promise<ToolResult> => {
    if (!(await deps.isToolAvailable('msfconsole'))) {
      return { success: false, error: 'metasploit (msfconsole) is not installed. Install the Metasploit Framework.' };
    }
    const p = context.parameters || {};
    const module = str(p.module);
    if (!module) return { success: false, error: 'metasploit requires a `module` (e.g. exploit/…, auxiliary/…).' };
    // module must be a clean msf module PATH — no spaces or metachars that could add stray tokens to
    // the `use` command (defense-in-depth on top of MSF_UNSAFE, which already blocks ; and newlines).
    if (!/^[A-Za-z0-9/_.-]+$/.test(module)) {
      return { success: false, error: `metasploit: invalid module '${module}' (module paths are alphanumeric plus / _ . -).` };
    }

    const target = resolveTarget(context);
    if (!target) return { success: false, error: 'metasploit requires a `target` (RHOSTS).' };
    if (unsafeTarget(target)) return { success: false, error: `metasploit: refusing malformed target '${target}' (must be a bare host / IP / CIDR).` };
    if (deps.scopeOk && !deps.scopeOk(target)) {
      return { success: false, error: `SCOPE DENIED: RHOSTS '${target}' is not in the authorized scope — metasploit refused before execution.` };
    }

    const payload = str(p.payload);
    if (payload && !/^[A-Za-z0-9/_.-]+$/.test(payload)) {
      return { success: false, error: `metasploit: invalid payload '${payload}' (payload names are alphanumeric plus / _ . -).` };
    }
    const options =
      p.options && typeof p.options === 'object' && !Array.isArray(p.options)
        ? (p.options as Record<string, unknown>)
        : {};

    // Every option key must be a clean msf option name [A-Za-z0-9_]+. This rejects whitespace-padded or
    // space-bearing keys ("RHOSTS ", "RHOSTS 9.9.9.9", "AutoRunScript multi/handler") that would slip
    // past the target-override guard below and inject a SECOND `set` directive into the -x string — a
    // scope escape to an arbitrary host (msf `set RHOSTS` is last-write-wins). Then refuse any option
    // that re-sets the target host: the target comes only via the scope-checked `target` param.
    for (const k of Object.keys(options)) {
      if (!/^[A-Za-z0-9_]+$/.test(k)) {
        return { success: false, error: `metasploit: invalid option key '${k}' (msf option names must be alphanumeric/underscore).` };
      }
      if (MSF_TARGET_OPT_KEYS.has(k.toLowerCase())) {
        return { success: false, error: `metasploit: set the target via the \`target\` param, not the \`${k}\` option (target override refused).` };
      }
    }

    // Sanitize every value that lands in the -x command string against msf-command injection.
    const values: Array<[string, string]> = [['module', module], ['RHOSTS', target]];
    if (payload) values.push(['PAYLOAD', payload]);
    for (const [k, v] of Object.entries(options)) values.push([k, String(v)]);
    for (const [k, v] of values) {
      if (MSF_UNSAFE.test(k) || MSF_UNSAFE.test(v)) {
        return { success: false, error: `metasploit: refusing a value with msf-command metacharacters (;, newline, quotes) in '${k}'.` };
      }
    }

    const commands = [
      `use ${module}`,
      `set RHOSTS ${target}`,
      ...(payload ? [`set PAYLOAD ${payload}`] : []),
      ...Object.entries(options).map(([k, v]) => `set ${k} ${String(v)}`),
      'run',
      'exit',
    ].join('; ');

    const result = await deps.runSubprocess('msfconsole', ['-q', '-x', commands], { timeout: 600_000 });
    if (result.exitCode !== 0) {
      return {
        success: false,
        error: `msfconsole exited ${result.exitCode}: ${result.stderr || result.stdout || 'no output'}`,
        output: result.stdout || undefined,
      };
    }
    return { success: true, output: result.stdout };
  };

  return {
    name: 'metasploit_module',
    description:
      'Run a Metasploit module (exploit/auxiliary/post) against an in-scope target via msfconsole. ' +
      'Params: module, target (RHOSTS), payload?, options{}. DANGEROUS — approval-gated live exploitation.',
    category: 'exploitation',
    riskTier: 'dangerous',
    parameters: [
      { name: 'module', type: 'string', description: 'Module path (e.g. exploit/linux/http/…, auxiliary/scanner/…).', required: true },
      { name: 'target', type: 'string', description: 'RHOSTS — the in-scope target host/IP.', required: true },
      { name: 'payload', type: 'string', description: 'Optional payload (e.g. linux/x64/meterpreter/reverse_tcp).', required: false },
      { name: 'options', type: 'object', description: 'Optional module options as {KEY: value} (e.g. {RPORT: 8080, LHOST: 10.0.0.2}).', required: false },
    ],
    handler,
  };
}

// =============================================================================
// HYDRA — online credential brute-force
// =============================================================================

/** Build a THC-Hydra driver tool: `hydra [-l user|-L userlist] [-p pass|-P passlist] -t N -f service://target`. */
export function createHydraTool(deps: AdapterToolDeps): CustomTool {
  const handler = async (context: ToolContext): Promise<ToolResult> => {
    if (!(await deps.isToolAvailable('hydra'))) {
      return { success: false, error: 'hydra is not installed. Install THC-Hydra.' };
    }
    const p = context.parameters || {};
    const service = str(p.service);
    const target = resolveTarget(context);
    if (!service) return { success: false, error: 'hydra requires a `service` (ssh, ftp, http-get, smb, …).' };
    if (!target) return { success: false, error: 'hydra requires a `target`.' };
    if (!/^[a-z0-9][a-z0-9._+-]*$/i.test(service)) {
      return { success: false, error: `hydra: invalid service '${service}' (expected a hydra module name).` };
    }

    const user = str(p.user);
    const userlist = str(p.userlist);
    const password = str(p.password);
    const passlist = str(p.passlist);
    if (unsafeTarget(target)) return { success: false, error: `hydra: refusing malformed target '${target}' (must be a bare host / IP).` };
    // Refuse option-looking credential values that hydra would reparse as its own flags.
    for (const [label, val] of [['user', user], ['password', password], ['userlist', userlist], ['passlist', passlist]] as const) {
      if (val && optionLooking(val)) return { success: false, error: `hydra: refusing option-looking ${label} '${val}'.` };
    }
    // A user/pass LIST path is LLM-controlled and hydra reads it and sends each line to the target —
    // refuse one that points at local keys/credentials so it can't become a file-exfiltration primitive.
    for (const [label, val] of [['userlist', userlist], ['passlist', passlist]] as const) {
      if (val && isSensitiveFilePath(val)) return { success: false, error: `hydra: refusing ${label} '${val}' — resolves to sensitive local material (keys/credentials).` };
    }
    if (deps.scopeOk && !deps.scopeOk(target)) {
      return { success: false, error: `SCOPE DENIED: target '${target}' is not in the authorized scope — hydra refused before execution.` };
    }

    const argv: string[] = [];
    if (userlist) argv.push('-L', userlist);
    else if (user) argv.push('-l', user);
    else return { success: false, error: 'hydra requires a `user` or a `userlist`.' };
    if (passlist) argv.push('-P', passlist);
    else if (password) argv.push('-p', password);
    else return { success: false, error: 'hydra requires a `password` or a `passlist`.' };

    const tasks = Math.min(Math.max(1, Math.floor(Number(p.tasks) || 4)), 16); // cap to avoid lockouts/DoS
    argv.push('-t', String(tasks), '-f', `${service}://${target}`);

    const result = await deps.runSubprocess('hydra', argv, { timeout: 600_000 });
    // hydra found-credential lines look like: "[22][ssh] host: X   login: Y   password: Z"
    const hits = [...result.stdout.matchAll(/login:\s*(\S+)\s+password:\s*(\S+)/gi)].map((m) => `${m[1]}:${m[2]}`);
    if (hits.length) {
      return { success: true, output: `${result.stdout}\n\nCREDENTIALS FOUND: ${hits.join(', ')}` };
    }
    if (result.exitCode !== 0 && !result.stdout) {
      return { success: false, error: `hydra exited ${result.exitCode}: ${result.stderr || 'no output'}` };
    }
    return { success: true, output: result.stdout || 'hydra completed; no credentials found.' };
  };

  return {
    name: 'hydra_bruteforce',
    description:
      'Online credential brute-force with THC-Hydra against an in-scope service. ' +
      'Params: service, target, user|userlist, password|passlist, tasks?. CREDENTIAL attack — approval-gated real auth traffic.',
    category: 'credential-access',
    riskTier: 'credential',
    parameters: [
      { name: 'service', type: 'string', description: 'Hydra service module (ssh, ftp, http-get, http-post-form, smb, …).', required: true },
      { name: 'target', type: 'string', description: 'In-scope target host/IP.', required: true },
      { name: 'user', type: 'string', description: 'Single username (or use userlist).', required: false },
      { name: 'userlist', type: 'string', description: 'Path to a username wordlist.', required: false },
      { name: 'password', type: 'string', description: 'Single password (or use passlist).', required: false },
      { name: 'passlist', type: 'string', description: 'Path to a password wordlist.', required: false },
      { name: 'tasks', type: 'number', description: 'Parallel tasks (1-16, default 4) — keep low to avoid lockouts.', required: false },
    ],
    handler,
  };
}

/** All purpose-built post-ex driver tools (metasploit, hydra). Registered by the engine when the full
 *  arsenal is armed; each is approval-gated by its riskTier. Bloodhound (collector→graph pipeline) is
 *  deliberately deferred — it's an AD-analysis tool, not a target-firing CLI, and least relevant to
 *  bug-bounty/CTF work. */
export function buildPostExTools(deps: AdapterToolDeps): CustomTool[] {
  return [createMetasploitTool(deps), createHydraTool(deps)];
}
