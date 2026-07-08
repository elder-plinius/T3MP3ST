// =============================================================================
// LOCAL AGENT CONNECTORS — "bring your own already-authed agent"
// =============================================================================
// Detect + connect agent CLIs that already live, authenticated, on the operator's machine
// (Claude Code, Codex, Hermes) and drive them headlessly as t3mp3st operators.
//
// SECURITY POSTURE (important):
//   - We NEVER read, print, log, or transmit credential contents. Auth is detected purely by the
//     PRESENCE of the CLI's own auth artifact (a file path or a macOS keychain item) — never its bytes.
//   - We do NOT enter or store any key. The CLIs are already logged in by the user; we only invoke them.
//   - A "ping"/"dispatch" spawns the user's own CLI as a child process with a prompt and captures its
//     stdout (the model's reply to OUR prompt — not secrets). Everything is local + user-initiated.
// =============================================================================

import { execFile, execFileSync, spawn } from 'child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'fs';
import { homedir, tmpdir } from 'os';
import { join } from 'path';

// t3mp3st injects its OWN provider keys (from .env) into the server process. If we let those leak into
// a spawned CLI, the CLI uses t3mp3st's key instead of the user's native login → 401. The entire point
// of this feature is "use the agent you already authed", so we strip these before spawning so each CLI
// falls back to its own auth (keychain / ~/.codex/auth.json / ~/.hermes/.env).
const PROVIDER_ENV_TO_STRIP = [
  'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL', 'ANTHROPIC_MODEL',
  'OPENAI_API_KEY', 'OPENAI_BASE_URL', 'OPENAI_API_BASE', 'OPENAI_ORGANIZATION',
  'OPENROUTER_API_KEY',
];

const HOME = homedir();
const AGENT_HOME = process.env.T3MP3ST_AGENT_HOME || process.env.T3MP3ST_REAL_HOME || HOME;
const expand = (p: string): string => (p.startsWith('~') ? AGENT_HOME + p.slice(1) : p);

export type LocalAgentId = 'claude' | 'codex' | 'hermes';

interface AgentSpec {
  id: LocalAgentId;
  label: string;
  vendor: string;
  bin: string;
  blurb: string;
  /** how we drive it as a one-shot, non-interactive operator */
  invokeHint: string;
  versionArgs: string[];
  parseVersion: (out: string) => string;
  /** any-of: presence ⇒ authed. PRESENCE ONLY — contents are never read. */
  authArtifacts: string[];
  /** macOS keychain fallback service name */
  keychainService?: string;
  /** build the argv for a headless one-shot prompt */
  oneShot: (prompt: string, model?: string) => string[];
}

const SPECS: AgentSpec[] = [
  {
    id: 'claude',
    label: 'Claude Code',
    vendor: 'Anthropic',
    bin: 'claude',
    blurb: 'Anthropic agentic CLI',
    invokeHint: 'claude -p "<prompt>"',
    versionArgs: ['--version'],
    parseVersion: (o) => (o.match(/[\d]+\.[\d]+(\.[\d]+)?/) || ['?'])[0],
    authArtifacts: ['~/.claude/.credentials.json', '~/.claude.json'],
    keychainService: 'Claude Code-credentials',
    oneShot: (p, m) => ['-p', p, '--output-format', 'text', ...(m ? ['--model', m] : [])],
  },
  {
    id: 'codex',
    label: 'Codex',
    vendor: 'OpenAI',
    bin: 'codex',
    blurb: 'OpenAI Codex CLI',
    invokeHint: 'codex exec "<prompt>"',
    versionArgs: ['--version'],
    parseVersion: (o) => (o.match(/[\d]+\.[\d]+(\.[\d]+)?/) || ['?'])[0],
    authArtifacts: ['~/.codex/auth.json', '~/.config/codex/auth.json'],
    oneShot: (p, m) => ['exec', ...(m ? ['-m', m] : []), p],
  },
  {
    id: 'hermes',
    label: 'Hermes',
    vendor: 'Hermes Agent',
    bin: 'hermes',
    blurb: 'Hermes Agent — tool-calling AI',
    // B-06: --yolo disables Hermes interactive confirmations; enabled by default for
    // non-interactive server use. Set HERMES_YOLO=0 to require confirmations.
    invokeHint: 'hermes -z "<prompt>" --yolo  # omit --yolo or set HERMES_YOLO=0 to require confirmations',
    versionArgs: ['--version'],
    parseVersion: (o) => (o.match(/v([\d]+\.[\d]+(\.[\d]+)?)/)?.[1]) || (o.match(/[\d]+\.[\d]+(\.[\d]+)?/) || ['?'])[0],
    authArtifacts: ['~/.hermes/.env', '~/.hermes/auth.json'],
    oneShot: (p, m) => {
      const yolo = process.env.HERMES_YOLO !== '0';
      return ['-z', p, ...(yolo ? ['--yolo'] : []), ...(m ? ['-m', m] : [])];
    },
  },
];

export function getSpec(id: string): AgentSpec | undefined {
  return SPECS.find((s) => s.id === id);
}

export interface AgentDetection {
  id: LocalAgentId;
  label: string;
  vendor: string;
  bin: string;
  blurb: string;
  invokeHint: string;
  installed: boolean;
  path?: string;
  version?: string;
  authed: boolean;
  authMethod?: string; // e.g. "file" or "keychain" — never the secret itself
  ready: boolean;      // installed && authed
}

function resolvePath(bin: string): string | undefined {
  try {
    return execFileSync('command', ['-v', bin], { shell: '/bin/bash', encoding: 'utf8' }).trim() || undefined;
  } catch {
    try { return execFileSync('which', [bin], { encoding: 'utf8' }).trim() || undefined; } catch { return undefined; }
  }
}

function authState(spec: AgentSpec): { authed: boolean; method?: string } {
  for (const a of spec.authArtifacts) {
    if (existsSync(expand(a))) return { authed: true, method: 'file' };
  }
  if (spec.keychainService) {
    try {
      execFileSync('security', ['find-generic-password', '-s', spec.keychainService], { stdio: 'ignore' });
      return { authed: true, method: 'keychain' };
    } catch { /* not in keychain */ }
  }
  return { authed: false };
}

function detectOne(spec: AgentSpec): Promise<AgentDetection> {
  const base = {
    id: spec.id, label: spec.label, vendor: spec.vendor, bin: spec.bin,
    blurb: spec.blurb, invokeHint: spec.invokeHint,
  };
  return new Promise((resolve) => {
    execFile(spec.bin, spec.versionArgs, { timeout: 8000 }, (err, stdout) => {
      if (err && (err as NodeJS.ErrnoException).code === 'ENOENT') {
        resolve({ ...base, installed: false, authed: false, ready: false });
        return;
      }
      // even a non-zero exit but no ENOENT means the binary exists
      const version = spec.parseVersion(String(stdout || ''));
      const auth = authState(spec);
      resolve({
        ...base,
        installed: true,
        path: resolvePath(spec.bin),
        version,
        authed: auth.authed,
        authMethod: auth.method,
        ready: auth.authed,
      });
    });
  });
}

/** Detect every known local agent CLI (installed? authed? ready?). No tokens spent. */
export async function detectLocalAgents(): Promise<AgentDetection[]> {
  return Promise.all(SPECS.map(detectOne));
}

export interface AgentRunResult {
  ok: boolean;
  latencyMs: number;
  output: string;
  error?: string;
}

/**
 * Drive a connected agent with a one-shot headless prompt (real round-trip — SPENDS the agent's quota).
 * Used by /ping (liveness proof) and /dispatch (actually using the operator).
 */
export function runLocalAgent(
  id: string,
  prompt: string,
  opts: { model?: string; timeoutMs?: number; maxChars?: number } = {},
): Promise<AgentRunResult> {
  const spec = getSpec(id);
  const t0 = Date.now();
  if (!spec) return Promise.resolve({ ok: false, latencyMs: 0, output: '', error: `unknown agent: ${id}` });
  const args = spec.oneShot(prompt, opts.model);
  const timeoutMs = opts.timeoutMs ?? 120000;
  const maxChars = opts.maxChars ?? 4000;
  // child env = ours minus the injected provider keys, so the CLI uses its OWN native login.
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: AGENT_HOME };
  for (const k of PROVIDER_ENV_TO_STRIP) delete env[k];
  return new Promise((resolve) => {
    // stdin:'ignore' so the agent doesn't stall waiting on piped input (e.g. `claude -p`'s 3s stdin wait).
    const child = spawn(spec.bin, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let errOut = '';
    let done = false;
    const finish = (r: AgentRunResult): void => { if (!done) { done = true; clearTimeout(timer); resolve(r); } };
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* noop */ }
      finish({ ok: false, latencyMs: Date.now() - t0, output: out.trim().slice(0, maxChars), error: `timed out after ${timeoutMs}ms` });
    }, timeoutMs);
    child.stdout?.on('data', (d) => { if (out.length < 1_000_000) out += String(d); });
    child.stderr?.on('data', (d) => { if (errOut.length < 100_000) errOut += String(d); });
    child.on('error', (e) => finish({ ok: false, latencyMs: Date.now() - t0, output: '', error: (e as Error).message }));
    child.on('close', (code) => {
      const latencyMs = Date.now() - t0;
      const output = out.trim().slice(0, maxChars);
      if (code === 0) finish({ ok: true, latencyMs, output });
      else finish({ ok: false, latencyMs, output, error: (errOut.trim() || `exited with code ${code}`).slice(0, 300) });
    });
  });
}

/** A cheap liveness probe — asks the agent to echo a token. SPENDS a tiny bit of the agent's quota. */
export function pingLocalAgent(id: string, prompt?: string, timeoutMs?: number): Promise<AgentRunResult> {
  return runLocalAgent(id, prompt || 'Reply with exactly the single word: PONG', {
    timeoutMs: timeoutMs ?? 90000,
    maxChars: 400,
  });
}

/**
 * Drive a connected agent as the LLM BACKEND for the mission/operator flow — a long-prompt one-shot
 * that returns ONLY the model's reply text (no CLI banner). Per-agent invocation: claude/codex feed
 * the prompt via STDIN (robust for long planning prompts), codex uses --output-last-message for a
 * clean reply, hermes takes the prompt as an arg. Provider keys are stripped so each CLI uses its own
 * login (no API key needed). Throws on non-zero exit / timeout so the LLMBackbone retry/fallback fires.
 */
export function localAgentChat(id: string, prompt: string, opts: { model?: string; timeoutMs?: number; signal?: AbortSignal } = {}): Promise<string> {
  const spec = getSpec(id);
  if (!spec) return Promise.reject(new Error(`unknown local agent: ${id}`));
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: AGENT_HOME };
  for (const k of PROVIDER_ENV_TO_STRIP) delete env[k];
  const model = opts.model && opts.model !== 'codex-default' && opts.model !== id ? opts.model : undefined;
  const timeoutMs = opts.timeoutMs ?? 240000;

  let args: string[];
  let viaStdin = true;
  let outFile: string | null = null;
  let workDir: string | null = null;
  if (id === 'claude') {
    args = ['-p', '--output-format', 'text', ...(model ? ['--model', model] : [])];
  } else if (id === 'codex') {
    workDir = mkdtempSync(join(tmpdir(), 't3mp3st-codexllm-'));
    outFile = join(workDir, 'reply.txt');
    args = ['exec', '--skip-git-repo-check', '--color', 'never', '--sandbox', 'read-only', '--output-last-message', outFile, ...(model ? ['-m', model] : [])];
  } else { // hermes — takes the prompt as an arg
    const yolo = process.env.HERMES_YOLO !== '0';
    args = ['-z', prompt, ...(yolo ? ['--yolo'] : []), ...(model ? ['-m', model] : [])];
    viaStdin = false;
  }

  const cleanup = () => { if (workDir) { try { rmSync(workDir, { recursive: true, force: true }); } catch { /* noop */ } } };
  return new Promise((resolve, reject) => {
    if (opts.signal?.aborted) { cleanup(); return reject(new Error('Aborted')); }
    const child = spawn(spec.bin, args, { env, stdio: [viaStdin ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
    let out = '';
    let errOut = '';
    let done = false;
    const finish = (fn: () => void) => { if (!done) { done = true; clearTimeout(timer); cleanup(); fn(); } };
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* noop */ } finish(() => reject(new Error(`${id} timed out after ${timeoutMs}ms`))); }, timeoutMs);
    const onAbort = () => { try { child.kill('SIGKILL'); } catch { /* noop */ } finish(() => reject(new Error('Aborted'))); };
    opts.signal?.addEventListener('abort', onAbort, { once: true });
    child.stdout?.on('data', (d) => { if (out.length < 8_000_000) out += String(d); });
    child.stderr?.on('data', (d) => { if (errOut.length < 200_000) errOut += String(d); });
    child.on('error', (e) => finish(() => reject(e)));
    child.on('close', (code) => {
      opts.signal?.removeEventListener('abort', onAbort);
      let content = out.trim();
      if (outFile) { try { content = (readFileSync(outFile, 'utf8').trim() || content); } catch { /* fall back to stdout */ } }
      finish(() => {
        if (code === 0 && content) resolve(content);
        else reject(new Error((errOut.trim() || content || `exited with code ${code}`).slice(0, 800)));
      });
    });
    if (viaStdin && child.stdin) { child.stdin.write(prompt); child.stdin.end(); }
  });
}
