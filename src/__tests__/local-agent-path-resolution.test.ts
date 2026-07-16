/**
 * REGRESSION (issue #78 — macOS/POSIX): the local-agent detector resolved the CLI binary
 * against the SERVER process PATH. When T3MP3ST is launched from Finder, the desktop app, or
 * any non-interactive shell, launchd hands it a minimal PATH (/usr/bin:/bin:/usr/sbin:/sbin) —
 * missing ~/.local/bin (Claude Code's native install), Homebrew, npm-global, and version-manager
 * shims (mise/nvm/fnm). `execFile('claude', …)` then throws ENOENT and an installed, working CLI
 * is reported `installed:false` (the Settings checkboxes go dead — reads like a UI bug).
 *
 * The fix is `resolveBin()`: pure-fs resolution over PATH + a curated set of well-known install
 * dirs under the real agent home, with an executable-file check, fail-open to the bare name.
 * These tests pin the resolver in isolation, the detector wiring, AND the two spawn call-sites
 * (runLocalAgent / localAgentChat) the fix rewired — all through the public API.
 *
 * POSIX-focused, with a small Windows boundary assertion: unresolved Windows shims fail closed
 * instead of returning a bare name that would bypass the safe .cmd/.bat launch path.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { resolveBin, detectLocalAgents, runLocalAgent, localAgentChat } from '../agent/local-agents.js';

const FAKE_CLI = '#!/bin/sh\necho "1.2.3"\n';
// For the chat path, which writes the prompt to the child's stdin: drain it before replying so the
// parent's write()/end() completes cleanly (no EPIPE races), then emit a clean, non-error reply.
const FAKE_CLI_STDIN = '#!/bin/sh\ncat >/dev/null 2>&1\necho "1.2.3"\n';
const tmpDirs: string[] = [];
const savedEnv = { PATH: process.env.PATH, AGENT_HOME: process.env.T3MP3ST_AGENT_HOME };

/** A throwaway dir; tracked for afterEach cleanup. */
function scratch(): string {
  const d = mkdtempSync(join(tmpdir(), 't3mp3st-pathres-'));
  tmpDirs.push(d);
  return d;
}

/** Drop an executable (0o755) fake binary at `dir/name`; returns its absolute path. */
function putExe(dir: string, name: string, content: string = FAKE_CLI): string {
  mkdirSync(dir, { recursive: true });
  const p = join(dir, name);
  writeFileSync(p, content, { mode: 0o755 });
  return p;
}

afterEach(() => {
  process.env.PATH = savedEnv.PATH;
  if (savedEnv.AGENT_HOME === undefined) delete process.env.T3MP3ST_AGENT_HOME; else process.env.T3MP3ST_AGENT_HOME = savedEnv.AGENT_HOME;
  for (const d of tmpDirs.splice(0)) { try { rmSync(d, { recursive: true, force: true }); } catch { /* noop */ } }
});

describe('resolveBin — macOS/POSIX well-known-dir resolution (issue #78)', () => {
  it('finds a CLI in ~/.local/bin even when PATH omits it (the reported bug)', () => {
    const home = scratch();
    const bin = putExe(join(home, '.local', 'bin'), 'faketool');
    process.env.T3MP3ST_AGENT_HOME = home;      // real agent home for this scan
    process.env.PATH = '/usr/bin:/bin';         // minimal launchd-style PATH — omits ~/.local/bin

    expect(resolveBin('faketool')).toBe(bin);
  });

  // A representative spread of the curated dirs (not just index-0 ~/.local/bin) so a typo or
  // reorder in any entry is caught. Paths are relative to the agent home.
  it.each([
    ['.asdf/shims'],
    ['.bun/bin'],
    ['.local/share/pnpm'],
  ])('resolves a CLI installed under the well-known dir %s', (rel) => {
    const home = scratch();
    const bin = putExe(join(home, ...rel.split('/')), 'faketool');
    process.env.T3MP3ST_AGENT_HOME = home;
    process.env.PATH = '/usr/bin:/bin';
    expect(resolveBin('faketool')).toBe(bin);
  });

  it('finds a CLI under an nvm per-version bin dir (dynamic enumeration)', () => {
    const home = scratch();
    const bin = putExe(join(home, '.nvm', 'versions', 'node', 'v20.11.0', 'bin'), 'faketool');
    process.env.T3MP3ST_AGENT_HOME = home;
    process.env.PATH = '/usr/bin:/bin';
    expect(resolveBin('faketool')).toBe(bin);
  });

  it('finds a CLI under an fnm per-version bin dir (dynamic enumeration)', () => {
    const home = scratch();
    const bin = putExe(join(home, '.local', 'share', 'fnm', 'node-versions', 'v20.11.0', 'installation', 'bin'), 'faketool');
    process.env.T3MP3ST_AGENT_HOME = home;
    process.env.PATH = '/usr/bin:/bin';
    expect(resolveBin('faketool')).toBe(bin);
  });

  it('resolves via PATH when the CLI is on it (rich-shell launch still works)', () => {
    const dir = scratch();
    const bin = putExe(dir, 'faketool');
    process.env.T3MP3ST_AGENT_HOME = scratch(); // empty home — force the hit to come from PATH
    process.env.PATH = `/usr/bin:${dir}`;

    expect(resolveBin('faketool')).toBe(bin);
  });

  it('prefers a PATH match over a well-known-dir match when both exist (shell precedence)', () => {
    const home = scratch();
    const wellKnown = putExe(join(home, '.local', 'bin'), 'faketool');
    const pathDir = scratch();
    const onPath = putExe(pathDir, 'faketool');
    process.env.T3MP3ST_AGENT_HOME = home;
    process.env.PATH = `/usr/bin:${pathDir}`;    // PATH scanned before well-known dirs

    expect(resolveBin('faketool')).toBe(onPath);
    expect(resolveBin('faketool')).not.toBe(wellKnown);
  });

  it('follows a symlink to an executable (asdf/nvm shims & Claude Code\'s own install are symlinks)', () => {
    const home = scratch();
    const real = putExe(join(home, 'tools'), 'realtool');
    const linkDir = join(home, '.local', 'bin');
    mkdirSync(linkDir, { recursive: true });
    const link = join(linkDir, 'faketool');
    symlinkSync(real, link);
    process.env.T3MP3ST_AGENT_HOME = home;
    process.env.PATH = '/usr/bin:/bin';

    expect(resolveBin('faketool')).toBe(link);   // the resolved candidate path, symlink followed for the file-check
  });

  it('skips a non-executable match (parity with execFile X_OK) and fails open to the bare name', () => {
    const home = scratch();
    const p = join(home, '.local', 'bin', 'faketool');
    mkdirSync(join(home, '.local', 'bin'), { recursive: true });
    writeFileSync(p, 'not executable', { mode: 0o644 });  // present but not +x
    process.env.T3MP3ST_AGENT_HOME = home;
    process.env.PATH = '/usr/bin:/bin';

    expect(resolveBin('faketool')).toBe('faketool');       // not the non-exec path
  });

  it('does NOT match a directory named like the CLI (dirs carry the search bit; execvp would skip it)', () => {
    // Regression guard: a bare `accessSync(X_OK)` passes for a directory, so resolveBin would return
    // the dir → execFile fails EACCES (not ENOENT) → a false installed:true. Require a regular file.
    const home = scratch();
    mkdirSync(join(home, '.local', 'bin', 'faketool'), { recursive: true });  // a DIRECTORY, not a binary
    process.env.T3MP3ST_AGENT_HOME = home;
    process.env.PATH = '/usr/bin:/bin';
    expect(resolveBin('faketool')).toBe('faketool');                          // bare name, not the dir path
  });

  it('returns an already-qualified path unchanged (the bin.includes("/") guard — no re-resolution)', () => {
    expect(resolveBin('/opt/custom/claude')).toBe('/opt/custom/claude');
    expect(resolveBin('./rel/claude')).toBe('./rel/claude');
  });

  it('fails open to the bare name when nothing matches anywhere', () => {
    process.env.T3MP3ST_AGENT_HOME = scratch();
    process.env.PATH = '/usr/bin:/bin';
    expect(resolveBin('definitely-not-a-real-cli-xyz')).toBe('definitely-not-a-real-cli-xyz');
  });

  it('does NOT scan POSIX dirs on win32 — unresolved shims fail closed', () => {
    const home = scratch();
    putExe(join(home, '.local', 'bin'), 'faketool');
    process.env.T3MP3ST_AGENT_HOME = home;
    process.env.PATH = '/usr/bin:/bin';
    const orig = Object.getOwnPropertyDescriptor(process, 'platform') || { value: process.platform, configurable: true };
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
    try {
      expect(resolveBin('faketool')).toBeUndefined();
    } finally {
      Object.defineProperty(process, 'platform', orig);
    }
  });
});

describe('detectLocalAgents — wiring: a well-known-dir CLI is reported installed (issue #78)', () => {
  it('reports Claude Code installed + versioned when `claude` lives in ~/.local/bin and PATH omits it', async () => {
    const home = scratch();
    const claudePath = putExe(join(home, '.local', 'bin'), 'claude');
    process.env.T3MP3ST_AGENT_HOME = home;
    process.env.PATH = '/usr/bin:/bin';         // pre-fix: execFile('claude') → ENOENT → installed:false
    delete process.env.T3MP3ST_DISABLE_LOCAL_AGENTS;  // insurance: a leaked disable flag would short-circuit to []

    const agents = await detectLocalAgents();
    const claude = agents.find((a) => a.id === 'claude');
    expect(claude?.installed).toBe(true);
    expect(claude?.path).toBe(claudePath);
    expect(claude?.version).toBe('1.2.3');       // parsed from the resolved binary's --version output
    // codex/hermes are absent from this temp home → still not installed (no false positives).
    expect(agents.find((a) => a.id === 'codex')?.installed).toBe(false);
  });
});

describe('spawn call-sites use the resolved path (issue #78 — detected-but-unspawnable would be worse)', () => {
  // Behavioral, not a spawn spy: if the rewiring regressed to the bare `spec.bin`, spawn('claude')
  // under PATH=/usr/bin:/bin throws ENOENT → ok:false / reject. Success proves the resolved path ran.
  it('runLocalAgent launches the well-known-dir CLI (not the bare name)', async () => {
    const home = scratch();
    putExe(join(home, '.local', 'bin'), 'claude');
    process.env.T3MP3ST_AGENT_HOME = home;
    process.env.PATH = '/usr/bin:/bin';

    const res = await runLocalAgent('claude', 'ping', { timeoutMs: 4000 });
    expect(res.ok).toBe(true);
    expect(res.output).toContain('1.2.3');
  });

  it('localAgentChat launches the well-known-dir CLI (not the bare name)', async () => {
    const home = scratch();
    putExe(join(home, '.local', 'bin'), 'claude', FAKE_CLI_STDIN);
    process.env.T3MP3ST_AGENT_HOME = home;
    process.env.PATH = '/usr/bin:/bin';

    await expect(localAgentChat('claude', 'ping', { timeoutMs: 4000 })).resolves.toContain('1.2.3');
  });
});
