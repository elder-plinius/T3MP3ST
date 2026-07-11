/**
 * Kali+ adapter → CustomTool factory (Phase-1).
 * Pins the load-bearing safety + behavior contract:
 *   - catalog_only / import_only adapters are NEVER minted (metasploit/hydra/bloodhound stay off the
 *     callable surface) — the factory returns null.
 *   - a missing binary DEGRADES (returns {success:false, error:<installHint>}) instead of throwing.
 *   - an out-of-scope target is refused (SCOPE DENIED) BEFORE the subprocess runs.
 *   - a mintable adapter produces a CustomTool with a working name + category + real stdout output.
 *   - buildAdapterTools drops non-mintable adapters and skips already-registered tool names.
 * All deps are injected fakes — no real binaries are spawned.
 */
import { describe, it, expect } from 'vitest';
import {
  adapterToCustomTool,
  buildAdapterTools,
  toolNameFor,
  isMintable,
  hasArgTemplate,
  type AdapterToolDeps,
  type SubprocessResult,
} from '../arsenal/adapter-tools.js';
import { TOOL_ADAPTERS } from '../arsenal/catalog.js';
import type { ToolAdapter } from '../arsenal/catalog.js';
import type { CustomTool, ToolContext } from '../types/index.js';

function adapter(id: string): ToolAdapter {
  const a = TOOL_ADAPTERS.find(x => x.id === id);
  if (!a) throw new Error(`test fixture: adapter '${id}' not found in catalog`);
  return a;
}

/** Mint an adapter and assert (for the type-checker and the test) that it was not gated to null. */
function mint(id: string, deps: AdapterToolDeps): CustomTool {
  const tool = adapterToCustomTool(adapter(id), deps);
  expect(tool, `${id} should be mintable`).not.toBeNull();
  return tool as CustomTool;
}

/** A deps double that records subprocess spawns and lets each behavior be configured per test. */
function makeDeps(overrides: Partial<AdapterToolDeps> = {}): AdapterToolDeps & { spawns: string[][] } {
  const spawns: string[][] = [];
  return {
    spawns,
    isToolAvailable: async () => true,
    runSubprocess: async (_command, args): Promise<SubprocessResult> => {
      spawns.push(args);
      return { stdout: 'FAKE_OUTPUT', stderr: '', exitCode: 0 };
    },
    ...overrides,
  };
}

const ctx = (parameters: Record<string, unknown>): ToolContext => ({ parameters });

describe('adapterToCustomTool — mint gate', () => {
  it('NEVER mints catalog_only / import_only adapters (metasploit, hydra, bloodhound → null)', () => {
    const deps = makeDeps();
    expect(adapterToCustomTool(adapter('metasploit'), deps)).toBeNull(); // catalog_only
    expect(adapterToCustomTool(adapter('hydra'), deps)).toBeNull();      // catalog_only
    expect(adapterToCustomTool(adapter('bloodhound'), deps)).toBeNull(); // import_only
    expect(adapterToCustomTool(adapter('pacu'), deps)).toBeNull();       // catalog_only (AWS exploitation framework)
    expect(adapterToCustomTool(adapter('frida'), deps)).toBeNull();      // catalog_only (runtime code injection)
  });

  it('mints a command-ready adapter with a working name + category', () => {
    const tool = mint('nmap', makeDeps());
    expect(tool.name).toBe(toolNameFor(adapter('nmap')));
    expect(tool.name).toBe('nmap_tool');
    expect(tool.category).toBe('network'); // passthrough of the catalog category
    expect(typeof tool.handler).toBe('function');
  });
});

describe('cloud/mobile category loadouts — presence + risk gating', () => {
  const deps = makeDeps();
  const execOf = (id: string) => adapter(id).execution;

  it('cloud: assessment/recon tools are receipt-gated; the exploitation framework is catalog-only', () => {
    expect(execOf('scoutsuite')).toBe('receipt_required');
    expect(execOf('cloudfox')).toBe('receipt_required');
    expect(execOf('pmapper')).toBe('receipt_required');
    expect(execOf('pacu')).toBe('catalog_only');
    expect(adapter('scoutsuite').category).toBe('cloud');
    expect(adapterToCustomTool(adapter('pacu'), deps)).toBeNull(); // never callable
  });

  it('mobile: static scanner is safe; dynamic/runtime tools are gated', () => {
    expect(execOf('apkleaks')).toBe('safe_command');
    expect(execOf('mobsfscan')).toBe('safe_command'); // static source scanner — safe
    expect(execOf('objection')).toBe('receipt_required');
    expect(execOf('frida')).toBe('catalog_only');
    expect(adapter('apkleaks').category).toBe('mobile');
    expect(adapterToCustomTool(adapter('frida'), deps)).toBeNull();        // never callable
    expect(adapterToCustomTool(adapter('apkleaks'), deps)).not.toBeNull(); // safe, mintable
  });
});

describe('adapterToCustomTool — degrade / scope / execution', () => {
  it('a missing binary DEGRADES (does not throw) and surfaces the installHint', async () => {
    const deps = makeDeps({ isToolAvailable: async () => false });
    const tool = mint('nmap', deps);
    const res = await tool.handler(ctx({ target: '127.0.0.1' }));
    expect(res.success).toBe(false);
    expect(res.error).toContain(adapter('nmap').installHint);
    expect(deps.spawns.length).toBe(0); // nothing was spawned
  });

  it('scopeOk=false → SCOPE DENIED before the subprocess runs', async () => {
    const deps = makeDeps({ scopeOk: () => false });
    const tool = mint('nuclei', deps);
    const res = await tool.handler(ctx({ url: 'https://evil.example.com' }));
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/SCOPE DENIED/);
    expect(res.error).toContain('evil.example.com');
    expect(deps.spawns.length).toBe(0); // refused before spawning
  });

  it('scopeOk=true → runs the subprocess and returns stdout as output', async () => {
    const deps = makeDeps({ scopeOk: () => true });
    const tool = mint('nuclei', deps);
    const res = await tool.handler(ctx({ url: 'https://target.example.com' }));
    expect(res.success).toBe(true);
    expect(res.output).toBe('FAKE_OUTPUT');
    expect(deps.spawns.length).toBe(1);
    // nuclei template threads the target through -target
    expect(deps.spawns[0]).toContain('https://target.example.com');
  });

  it('a networked adapter with no target degrades gracefully (no spawn)', async () => {
    const deps = makeDeps();
    const tool = mint('nuclei', deps);
    const res = await tool.handler(ctx({}));
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/requires a target/);
    expect(deps.spawns.length).toBe(0);
  });

  it('a non-zero exit code is reported as failure, not a throw', async () => {
    const deps = makeDeps({
      scopeOk: () => true,
      runSubprocess: async () => ({ stdout: '', stderr: 'boom', exitCode: 2 }),
    });
    const tool = mint('nikto', deps);
    const res = await tool.handler(ctx({ url: 'https://target.example.com' }));
    expect(res.success).toBe(false);
    expect(res.error).toContain('boom');
  });
});

describe('adapterToCustomTool — argument-injection hardening', () => {
  it('nmap IGNORES an LLM-supplied free-form flags param (no -oN/--script reaches argv)', async () => {
    const deps = makeDeps({ scopeOk: () => true });
    const tool = mint('nmap', deps);
    const res = await tool.handler(ctx({
      target: 'target.example.com',
      flags: '-oN /tmp/pwned --script vuln,exploit', // injection attempt
    }));
    expect(res.success).toBe(true);
    const argv = deps.spawns[0];
    expect(argv).toEqual(['-sV', '-T4', 'target.example.com']); // flags hardcoded; injection dropped
    expect(argv).not.toContain('-oN');
    expect(argv.join(' ')).not.toContain('--script');
  });

  it('nmap accepts a clean port spec but drops one carrying an injected flag', async () => {
    const deps = makeDeps({ scopeOk: () => true });
    const tool = mint('nmap', deps);
    await tool.handler(ctx({ target: 'target.example.com', ports: '22,80,443' }));
    expect(deps.spawns[0]).toEqual(['-sV', '-T4', '-p', '22,80,443', 'target.example.com']);
    await tool.handler(ctx({ target: 'target.example.com', ports: '80 -oN /tmp/x' }));
    expect(deps.spawns[1]).toEqual(['-sV', '-T4', 'target.example.com']); // malicious ports dropped
  });

  it('refuses an option-looking target (leading dash) before spawning', async () => {
    const deps = makeDeps({ scopeOk: () => true });
    const tool = mint('nmap', deps);
    const res = await tool.handler(ctx({ target: '-oN/tmp/pwned' }));
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/option-looking target/);
    expect(deps.spawns.length).toBe(0); // never spawned
  });

  it('curl sends a literal body via --data-raw and REFUSES a local-file-read data value (-d @file)', async () => {
    const deps = makeDeps({ scopeOk: () => true });
    const tool = mint('curl', deps);
    // a clean body is sent verbatim with --data-raw (never plain -d, which would file-interpret @/<)
    const ok = await tool.handler(ctx({ url: 'https://target.example.com/', data: 'a=1&b=2' }));
    expect(ok.success).toBe(true);
    expect(deps.spawns[0]).toContain('--data-raw');
    expect(deps.spawns[0]).not.toContain('-d');
    // `@/etc/passwd` (and `<file`) make curl read a local file into the body — must be refused, no spawn
    for (const evil of ['@/etc/passwd', '@-', '<secret.txt']) {
      const res = await tool.handler(ctx({ url: 'https://target.example.com/', data: evil }));
      expect(res.success, `data '${evil}' must be refused`).toBe(false);
      expect(res.error).toMatch(/read a local file/);
    }
    expect(deps.spawns.length).toBe(1); // only the clean call ever spawned
  });
});

describe('buildAdapterTools', () => {
  it('drops non-mintable adapters (metasploit/hydra/bloodhound never appear)', () => {
    const tools = buildAdapterTools(TOOL_ADAPTERS, makeDeps());
    const names = tools.map(t => t.name);
    expect(names).toContain(toolNameFor(adapter('nmap')));
    expect(names).not.toContain(toolNameFor(adapter('metasploit')));
    expect(names).not.toContain(toolNameFor(adapter('hydra')));
    expect(names).not.toContain(toolNameFor(adapter('bloodhound')));
    // count matches the catalog's mintable population
    const mintable = TOOL_ADAPTERS.filter(
      a => a.execution === 'safe_command' || a.execution === 'receipt_required'
    ).length;
    expect(tools.length).toBe(mintable);
  });

  it('skips adapters whose minted name is already registered', () => {
    const already = new Set([toolNameFor(adapter('nmap'))]);
    const tools = buildAdapterTools(TOOL_ADAPTERS, makeDeps(), already);
    expect(tools.map(t => t.name)).not.toContain(toolNameFor(adapter('nmap')));
  });
});

describe('source / supply-chain scanners run a real invocation (not `<binary> <target>`)', () => {
  // Each entry: [adapter id, argv for `path: 'src'`]. Without bespoke templates these all fell
  // through to DEFAULT_TEMPLATE and spawned `['src']` (or `['']` with no path) — a broken scan.
  const CASES: Array<[string, string[]]> = [
    ['semgrep', ['scan', '--config', 'auto', '--json', 'src']],
    ['gitleaks', ['detect', '--source', 'src', '--report-format', 'json', '--redact', '--no-banner']],
    ['trufflehog', ['filesystem', 'src', '--json', '--no-update']],
    ['trivy', ['fs', '--format', 'json', 'src']],
    ['syft', ['dir:src', '-o', 'cyclonedx-json']],
    ['grype', ['dir:src', '-o', 'json']],
    ['checkov', ['-d', 'src', '-o', 'json']],
  ];

  it.each(CASES)('%s builds its real scanner argv for an explicit path', async (id, expected) => {
    const deps = makeDeps();
    await mint(id, deps).handler(ctx({ path: 'src' }));
    expect(deps.spawns[0]).toEqual(expected);
  });

  it.each(CASES)('%s defaults to the working dir "." when no path is given', async (id) => {
    const deps = makeDeps();
    await mint(id, deps).handler(ctx({}));
    // The path slot resolves to "." — assert "." is present and the argv is more than a bare target.
    expect(deps.spawns[0].some(a => a === '.' || a === 'dir:.')).toBe(true);
    expect(deps.spawns[0].length).toBeGreaterThan(1);
  });

  it('never inherits an http(s) mission target as a scan path (falls back to ".")', async () => {
    const deps = makeDeps();
    // A networked mission address must not become `semgrep scan --config auto --json https://x` —
    // that is not a filesystem path. scanPath rejects it and falls back to ".".
    await mint('semgrep', deps).handler(ctx({ target: 'https://victim.example' }));
    expect(deps.spawns[0]).toEqual(['scan', '--config', 'auto', '--json', '.']);
  });

  it('refuses an option-looking path (leading "-" would be a scanner flag) — no spawn', async () => {
    const deps = makeDeps();
    // The factory's option-looking-target guard fires before argv is built, so the scanner never runs.
    const result = await mint('trivy', deps).handler(ctx({ path: '--output=/etc/x' }));
    expect(result.success).toBe(false);
    expect(deps.spawns.length).toBe(0);
  });
});

describe('reverse / mobile / smart-contract analysers run a real invocation (not `<binary> <file>`)', () => {
  // Each entry: [adapter id, params, expected argv]. Without bespoke templates these all fell through
  // to DEFAULT_TEMPLATE and spawned `['<file>']` — a broken invocation for a subcommand/flag-driven
  // analyser (and, for r2, one that drops into an interactive shell and hangs the loop).
  const CASES: Array<[string, Record<string, unknown>, string[]]> = [
    ['objdump', { file: 'a.out' }, ['-d', '-M', 'intel', 'a.out']],
    ['readelf', { file: 'a.out' }, ['-a', 'a.out']],
    ['checksec', { file: 'a.out' }, ['--file=a.out']],
    ['radare2', { file: 'a.out' }, ['-q', '-e', 'scr.color=0', '-c', 'ij', 'a.out']],
    ['exiftool', { file: 'a.out' }, ['-json', 'a.out']],
    ['mythril', { file: 'Vault.sol' }, ['analyze', 'Vault.sol', '-o', 'json']],
    ['apkleaks', { file: 'app.apk' }, ['-f', 'app.apk']],
    ['slither', { path: 'contracts' }, ['contracts', '--json', '-']],
    ['mobsfscan', { path: 'app-src' }, ['--json', 'app-src']],
  ];

  it.each(CASES)('%s builds its real analyser argv', async (id, params, expected) => {
    const deps = makeDeps();
    await mint(id, deps).handler(ctx(params));
    expect(deps.spawns[0]).toEqual(expected);
  });

  it('radare2 never drops into an interactive shell (batch `-q -c`, never a bare file)', async () => {
    const deps = makeDeps();
    await mint('radare2', deps).handler(ctx({ file: 'a.out' }));
    const argv = deps.spawns[0];
    expect(argv).toContain('-q'); // quit after the command
    expect(argv).toContain('-c'); // run one command, non-interactive
    expect(argv).not.toEqual(['a.out']); // the old broken/hanging positional default
  });

  it('a file-oriented analyser with no path degrades (clean failure, no spawn)', async () => {
    const deps = makeDeps();
    const res = await mint('objdump', deps).handler(ctx({}));
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/file\/artifact path/);
    expect(deps.spawns.length).toBe(0); // never spawned `objdump ''`
  });

  it('a file-oriented analyser refuses an http(s) URL as a local artifact (no spawn)', async () => {
    const deps = makeDeps();
    // A networked mission address inherited via context must not become `objdump https://x`.
    const res = await mint('readelf', deps).handler(ctx({ file: 'https://victim.example/firmware.bin' }));
    expect(res.success).toBe(false);
    expect(deps.spawns.length).toBe(0);
  });
});

describe('invocation-honesty guard — every mintable adapter is classified, none silently falls through', () => {
  // Every adapter that CAN be minted either carries a bespoke ARG_TEMPLATE (a real invocation) or is
  // explicitly filed under exactly one reason for legitimately falling through to `<binary> <target>`.
  // This is the invocation-correctness sibling of the tool-count honesty test: a newly-catalogued
  // subcommand tool (e.g. a future `zzuf`/`radare2`-style binary) FAILS this test until someone
  // decides whether it needs a template — it can never silently ship a broken positional invocation.

  // `<binary> <target>` is genuinely a correct, useful invocation for these.
  const POSITIONAL_TARGET_OK = new Set([
    'file', 'strings', 'binwalk', 'radamsa', 'jadx', 'class-dump', 'solhint', 'echidna', 'john',
  ]);
  // No single safe default exists: the operator supplies the full command (cloud CLIs, model-config
  // red-team harnesses, device-runtime tools, project-scaffolded RE, or a target-executing debugger).
  const OPERATOR_DRIVEN = new Set([
    'prowler', 'scoutsuite', 'cloudfox', 'pmapper', 'aws-cli', 'az-cli', 'gcloud-cli',
    'garak', 'promptfoo', 'foundry-forge', 'foundry-cast', 'openssl', 'afl-fuzz', 'ghidra',
    'gdb', 'objection', 'drozer',
  ]);
  // KNOWN DEBT: the positional default is broken/degraded and these SHOULD get a template later.
  // Tracked honestly here rather than hidden — a good follow-up PR shrinks this set.
  const KNOWN_DEBT = new Set([
    'feroxbuster', 'osv-scanner', 'hashcat', 'apktool', 'yara',
  ]);

  const mintable = TOOL_ADAPTERS.filter(isMintable);
  const classified = [POSITIONAL_TARGET_OK, OPERATOR_DRIVEN, KNOWN_DEBT];

  it('every mintable adapter is either templated or explicitly filed under one fall-through reason', () => {
    const unaccounted = mintable
      .filter(a => !hasArgTemplate(a))
      .map(a => a.id)
      .filter(id => !classified.some(s => s.has(id)));
    expect(unaccounted, 'these mintable adapters silently fall through to `<binary> <target>`').toEqual([]);
  });

  it('the fall-through allow-lists are disjoint and never overlap a templated adapter', () => {
    const seen = new Set<string>();
    for (const set of classified) {
      for (const id of set) {
        expect(seen.has(id), `${id} is listed in more than one fall-through set`).toBe(false);
        seen.add(id);
        const a = TOOL_ADAPTERS.find(x => x.id === id);
        expect(a, `allow-listed id '${id}' is not in the catalog`).toBeTruthy();
        expect(isMintable(a as ToolAdapter), `${id} is not mintable — remove it`).toBe(true);
        expect(hasArgTemplate(a as ToolAdapter), `${id} IS templated — remove it from the fall-through lists`).toBe(false);
      }
    }
  });

  it('the reverse/mobile/smart-contract loadout is actually templated (regression pin)', () => {
    for (const id of ['objdump', 'readelf', 'checksec', 'radare2', 'exiftool', 'mythril', 'apkleaks', 'slither', 'mobsfscan']) {
      expect(hasArgTemplate(adapter(id)), `${id} lost its ARG_TEMPLATE`).toBe(true);
    }
  });
});
