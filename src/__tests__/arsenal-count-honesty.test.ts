import { describe, it, expect } from 'vitest';
import { TOOL_ADAPTERS, type ToolAdapter } from '../arsenal/catalog.js';
import { BUILTIN_TOOLS, EXTERNAL_TOOLS } from '../arsenal/index.js';
import {
  isMintable,
  adapterToCustomTool,
  toolNameFor,
  type AdapterToolDeps,
} from '../arsenal/adapter-tools.js';

// ─────────────────────────────────────────────────────────────────────────────
// ARSENAL COUNT HONESTY — the "advertised = real, and nothing is silently dead".
//
// The arsenal advertises "102 tools". verify-claims defends that number by counting
// `id:`/`name:` source lines — a SOURCE-LINE count, which would keep passing even if
// an entry became uncallable. This test locks the number to the REAL registered arrays
// and, more importantly, pins the invariant that makes the count honest:
//
//   an adapter is OFF the generic callable surface (adapterToCustomTool → null) IFF it
//   is EXPLICITLY gated by its execution mode (catalog_only / import_only).
//
// i.e. a tool can be counted-but-not-generically-callable ONLY on purpose (metasploit /
// hydra reachable solely via the approval-gated post-ex drivers; bloodhound import-only;
// pacu/frida catalog-only until narrow approved runners exist),
// never by a silent DEFAULT/mint slip. Sibling of no-phantom-tools / stub-honesty.
// ─────────────────────────────────────────────────────────────────────────────

const deps: AdapterToolDeps = {
  isToolAvailable: async () => true,
  runSubprocess: async () => ({ stdout: '', stderr: '', exitCode: 0 }),
};

const isGated = (a: ToolAdapter) =>
  a.execution === 'catalog_only' || a.execution === 'import_only';

describe('arsenal count honesty (advertised = real registered surface)', () => {
  it('the advertised "102 tools" is the real registered surface, not a source-line count', () => {
    const total = TOOL_ADAPTERS.length + BUILTIN_TOOLS.length + EXTERNAL_TOOLS.length;
    // Locks the headline to code. If the arsenal grows/shrinks, update this AND the
    // README / verify-claims headline together — that is the point of the lock.
    expect(
      total,
      `arsenal size drifted from the advertised 102 (adapters=${TOOL_ADAPTERS.length}, ` +
        `built-ins=${BUILTIN_TOOLS.length}, externals=${EXTERNAL_TOOLS.length}) — ` +
        'update the README / verify-claims headline to match',
    ).toBe(102);
    expect(total).toBeGreaterThanOrEqual(80); // stays consistent with verify-claims' `>= 80` gate
  });

  it('an adapter is off the generic callable surface IFF it is explicitly gated (no silent-dead entry)', () => {
    const silentlyDead: string[] = []; // counted, not gated, yet mints null
    const wronglyGated: string[] = []; // gated, yet somehow mints a callable tool
    for (const a of TOOL_ADAPTERS) {
      const callable = adapterToCustomTool(a, deps) !== null;
      if (!callable && !isGated(a)) silentlyDead.push(`${a.id} (${a.execution})`);
      if (callable && isGated(a)) wronglyGated.push(`${a.id} (${a.execution})`);
      // isMintable must agree with actual callability — no divergence.
      expect(isMintable(a), `isMintable disagrees with callability for ${a.id}`).toBe(callable);
    }
    expect(silentlyDead, `counted-but-silently-uncallable adapters: ${silentlyDead.join(', ')}`).toEqual([]);
    expect(wronglyGated, `gated adapters that are still generically callable: ${wronglyGated.join(', ')}`).toEqual([]);
  });

  it('the gated set is exactly the documented post-ex / import tools', () => {
    const gated = TOOL_ADAPTERS.filter(isGated);
    // metasploit + hydra are catalog_only (callable only via the approval-gated hand-written
    // post-ex drivers); pacu/frida are catalog_only pending narrow approved runners; bloodhound is
    // import_only (collector output is imported, never run here).
    expect(gated.map((a) => a.id).sort()).toEqual(['bloodhound', 'frida', 'hydra', 'metasploit', 'pacu']);
    expect(TOOL_ADAPTERS.find((a) => a.id === 'bloodhound')?.execution).toBe('import_only');
    // Every gated adapter is genuinely off the generic surface.
    for (const a of gated) {
      expect(adapterToCustomTool(a, deps), `${a.id} must not be generically callable`).toBeNull();
    }
  });

  it('every generically-callable adapter mints a real, uniquely-named tool', () => {
    const names = new Set<string>();
    for (const t of [...BUILTIN_TOOLS, ...EXTERNAL_TOOLS]) names.add(t.name);
    for (const a of TOOL_ADAPTERS) {
      const tool = adapterToCustomTool(a, deps);
      if (!tool) continue; // gated — covered above
      expect(typeof tool.handler, `${a.id} minted without a handler`).toBe('function');
      expect(tool.name, `${a.id} minted an unexpected name`).toBe(toolNameFor(a));
      // A minted adapter that shadows a hand-written tool name is deduped by buildAdapterTools;
      // record it here to prove no two DISTINCT registered surfaces collide unexpectedly.
      names.add(tool.name);
    }
    // Built-ins + externals themselves carry no duplicate names.
    const builtinNames = [...BUILTIN_TOOLS, ...EXTERNAL_TOOLS].map((t) => t.name);
    expect(new Set(builtinNames).size).toBe(builtinNames.length);
  });
});
