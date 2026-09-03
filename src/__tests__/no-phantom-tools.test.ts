import { describe, it, expect } from 'vitest';
import { ARCHETYPE_PROFILES } from '../operators/index.js';
import { BUILTIN_TOOLS, EXTERNAL_TOOLS } from '../arsenal/index.js';
import { buildAdapterTools } from '../arsenal/adapter-tools.js';
import { TOOL_ADAPTERS } from '../arsenal/catalog.js';
import { OPERATOR_SYSTEM_PROMPTS } from '../prompts/index.js';

// ─────────────────────────────────────────────────────────────────────────────
// NO PHANTOM TOOLS — the "advertised = wired" guard for the arsenal.
//
// An operator must never advertise a tool the harness can't call. Phantom names
// (metasploit/mimikatz, or a bare "nmap" when the real tool is "nmap_scan")
// burn the agent's iterations on calls that 404. This test makes that fail the
// build by construction — the same discipline as test:no-fitting, applied to tools.
// ─────────────────────────────────────────────────────────────────────────────

const REGISTERED = new Set([...BUILTIN_TOOLS, ...EXTERNAL_TOOLS].map((t) => t.name));
// FULL-arsenal adapters are minted per-mission; toolkits may reference them by
// their minted names (e.g. sqlmap_tool) — count them as wired too.
const ADAPTER_MINTED = new Set(
  buildAdapterTools(TOOL_ADAPTERS, {
    runSubprocess: async () => ({ stdout: '', stderr: '', exitCode: 0 }),
    isToolAvailable: async () => true,
    scopeOk: () => true,
    createReportWorkspace: async () => ({ reportBase: '', cleanup: () => Promise.resolve() }),
    readToolReport: async () => '',
  }, new Set()).map((t) => t.name),
);

describe('no phantom tools (advertised = wired)', () => {
  it('the arsenal registers a non-trivial, unique set of callable tools', () => {
    const all = [...BUILTIN_TOOLS, ...EXTERNAL_TOOLS].map((t) => t.name);
    expect(all.length).toBeGreaterThanOrEqual(20);
    expect(new Set(all).size).toBe(all.length); // no duplicate tool names
  });

  it('every archetype defaultTool is a REGISTERED, callable tool', () => {
    const phantoms: string[] = [];
    for (const [archetype, profile] of Object.entries(ARCHETYPE_PROFILES)) {
      for (const tool of profile.defaultTools) {
        if (!REGISTERED.has(tool) && !ADAPTER_MINTED.has(tool)) phantoms.push(`${archetype} → "${tool}"`);
      }
    }
    expect(
      phantoms,
      `phantom tools advertised by archetypes but not registered in the arsenal: ${phantoms.join(', ')}`,
    ).toEqual([]);
  });

  it('operator system prompts reference no phantom binaries (advertise only what is wired)', () => {
    // Classic phantoms we do NOT wrap. Backtick-bare forms (`nmap`) distinguish the phantom
    // bare binary from the real registered tool (nmap_scan, which is `nmap_scan`).
    const PHANTOMS = ['metasploit', 'mimikatz', 'sqlmap', 'bloodhound', 'crackmapexec', 'nikto', 'wpscan', 'psexec', '`nmap`', '`nuclei`', '`burp`'];
    const hits: string[] = [];
    for (const [archetype, prompt] of Object.entries(OPERATOR_SYSTEM_PROMPTS)) {
      const low = String(prompt).toLowerCase();
      for (const p of PHANTOMS) if (low.includes(p.toLowerCase())) hits.push(`${archetype}: ${p}`);
    }
    expect(hits, `phantom binaries named in operator prompts: ${hits.join(', ')}`).toEqual([]);
  });

  it('every registered tool has a real handler (no metadata-only stubs)', () => {
    const noHandler = [...BUILTIN_TOOLS, ...EXTERNAL_TOOLS]
      .filter((t) => typeof t.handler !== 'function')
      .map((t) => t.name);
    expect(noHandler, `registered tools missing an executable handler: ${noHandler.join(', ')}`).toEqual([]);
  });
});
