/**
 * Operator role toolkits — the per-operator tool allowlist (the swarm's specialization layer).
 * Each archetype's `defaultTools` is enforced at the AgentLoop via the arsenal name-allowlist
 * (getToolDefinitions(_, names)). Pins the four properties: real tools only, the gate exposes
 * exactly the toolkit, each operator has BROAD coverage, the swarm collectively covers every
 * tool, and overlap (same tool on several operators) is allowed.
 */
import { describe, it, expect } from 'vitest';
import { Arsenal, BUILTIN_TOOLS, EXTERNAL_TOOLS } from '../arsenal/index.js';
import { buildAdapterTools } from '../arsenal/adapter-tools.js';
import { TOOL_ADAPTERS } from '../arsenal/catalog.js';
import { ARCHETYPE_PROFILES } from '../operators/index.js';

describe('Operator role toolkits — specialized · broad · full-coverage · overlap-OK', () => {
  const arsenal = new Arsenal();
  arsenal.registerMany(BUILTIN_TOOLS);   // same population the mission does (src/index.ts)
  arsenal.registerMany(EXTERNAL_TOOLS);
  // FULL-arsenal adapters are minted per-mission (T3MP3ST_FULL_ARSENAL). They
  // widen the generic surface (also reachable via explicit /api/tools/execute);
  // toolkits may reference a FEW of them deliberately (e.g. sqlmap_tool) — those
  // references are validated below against the real minted adapter surface.
  const existing = new Set(arsenal.getToolDefinitions().map(t => t.name));
  const mintedAdapters = buildAdapterTools(TOOL_ADAPTERS, {
    runSubprocess: async () => ({ stdout: '', stderr: '', exitCode: 0 }),
    isToolAvailable: async () => true,
    scopeOk: () => true,
    createReportWorkspace: async () => ({ reportBase: '', cleanup: () => Promise.resolve() }),
    readToolReport: async () => '',
  }, existing);
  arsenal.registerMany(mintedAdapters); // full production surface for the gate test
  const adapterNames = new Set(mintedAdapters.map(t => t.name));
  const allNames = arsenal.getToolDefinitions().map(t => t.name);
  const coreNames = new Set([...BUILTIN_TOOLS, ...EXTERNAL_TOOLS].map(t => t.name));
  const archetypes = Object.keys(ARCHETYPE_PROFILES) as (keyof typeof ARCHETYPE_PROFILES)[];

  it('every operator toolkit contains only REAL arsenal tools (no phantoms)', () => {
    for (const a of archetypes) {
      const phantom = ARCHETYPE_PROFILES[a].defaultTools.filter(t => !allNames.includes(t) && !adapterNames.has(t));
      expect(phantom, `${a} references non-existent tools`).toEqual([]);
    }
  });

  it('the name-allowlist gate exposes EXACTLY the operator toolkit', () => {
    for (const a of archetypes) {
      const kit = ARCHETYPE_PROFILES[a].defaultTools;
      const exposed = arsenal.getToolDefinitions(undefined, kit).map(t => t.name).sort();
      expect(exposed, `${a} exposed tool set`).toEqual([...new Set(kit)].sort());
    }
  });

  it('each operator has BROAD coverage (>= 12 tools)', () => {
    for (const a of archetypes) {
      expect(ARCHETYPE_PROFILES[a].defaultTools.length, `${a} toolkit size`).toBeGreaterThanOrEqual(12);
    }
  });

  it('the swarm collectively covers EVERY arsenal tool', () => {
    const covered = new Set(archetypes.flatMap(a => ARCHETYPE_PROFILES[a].defaultTools));
    // Coverage contract is over the core surface (built-ins + externals) — the
    // swarm must reach every core tool. FULL-arsenal adapters are a wider generic
    // surface (also callable via explicit execution) and may intentionally stay
    // off operator toolkits; toolkit references to them are validated separately.
    const uncovered = allNames.filter(n => !covered.has(n) && coreNames.has(n));
    expect(uncovered, 'tools no operator can reach').toEqual([]);
  });

  it('toolkit references to FULL-arsenal adapters exist on the minted adapter surface', () => {
    const referenced = new Set(archetypes.flatMap(a => ARCHETYPE_PROFILES[a].defaultTools));
    const phantoms = [...referenced].filter(n => !allNames.includes(n) && !adapterNames.has(n));
    expect(phantoms, 'toolkit references to non-existent adapter tools').toEqual([]);
  });

  it('overlap is allowed — generalist tools appear on multiple operators', () => {
    const counts: Record<string, number> = {};
    for (const a of archetypes) for (const t of ARCHETYPE_PROFILES[a].defaultTools) counts[t] = (counts[t] || 0) + 1;
    expect(counts['http_request'], 'http_request should be broadly shared').toBeGreaterThan(1);
    expect(counts['technology_detect'], 'technology_detect should be broadly shared').toBeGreaterThan(1);
  });
});
