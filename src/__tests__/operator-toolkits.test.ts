/**
 * Operator role toolkits — the per-operator tool allowlist (the swarm's specialization layer).
 * Each archetype's `defaultTools` is enforced at the AgentLoop via the arsenal name-allowlist
 * (getToolDefinitions(_, names)). Pins the four properties: real tools only, the gate exposes
 * exactly the toolkit, each operator has BROAD coverage, the swarm collectively covers every
 * tool, and overlap (same tool on several operators) is allowed.
 */
import { describe, it, expect } from 'vitest';
import { Arsenal, BUILTIN_TOOLS, EXTERNAL_TOOLS } from '../arsenal/index.js';
import { OSINT_TOOLS } from '../tools/osint.js';
import { OSINT_DEEP_TOOLS } from '../tools/osint-correlate.js';
import { INFRA_TOOLS } from '../tools/osint-infra.js';
import { GOOGLE_OSINT_TOOLS } from '../tools/osint-google.js';
import { ARCHETYPE_PROFILES } from '../operators/index.js';

describe('Operator role toolkits — specialized · broad · full-coverage · overlap-OK', () => {
  const arsenal = new Arsenal();
  arsenal.registerMany(BUILTIN_TOOLS);   // same population the mission does (src/index.ts)
  arsenal.registerMany(EXTERNAL_TOOLS);
  arsenal.registerMany(OSINT_TOOLS);
  arsenal.registerMany(OSINT_DEEP_TOOLS);   // the mission registers these too (src/index.ts)
  arsenal.registerMany(INFRA_TOOLS); // domain/IP/hash infrastructure lanes (src/index.ts)
  arsenal.registerMany(GOOGLE_OSINT_TOOLS); // Google app-linkage + WiFi geo lanes (src/index.ts)
  const allNames = arsenal.getToolDefinitions().map(t => t.name);
  const archetypes = Object.keys(ARCHETYPE_PROFILES) as (keyof typeof ARCHETYPE_PROFILES)[];

  it('every operator toolkit contains only REAL arsenal tools (no phantoms)', () => {
    for (const a of archetypes) {
      const phantom = ARCHETYPE_PROFILES[a].defaultTools.filter(t => !allNames.includes(t));
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
    const uncovered = allNames.filter(n => !covered.has(n));
    expect(uncovered, 'tools no operator can reach').toEqual([]);
  });

  it('overlap is allowed — generalist tools appear on multiple operators', () => {
    const counts: Record<string, number> = {};
    for (const a of archetypes) for (const t of ARCHETYPE_PROFILES[a].defaultTools) counts[t] = (counts[t] || 0) + 1;
    expect(counts['http_request'], 'http_request should be broadly shared').toBeGreaterThan(1);
    expect(counts['technology_detect'], 'technology_detect should be broadly shared').toBeGreaterThan(1);
  });
});
