import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

// Static invariants for the Kimi Code local-agent adapter (Kimi K3 subscription
// via the operator's own `kimi login` — keyless, same posture as claude/codex/hermes).
// Pinned failure modes:
//   (1) the backbone dispatch (localAgentChat) fell through to the hermes `-z` argv
//       for any non-claude/codex id — kimi has no `-z` flag, so every backbone call
//       would fail with an unknown-flag error;
//   (2) the kimi bin installs under ~/.kimi-code/bin, outside PATH on minimal shells,
//       so detection must scan that dir explicitly;
//   (3) kimi's one-shot puts thinking bullets and the session-resume trailer on
//       STDERR — stdout is reply-only — so `-p ... --output-format text` needs no
//       output filtering (verified live against kimi-code).

const agentSource = readFileSync(join(process.cwd(), 'src/agent/local-agents.ts'), 'utf8');
const configSource = readFileSync(join(process.cwd(), 'src/config/index.ts'), 'utf8');

function block(source: string, startMarker: string, endMarker: string): string {
  const start = source.indexOf(startMarker);
  expect(start, `missing marker "${startMarker}"`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf(endMarker, start);
  expect(end, `missing end marker "${endMarker}"`).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe('kimi local-agent adapter', () => {
  it('registers kimi in the agent id union', () => {
    expect(agentSource).toMatch(/LocalAgentId = 'claude' \| 'codex' \| 'hermes' \| 'kimi'/);
  });

  it('ships a kimi spec with the verified one-shot argv and auth artifact', () => {
    const spec = block(agentSource, "id: 'kimi',", '];');
    expect(spec).toContain("bin: 'kimi'");
    // Device-code OAuth login artifact (dir, perms 700) — presence-only detection.
    expect(spec).toContain('~/.kimi-code/credentials');
    // oneShot: kimi -p <prompt> --output-format text [-m model]
    expect(spec).toContain("'-p'");
    expect(spec).toContain("'--output-format', 'text'");
    expect(spec).toContain("'-m'");
  });

  it('drives the backbone chat path with kimi argv, never the hermes -z fallback', () => {
    const chat = block(agentSource, 'export function localAgentChat', 'if (viaStdin && child.stdin)');
    // Explicit kimi branch BEFORE the hermes catch-all else.
    const kimiAt = chat.indexOf("id === 'kimi'");
    const hermesAt = chat.indexOf('// hermes');
    expect(kimiAt, 'localAgentChat has no kimi branch — falls through to hermes argv').toBeGreaterThanOrEqual(0);
    expect(hermesAt, 'localAgentChat lost the hermes fallback branch').toBeGreaterThan(kimiAt);
    const kimiBranch = block(chat, "} else if (id === 'kimi') {", '} else {');
    expect(kimiBranch).toContain("'-p'");
    expect(kimiBranch).toContain("'--output-format', 'text'");
    expect(kimiBranch).toContain('viaStdin = false');
    expect(kimiBranch).not.toContain("'-z'");
  });

  it('scans the kimi-code install dir when resolving the bin', () => {
    expect(agentSource).toContain("join(home, '.kimi-code', 'bin')");
  });

  it('exposes kimi in the local-agent model catalog', () => {
    const catalog = block(configSource, "'local-agent': [", '];');
    expect(catalog).toContain("id: 'kimi'");
  });

  it('resolves local-agent in getLLMConfig (no Unknown provider throw)', () => {
    // buildDecompositionConfig passes TEMPEST_*_PROVIDER straight into getLLMConfig;
    // without this case `local-agent` hit `default: throw Unknown provider`.
    const sw = block(configSource, 'switch (actualProvider) {', 'default:');
    expect(sw).toContain("case 'local-agent':");
  });

  it('floors the local-agent timeout at the agent dispatch default (600s)', () => {
    // LLMConfig.timeout is passed as an explicit timeoutMs into localAgentChat,
    // overriding its built-in 600s — so the config floor must match the agent
    // dispatch default, with T3MP3ST_LOCAL_AGENT_TIMEOUT_MS as the operator knob.
    // (A 120s floor here killed the first real white-box run: orchestrator
    // planning prompts legitimately take minutes on an agent CLI.)
    expect(configSource).toContain("actualProvider === 'local-agent'");
    expect(configSource).toContain('T3MP3ST_LOCAL_AGENT_TIMEOUT_MS');
    expect(configSource).toContain('600000');
  });
});
