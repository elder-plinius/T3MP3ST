/**
 * REGRESSION (keyless-path bug): the local-agent / codex text-CLI backbones must surface `toolCalls`
 * parsed from the agent's reply. If they don't, the ReAct loop takes its "final answer" branch on
 * turn 0 and every operator abstains without ever running the Arsenal. These tests pin the fix AND
 * the parser-hardening from the PR #16 audit (over-match, ReDoS, drift-abstains, string args, Codex coverage).
 */
import { describe, it, expect, vi } from 'vitest';
import { EventEmitter } from 'events';

// Mock the local-agent CLI bridge (LocalAgentAdapter) and the codex spawn/file read (CodexAdapter).
vi.mock('../agent/local-agents.js', () => ({ localAgentChat: vi.fn() }));
vi.mock('child_process', () => ({
  spawn: vi.fn(() => {
    const child = new EventEmitter() as EventEmitter & { stdin: { end: () => void }; stdout: EventEmitter; stderr: EventEmitter };
    child.stdin = { end: () => setTimeout(() => child.emit('close', 0), 0) };
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    return child;
  }),
}));
vi.mock('fs/promises', async (orig) => {
  const actual = await orig<typeof import('fs/promises')>();
  return { ...actual, readFile: vi.fn() };
});

import { parseTextToolCalls, LLMBackbone } from '../llm/index.js';
import { localAgentChat } from '../agent/local-agents.js';
import { readFile } from 'fs/promises';
const cli = vi.mocked(localAgentChat);
const fileRead = vi.mocked(readFile as unknown as (...a: unknown[]) => Promise<string>);

const TOOLS = [{
  name: 'nmap_scan', description: 'port scan a host',
  parameters: { type: 'object' as const, properties: { target: { type: 'string' } }, required: ['target'] },
}];
const localBackbone = () => new LLMBackbone({ provider: 'local-agent', model: 'codex' } as never);
const codexBackbone = () => new LLMBackbone({ provider: 'codex', model: 'codex-default' } as never);

describe('parseTextToolCalls — happy path + drift tolerance', () => {
  it('parses a contracted fenced block', () => {
    expect(parseTextToolCalls('reasoning\n```json\n{"tool_calls":[{"name":"nmap_scan","arguments":{"target":"x"}}]}\n```'))
      .toMatchObject([{ name: 'nmap_scan', arguments: { target: 'x' } }]);
  });
  it('prose-only debrief is the final answer (no calls)', () => {
    expect(parseTextToolCalls('Surface exhausted; no findings. Abstaining.')).toBeUndefined();
  });
  // --- audit must-fixes below ---
  it('unfenced object + a stray brace elsewhere still parses (was: greedy over-match → silent abstain)', () => {
    const r = parseTextToolCalls('example shape {"x":1}\n{"tool_calls":[{"name":"port_scan","arguments":{"host":"h"}}]}\ntrailing {note}');
    expect(r).toHaveLength(1);
    expect(r![0].name).toBe('port_scan');
  });
  it('tolerates a trailing comma', () => {
    expect(parseTextToolCalls('```json\n{"tool_calls":[{"name":"nmap_scan","arguments":{"target":"x"}},]}\n```')).toHaveLength(1);
  });
  it('accepts a single un-wrapped {name,arguments} object', () => {
    expect(parseTextToolCalls('```json\n{"name":"nmap_scan","arguments":{"target":"x"}}\n```')).toMatchObject([{ name: 'nmap_scan' }]);
  });
  it('accepts an "actions" wrapper key', () => {
    expect(parseTextToolCalls('{"actions":[{"name":"curl_request","arguments":{}}]}')).toHaveLength(1);
  });
  it('coerces a string "arguments" into an object (scope-gate blind-spot fix)', () => {
    const r = parseTextToolCalls('{"tool_calls":[{"name":"nmap_scan","arguments":"{\\"target\\":\\"x\\"}"}]}');
    expect(r![0].arguments).toEqual({ target: 'x' });
  });
  it('is DoS-safe on pathological brace input (was: quadratic ReDoS)', () => {
    const t0 = Date.now();
    expect(parseTextToolCalls('{'.repeat(80000))).toBeUndefined();
    expect(Date.now() - t0).toBeLessThan(300); // bounded — the old greedy regex took ~2100ms
  });
});

describe('local-agent backbone surfaces toolCalls (keyless-path fix)', () => {
  it('returns toolCalls + finishReason=tool_calls when the agent requests a tool', async () => {
    cli.mockResolvedValueOnce('```json\n{"tool_calls":[{"name":"nmap_scan","arguments":{"target":"x"}}]}\n```');
    const res = await localBackbone().chatWithTools([{ role: 'user', content: 'scan' }], TOOLS as never);
    expect(res.toolCalls?.[0]?.name).toBe('nmap_scan');
    expect(res.finishReason).toBe('tool_calls');
  });
  it('returns no toolCalls (final answer) on a prose debrief', async () => {
    cli.mockResolvedValueOnce('Final debrief: nothing exploitable.');
    const res = await localBackbone().chatWithTools([{ role: 'user', content: 'scan' }], TOOLS as never);
    expect(res.toolCalls).toBeUndefined();
    expect(res.finishReason).toBe('stop');
  });
});

describe('codex backbone surfaces toolCalls (guards the CodexAdapter half of the fix)', () => {
  it('returns toolCalls when codex emits the contract', async () => {
    fileRead.mockResolvedValueOnce('```json\n{"tool_calls":[{"name":"nmap_scan","arguments":{"target":"x"}}]}\n```');
    const res = await codexBackbone().chatWithTools([{ role: 'user', content: 'scan' }], TOOLS as never);
    expect(res.toolCalls?.[0]?.name).toBe('nmap_scan');
  });
  it('returns no toolCalls on a codex prose debrief', async () => {
    fileRead.mockResolvedValueOnce('No exploitable surface. Final debrief.');
    const res = await codexBackbone().chatWithTools([{ role: 'user', content: 'scan' }], TOOLS as never);
    expect(res.toolCalls).toBeUndefined();
  });
});
