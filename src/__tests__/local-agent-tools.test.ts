/**
 * Text-mode tool calling for the KEYLESS local-agent backbone (Codex / Claude / Hermes).
 *
 * Regression for the "operators never execute a single Arsenal tool" defect: the ReAct
 * AgentLoop drives execution through `chatWithTools(...).toolCalls`, but the CLI-agent
 * adapters returned text only and silently dropped `options.tools`, so `toolCalls` was
 * ALWAYS undefined → the loop concluded on iteration 0 and no tool ever fired.
 *
 * The fix teaches the CLI-agent adapters a text protocol: describe the tools in the
 * prompt, and parse a fenced ```tool JSON block back into structured `toolCalls`.
 * Execution still runs in-process via `arsenal.execute` — the CLI's own sandbox is
 * irrelevant because we only ask it to PICK the tool, not run it.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockLocalAgentChat } = vi.hoisted(() => ({ mockLocalAgentChat: vi.fn() }));
vi.mock('../agent/local-agents.js', () => ({ localAgentChat: mockLocalAgentChat }));

import { LLMBackbone } from '../llm/index.js';
import type { LLMToolDefinition, LLMMessage, LLMConfig } from '../types/index.js';

const portScan: LLMToolDefinition = {
  name: 'port_scan',
  description: 'Scan TCP ports on a target host',
  parameters: { type: 'object', properties: { target: { type: 'string' } }, required: ['target'] },
};
const messages: LLMMessage[] = [{ role: 'user', content: 'Assess 192.168.68.157' }];
const cfg = (): LLMConfig => ({ provider: 'local-agent', model: 'codex', maxTokens: 4096, temperature: 0.4 });

describe('local-agent backbone — text-mode tool calling', () => {
  beforeEach(() => mockLocalAgentChat.mockReset());

  it('exposes the tool catalog to the agent (prompt names the callable tools)', async () => {
    mockLocalAgentChat.mockResolvedValue('done, no tools needed');
    const llm = new LLMBackbone(cfg());
    await llm.chatWithTools(messages, [portScan]);
    const promptSent = String(mockLocalAgentChat.mock.calls[0][1]);
    expect(promptSent).toContain('port_scan');
    expect(promptSent).toContain('Scan TCP ports');
  });

  it('parses a fenced ```tool JSON block into a structured toolCall the ReAct loop can execute', async () => {
    mockLocalAgentChat.mockResolvedValue(
      'I will map the reachable services first.\n\n```tool\n{"tool":"port_scan","arguments":{"target":"192.168.68.157"}}\n```'
    );
    const llm = new LLMBackbone(cfg());
    const res = await llm.chatWithTools(messages, [portScan]);
    expect(res.toolCalls).toBeDefined();
    expect(res.toolCalls).toHaveLength(1);
    expect(res.toolCalls![0]).toMatchObject({ name: 'port_scan', arguments: { target: '192.168.68.157' } });
    expect(res.toolCalls![0].id).toBeTruthy();
  });

  it('treats a prose reply with no tool block as the final debrief (no toolCalls)', async () => {
    mockLocalAgentChat.mockResolvedValue('Final debrief: host appears filtered; no vulnerabilities confirmed.');
    const llm = new LLMBackbone(cfg());
    const res = await llm.chatWithTools(messages, [portScan]);
    expect(res.toolCalls).toBeUndefined();
    expect(res.content).toContain('Final debrief');
  });

  it('does NOT misread an unrelated JSON object (findings debrief) as a tool call', async () => {
    mockLocalAgentChat.mockResolvedValue('```json\n{"findings":[],"abstained":true}\n```');
    const llm = new LLMBackbone(cfg());
    const res = await llm.chatWithTools(messages, [portScan]);
    expect(res.toolCalls).toBeUndefined();
  });

  it('without tools, behaves as a plain text completion (unchanged legacy path)', async () => {
    mockLocalAgentChat.mockResolvedValue('plain analysis');
    const llm = new LLMBackbone(cfg());
    const res = await llm.chat(messages);
    expect(res.toolCalls).toBeUndefined();
    expect(res.content).toBe('plain analysis');
  });
});
