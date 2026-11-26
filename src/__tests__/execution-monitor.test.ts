/**
 * Execution Monitor + Mentor + Arg Reflector Tests
 *
 * Pentagi-port behavior: same-tool/total thresholds, mentor wrap format,
 * failure-soft mentor, bounded JSON arg repair, and the AgentLoop integration
 * (monitor wrap visible in the tool message sent back to the LLM).
 */

import { describe, it, expect, vi } from 'vitest';
import { ExecutionMonitor, formatEnhancedToolResponse, performMentor, fixToolCallArgs } from '../agent/monitor.js';
import { createAgentLoop } from '../agent/index.js';
import { Arsenal } from '../arsenal/index.js';
import type { LLMBackbone } from '../llm/index.js';
import type { LLMResponse, LLMToolCall, Task } from '../types/index.js';

function makeTask(): Task {
  return {
    id: 'task-1',
    missionId: 'mission-1',
    name: 'Test Task',
    description: 'A test task',
    phase: 'reconnaissance' as any,
    operatorType: 'recon',
    status: 'in_progress',
    priority: 5,
    dependencies: [],
    createdAt: Date.now(),
  };
}

function makeLLMResponse(toolCalls: LLMToolCall[], content?: string): LLMResponse {
  return { content: content || '', model: 'test-model', toolCalls, usage: { promptTokens: 10, completionTokens: 5, totalTokens: 15 } };
}

describe('ExecutionMonitor thresholds', () => {
  it('fires at the same-tool limit (5 consecutive identical calls)', () => {
    const monitor = new ExecutionMonitor();
    for (let i = 0; i < 4; i++) expect(monitor.shouldInvokeMentor('port_scan')).toBe(false);
    expect(monitor.shouldInvokeMentor('port_scan')).toBe(true);
  });

  it('resets the same-tool streak when the tool changes', () => {
    const monitor = new ExecutionMonitor();
    for (let i = 0; i < 4; i++) monitor.shouldInvokeMentor('port_scan');
    expect(monitor.shouldInvokeMentor('dns_lookup')).toBe(false);
    for (let i = 0; i < 3; i++) monitor.shouldInvokeMentor('dns_lookup');
    expect(monitor.shouldInvokeMentor('dns_lookup')).toBe(true);
  });

  it('fires on the total-call limit (10) regardless of tool variety', () => {
    const monitor = new ExecutionMonitor();
    const tools = ['a', 'b', 'c', 'd', 'e'];
    for (let i = 0; i < 9; i++) expect(monitor.shouldInvokeMentor(tools[i % tools.length])).toBe(false);
    expect(monitor.shouldInvokeMentor('a')).toBe(true);
  });

  it('reset() zeroes both counters (pentagi parity)', () => {
    const monitor = new ExecutionMonitor();
    for (let i = 0; i < 5; i++) monitor.shouldInvokeMentor('x');
    monitor.reset();
    expect(monitor.calls.totalCallCount).toBe(0);
    expect(monitor.calls.sameToolCount).toBe(0);
    expect(monitor.shouldInvokeMentor('x')).toBe(false);
  });

  it('honors custom thresholds', () => {
    const monitor = new ExecutionMonitor({ sameToolLimit: 2, totalToolLimit: 100 });
    expect(monitor.shouldInvokeMentor('x')).toBe(false);
    expect(monitor.shouldInvokeMentor('x')).toBe(true);
  });
});

describe('formatEnhancedToolResponse', () => {
  it('wraps result and analysis in the exact pentagi format', () => {
    const wrapped = formatEnhancedToolResponse('RAW', 'ANALYSIS');
    expect(wrapped).toBe(
      '<enhanced_response>\n<original_result>\nRAW\n</original_result>\n\n<mentor_analysis>\nANALYSIS\n</mentor_analysis>\n</enhanced_response>'
    );
  });

  it('returns the original untouched when the analysis is empty', () => {
    expect(formatEnhancedToolResponse('RAW', '')).toBe('RAW');
  });
});

describe('performMentor', () => {
  it('sends a system+user prompt and returns the analysis', async () => {
    const llm = {
      chat: vi.fn().mockResolvedValue({ content: ' The agent should pivot to HTTPS. ', model: 'm' }),
    } as unknown as LLMBackbone;
    const out = await performMentor(llm, {
      taskDescription: 'scan the host',
      toolName: 'port_scan',
      toolArgs: { target: '10.0.0.1' },
      toolResult: 'Success: true\nports 80,443 open',
    });
    expect(out).toBe('The agent should pivot to HTTPS.');
    const messages = (llm.chat as any).mock.calls[0][0];
    expect(messages).toHaveLength(2);
    expect(messages[0].role).toBe('system');
    expect(messages[1].content).toContain('port_scan');
    expect(messages[1].content).toContain('ports 80,443 open');
  });

  it('propagates backbone errors (callers are failure-soft)', async () => {
    const llm = { chat: vi.fn().mockRejectedValue(new Error('down')) } as unknown as LLMBackbone;
    await expect(
      performMentor(llm, { taskDescription: 't', toolName: 'x', toolResult: 'r' })
    ).rejects.toThrow('down');
  });
});

describe('fixToolCallArgs', () => {
  it('repairs args from a JSON-fenced reply', async () => {
    const llm = {
      chat: vi.fn().mockResolvedValue({ content: '```json\n{"target":"10.0.0.1","ports":"80"}\n```', model: 'm' }),
    } as unknown as LLMBackbone;
    const repaired = await fixToolCallArgs(llm, {
      toolName: 'port_scan',
      argsJson: '{"target":"10.0.0.1","ports":80}',
      error: 'ports must be a string',
    });
    expect(repaired).toEqual({ target: '10.0.0.1', ports: '80' });
  });

  it('returns null after maxRetries unparseable attempts', async () => {
    const llm = { chat: vi.fn().mockResolvedValue({ content: 'I cannot help with that.', model: 'm' }) } as unknown as LLMBackbone;
    const repaired = await fixToolCallArgs(llm, { toolName: 'x', argsJson: '{}', error: 'bad' }, 3);
    expect(repaired).toBeNull();
    expect((llm.chat as any).mock.calls).toHaveLength(3);
  });
});

describe('AgentLoop mentor integration', () => {
  it('wraps a successful tool result with the mentor analysis before it reaches the LLM', async () => {
    const arsenal = new Arsenal();
    arsenal.register({
      name: 'header_analysis',
      description: 'Fetch headers',
      category: 'recon',
      handler: async () => ({ success: true, output: 'HTTP/1.1 200 OK' }),
    });

    const toolCall: LLMToolCall = { id: 'call-1', name: 'header_analysis', arguments: { url: 'https://x' } };
    let secondCallMessages: any[] = [];
    const chatWithTools = vi
      .fn()
      .mockImplementationOnce(async (messages: any[]) => {
        secondCallMessages = messages;
        return makeLLMResponse([toolCall]);
      })
      .mockImplementationOnce(async () => makeLLMResponse([], 'All done.'));
    const llm = {
      getProvider: vi.fn().mockReturnValue('mock'),
      chat: vi.fn().mockResolvedValue({ content: 'Result looks complete; move to reporting.', model: 'm' }),
      chatWithTools,
    } as unknown as LLMBackbone;

    const agent = createAgentLoop(llm, arsenal, {
      maxIterations: 3,
      executionMonitor: new ExecutionMonitor({ sameToolLimit: 1, totalToolLimit: 100 }),
    });
    const result = await agent.run(makeTask(), 'scan', undefined);
    expect(result.success).toBe(true);
    expect((llm.chat as any).mock.calls.length).toBe(1);

    const toolMessage = secondCallMessages.find((m: any) => m.role === 'tool');
    expect(toolMessage).toBeTruthy();
    expect(toolMessage.content).toContain('<mentor_analysis>');
    expect(toolMessage.content).toContain('move to reporting');
    expect(toolMessage.content).toContain('HTTP/1.1 200 OK');
  });

  it('keeps the raw result when the mentor errors (failure-soft)', async () => {
    const arsenal = new Arsenal();
    arsenal.register({
      name: 'header_analysis',
      description: 'Fetch headers',
      category: 'recon',
      handler: async () => ({ success: true, output: 'HTTP/1.1 200 OK' }),
    });

    const toolCall: LLMToolCall = { id: 'call-1', name: 'header_analysis', arguments: { url: 'https://x' } };
    let secondCallMessages: any[] = [];
    const chatWithTools = vi
      .fn()
      .mockImplementationOnce(async (messages: any[]) => {
        secondCallMessages = messages;
        return makeLLMResponse([toolCall]);
      })
      .mockImplementationOnce(async () => makeLLMResponse([], 'Done.'));
    const llm = {
      getProvider: vi.fn().mockReturnValue('mock'),
      chat: vi.fn().mockRejectedValue(new Error('mentor down')),
      chatWithTools,
    } as unknown as LLMBackbone;

    const agent = createAgentLoop(llm, arsenal, {
      maxIterations: 3,
      executionMonitor: new ExecutionMonitor({ sameToolLimit: 1, totalToolLimit: 100 }),
    });
    const result = await agent.run(makeTask(), 'scan', undefined);
    expect(result.success).toBe(true);
    const toolMessage = secondCallMessages.find((m: any) => m.role === 'tool');
    expect(toolMessage.content).not.toContain('<mentor_analysis>');
    expect(toolMessage.content).toContain('HTTP/1.1 200 OK');
  });
});
