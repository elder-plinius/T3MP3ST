/**
 * Agent Error Feedback Tests
 *
 * Tests for structured error feedback to the LLM after failed tool executions.
 * Ensures the LLM receives categorized errors without raw internals.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createAgentLoop } from '../agent/index.js';
import { Arsenal } from '../arsenal/index.js';
import type { LLMBackbone } from '../llm/index.js';
import type { LLMResponse, LLMToolCall } from '../types/index.js';
import type { Task } from '../types/index.js';
import { ToolError, ToolErrorCategory } from '../types/index.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeToolCall(id: string, name: string, args: Record<string, unknown>): LLMToolCall {
  return { id, name, arguments: args };
}

function makeLLMResponse(toolCalls: LLMToolCall[], content?: string): LLMResponse {
  return {
    content: content || '',
    model: 'test-model',
    toolCalls,
    usage: { promptTokens: 100, completionTokens: 50, totalTokens: 150 },
  };
}

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

function createMockLLM(responses: LLMResponse[]): LLMBackbone {
  let callIndex = 0;
  return {
    getProvider: vi.fn().mockReturnValue('mock'),
    chat: vi.fn().mockImplementation(async () => {
      const response = responses[callIndex] || responses[responses.length - 1];
      callIndex++;
      return response;
    }),
    chatWithTools: vi.fn().mockImplementation(async () => {
      const response = responses[callIndex] || responses[responses.length - 1];
      callIndex++;
      return response;
    }),
  } as unknown as LLMBackbone;
}

// =============================================================================
// Tests
// =============================================================================

describe('Agent Error Feedback to LLM', () => {
  let arsenal: Arsenal;

  beforeEach(() => {
    arsenal = new Arsenal();
  });

  // ── 1. Failed tool call adds error message to conversation ────────────────────

  describe('error message added to conversation', () => {
    it('should add tool error result to messages when tool fails', async () => {
      arsenal.register({
        name: 'failing_tool',
        description: 'Always fails',
        category: 'test',
        parameters: [],
        handler: async () => {
          throw new Error('Something went wrong');
        },
      });

      const toolCalls = [makeToolCall('c1', 'failing_tool', {})];
      const llm = createMockLLM([
        makeLLMResponse(toolCalls),
        makeLLMResponse([], 'Done.'),
      ]);

      const agent = createAgentLoop(llm, arsenal, { maxIterations: 5 });
      await agent.run(makeTask(), 'Execute tool.');

      // The LLM should have received a tool result message
      const chatWithToolsCalls = (llm.chatWithTools as any).mock.calls;
      // First call: system + user prompt
      // After tool execution: assistant + tool result messages should be in the context
      // Second call: should include the error feedback
      expect(chatWithToolsCalls.length).toBeGreaterThanOrEqual(2);

      // Check the messages passed to the second chatWithTools call
      const secondCallMessages = chatWithToolsCalls[1][0];
      const toolMessages = secondCallMessages.filter((m: any) => m.role === 'tool');
      expect(toolMessages.length).toBeGreaterThanOrEqual(1);

      // The tool message should contain error information
      const errorMsg = toolMessages[0].content;
      expect(errorMsg).toBeDefined();
    });
  });

  // ── 2. Error message contains category, not raw error ─────────────────────────

  describe('error category in feedback', () => {
    it('should include error category in tool result message', async () => {
      arsenal.register({
        name: 'crashing_tool',
        description: 'Crashes',
        category: 'test',
        parameters: [],
        handler: async () => {
          throw new ToolError(ToolErrorCategory.ExecutionError, 'Internal failure');
        },
      });

      const toolCalls = [makeToolCall('c1', 'crashing_tool', {})];
      const llm = createMockLLM([
        makeLLMResponse(toolCalls),
        makeLLMResponse([], 'Done.'),
      ]);

      const agent = createAgentLoop(llm, arsenal, { maxIterations: 5 });
      await agent.run(makeTask(), 'Execute.');

      // Get the messages from the second LLM call
      const chatWithToolsCalls = (llm.chatWithTools as any).mock.calls;
      const secondCallMessages = chatWithToolsCalls[1][0];
      const toolMessages = secondCallMessages.filter((m: any) => m.role === 'tool');

      expect(toolMessages.length).toBeGreaterThanOrEqual(1);

      // Parse the error content — it should be JSON with category
      const content = toolMessages[0].content;
      // The content should contain the error category
      expect(content).toContain('execution_error');
    });

    it('should not expose raw error message in tool feedback', async () => {
      arsenal.register({
        name: 'leaky_tool',
        description: 'Leaks internals',
        category: 'test',
        parameters: [],
        handler: async () => {
          throw new Error('SECRET_db_password=abc123');
        },
      });

      const toolCalls = [makeToolCall('c1', 'leaky_tool', {})];
      const llm = createMockLLM([
        makeLLMResponse(toolCalls),
        makeLLMResponse([], 'Done.'),
      ]);

      const agent = createAgentLoop(llm, arsenal, { maxIterations: 5 });
      await agent.run(makeTask(), 'Execute.');

      const chatWithToolsCalls = (llm.chatWithTools as any).mock.calls;
      const secondCallMessages = chatWithToolsCalls[1][0];
      const toolMessages = secondCallMessages.filter((m: any) => m.role === 'tool');

      expect(toolMessages.length).toBeGreaterThanOrEqual(1);
      const content = toolMessages[0].content;
      // Raw error with secrets should NOT appear in the feedback
      expect(content).not.toContain('SECRET_db_password');
      expect(content).not.toContain('abc123');
    });
  });

  // ── 3. LLM receives error feedback and can retry ──────────────────────────────

  describe('LLM retry after error', () => {
    it('should allow LLM to retry after receiving error feedback', async () => {
      let callCount = 0;
      arsenal.register({
        name: 'retry_tool',
        description: 'Fails first, succeeds second',
        category: 'test',
        parameters: [
          { name: 'attempt', type: 'string', description: 'Attempt', required: true },
        ],
        handler: async (ctx) => {
          callCount++;
          if (ctx.parameters.attempt === 'first') {
            throw new Error('First attempt failed');
          }
          return { success: true, output: 'Second attempt succeeded' };
        },
      });

      // First call: tool fails. Second call: LLM retries with different args. Third call: done.
      const llm = createMockLLM([
        makeLLMResponse([makeToolCall('c1', 'retry_tool', { attempt: 'first' })]),
        makeLLMResponse([makeToolCall('c2', 'retry_tool', { attempt: 'second' })]),
        makeLLMResponse([], 'Retry succeeded.'),
      ]);

      const agent = createAgentLoop(llm, arsenal, { maxIterations: 5 });
      const result = await agent.run(makeTask(), 'Try the tool.');

      expect(result.success).toBe(true);
      // Both calls should have been made
      expect(callCount).toBe(2);

      // Should have tool call steps for both attempts
      const toolSteps = result.steps.filter(s => s.type === 'tool_call');
      expect(toolSteps).toHaveLength(2);
      expect(toolSteps[0].toolResult?.success).toBe(false);
      expect(toolSteps[1].toolResult?.success).toBe(true);
    });
  });

  // ── 4. Multiple failures produce separate error messages ──────────────────────

  describe('multiple failures', () => {
    it('should produce separate error messages for each failed tool call', async () => {
      arsenal.register({
        name: 'fail_a',
        description: 'Fails A',
        category: 'test',
        parameters: [],
        handler: async () => { throw new Error('Error A'); },
      });

      arsenal.register({
        name: 'fail_b',
        description: 'Fails B',
        category: 'test',
        parameters: [],
        handler: async () => { throw new Error('Error B'); },
      });

      const toolCalls = [
        makeToolCall('c1', 'fail_a', {}),
        makeToolCall('c2', 'fail_b', {}),
      ];

      const llm = createMockLLM([
        makeLLMResponse(toolCalls),
        makeLLMResponse([], 'Both failed.'),
      ]);

      const agent = createAgentLoop(llm, arsenal, { maxIterations: 5 });
      await agent.run(makeTask(), 'Execute both.');

      // Check that both error messages were added to the conversation
      const chatWithToolsCalls = (llm.chatWithTools as any).mock.calls;
      const secondCallMessages = chatWithToolsCalls[1][0];
      const toolMessages = secondCallMessages.filter((m: any) => m.role === 'tool');

      // Should have 2 tool messages (one per failed call)
      expect(toolMessages).toHaveLength(2);

      // Each should have a unique toolCallId
      const toolCallIds = toolMessages.map((m: any) => m.toolCallId);
      expect(toolCallIds[0]).not.toBe(toolCallIds[1]);
    });

    it('should have toolCallId matching the original tool call', async () => {
      arsenal.register({
        name: 'fail_tool',
        description: 'Fails',
        category: 'test',
        parameters: [],
        handler: async () => { throw new Error('Fail'); },
      });

      const toolCall = makeToolCall('unique-call-id', 'fail_tool', {});
      const llm = createMockLLM([
        makeLLMResponse([toolCall]),
        makeLLMResponse([], 'Done.'),
      ]);

      const agent = createAgentLoop(llm, arsenal, { maxIterations: 5 });
      await agent.run(makeTask(), 'Execute.');

      const chatWithToolsCalls = (llm.chatWithTools as any).mock.calls;
      const secondCallMessages = chatWithToolsCalls[1][0];
      const toolMessages = secondCallMessages.filter((m: any) => m.role === 'tool');

      expect(toolMessages).toHaveLength(1);
      expect(toolMessages[0].toolCallId).toBe('unique-call-id');
    });
  });

  // ── 5. Error feedback structure ───────────────────────────────────────────────

  describe('error feedback structure', () => {
    it('should include error flag in structured feedback', async () => {
      arsenal.register({
        name: 'structured_fail',
        description: 'Structured failure',
        category: 'test',
        parameters: [],
        handler: async () => { throw new Error('Test error'); },
      });

      const toolCalls = [makeToolCall('c1', 'structured_fail', {})];
      const llm = createMockLLM([
        makeLLMResponse(toolCalls),
        makeLLMResponse([], 'Done.'),
      ]);

      const agent = createAgentLoop(llm, arsenal, { maxIterations: 5 });
      await agent.run(makeTask(), 'Execute.');

      const chatWithToolsCalls = (llm.chatWithTools as any).mock.calls;
      const secondCallMessages = chatWithToolsCalls[1][0];
      const toolMessages = secondCallMessages.filter((m: any) => m.role === 'tool');

      expect(toolMessages).toHaveLength(1);
      const content = toolMessages[0].content;
      // Should contain the error category
      expect(content).toContain('execution_error');
      // Should contain the tool name
      expect(content).toContain('structured_fail');
    });
  });
});
