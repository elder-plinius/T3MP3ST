/**
 * Ollama Native Function Calling — Phase 6 / PR 3
 *
 * Tests that LocalAdapter probes, caches, and uses native Ollama /api/chat tool_calls
 * (with fallback to the existing text-based path for models that don't support it).
 *
 * Spec coverage:
 *   1. Probe detects native support → native tool calls parsed
 *   2. Probe failure → falls back to text-based tool calling
 *   3. Probe result cached per model → no re-probe on subsequent calls
 *   4. nativeTools=false config → skips probe entirely (always text)
 *   5. nativeTools=true config → forces native mode
 *   6. OpenAI-compatible wire → native tools sent correctly
 *   7. OpenAI-compatible wire → text fallback on probe failure
 */
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { LLMBackbone, __resetLocalAdapterCache } from '../llm/index.js';
import type { LLMToolDefinition } from '../types/index.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

const TOOLS: LLMToolDefinition[] = [{
  name: 'test_tool',
  description: 'a test tool',
  parameters: {
    type: 'object',
    properties: { input: { type: 'string', description: 'input value' } },
    required: ['input'],
  },
}];

function localBackbone(model = 'test-model', overrides: Record<string, unknown> = {}): LLMBackbone {
  return new LLMBackbone({
    provider: 'local',
    model,
    baseUrl: 'http://localhost:11434/api',
    maxTokens: 4096,
    temperature: 0.7,
    ...overrides,
  } as never);
}

function mockFetch(body: unknown, ok = true) {
  return vi.fn(async (_url: string, _init: { body: string }) => ({
    ok,
    status: ok ? 200 : 500,
    json: async () => body,
  } as unknown as Response));
}

const origFetch = global.fetch;

// ── Tests ────────────────────────────────────────────────────────────────────

describe('Ollama native wire (/api/chat)', () => {
  beforeEach(() => { __resetLocalAdapterCache(); });
  afterEach(() => { global.fetch = origFetch; });

  it('probe detects native support: sends tools array, parses tool_calls from response', async () => {
    const spy = mockFetch({
      model: 'test-model',
      message: {
        role: 'assistant',
        content: '',
        tool_calls: [
          { function: { name: 'test_tool', arguments: '{"input":"hello"}' } },
        ],
      },
    });
    global.fetch = spy as unknown as typeof fetch;

    const bb = localBackbone('native-probe-1');
    const res = await bb.chatWithTools([{ role: 'user', content: 'use the tool' }], TOOLS);

    // Tool calls parsed correctly
    expect(res.toolCalls).toBeDefined();
    expect(res.toolCalls).toHaveLength(1);
    expect(res.toolCalls![0].name).toBe('test_tool');
    expect(res.toolCalls![0].arguments).toEqual({ input: 'hello' });
    expect(res.finishReason).toBe('tool_calls');

    // Request body included tools in Ollama native format
    const body = JSON.parse(spy.mock.calls[0][1].body);
    expect(body.tools).toBeDefined();
    expect(body.tools).toHaveLength(1);
    expect(body.tools[0].type).toBe('function');
    expect(body.tools[0].function.name).toBe('test_tool');
    expect(body.tools[0].function.parameters).toBeDefined();
  });

  it('falls back to text-based parsing when model lacks native tool_calls in response', async () => {
    const spy = mockFetch({
      model: 'test-model',
      message: {
        role: 'assistant',
        content: '```json\n{"tool_calls":[{"name":"test_tool","arguments":{"input":"hello"}}]}\n```',
      },
    });
    global.fetch = spy as unknown as typeof fetch;

    const bb = localBackbone('native-probe-fail-1');
    const res = await bb.chatWithTools([{ role: 'user', content: 'use the tool' }], TOOLS);

    // Text-based fallback works — tool calls still parsed
    expect(res.toolCalls).toBeDefined();
    expect(res.toolCalls).toHaveLength(1);
    expect(res.toolCalls![0].name).toBe('test_tool');
    expect(res.toolCalls![0].arguments).toEqual({ input: 'hello' });
    expect(res.finishReason).toBe('tool_calls');
  });

  it('caches failed probe: second call omits native tools from request', async () => {
    let callIdx = 0;
    const spy = vi.fn(async (_url: string, init: { body: string }) => {
      const body = JSON.parse(init.body);
      if (callIdx === 0) {
        // First call: native tools ARE sent (optimistic probe)
        expect(body.tools).toBeDefined();
        callIdx++;
        return {
          ok: true,
          json: async () => ({
            model: 'cache-test-1',
            message: {
              role: 'assistant',
              content: '```json\n{"tool_calls":[{"name":"test_tool","arguments":{"input":"first"}}]}\n```',
            },
          }),
        } as unknown as Response;
      }
      // Second call: native tools NOT sent (cache says not supported)
      expect(body.tools).toBeUndefined();
      callIdx++;
      return {
        ok: true,
        json: async () => ({
          model: 'cache-test-1',
          message: { role: 'assistant', content: '```json\n{"tool_calls":[{"name":"test_tool","arguments":{"input":"second"}}]}\n```' },
        }),
      } as unknown as Response;
    });
    global.fetch = spy as unknown as typeof fetch;

    const bb = localBackbone('cache-test-1');
    const res1 = await bb.chatWithTools([{ role: 'user', content: 'first' }], TOOLS);
    expect(res1.toolCalls).toBeDefined();

    const res2 = await bb.chatWithTools([{ role: 'user', content: 'second' }], TOOLS);
    expect(res2.toolCalls).toBeDefined();
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it('caches successful probe: second call still sends native tools', async () => {
    let _callIdx = 0;
    const spy = vi.fn(async (_url: string, _init: { body: string }) => {
      _callIdx++;
      return {
        ok: true,
        json: async () => ({
          model: 'cache-test-2',
          message: {
            role: 'assistant',
            content: '',
            tool_calls: [
              { function: { name: 'test_tool', arguments: '{"input":"x"}' } },
            ],
          },
        }),
      } as unknown as Response;
    });
    global.fetch = spy as unknown as typeof fetch;

    const bb = localBackbone('cache-test-2');
    await bb.chatWithTools([{ role: 'user', content: 'first' }], TOOLS);
    await bb.chatWithTools([{ role: 'user', content: 'second' }], TOOLS);

    // Both calls should have tools in request (native supported)
    const body1 = JSON.parse(spy.mock.calls[0][1].body);
    const body2 = JSON.parse(spy.mock.calls[1][1].body);
    expect(body1.tools).toBeDefined();
    expect(body2.tools).toBeDefined();
    expect(spy).toHaveBeenCalledTimes(2);
  });
});

describe('nativeTools config option', () => {
  beforeEach(() => { __resetLocalAdapterCache(); });
  afterEach(() => { global.fetch = origFetch; });

  it('nativeTools=false skips native tools entirely (always text-based)', async () => {
    const spy = mockFetch({
      model: 'test-model',
      message: { role: 'assistant', content: 'tool result in text' },
    });
    global.fetch = spy as unknown as typeof fetch;

    const bb = localBackbone('config-false-1', { nativeTools: false });
    await bb.chatWithTools([{ role: 'user', content: 'do it' }], TOOLS);

    const body = JSON.parse(spy.mock.calls[0][1].body);
    expect(body.tools).toBeUndefined();
  });

  it('nativeTools=true forces native mode even if cache would say false', async () => {
    const spy = mockFetch({
      model: 'test-model',
      message: {
        role: 'assistant',
        content: '',
        tool_calls: [
          { function: { name: 'test_tool', arguments: '{"input":"forced"}' } },
        ],
      },
    });
    global.fetch = spy as unknown as typeof fetch;

    const bb = localBackbone('config-true-1', { nativeTools: true });
    const res = await bb.chatWithTools([{ role: 'user', content: 'force' }], TOOLS);

    const body = JSON.parse(spy.mock.calls[0][1].body);
    expect(body.tools).toBeDefined();
    expect(res.toolCalls).toBeDefined();
    expect(res.toolCalls![0].arguments).toEqual({ input: 'forced' });
  });
});

describe('OpenAI-compatible wire (/v1/chat/completions)', () => {
  beforeEach(() => { __resetLocalAdapterCache(); });
  afterEach(() => { global.fetch = origFetch; });

  it('sends native tools when probe succeeds on OpenAI-compatible endpoint', async () => {
    const spy = mockFetch({
      model: 'local',
      choices: [{
        message: {
          content: '',
          tool_calls: [
            { id: 'call_1', type: 'function', function: { name: 'test_tool', arguments: '{"input":"via-openai-wire"}' } },
          ],
        },
        finish_reason: 'tool_calls',
      }],
    });
    global.fetch = spy as unknown as typeof fetch;

    const bb = localBackbone('openai-wire-1', { baseUrl: 'http://localhost:1234/v1' });
    const res = await bb.chatWithTools([{ role: 'user', content: 'scan' }], TOOLS);

    expect(res.toolCalls).toBeDefined();
    expect(res.toolCalls).toHaveLength(1);
    expect(res.toolCalls![0].name).toBe('test_tool');
    expect(res.toolCalls![0].arguments).toEqual({ input: 'via-openai-wire' });

    const body = JSON.parse(spy.mock.calls[0][1].body);
    expect(body.tools).toBeDefined();
    expect(body.tools[0].type).toBe('function');
    expect(body.tools[0].function.name).toBe('test_tool');
    // OpenAI-compatible wire hits /v1/chat/completions
    expect(spy.mock.calls[0][0]).toContain('/v1/chat/completions');
  });

  it('falls back to text-based parsing on OpenAI-compatible wire when no native tool_calls', async () => {
    const spy = mockFetch({
      model: 'local',
      choices: [{
        message: {
          content: '{"tool_calls":[{"name":"test_tool","arguments":{"input":"text-fallback"}}]}',
        },
        finish_reason: 'stop',
      }],
    });
    global.fetch = spy as unknown as typeof fetch;

    const bb = localBackbone('openai-wire-fallback-1', { baseUrl: 'http://localhost:1234/v1' });
    const res = await bb.chatWithTools([{ role: 'user', content: 'scan' }], TOOLS);

    expect(res.toolCalls).toBeDefined();
    expect(res.toolCalls).toHaveLength(1);
    expect(res.toolCalls![0].name).toBe('test_tool');
    expect(res.toolCalls![0].arguments).toEqual({ input: 'text-fallback' });
  });
});

describe('existing text-based path preserved', () => {
  beforeEach(() => { __resetLocalAdapterCache(); });
  afterEach(() => { global.fetch = origFetch; });

  it('prose-only response produces no toolCalls (final answer)', async () => {
    const spy = mockFetch({
      model: 'test-model',
      message: {
        role: 'assistant',
        content: 'Surface exhausted. No vulnerabilities found.',
      },
    });
    global.fetch = spy as unknown as typeof fetch;

    const bb = localBackbone('prose-only-1');
    const res = await bb.chatWithTools([{ role: 'user', content: 'done' }], TOOLS);

    expect(res.toolCalls).toBeUndefined();
    expect(res.finishReason).toBe('stop');
    expect(res.content).toContain('Surface exhausted');
  });

  it('no tools offered → no tool contract injected, no native tools', async () => {
    const spy = mockFetch({
      model: 'test-model',
      message: { role: 'assistant', content: 'ok' },
    });
    global.fetch = spy as unknown as typeof fetch;

    const bb = localBackbone('no-tools-1');
    const res = await bb.chat([{ role: 'user', content: 'hello' }]);

    const body = JSON.parse(spy.mock.calls[0][1].body);
    expect(body.tools).toBeUndefined();
    expect(res.content).toBe('ok');
  });
});
