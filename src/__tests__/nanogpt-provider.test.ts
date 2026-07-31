import { afterEach, describe, expect, it, vi } from 'vitest';
import { AVAILABLE_MODELS, config } from '../config/index.js';
import { createNanoGPTBackbone } from '../llm/index.js';

const KEY = 'sk-nano-12345678-1234-1234-1234-123456789abc';

describe('NanoGPT provider wiring', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    delete process.env.NANOGPT_API_KEY;
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('uses the canonical base URL, documented key name, and fail-open model', () => {
    process.env.NANOGPT_API_KEY = KEY;

    const cfg = config.getLLMConfig('nanogpt');
    expect(cfg.provider).toBe('nanogpt');
    expect(cfg.baseUrl).toBe('https://nano-gpt.com/api/v1');
    expect(cfg.model).toBe('minimax/minimax-m2.7');
    expect(cfg.apiKey).toBe(KEY);
    expect(`${cfg.baseUrl}/chat/completions`)
      .toBe('https://nano-gpt.com/api/v1/chat/completions');
  });

  it('does not recognize the obsolete RBE_API_KEY identifier', () => {
    process.env.RBE_API_KEY = KEY;
    try {
      expect(config.getLLMConfig('nanogpt').apiKey).toBeUndefined();
    } finally {
      delete process.env.RBE_API_KEY;
    }
  });

  it('routes chat directly to NanoGPT with Bearer authentication', async () => {
    const fetchSpy = vi.fn(async (_url: string | URL, _init?: RequestInit) => ({
      ok: true,
      json: async () => ({
        id: 'chatcmpl-test',
        model: 'minimax/minimax-m2.7',
        choices: [{ message: { content: 'ok' }, finish_reason: 'stop' }],
      }),
    }));
    global.fetch = fetchSpy as unknown as typeof fetch;

    const response = await createNanoGPTBackbone(KEY).chat([
      { role: 'user', content: 'hello' },
    ]);

    expect(response.content).toBe('ok');
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://nano-gpt.com/api/v1/chat/completions');
    expect((init as RequestInit).headers).toMatchObject({
      Authorization: `Bearer ${KEY}`,
      'Content-Type': 'application/json',
    });
  });

  it('requires a NanoGPT key and surfaces configured provider state', () => {
    const bb = createNanoGPTBackbone();
    expect(bb.getProvider()).toBe('nanogpt');
    expect(bb.validateConfig()).toEqual({
      valid: false,
      error: expect.stringContaining('NANOGPT_API_KEY'),
    });

    process.env.NANOGPT_API_KEY = KEY;
    expect(config.getConfiguredProviders()).toContain('nanogpt');
    expect(AVAILABLE_MODELS.nanogpt.map((model) => model.id))
      .toEqual(['minimax/minimax-m2.7']);
  });
});
