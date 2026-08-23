import { describe, expect, it, afterEach, vi } from 'vitest';
import { config, AVAILABLE_MODELS } from '../config/index.js';
import { createNovitaBackbone } from '../llm/index.js';

const KEY = 'sk_novita-test-key-0123456789';

describe('Novita AI provider wiring', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    delete process.env.NOVITA_API_KEY;
    delete process.env.TEMPEST_MODEL_FALLBACK;
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('resolves the Novita base URL, default model, and key from NOVITA_API_KEY', () => {
    process.env.NOVITA_API_KEY = KEY;
    const cfg = config.getLLMConfig('novita');
    expect(cfg.provider).toBe('novita');
    expect(cfg.baseUrl).toBe('https://api.novita.ai/openai/v1');
    expect(cfg.model).toBe('zai-org/glm-5.2');
    expect(cfg.apiKey).toBe(KEY);
    expect(`${cfg.baseUrl}/chat/completions`).toBe(
      'https://api.novita.ai/openai/v1/chat/completions',
    );
  });

  it('routes through the OpenAI-compatible backbone and validates with a key', () => {
    process.env.NOVITA_API_KEY = KEY;
    const bb = createNovitaBackbone();
    expect(bb.getProvider()).toBe('novita');
    expect(bb.validateConfig().valid).toBe(true);
  });

  it('requires the provider-specific key instead of reporting an OpenAI credential error', () => {
    expect(createNovitaBackbone().validateConfig()).toEqual({
      valid: false,
      error: expect.stringContaining('NOVITA_API_KEY'),
    });
  });

  it('sends chat to the Novita endpoint with Bearer auth and the configured model', async () => {
    const fetchSpy = vi.fn(async (_url: string | URL, _init?: RequestInit) => ({
      ok: true,
      json: async () => ({
        model: 'zai-org/glm-5.2',
        choices: [{ message: { content: 'ok' }, finish_reason: 'stop' }],
      }),
    }));
    global.fetch = fetchSpy as unknown as typeof fetch;

    const response = await createNovitaBackbone(KEY).chat([{ role: 'user', content: 'hello' }]);
    expect(response.content).toBe('ok');
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://api.novita.ai/openai/v1/chat/completions');
    expect((init as RequestInit).headers).toMatchObject({
      Authorization: `Bearer ${KEY}`,
      'Content-Type': 'application/json',
    });
    expect(JSON.parse(String((init as RequestInit).body))).toMatchObject({
      model: 'zai-org/glm-5.2',
      messages: [{ role: 'user', content: 'hello' }],
    });
  });

  it.each([401, 429])('surfaces HTTP %i without silently changing providers', async (status) => {
    const fetchSpy = vi.fn(async (_url: string | URL, _init?: RequestInit) => ({
      ok: false,
      status,
      headers: { get: () => null },
      text: async () => 'provider error',
    }));
    global.fetch = fetchSpy as unknown as typeof fetch;

    await expect(createNovitaBackbone(KEY).chat([{ role: 'user', content: 'hello' }]))
      .rejects.toMatchObject({ status });
    expect(fetchSpy).toHaveBeenCalledTimes(status === 401 ? 1 : 3);
    for (const [url] of fetchSpy.mock.calls) {
      expect(url).toBe('https://api.novita.ai/openai/v1/chat/completions');
    }
  }, 10_000);

  it('keeps cross-provider fallback disabled unless the operator opts in', () => {
    process.env.NOVITA_API_KEY = KEY;
    expect(config.getLLMConfig('novita').fallbackChain).toEqual([]);
  });

  it('publishes a non-empty Novita model catalog and configured provider state', () => {
    process.env.NOVITA_API_KEY = KEY;
    expect(AVAILABLE_MODELS.novita?.length ?? 0).toBeGreaterThan(0);
    expect(config.getConfiguredProviders()).toContain('novita');
  });
});
