import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Some cases below persist provider/model choices and an API key, so this file binds the
// config singleton to a throwaway T3MP3ST_CONFIG_DIR instead of the operator's real store.
// Its env file also exercises LLM_PROVIDER=abliteratedllm loading.
const ISOLATED_ENV = [
  'T3MP3ST_CONFIG_DIR',
  'ABLITERATEDLLM_API_KEY',
  'LLM_PROVIDER',
  'TEMPEST_DEFAULT_PROVIDER',
  'TEMPEST_MODEL_FALLBACK',
] as const;
const savedEnv = new Map(ISOLATED_ENV.map((name) => [name, process.env[name]]));
for (const name of ISOLATED_ENV) delete process.env[name];
const configDir = mkdtempSync(join(tmpdir(), 't3mp3st-abliteratedllm-'));
writeFileSync(join(configDir, '.env'), 'LLM_PROVIDER=abliteratedllm\n');
process.env.T3MP3ST_CONFIG_DIR = configDir;

// Dynamic on purpose: a static import would construct the config singleton (and read env
// files) before the isolation above runs.
const { AVAILABLE_MODELS, config } = await import('../config/index.js');
const { LLMBackbone, classifyErrorKind, createAbliteratedLLMBackbone } = await import('../llm/index.js');

const KEY = 'abliteratedllm-test-key-0123456789';
const BASE_URL = 'https://api.abliteratedllm.dev/v1';
const CHAT_URL = `${BASE_URL}/chat/completions`;
const CYBER = 'glm-5.3-cyber-abliterated';
const FLASH = 'glm-5.3-flash-abliterated';
const HELLO = [{ role: 'user' as const, content: 'hello' }];

async function rejection(run: () => Promise<unknown>): Promise<Error> {
  try {
    await run();
  } catch (error) {
    if (error instanceof Error) return error;
    throw error;
  }
  throw new Error('expected the chat call to reject');
}

describe('AbliteratedLLM provider wiring', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    delete process.env.ABLITERATEDLLM_API_KEY;
    delete process.env.TEMPEST_MODEL_FALLBACK;
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  afterAll(() => {
    for (const [name, value] of savedEnv) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    rmSync(configDir, { recursive: true, force: true });
  });

  it('loads LLM_PROVIDER=abliteratedllm and resolves the base URL, cyber default model, and ABLITERATEDLLM_API_KEY', () => {
    process.env.ABLITERATEDLLM_API_KEY = KEY;
    const cfg = config.getLLMConfig();
    expect(cfg.provider).toBe('abliteratedllm');
    expect(cfg.baseUrl).toBe(BASE_URL);
    expect(cfg.model).toBe(CYBER);
    expect(cfg.apiKey).toBe(KEY);
    expect(`${cfg.baseUrl}/chat/completions`).toBe(CHAT_URL);
  });

  it('publishes the cyber default and the lower-cost flash model, and reports configured state from the key', () => {
    expect(AVAILABLE_MODELS.abliteratedllm.map((model) => model.id)).toEqual([CYBER, FLASH]);
    for (const model of AVAILABLE_MODELS.abliteratedllm) {
      expect(model).toMatchObject({ provider: 'AbliteratedLLM', contextWindow: 1048576, maxOutput: 131072 });
    }
    expect(config.getConfiguredProviders()).not.toContain('abliteratedllm');
    process.env.ABLITERATEDLLM_API_KEY = KEY;
    expect(config.getConfiguredProviders()).toContain('abliteratedllm');
  });

  it('requires ABLITERATEDLLM_API_KEY instead of reporting an OpenAI credential error', () => {
    const bb = createAbliteratedLLMBackbone();
    expect(bb.getProvider()).toBe('abliteratedllm');
    expect(bb.validateConfig()).toEqual({
      valid: false,
      error: expect.stringContaining('ABLITERATEDLLM_API_KEY'),
    });
  });

  it.each([
    ['the default cyber model', undefined, CYBER],
    ['the lower-cost flash model', FLASH, FLASH],
  ])('sends chat for %s to the AbliteratedLLM endpoint with Bearer auth', async (_label, requested, expected) => {
    const fetchSpy = vi.fn(async (_url: string | URL, _init?: RequestInit) => ({
      ok: true,
      json: async () => ({
        model: expected,
        choices: [{ message: { content: 'ok' }, finish_reason: 'stop' }],
        usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
      }),
    }));
    global.fetch = fetchSpy as unknown as typeof fetch;

    const response = await createAbliteratedLLMBackbone(KEY, requested).chat(HELLO);
    expect(response).toMatchObject({ content: 'ok', model: expected, usage: { totalTokens: 4 } });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe(CHAT_URL);
    expect(init).toMatchObject({
      method: 'POST',
      headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' },
    });
    expect(JSON.parse(String(init?.body))).toMatchObject({
      model: expected,
      messages: [{ role: 'user', content: 'hello' }],
    });
  });

  it('surfaces HTTP 401 once as an auth error, without retrying or changing providers', async () => {
    const fetchSpy = vi.fn(async (_url: string | URL, _init?: RequestInit) => ({
      ok: false,
      status: 401,
      headers: { get: () => null },
      text: async () => 'invalid api key',
    }));
    global.fetch = fetchSpy as unknown as typeof fetch;

    const error = await rejection(() => createAbliteratedLLMBackbone(KEY).chat(HELLO));
    expect(error).toMatchObject({ status: 401 });
    expect(classifyErrorKind(error)).toBe('auth');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy.mock.calls[0][0]).toBe(CHAT_URL);
  });

  it('retries HTTP 429 in place, keeps Retry-After, and then surfaces the rate limit', async () => {
    const fetchSpy = vi.fn(async (_url: string | URL, _init?: RequestInit) => ({
      ok: false,
      status: 429,
      headers: { get: (name: string) => (name.toLowerCase() === 'retry-after' ? '1' : null) },
      text: async () => 'no serving capacity',
    }));
    global.fetch = fetchSpy as unknown as typeof fetch;

    const error = await rejection(() => createAbliteratedLLMBackbone(KEY).chat(HELLO));
    expect(error).toMatchObject({ status: 429, retryAfterMs: 1000 });
    expect(classifyErrorKind(error)).toBe('rate_limit');
    expect(fetchSpy).toHaveBeenCalledTimes(3);
    for (const [url] of fetchSpy.mock.calls) expect(url).toBe(CHAT_URL);
  }, 10_000);

  it('aborts a stalled request at the configured timeout and surfaces it as a timeout', async () => {
    const fetchSpy = vi.fn((_url: string | URL, init?: RequestInit) => new Promise<never>((_resolve, reject) => {
      const signal = init?.signal;
      if (!signal) {
        reject(new Error('request was sent without an abort signal'));
        return;
      }
      signal.addEventListener('abort', () => reject(signal.reason), { once: true });
    }));
    global.fetch = fetchSpy as unknown as typeof fetch;

    const backbone = new LLMBackbone({ ...config.getLLMConfig('abliteratedllm'), apiKey: KEY, timeout: 25 });
    const error = await rejection(() => backbone.chat(HELLO));
    expect(error.name).toBe('TimeoutError');
    expect(classifyErrorKind(error)).toBe('timeout');
    expect(fetchSpy).toHaveBeenCalledTimes(3);
    for (const [url] of fetchSpy.mock.calls) expect(url).toBe(CHAT_URL);
  }, 10_000);

  it('rejects a malformed 200 body instead of reporting a completion', async () => {
    const fetchSpy = vi.fn(async (_url: string | URL, _init?: RequestInit) => ({
      ok: true,
      json: async () => ({ object: 'error' }),
    }));
    global.fetch = fetchSpy as unknown as typeof fetch;

    await expect(createAbliteratedLLMBackbone(KEY).chat(HELLO)).rejects.toThrow();
    expect(fetchSpy).toHaveBeenCalledTimes(3);
    for (const [url] of fetchSpy.mock.calls) expect(url).toBe(CHAT_URL);
  }, 10_000);

  it('keeps cross-provider fallback off unless the operator opts in, then offers AbliteratedLLM as a hop', () => {
    process.env.ABLITERATEDLLM_API_KEY = KEY;
    expect(config.getLLMConfig('abliteratedllm').fallbackChain).toEqual([]);
    expect(config.getLLMConfig('mock').fallbackChain).toEqual([]);

    process.env.TEMPEST_MODEL_FALLBACK = '1';
    expect(config.getLLMConfig('abliteratedllm').fallbackChain?.map((hop) => hop.provider))
      .not.toContain('abliteratedllm');
    expect(config.getLLMConfig('mock').fallbackChain).toContainEqual({
      provider: 'abliteratedllm',
      model: CYBER,
      apiKey: KEY,
      baseUrl: BASE_URL,
    });
  });

  it('persists the default provider and model so the lower-cost model can be selected', () => {
    try {
      config.setDefaultProvider('abliteratedllm');
      expect(config.get('defaultProvider')).toBe('abliteratedllm');
      expect(config.get('defaultModel')).toBe(CYBER);

      config.setDefaultModel('abliteratedllm', FLASH);
      expect(config.get('abliteratedllm').defaultModel).toBe(FLASH);
      expect(config.get('defaultModel')).toBe(FLASH);
      expect(config.getLLMConfig('abliteratedllm').model).toBe(FLASH);
    } finally {
      config.setDefaultModel('abliteratedllm', CYBER);
    }
  });

  it('redacts a stored key on export and documents ABLITERATEDLLM_API_KEY in the env template', () => {
    const exportPath = join(configDir, 'export.json');
    const templatePath = join(configDir, 'env.template');
    config.setApiKey('abliteratedllm', KEY);
    try {
      config.exportConfig(exportPath);
      const exported = readFileSync(exportPath, 'utf8');
      expect(exported).not.toContain(KEY);
      expect(JSON.parse(exported)).toMatchObject({ apiKeys: { abliteratedllm: '***REDACTED***' } });
    } finally {
      config.removeApiKey('abliteratedllm');
    }

    config.createEnvTemplate(templatePath);
    expect(readFileSync(templatePath, 'utf8')).toContain('ABLITERATEDLLM_API_KEY=');
  });

  it('offers AbliteratedLLM in the browser Universal API Config with its canonical base URL', () => {
    const ui = readFileSync(join(process.cwd(), 'docs/index.html'), 'utf8');
    expect(ui).toContain('<option value="abliteratedllm">AbliteratedLLM · OpenAI-compatible</option>');
    expect(ui).toContain(`abliteratedllm: '${BASE_URL}'`);
  });
});
