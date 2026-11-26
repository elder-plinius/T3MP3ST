import { afterEach, describe, expect, it } from 'vitest';
import { config, AVAILABLE_MODELS } from '../config/index.js';
import { createOllamaBackbone } from '../llm/index.js';
import { listProviderModels } from '../config/provider-models.js';

const PREV_BASE = process.env.OLLAMA_BASE_URL;
const PREV_MODEL = process.env.OLLAMA_MODEL;
const PREV_KEY = process.env.OLLAMA_API_KEY;
const PREV_LOCAL_BASE = process.env.TEMPEST_LOCAL_BASE_URL;
const PREV_LOCAL_MODEL = process.env.TEMPEST_LOCAL_MODEL;

function restore(v: string | undefined, name: string) {
  if (v === undefined) delete process.env[name];
  else process.env[name] = v;
}

describe('Ollama provider wiring (issue #164)', () => {
  afterEach(() => {
    restore(PREV_BASE, 'OLLAMA_BASE_URL');
    restore(PREV_MODEL, 'OLLAMA_MODEL');
    restore(PREV_KEY, 'OLLAMA_API_KEY');
    restore(PREV_LOCAL_BASE, 'TEMPEST_LOCAL_BASE_URL');
    restore(PREV_LOCAL_MODEL, 'TEMPEST_LOCAL_MODEL');
  });

  it('resolves from OLLAMA_BASE_URL / OLLAMA_MODEL with keyless defaults', () => {
    process.env.OLLAMA_BASE_URL = 'http://127.0.0.1:11434/api';
    process.env.OLLAMA_MODEL = 'gemma4:latest';
    delete process.env.OLLAMA_API_KEY;

    const cfg = config.getLLMConfig('ollama');
    expect(cfg.provider).toBe('ollama');
    expect(cfg.baseUrl).toBe('http://127.0.0.1:11434/api');
    expect(cfg.model).toBe('gemma4:latest');
    expect(cfg.apiKey).toBeUndefined();
    // Local-class timeout floor applies to ollama too.
    expect(cfg.timeout).toBeGreaterThanOrEqual(120000);
  });

  it('defaults to the local Ollama daemon when no env is set', () => {
    delete process.env.OLLAMA_BASE_URL;
    delete process.env.OLLAMA_MODEL;
    delete process.env.OLLAMA_API_KEY;
    delete process.env.TEMPEST_LOCAL_BASE_URL;
    delete process.env.TEMPEST_LOCAL_MODEL;
    const cfg = config.getLLMConfig('ollama');
    expect(cfg.baseUrl).toBe('http://localhost:11434/api');
    expect(cfg.model).toBe('llama3');
  });

  it('falls back to the generic TEMPEST_LOCAL_* vars when the OLLAMA_* vars are unset', () => {
    delete process.env.OLLAMA_BASE_URL;
    delete process.env.OLLAMA_MODEL;
    process.env.TEMPEST_LOCAL_BASE_URL = 'http://192.168.1.50:11434/api';
    process.env.TEMPEST_LOCAL_MODEL = 'qwen3.6:23b';
    const cfg = config.getLLMConfig('ollama');
    expect(cfg.baseUrl).toBe('http://192.168.1.50:11434/api');
    expect(cfg.model).toBe('qwen3.6:23b');
  });

  it('explicit OLLAMA_* env beats the generic local vars', () => {
    process.env.OLLAMA_BASE_URL = 'http://10.0.0.9:11434/api';
    process.env.OLLAMA_MODEL = 'llama3';
    process.env.TEMPEST_LOCAL_BASE_URL = 'http://192.168.1.50:11434/api';
    process.env.TEMPEST_LOCAL_MODEL = 'qwen3.6:23b';
    const cfg = config.getLLMConfig('ollama');
    expect(cfg.baseUrl).toBe('http://10.0.0.9:11434/api');
    expect(cfg.model).toBe('llama3');
  });

  it('the local provider also honors OLLAMA_* env as a fallback alias', () => {
    delete process.env.TEMPEST_LOCAL_BASE_URL;
    delete process.env.TEMPEST_LOCAL_MODEL;
    process.env.OLLAMA_BASE_URL = 'http://10.0.0.9:11434/api';
    process.env.OLLAMA_MODEL = 'gemma4:latest';
    const cfg = config.getLLMConfig('local');
    expect(cfg.baseUrl).toBe('http://10.0.0.9:11434/api');
    expect(cfg.model).toBe('gemma4:latest');
  });

  it('is advertised as a configured provider and has a static catalog entry', () => {
    expect(config.getConfiguredProviders()).toContain('ollama');
    expect(AVAILABLE_MODELS.ollama?.length ?? 0).toBeGreaterThan(0);
    expect(AVAILABLE_MODELS.ollama[0].provider).toBe('Ollama');
  });

  it('builds a backbone through the LocalAdapter wire protocol', () => {
    const backbone = createOllamaBackbone();
    expect(backbone.getProvider()).toBe('ollama');
    expect(backbone.validateConfig().valid).toBe(true);
  });

  it('model enumeration uses Ollama native /api/tags, tolerating base with or without /api', async () => {
    const calls: string[] = [];
    const f = (url: string, _init?: { headers?: Record<string, string>; signal?: AbortSignal }) => {
      calls.push(url);
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({ models: [{ name: 'llama3' }, { name: 'gemma4:latest' }] }),
      });
    };

    const bare = await listProviderModels('ollama', { baseUrl: 'http://localhost:11434', fetchImpl: f });
    expect(calls[0]).toBe('http://localhost:11434/api/tags');
    expect(bare.map((m) => m.id)).toEqual(['llama3', 'gemma4:latest']);

    const apiForm = await listProviderModels('ollama', { baseUrl: 'http://localhost:11434/api', fetchImpl: f });
    expect(calls[1]).toBe('http://localhost:11434/api/tags');
    expect(apiForm.length).toBe(2);
  });
});
