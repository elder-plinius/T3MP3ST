import { describe, expect, it, afterEach } from 'vitest';
import { config, AVAILABLE_MODELS } from '../config/index.js';
import { createHuggingFaceBackbone } from '../llm/index.js';

const KEY = 'hf_abcdef1234567890';

// Hugging Face serves open models through its OpenAI-compatible Inference Providers
// router. The engine dispatches it through OpenAIAdapter, which posts to
// `${baseUrl}/chat/completions`, so the base URL MUST end at /v1 →
// https://router.huggingface.co/v1/chat/completions.
describe('HuggingFace provider wiring', () => {
  afterEach(() => {
    delete process.env.HF_TOKEN;
    delete process.env.HUGGINGFACE_API_KEY;
    delete process.env.HUGGINGFACE_TOKEN;
  });

  it('resolves the HF router base URL, default model, and key from HF_TOKEN', () => {
    process.env.HF_TOKEN = KEY;
    const cfg = config.getLLMConfig('huggingface');
    expect(cfg.provider).toBe('huggingface');
    expect(cfg.baseUrl).toBe('https://router.huggingface.co/v1');
    expect(cfg.model).toBe('meta-llama/Llama-3.3-70B-Instruct');
    expect(cfg.apiKey).toBe(KEY);
  });

  it('routes `${baseUrl}/chat/completions` under the OpenAI-compatible /v1 router', () => {
    const cfg = config.getLLMConfig('huggingface');
    expect(`${cfg.baseUrl}/chat/completions`).toBe(
      'https://router.huggingface.co/v1/chat/completions',
    );
  });

  it('accepts HUGGINGFACE_API_KEY and HUGGINGFACE_TOKEN as aliases for HF_TOKEN', () => {
    process.env.HUGGINGFACE_API_KEY = KEY;
    expect(config.hasApiKey('huggingface')).toBe(true);
    delete process.env.HUGGINGFACE_API_KEY;

    process.env.HUGGINGFACE_TOKEN = KEY;
    expect(config.hasApiKey('huggingface')).toBe(true);
  });

  it('routes through the OpenAI-compatible backbone and validates with a key', () => {
    process.env.HF_TOKEN = KEY;
    const bb = createHuggingFaceBackbone();
    expect(bb.getProvider()).toBe('huggingface');
    expect(bb.validateConfig().valid).toBe(true);
  });

  it('publishes full HF repo-id models and surfaces configured provider state', () => {
    process.env.HF_TOKEN = KEY;
    const ids = AVAILABLE_MODELS.huggingface?.map(m => m.id) ?? [];
    expect(ids.length).toBeGreaterThan(0);
    expect(ids).toContain('meta-llama/Llama-3.3-70B-Instruct');
    // HF ids are the full `org/repo` slug — must carry a slash, unlike bare native ids.
    for (const id of ids) expect(id).toContain('/');
    expect(config.getConfiguredProviders()).toContain('huggingface');
  });
});
