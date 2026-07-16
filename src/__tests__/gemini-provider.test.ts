import { describe, expect, it } from 'vitest';
import { config, AVAILABLE_MODELS } from '../config/index.js';

// Regression coverage for #52: native Google Gemini support.
// The engine dispatches Gemini through OpenAIAdapter, which posts to
// `${baseUrl}/chat/completions`. Gemini's OpenAI-compatible surface lives under
// /v1beta/openai, so the base URL MUST carry that path segment — the single most
// important thing to get right, and the exact detail an earlier attempt missed.
describe('Gemini native provider wiring (#52)', () => {
  it('routes gemini through the OpenAI-compatible endpoint including the /openai segment', () => {
    const cfg = config.getLLMConfig('gemini');
    expect(cfg.provider).toBe('gemini');
    expect(cfg.baseUrl).toBe('https://generativelanguage.googleapis.com/v1beta/openai');
    // Guard the regression directly: `${baseUrl}/chat/completions` must resolve under /v1beta/openai.
    expect(`${cfg.baseUrl}/chat/completions`).toBe(
      'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions',
    );
  });

  it('defaults to a bare native Gemini model id (no google/ prefix)', () => {
    const cfg = config.getLLMConfig('gemini');
    expect(cfg.model).toBe('gemini-2.5-flash');
    expect(cfg.model.startsWith('google/')).toBe(false);
  });

  it('publishes a non-empty native Gemini model catalog with bare ids', () => {
    expect(AVAILABLE_MODELS.gemini?.length ?? 0).toBeGreaterThan(0);
    for (const m of AVAILABLE_MODELS.gemini) {
      expect(m.id.startsWith('google/')).toBe(false);
    }
  });

  it('maps the gemini provider to the GEMINI_API_KEY environment variable', () => {
    const prev = process.env.GEMINI_API_KEY;
    process.env.GEMINI_API_KEY = 'test-gemini-key-0123456789';
    try {
      expect(config.hasApiKey('gemini')).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.GEMINI_API_KEY;
      else process.env.GEMINI_API_KEY = prev;
    }
  });
});
