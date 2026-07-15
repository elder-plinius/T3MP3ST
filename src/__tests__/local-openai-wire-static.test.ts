import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

// Static invariants for the `local` provider. Two real OpenAI-compatible servers
// broke against the old code: (1) the wire detector only matched a literal /v1, so
// versioned paths like Zhipu/z.ai's /api/paas/v4 silently fell through to the
// Ollama native format and failed; (2) the provider was treated as always-keyless,
// so servers that require a bearer (Zhipu, Together, …) could never authenticate.
// These tests pin the fixes in place and document the intent.

const llmSource = readFileSync(join(process.cwd(), 'src/llm/index.ts'), 'utf8');
const configSource = readFileSync(join(process.cwd(), 'src/config/index.ts'), 'utf8');

function block(source: string, startMarker: string, endMarker: string): string {
  const start = source.indexOf(startMarker);
  expect(start, `missing marker "${startMarker}"`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf(endMarker, start);
  expect(end, `missing end marker "${endMarker}"`).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe('local OpenAI-compatible provider hardening', () => {
  it('isOpenAIWire detects ANY versioned path (/v1, /v4, …), not only /v1', () => {
    const fn = block(
      llmSource,
      'private isOpenAIWire(baseUrl: string): boolean {',
      '\n  }',
    );

    // Must be version-agnostic: a digit class, not a literal `1`.
    expect(fn).toMatch(/v\\d\+/);
    // No literal-/v1-only form must remain.
    expect(fn).not.toMatch(/\/v1\(/);
  });

  it('getLLMConfig forwards an optional bearer for local servers that require auth', () => {
    const localCase = block(configSource, "case 'local':", 'break;');

    expect(localCase).toContain('TEMPEST_LOCAL_API_KEY');
    // Provider-specific aliases are accepted as a convenience.
    expect(localCase).toMatch(/ZAI_API_KEY/);
    expect(localCase).toMatch(/ZHIPUAI_API_KEY/);
  });

  it('getLLMConfig treats UI local placeholders as unset model names', () => {
    const localCase = block(configSource, "case 'local':", 'break;');

    expect(localCase).toContain('local-model');
    expect(localCase).toContain('local/ollama');
    expect(localCase).toContain('TEMPEST_LOCAL_MODEL');
  });

  it('getApiKey resolves a local key from env without persisting it', () => {
    // The local key is read in-memory from env, matching the env-key hardening
    // invariant (env keys are never written to the store).
    const getApiKey = block(configSource, 'getApiKey(provider:', 'envVarMap');

    expect(getApiKey).toContain("provider === 'local'");
    expect(getApiKey).toContain('TEMPEST_LOCAL_API_KEY');
  });

  it('the local key slot is part of the typed apiKeys store', () => {
    expect(configSource).toMatch(/local\?:\s*string;/);
  });

  it('the env template documents the local provider options', () => {
    const template = block(configSource, 'createEnvTemplate(', '`;');

    expect(template).toContain('TEMPEST_LOCAL_BASE_URL');
    expect(template).toContain('TEMPEST_LOCAL_MODEL');
    expect(template).toContain('TEMPEST_LOCAL_API_KEY');
  });
});
