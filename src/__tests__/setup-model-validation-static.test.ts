import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

// Static invariants for setup-wizard key validation and the Anthropic wire body.
// The setup wizard used to test new keys against retired models (Anthropic
// claude-sonnet-4-20250514, retired 2026-06-15; OpenAI gpt-4-turbo-preview,
// retired 2026-03-26), so every key failed validation and was never saved. And
// the Anthropic adapter sent `temperature`, which Claude 4.7+ reject (400) on the
// adapter's API version — so even a current model would have failed. These tests
// pin the fixes in place and document the intent.

const setupSource = readFileSync(join(process.cwd(), 'src/setup.ts'), 'utf8');
const configSource = readFileSync(join(process.cwd(), 'src/config/index.ts'), 'utf8');
const llmSource = readFileSync(join(process.cwd(), 'src/llm/index.ts'), 'utf8');

function block(source: string, startMarker: string, endMarker: string): string {
  const start = source.indexOf(startMarker);
  expect(start, `missing marker "${startMarker}"`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf(endMarker, start);
  expect(end, `missing end marker "${endMarker}"`).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe('setup wizard validates keys against current models', () => {
  it('never validates against known-retired model ids', () => {
    expect(setupSource).not.toContain('claude-sonnet-4-20250514');
    expect(setupSource).not.toContain('gpt-4-turbo-preview');
    expect(configSource).not.toContain('gpt-4-turbo-preview');
  });

  it('tests a new Anthropic key with an active model', () => {
    const anthropicSetup = block(setupSource, 'provider: \'anthropic\',', '});');
    expect(anthropicSetup).toContain('claude-sonnet-5-5');
  });

  it('tests a new OpenAI key with an active model', () => {
    const openaiSetup = block(setupSource, 'provider: \'openai\',', '});');
    expect(openaiSetup).toContain('gpt-5.6-sol');
  });
});

describe('Anthropic adapter omits rejected sampling parameters', () => {
  it('does not send temperature/top_p/top_k in the request body', () => {
    const adapter = block(
      llmSource,
      'class AnthropicAdapter implements LLMProviderAdapter {',
      'class OpenAIAdapter implements LLMProviderAdapter {',
    );
    const requestBody = block(adapter, 'const requestBody', ';\n');
    expect(requestBody).not.toContain('temperature');
    expect(requestBody).not.toContain('top_p');
    expect(requestBody).not.toContain('top_k');
  });
});
