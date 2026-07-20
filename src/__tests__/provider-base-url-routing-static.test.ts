import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

describe('provider base URL routing regression', () => {
  const serverSource = readFileSync(join(process.cwd(), 'src/server.ts'), 'utf8');

  it('propagates the selected provider base URL into general LLM configuration', () => {
    expect(serverSource).toMatch(
      /function resolveGeneralLLMConfig[\s\S]*?baseUrl:\s*baseConfig\.baseUrl,/,
    );
  });

  it('propagates the selected provider base URL into operator execution', () => {
    expect(serverSource).toMatch(
      /function createTempestCommandInstance[\s\S]*?const baseConfig = config\.getLLMConfig\([\s\S]*?baseUrl:\s*baseConfig\.baseUrl,/,
    );
  });
});
