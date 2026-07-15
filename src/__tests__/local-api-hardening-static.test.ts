import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

const serverSource = readFileSync(join(process.cwd(), 'src/server.ts'), 'utf8');
const uiSource = readFileSync(join(process.cwd(), 'docs/index.html'), 'utf8');

function routeBlock(startMarker: string, endMarker: string): string {
  const start = serverSource.indexOf(startMarker);
  expect(start, `missing route marker ${startMarker}`).toBeGreaterThanOrEqual(0);
  const end = serverSource.indexOf(endMarker, start);
  expect(end, `missing end marker ${endMarker}`).toBeGreaterThan(start);
  return serverSource.slice(start, end);
}

describe('local API authorization hardening invariants', () => {
  it('server mission/general routes default to the configured LLM instead of hardcoded OpenRouter', () => {
    const resolver = routeBlock('function resolveGeneralLLMConfig(', '/**\n * Bring a planned mission UP for real');
    const missionRoute = routeBlock("app.post('/api/mission/start'", "app.get('/api/mission/report'");
    const generalRoutes = routeBlock("app.post('/api/general/plan'", '// =============================================================================\n// THE ADMIRAL');

    expect(resolver).toContain('config.getLLMConfig()');
    expect(resolver).toContain('provider || defaultConfig.provider');
    expect(missionRoute).toContain('resolveGeneralLLMConfig(provider, model, apiKey)');
    expect(`${missionRoute}\n${generalRoutes}`).not.toMatch(/provider\s*=\s*['"]openrouter['"]/);
    expect(`${missionRoute}\n${generalRoutes}`).not.toMatch(/model\s*=\s*['"]anthropic\/claude-sonnet-4['"]/);
  });

  it('health and LLM status count keyless local backends as configured', () => {
    const health = routeBlock('function healthPayload()', '// =============================================================================\n// API ENDPOINTS - HEALTH & STATUS');
    const llmStatus = routeBlock("app.get('/api/llm/status'", '// =============================================================================\n// TOOL EXECUTION ENDPOINTS');

    expect(health).toContain('providerRunsKeyless(llmConfig.provider)');
    expect(llmStatus).toContain('providerRunsKeyless(llmConfig.provider)');
  });

  it('War Room no-key/no-agent backend dispatch defers to the server-configured LLM', () => {
    expect(uiSource).toContain("serverLLM: null");
    expect(uiSource).toContain('this.serverLLM = data.llm');
    expect(uiSource).toContain('No browser API key — using the server-configured LLM backend');
    expect(uiSource).toContain('LLM backend: server default — no browser API key sent');
    expect(uiSource).not.toMatch(/let provider = ['"]openrouter['"];\s*\n\s*let model = state\.settings\.selectedModel/);
  });

  it('/api/events does not grant wildcard CORS and rejects foreign browser origins before opening SSE', () => {
    const route = routeBlock("app.get('/api/events'", '// =============================================================================\n// API ENDPOINTS - HEALTH & STATUS');

    expect(route).not.toMatch(/Access-Control-Allow-Origin['"]\s*:\s*['"]\*['"]/);
    expect(route).toMatch(/const\s+origin\s*=\s*_?req\.get\(['"]origin['"]\)/);
    expect(route).toMatch(/origin\s*&&\s*!isLoopbackOrigin\(origin\)/);
    expect(route).toMatch(/Access-Control-Allow-Origin['"]\]\s*=\s*origin/);
  });

  it('/api/tools/execute binds approval to the parsed command target, not a caller-supplied target override', () => {
    const route = routeBlock("app.post('/api/tools/execute'", "app.post('/api/tools/recon'");

    expect(route).not.toMatch(/body\.target\s*\|\|\s*inferCommandTarget\(parsed\)/);
    expect(route).toMatch(/resolveCommandExecutionTarget\(body, parsed\)/);
    expect(route).toMatch(/guardAction\(body,\s*['"]command_execution['"],\s*targetResolution\.target/);
  });

  it('Admiral live launch re-checks every General-produced execution target before mission bring-up', () => {
    const route = routeBlock("app.post('/api/admiral/launch'", '// =============================================================================\n// BOUNTY PLATFORM INTEGRATIONS');

    expect(route).toMatch(/ensureExecTargetsWithinApprovedTarget\(execConfig\.targets, brief\.target\)/);
    expect(route).toMatch(/outOfScopeTargets\.length/);
    expect(route.indexOf('ensureExecTargetsWithinApprovedTarget(execConfig.targets, brief.target)'))
      .toBeLessThan(route.indexOf('bringUpMissionFromPlan(execConfig, generalConfig)'));
  });
});
