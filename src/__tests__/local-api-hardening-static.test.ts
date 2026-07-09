import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

const serverSource = readFileSync(join(process.cwd(), 'src/server.ts'), 'utf8');

function routeBlock(startMarker: string, endMarker: string): string {
  const start = serverSource.indexOf(startMarker);
  expect(start, `missing route marker ${startMarker}`).toBeGreaterThanOrEqual(0);
  const end = serverSource.indexOf(endMarker, start);
  expect(end, `missing end marker ${endMarker}`).toBeGreaterThan(start);
  return serverSource.slice(start, end);
}

describe('local API authorization hardening invariants', () => {
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
