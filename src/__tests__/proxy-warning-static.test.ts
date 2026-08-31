import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

describe('SOCKS / Proxy Offline Warning on Scan Start', () => {
  const root = process.cwd();

  it('server.ts checks getProxyStatus() on mission start and adds opsec warning when proxy is offline', () => {
    const serverSrc = readFileSync(join(root, 'src', 'server.ts'), 'utf8');
    const startRouteIdx = serverSrc.indexOf("app.post('/api/mission/start'");
    expect(startRouteIdx).toBeGreaterThan(0);
    const endRouteIdx = serverSrc.indexOf("app.post('/api/whitebox/analyze'", startRouteIdx);
    expect(endRouteIdx).toBeGreaterThan(startRouteIdx);
    const startRouteBody = serverSrc.slice(startRouteIdx, endRouteIdx);

    expect(startRouteBody).toContain('getProxyStatus()');
    expect(startRouteBody).toContain('proxyStatus.enabled');
    expect(startRouteBody).toContain('proxyActive');
    expect(startRouteBody).toContain('opsecWarning');
  });

  it('docs/index.html warns when a scan/mission is started with proxy offline', () => {
    const indexSrc = readFileSync(join(root, 'docs', 'index.html'), 'utf8');
    expect(indexSrc).toContain('startMissionFromDashboard');
    expect(indexSrc).toMatch(/_isProxyActive|_lastEgressCheck/);
    expect(indexSrc).toMatch(/OPSEC Warning.*proxy|SOCKS proxy is offline/i);
  });
});
