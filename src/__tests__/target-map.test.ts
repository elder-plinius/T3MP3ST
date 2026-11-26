import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

describe('Target Map & Attack Plan Engine', () => {
  it('should verify index.html contains the Target Map & Attack Plan card', () => {
    const htmlPath = resolve(__dirname, '../../docs/index.html');
    expect(existsSync(htmlPath)).toBe(true);
    const content = readFileSync(htmlPath, 'utf-8');

    expect(content).toContain('id="targetMapPanel"');
    expect(content).toContain('Target Map & Attack Plan');
    expect(content).toContain('id="targetMapStatsBadge"');
    expect(content).toContain('id="targetMapEpssBadge"');
    expect(content).toContain('id="targetMapSvgCanvas"');
    expect(content).toContain('id="targetMapNodesContainer"');
    expect(content).toContain('id="targetMapPathsContainer"');
    expect(content).toContain('id="targetMapModalOverlay"');
    expect(content).toContain('id="findingHoverTooltip"');
    expect(content).toContain('showFindingAttackTooltip');
    expect(content).toContain('getFindingAttackPlanIntel');
    expect(content).toContain('refreshTargetMap');
    expect(content).toContain('openTargetMapNodeModal');
    expect(content).toContain('drawTargetMapStrings');
    expect(content).toContain('setTargetMapView');
  });

  it('should verify server.ts contains the /api/mission/target-map route', () => {
    const serverPath = resolve(__dirname, '../../src/server.ts');
    expect(existsSync(serverPath)).toBe(true);
    const content = readFileSync(serverPath, 'utf-8');

    expect(content).toContain("app.get('/api/mission/target-map'");
    expect(content).toContain('TargetMapNode');
    expect(content).toContain('TargetMapLink');
    expect(content).toContain('CveCorrelator.correlate');
    expect(content).toContain('attackPaths');
  });
});
