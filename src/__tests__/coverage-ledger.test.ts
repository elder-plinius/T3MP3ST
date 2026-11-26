import { describe, expect, it } from 'vitest';
import { coverageReport } from '../coverage-ledger/index.js';
import type { AssetNode } from '../asset-graph/types.js';
import type { InvestigationAnchor } from '../investigation/types.js';

const app: AssetNode = { id: 'a1', kind: 'host', name: 'app.example' };

describe('coverage ledger', () => {
  it('marks an anchored scope name tested and a missing ledger name untested', () => {
    const anchors: InvestigationAnchor[] = [{ nodeId: 'i1', assetId: 'a1' }];
    const report = coverageReport([app], anchors, ['app.example', 'other.example']);
    expect(report).toEqual({
      ok: true,
      tested: 1,
      untested: 1,
      rows: [
        { name: 'app.example', status: 'tested' },
        { name: 'other.example', status: 'untested' },
      ],
    });
    expect(report).not.toHaveProperty('layout');
  });

  it('marks every scope name untested when nothing is anchored', () => {
    const report = coverageReport([], [], ['app.example', 'lonely.example']);
    expect(report.ok).toBe(true);
    if (report.ok) {
      expect(report.untested).toBe(2);
      expect(report.rows.every((row) => row.status === 'untested')).toBe(true);
    }
  });

  it('fails when an anchor cites an unknown asset', () => {
    const report = coverageReport([app], [{ nodeId: 'i1', assetId: 'missing' }], ['app.example']);
    expect(report.ok).toBe(false);
    if (!report.ok) expect(report.reason).toMatch(/missing/);
  });
});
