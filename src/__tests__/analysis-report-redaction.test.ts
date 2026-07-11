import { describe, expect, it } from 'vitest';
import { AnalysisEngine } from '../analysis/index.js';
import type { Report } from '../types/index.js';
import { KillChainPhase } from '../types/index.js';

function makeReport(): Report {
  return {
    id: 'report-1',
    missionId: 'mission-1',
    type: 'full_report',
    generatedAt: 123,
    summary: {
      overview: 'Summary includes Bearer summaryabcdefghijklmnop',
      riskRating: 'critical',
      criticalFindings: 1,
      highFindings: 0,
      mediumFindings: 0,
      lowFindings: 0,
      infoFindings: 0,
      successfulExploits: 1,
      credentialsHarvested: 1,
      systemsCompromised: 1,
    },
    findings: [
      {
        id: 'finding-1',
        title: 'Leaked token',
        description: 'Captured Anthropic key sk-ant-api03-ABCDEFGHIJKLMNOP in config',
        severity: 'critical',
        targetId: 'target-1',
        operatorId: 'operator-1',
        phase: KillChainPhase.EXPLOIT,
        evidence: [
          {
            type: 'output',
            content: 'curl -H "Authorization: Bearer evidenceabcdefghijklmnop" https://svc.local',
            timestamp: 123,
          },
        ],
        remediation: 'Rotate token=rawsecretvalue123456 immediately',
        discoveredAt: 123,
      },
    ],
    attackPaths: [
      {
        id: 'path-1',
        name: 'Use https://admin:hunter2@example.test/login',
        description: 'Pivot with Bearer attackpathabcdefghijklmnop',
        steps: ['Replay sk-ant-api03-QRSTUVWXABCDEFGHIJKLMNOP against API'],
        findings: ['finding-1'],
        impactLevel: 'critical',
      },
    ],
    recommendations: [
      {
        id: 'rec-1',
        findingId: 'finding-1',
        priority: 'immediate',
        title: 'Remove API key',
        description: 'Delete api_key=anotherrawsecretvalue from docs',
        effort: 'low',
        impact: 'high',
      },
    ],
  };
}

describe('AnalysisEngine report redaction', () => {
  it('redacts secrets before exporting Markdown reports', () => {
    const engine = Object.create(AnalysisEngine.prototype) as AnalysisEngine;
    const markdown = engine.exportToMarkdown(makeReport());

    for (const raw of [
      'sk-ant-api03-ABCDEFGHIJKLMNOP',
      'Bearer summaryabcdefghijklmnop',
      'Bearer evidenceabcdefghijklmnop',
      'rawsecretvalue123456',
      'hunter2',
      'attackpathabcdefghijklmnop',
      'sk-ant-api03-QRSTUVWXABCDEFGHIJKLMNOP',
      'anotherrawsecretvalue',
    ]) {
      expect(markdown).not.toContain(raw);
    }
    expect(markdown).toContain('[redacted]');
  });
});
