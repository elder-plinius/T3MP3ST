import { describe, it, expect } from 'vitest';
import { ChainSummarizer } from '../llm/csum.js';
import { ToolcallRepairer } from '../llm/repair.js';
import { AgentReflector } from '../agent/reflector.js';

describe('PentAGI Ported Subsystems', () => {
  describe('ChainSummarizer (csum)', () => {
    it('preserves small message histories intact', () => {
      const summarizer = new ChainSummarizer({ triggerTokenThreshold: 1000 });
      const msgs: any[] = [
        { role: 'system', content: 'You are T3MP3ST.' },
        { role: 'user', content: 'Scan target.' },
        { role: 'assistant', content: 'Scanning port 80.' }
      ];
      const res = summarizer.compress(msgs);
      expect(res.length).toBe(3);
    });

    it('summarizes older rounds when exceeding token threshold while preserving system message', () => {
      const summarizer = new ChainSummarizer({ triggerTokenThreshold: 50, activeWindowMaxBytes: 200 });
      const msgs: any[] = [
        { role: 'system', content: 'You are T3MP3ST security intelligence agent.' },
        { role: 'user', content: 'A'.repeat(300) },
        { role: 'assistant', content: 'B'.repeat(300) },
        { role: 'user', content: 'C'.repeat(300) },
        { role: 'assistant', content: 'Recent response.' }
      ];
      const res = summarizer.compress(msgs);
      expect(res.length).toBeLessThan(msgs.length);
      expect(res[0].role).toBe('system');
      expect(res[1].content).toContain('[T3MP3ST Context Summary]');
    });
  });

  describe('ToolcallRepairer', () => {
    it('repairs JSON with single quotes and unquoted keys', () => {
      const malformed = "{ tool: 'sploitus', query: 'MariaDB 10.3', }";
      const repaired = ToolcallRepairer.repairJSON(malformed);
      expect(repaired.tool).toBe('sploitus');
      expect(repaired.query).toBe('MariaDB 10.3');
    });

    it('extracts tool calls enclosed in markdown code blocks', () => {
      const llmOutput = "I will query the exploit database now:\n```json\n{\n  \"tool\": \"sploitus\",\n  \"args\": {\n    \"query\": \"CVE-2021-44228\"\n  }\n}\n```\nPlease stand by.";
      const calls = ToolcallRepairer.extractToolCalls(llmOutput);
      expect(calls.length).toBe(1);
      expect(calls[0].name).toBe('sploitus');
      expect(calls[0].args.query).toBe('CVE-2021-44228');
    });
  });

  describe('AgentReflector', () => {
    it('detects goal achievement on flag patterns', () => {
      const verdict = AgentReflector.reflect({
        target: 'localhost:8080',
        goal: 'Capture the flag',
        lastCommand: 'nc localhost 8080',
        output: 'Welcome! Flag is T3MP3ST{example_solve_123}'
      });
      expect(verdict.assessment).toBe('goal_achieved');
      expect(verdict.identifiedArtifacts).toContain('T3MP3ST{example_solve_123}');
    });

    it('detects dead ends on connection refusal', () => {
      const verdict = AgentReflector.reflect({
        target: '192.168.1.50',
        goal: 'Enumerate services',
        lastCommand: 'curl http://192.168.1.50:8080',
        output: 'curl: (7) Failed to connect: Connection refused'
      });
      expect(verdict.assessment).toBe('dead_end');
      expect(verdict.suggestedAction).toContain('Pivot');
    });
  });
});
