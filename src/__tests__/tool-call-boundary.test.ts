import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { enforceToolCallBoundary, reflectStrategy, ToolCallBoundaryError } from '../llm/tool-call-boundary.js';
import type { LLMToolDefinition } from '../types/index.js';

const tools: LLMToolDefinition[] = [{
  name: 'http_probe', description: 'Probe an authorized URL',
  parameters: {
    type: 'object', required: ['url'],
    properties: { url: { type: 'string' }, timeout: { type: 'number' } },
  },
}];

describe('tool-call repair boundary', () => {
  it('repairs only trailing commas and preserves supplied arguments', () => {
    const result = enforceToolCallBoundary('```json\n{"tool_calls":[{"name":"http_probe","arguments":{"url":"https://lab",}},]}\n```', tools);
    expect(result.calls).toEqual([{ id: expect.stringMatching(/^repaired_/), name: 'http_probe', arguments: { url: 'https://lab' } }]);
  });

  it('decodes a JSON-encoded argument object without filling missing fields', () => {
    const result = enforceToolCallBoundary('{"tool_calls":[{"name":"http_probe","arguments":"{\\"url\\":\\"https://lab\\",}"}]}', tools);
    expect(result.calls?.[0].arguments).toEqual({ url: 'https://lab' });
  });

  it('treats ordinary prose as a final response rather than an invalid call', () => {
    expect(enforceToolCallBoundary('Testing is complete; no further action.', tools)).toEqual({ attempted: false });
  });

  it.each([
    ['```json\n{"tool_calls":[}\n```', 'malformed JSON'],
    ['{"tool_calls":[{"name":"shell","arguments":{}}]}', 'unknown tool'],
    ['{"tool_calls":[{"name":"http_probe","arguments":{}}]}', 'url is required'],
    ['{"tool_calls":[{"name":"http_probe","arguments":{"url":"https://lab","authorization":true}}]}', 'authorization is not allowed'],
    ['{"tool_calls":[{"name":"http_probe","arguments":{"url":"https://lab"}},{"name":"http_probe","arguments":{"url":"https://lab"}}]}', 'duplicates'],
    ['{"tool_calls":[{"name":"http_probe","arguments":{"url":"https://lab","timeout":"invent-me"}}]}', 'timeout must be a number'],
  ])('fails closed with an observable error: %s', (input, message) => {
    expect(() => enforceToolCallBoundary(input, tools)).toThrowError(expect.objectContaining({ name: 'ToolCallBoundaryError', message: expect.stringContaining(message) }));
  });

  it('rejects hostile oversized content before parsing', () => {
    expect(() => enforceToolCallBoundary(`{"name":"http_probe"}${'x'.repeat(1_000_000)}`, tools)).toThrow(ToolCallBoundaryError);
  });

  it('is wired inside text adapters so boundary errors enter the bounded retry loop', () => {
    const source = readFileSync(new URL('../llm/index.ts', import.meta.url), 'utf8');
    expect(source.match(/enforceToolCallBoundary\([^;]+/g)?.length).toBe(3);
    expect(source).toContain('for (let attempt = 1; attempt <= this.retryAttempts; attempt++)');
    expect(source).toContain("this.emit('request:retry'");
  });

  it('is wired into anti-stall handling as an advisory event', () => {
    const source = readFileSync(new URL('../agent/index.ts', import.meta.url), 'utf8');
    expect(source).toContain("this.emit('agent:reflection'");
    expect(source).toContain('all scope, approval, receipt, budget, and evidence gates still apply');
  });
});

describe('strategic reflection boundary', () => {
  it('can recommend a pivot but cannot execute or alter authority and evidence gates', () => {
    const boundary = { scope: ['lab.local'], approvedTools: ['http_probe'], approvalsRequired: true, receiptsRequired: true, evidenceRequired: true, remainingIterations: 4, remainingTokens: 1200 };
    const result = reflectStrategy({ successful: false, duplicate: true, attempts: 2, maxAttempts: 3, proposedTool: 'shell', proposedTarget: 'outside.example', boundary });

    expect(result).toMatchObject({ assessment: 'stalled', mayExecute: false, requiresApproval: true, boundary });
    expect(result.boundary).not.toBe(boundary);
    expect(result.boundary.scope).not.toBe(boundary.scope);
  });

  it('reports retry exhaustion without manufacturing success or authority', () => {
    const result = reflectStrategy({ successful: false, duplicate: false, attempts: 3, maxAttempts: 3, boundary: { scope: [], approvedTools: [], approvalsRequired: true, receiptsRequired: true, evidenceRequired: true, remainingIterations: 0, remainingTokens: 0 } });
    expect(result).toMatchObject({ assessment: 'retry-exhausted', mayExecute: false, requiresApproval: false });
  });
});
