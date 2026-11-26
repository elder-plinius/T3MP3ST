/**
 * ChainAST Tests
 *
 * Pentagi pkg/cast port: section parsing (system/human headers), body pairs
 * (request-response / completion / summarization), tool-call matching, force
 * repair, ID normalization, size accounting, and round-trip stability.
 */

import { describe, it, expect } from 'vitest';
import {
  ChainAST,
  newChainAST,
  sectionSize,
  sanitizeJSONControlChars,
  SUMMARIZATION_TOOL_NAME,
  FALLBACK_RESPONSE_CONTENT,
} from '../llm/chain-ast.js';
import type { LLMMessage } from '../types/index.js';

function sys(content: string): LLMMessage {
  return { role: 'system', content };
}
function human(content: string): LLMMessage {
  return { role: 'user', content };
}
function ai(content: string, toolCalls?: LLMMessage['toolCalls']): LLMMessage {
  return { role: 'assistant', content, toolCalls };
}
function tool(callId: string, name: string, content: string): LLMMessage {
  return { role: 'tool', content, toolCallId: callId, name };
}
function call(id: string, name = 'port_scan', args: Record<string, unknown> = { target: 'x' }) {
  return { id, name, arguments: args };
}

describe('newChainAST parsing', () => {
  it('parses a basic conversation into one section with header + pairs', () => {
    const chain = [
      sys('you are a scanner'),
      human('scan 10.0.0.1'),
      ai('running scan', [call('c1')]),
      tool('c1', 'port_scan', '80 open'),
      ai('found port 80'),
    ];
    const ast = newChainAST(chain);
    expect(ast.sections).toHaveLength(1);
    expect(ast.sections[0].header.system?.content).toBe('you are a scanner');
    expect(ast.sections[0].header.human?.content).toBe('scan 10.0.0.1');
    expect(ast.sections[0].body).toHaveLength(2);
    expect(ast.sections[0].body[0].type).toBe('request-response');
    expect(ast.sections[0].body[1].type).toBe('completion');
  });

  it('classifies a summarization-only pair (synthetic tool name)', () => {
    const chain = [human('go'), ai('', [call('s1', SUMMARIZATION_TOOL_NAME, { question: 'q' })]), tool('s1', SUMMARIZATION_TOOL_NAME, 'summary text')];
    const ast = newChainAST(chain);
    expect(ast.sections[0].body[0].type).toBe('summarization');
  });

  it('starts a new section at a human message after assistant turns', () => {
    const chain = [human('first'), ai('ack'), human('second directive'), ai('ack2')];
    const ast = newChainAST(chain);
    expect(ast.sections).toHaveLength(2);
    expect(ast.sections[0].header.human?.content).toBe('first');
    expect(ast.sections[1].header.human?.content).toBe('second directive');
  });

  it('merges double human messages into the section header', () => {
    const chain = [human('part one'), human('part two'), ai('ok')];
    const ast = newChainAST(chain);
    expect(ast.sections).toHaveLength(1);
    expect(ast.sections[0].header.human?.content).toContain('part one');
    expect(ast.sections[0].header.human?.content).toContain('part two');
  });

  it('tracks size in bytes across content and tool-call arguments', () => {
    const chain = [human('abc'), ai('de', [call('c1', 't', { a: 'xyz' })]), tool('c1', 't', 'resp')];
    const ast = newChainAST(chain);
    // 'abc'(3) + 'de'(2) + args {"a":"xyz"}(9) + ids/names + 'resp'(4) — just sanity-bound it
    expect(ast.size()).toBeGreaterThan(16);
    expect(sectionSize(ast.sections[0])).toBe(ast.size());
  });
});

describe('tool-call matching', () => {
  it('findToolCallResponses returns matching tool messages', () => {
    const chain = [human('go'), ai('run', [call('c1'), call('c2')]), tool('c1', 'a', 'one'), tool('c2', 'b', 'two')];
    const ast = newChainAST(chain);
    expect(ast.findToolCallResponses('c1')).toHaveLength(1);
    expect(ast.findToolCallResponses('c2')[0].content).toBe('two');
  });

  it('getToolCallsInfo reports pending and unmatched IDs', () => {
    const pendingChain = [human('go'), ai('run', [call('c1'), call('c2')]), tool('c1', 'a', 'one')];
    const ast = newChainAST(pendingChain);
    const info = ast.getToolCallsInfo(ast.sections[0].body[0]);
    expect(info.pendingIds).toEqual(['c2']);
    expect(info.unmatchedIds).toEqual([]);
  });
});

describe('force repair', () => {
  it('fabricates fallback responses for pending tool calls', () => {
    const chain = [human('go'), ai('run', [call('c1')])];
    const ast = newChainAST(chain, true);
    const pair = ast.sections[0].body[0];
    expect(pair.toolMessages).toHaveLength(1);
    expect(pair.toolMessages[0].content).toBe(FALLBACK_RESPONSE_CONTENT);
    expect(pair.toolMessages[0].toolCallId).toBe('c1');
  });

  it('fabricates owning tool calls for stray tool results', () => {
    const chain = [human('go'), tool('c9', 'orphan', 'lost result')];
    const ast = newChainAST(chain, true);
    const pair = ast.sections[0].body[0];
    expect(pair.assistant.toolCalls?.[0].id).toBe('c9');
    expect(pair.toolMessages[0].content).toBe('lost result');
  });

  it('leaves pending calls unresolved when force=false (stray tool dropped)', () => {
    const pendingChain = [human('go'), ai('run', [call('c1')])];
    const ast = newChainAST(pendingChain, false);
    expect(ast.sections[0].body[0].toolMessages).toHaveLength(0);
    const strayChain = [human('go'), tool('c9', 'orphan', 'lost')];
    const ast2 = newChainAST(strayChain, false);
    expect(ast2.sections[0].body).toHaveLength(0);
  });

  it('round-trips messages() stably for a well-formed chain', () => {
    const chain = [
      sys('s'),
      human('h'),
      ai('a', [call('c1', 't', { q: '1' })]),
      tool('c1', 't', 'r'),
      ai('final'),
    ];
    const ast = newChainAST(chain, true);
    expect(ast.messages()).toEqual(chain);
  });
});

describe('normalizeToolCallIDs', () => {
  it('renumbers call IDs and keeps responses paired', () => {
    const chain = [human('go'), ai('a', [call('old-1'), call('old-2')]), tool('old-1', 'a', 'one'), tool('old-2', 'b', 'two')];
    const ast = newChainAST(chain);
    ast.normalizeToolCallIDs('call_{n}');
    const msgs = ast.messages();
    const assistant = msgs.find((m) => m.role === 'assistant')!;
    expect(assistant.toolCalls?.map((c) => c.id)).toEqual(['call_1', 'call_2']);
    const toolMsgs = msgs.filter((m) => m.role === 'tool');
    expect(toolMsgs.map((m) => m.toolCallId).sort()).toEqual(['call_1', 'call_2']);
  });
});

describe('sanitizeJSONControlChars + sanitizeToolCallArguments', () => {
  it('strips control characters but keeps newlines and tabs', () => {
    const dirty = 'a\u0000b\u0007c\nd\te';
    expect(sanitizeJSONControlChars(dirty)).toBe('abc\nd\te');
  });

  it('cleans tool-call argument strings in place', () => {
    const chain = [human('go'), ai('a', [call('c1', 't', { q: 'x\u0001y' })])];
    const ast = newChainAST(chain);
    ast.sanitizeToolCallArguments();
    expect(ast.messages()[1].toolCalls?.[0].arguments).toEqual({ q: 'xy' });
  });
});

describe('ChainAST mutation helpers', () => {
  it('addSection / appendHumanMessage build new sections', () => {
    const ast = new ChainAST();
    ast.appendHumanMessage('first');
    ast.appendHumanMessage('second');
    expect(ast.sections).toHaveLength(2);
    expect(ast.messages().map((m) => m.content)).toEqual(['first', 'second']);
  });
});
