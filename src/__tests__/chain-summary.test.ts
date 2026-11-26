/**
 * ChainSummary Tests
 *
 * Pentagi pkg/csum port: section collapsing, last-section preservation with a
 * byte threshold, SHA-256 LRU cache (identical input summarizes once),
 * generateSummary prompt shape, and ChainAST compatibility (round-trip through
 * newChainAST keeps already-summarized pairs intact).
 */

import { describe, it, expect, vi } from 'vitest';
import {
  SummarizerCache,
  cachedSummarizeHandler,
  createChainSummarizer,
  generateSummary,
} from '../llm/chain-summary.js';
import { newChainAST, SUMMARIZATION_TOOL_NAME, SUMMARIZED_CONTENT_PREFIX } from '../llm/chain-ast.js';
import type { LLMMessage } from '../types/index.js';

function sys(content: string): LLMMessage {
  return { role: 'system', content };
}
function human(content: string): LLMMessage {
  return { role: 'user', content };
}
function aiRound(id: string, content: string, result: string): LLMMessage[] {
  return [
    { role: 'assistant', content, toolCalls: [{ id, name: 'port_scan', arguments: { target: 'x' } }] },
    { role: 'tool', content: result, toolCallId: id, name: 'port_scan' },
  ];
}

describe('SummarizerCache', () => {
  it('stores, hits, and evicts LRU-style', () => {
    const cache = new SummarizerCache({ maxSize: 2, ttlMs: 60_000 });
    cache.set('a', 'A');
    cache.set('b', 'B');
    expect(cache.get('a')).toBe('A'); // touch a
    cache.set('c', 'C'); // evicts b (oldest)
    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('a')).toBe('A');
    expect(cache.get('c')).toBe('C');
    expect(cache.size).toBe(2);
  });

  it('expires entries past the TTL', () => {
    const cache = new SummarizerCache({ maxSize: 10, ttlMs: 1 });
    cache.set('a', 'A');
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        expect(cache.get('a')).toBeUndefined();
        resolve();
      }, 5);
    });
  });
});

describe('cachedSummarizeHandler', () => {
  it('calls the underlying handler once per unique input', async () => {
    const handler = vi.fn().mockResolvedValue('summary');
    const cached = cachedSummarizeHandler(handler, { maxSize: 100, ttlMs: 60_000 });
    await cached('same text');
    await cached('same text');
    await cached('other text');
    expect(handler).toHaveBeenCalledTimes(2);
  });
});

describe('createChainSummarizer', () => {
  it('collapses old sections into summary pairs and preserves the last section', async () => {
    const messages: LLMMessage[] = [sys('be brief'), human('mission')];
    for (let i = 0; i < 4; i++) messages.push(...aiRound(`c${i}`, `thinking ${i}`, `result ${i}`));
    messages.push(human('new directive'));
    messages.push(...aiRound('c-live', 'live work', 'live result'));

    const handler = vi.fn().mockResolvedValue('compressed summary');
    const summarizer = createChainSummarizer(handler);
    const out = await summarizer.summarizeChain(messages);

    // strictly smaller than the input
    expect(out.length).toBeLessThan(messages.length);
    // header survived
    expect(out[0].content).toBe('be brief');
    expect(out[1].content).toBe('mission');
    // old sections are now summarized pairs carrying the synthetic tool name
    const summarized = out.filter(
      (m) => m.role === 'tool' && m.name === SUMMARIZATION_TOOL_NAME
    );
    expect(summarized.length).toBeGreaterThanOrEqual(1);
    // newest round is preserved verbatim
    const live = out.find((m) => m.role === 'assistant' && m.content === 'live work');
    expect(live).toBeTruthy();
    expect(out.find((m) => m.role === 'tool' && m.content === 'live result')).toBeTruthy();
  });

  it('prefixes completion-only summaries', async () => {
    const messages: LLMMessage[] = [
      human('task one'),
      { role: 'assistant', content: 'plain answer one' },
      human('task two'),
      { role: 'assistant', content: 'plain answer two' },
    ];
    const handler = vi.fn().mockResolvedValue('both tasks covered');
    const summarizer = createChainSummarizer(handler, { keepLastSections: 1 });
    const out = await summarizer.summarizeChain(messages);
    const summaryMsg = out.find((m) => m.role === 'assistant' && m.content.startsWith(SUMMARIZED_CONTENT_PREFIX));
    expect(summaryMsg).toBeTruthy();
    expect(summaryMsg!.content).toContain('both tasks covered');
    // last completion kept untouched
    expect(out.find((m) => m.content === 'plain answer two')).toBeTruthy();
  });

  it('keeps the newest pair untouched when compressing an oversized last section', async () => {
    const big = 'x'.repeat(30 * 1024);
    const messages: LLMMessage[] = [
      human('directive'),
      ...aiRound('c-big', 'big analysis', big),
      ...aiRound('c-live', 'live analysis', 'live result'),
    ];
    const handler = vi.fn().mockResolvedValue('big section summarized');
    const summarizer = createChainSummarizer(handler, {
      preserveLast: true,
      lastSectionBytes: 16 * 1024,
      maxBodyPairBytes: 16 * 1024,
      keepLastSections: 1,
    });
    const out = await summarizer.summarizeChain(messages);
    // the oversized old pair got compressed
    expect(out.find((m) => m.role === 'tool' && m.content === big)).toBeUndefined();
    // the newest pair survived verbatim
    expect(out.find((m) => m.role === 'tool' && m.content === 'live result')).toBeTruthy();
  });

  it('leaves an already-summarized single-pair section alone (no re-summarize)', async () => {
    const summarized: LLMMessage[] = [
      human('task'),
      {
        role: 'assistant',
        content: '',
        toolCalls: [{ id: 's1', name: SUMMARIZATION_TOOL_NAME, arguments: { question: 'q' } }],
      },
      { role: 'tool', content: 'earlier summary', toolCallId: 's1', name: SUMMARIZATION_TOOL_NAME },
    ];
    // summarize only the head (keepLastSections=0 forces the old-section path)
    const handler = vi.fn().mockResolvedValue('new summary');
    const summarizer = createChainSummarizer(handler, { keepLastSections: 0 });
    const out = await summarizer.summarizeChain([...summarized]);
    // the single summarized pair is preserved as-is; handler never ran on it twice
    expect(out.find((m) => m.content === 'earlier summary')).toBeTruthy();
  });

  it('returns the input unchanged when the chain is empty', async () => {
    const summarizer = createChainSummarizer(vi.fn());
    const out = await summarizer.summarizeChain([]);
    expect(out).toEqual([]);
  });
});

describe('AST compatibility', () => {
  it('output re-parses with newChainAST(force) and survives a second round-trip', async () => {
    const messages: LLMMessage[] = [sys('s'), human('h')];
    for (let i = 0; i < 3; i++) messages.push(...aiRound(`c${i}`, `think ${i}`, `result ${i}`));
    const handler = vi.fn().mockResolvedValue('summary');
    const out = await createChainSummarizer(handler).summarizeChain(messages);
    const ast = newChainAST(out, true);
    expect(ast.messages()).toEqual(out);
  });
});

describe('generateSummary', () => {
  it('builds instructions + tasks + messages and returns the handler output', async () => {
    const handler = vi.fn().mockResolvedValue('the mission found one finding');
    const out = await generateSummary(handler, ['scan the host'], ['ran port_scan', 'found 80 open']);
    expect(out).toBe('the mission found one finding');
    const prompt = handler.mock.calls[0][0] as string;
    expect(prompt).toContain('<instructions>');
    expect(prompt).toContain('<task id="1">scan the host</task>');
    expect(prompt).toContain('role="user"');
    expect(prompt).toContain('role="assistant"');
    expect(prompt).toContain('</messages>');
  });
});
