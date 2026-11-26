/**
 * ChainSummary — context-window compression for long agent chains
 *
 * TypeScript port of Pentagi's pkg/csum (chain_summary.go) plus the provider
 * layer's SHA-256 LRU summarizer cache (providers.go: 1000 entries, 4h TTL).
 *
 * Algorithm (SummarizerConfig defaults mirror csum):
 *   1. Parse the chain with ChainAST (force=true).
 *   2. Collapse every section except the newest `keepLastSections` into a
 *      single summary pair (Summarization type when the section contained
 *      tool traffic, Completion-with-prefix otherwise).
 *   3. Preserve the last section: summarize oversized body pairs in place
 *      (never the newest pair — it holds the live reasoning), then if the
 *      section still exceeds `lastSectionBytes`, keep the newest pairs under
 *      a 75% threshold and summarize the rest into a prepended pair.
 *   4. Optional QA rebuild (`useQA`) when sections/bytes blow past limits.
 *
 * All summaries go through a `SummarizeHandler` (model call); identical inputs
 * are memoized in an expirable LRU keyed by SHA-256.
 */

import { createHash } from 'node:crypto';
import type { LLMMessage } from '../types/index.js';
import {
  ChainAST,
  SUMMARIZATION_TOOL_NAME,
  SUMMARIZED_CONTENT_PREFIX,
  newChainAST,
  sectionSize,
  type ChainBodyPair,
  type ChainSection,
} from './chain-ast.js';

export type SummarizeHandler = (result: string) => Promise<string>;

export interface SummarizerConfig {
  /** Preserve (and selectively compress) the newest section (default: true) */
  preserveLast?: boolean;
  /** Rebuild as QA when section/byte limits are exceeded (default: false) */
  useQA?: boolean;
  /** Max bytes for the preserved last section (default: 50 KiB) */
  lastSectionBytes?: number;
  /** Max bytes for a single body pair before in-place summarization (default: 16 KiB) */
  maxBodyPairBytes?: number;
  /** Max sections before the QA rebuild kicks in (default: 10) */
  maxQASections?: number;
  /** Max chain bytes before the QA rebuild kicks in (default: 64 KiB) */
  maxQABytes?: number;
  /** Newest sections kept untouched (default: 1) */
  keepLastSections?: number;
}

const DEFAULTS = {
  preserveLast: true,
  useQA: false,
  lastSectionBytes: 50 * 1024,
  maxBodyPairBytes: 16 * 1024,
  maxQASections: 10,
  maxQABytes: 64 * 1024,
  keepLastSections: 1,
};

// =============================================================================
// SHA-256 LRU CACHE (pentagi: 1000 entries, 4h TTL)
// =============================================================================

export interface CacheOptions {
  maxSize?: number;
  ttlMs?: number;
}

export class SummarizerCache {
  private entries = new Map<string, { value: string; at: number }>();
  private readonly maxSize: number;
  private readonly ttlMs: number;

  constructor(options?: CacheOptions) {
    this.maxSize = Math.max(1, options?.maxSize ?? 1000);
    this.ttlMs = Math.max(1, options?.ttlMs ?? 4 * 60 * 60 * 1000);
  }

  private static key(input: string): string {
    return createHash('sha256').update(input, 'utf8').digest('hex');
  }

  get(input: string): string | undefined {
    const key = SummarizerCache.key(input);
    const hit = this.entries.get(key);
    if (!hit) return undefined;
    if (Date.now() - hit.at > this.ttlMs) {
      this.entries.delete(key);
      return undefined;
    }
    // LRU touch: delete + re-insert moves the key to the newest position
    this.entries.delete(key);
    this.entries.set(key, hit);
    return hit.value;
  }

  set(input: string, value: string): void {
    const key = SummarizerCache.key(input);
    if (this.entries.has(key)) this.entries.delete(key);
    this.entries.set(key, { value, at: Date.now() });
    while (this.entries.size > this.maxSize) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
  }

  get size(): number {
    return this.entries.size;
  }
}

/** Wrap a raw handler with the SHA-256 LRU so identical inputs summarize once. */
export function cachedSummarizeHandler(handler: SummarizeHandler, options?: CacheOptions): SummarizeHandler {
  const cache = new SummarizerCache(options);
  return async (input: string) => {
    const hit = cache.get(input);
    if (hit !== undefined) return hit;
    const value = await handler(input);
    cache.set(input, value);
    return value;
  };
}

// =============================================================================
// SUMMARIZER
// =============================================================================

export interface ChainSummarizer {
  summarizeChain(messages: LLMMessage[]): Promise<LLMMessage[]>;
}

export function createChainSummarizer(handler: SummarizeHandler, config?: SummarizerConfig): ChainSummarizer {
  const cfg = resolveConfig(config);
  return {
    async summarizeChain(messages: LLMMessage[]): Promise<LLMMessage[]> {
      if (messages.length === 0) return messages;
      const ast = newChainAST(messages, true);
      const sections = ast.sections;
      if (sections.length === 0) return messages;

      const keep = Math.max(0, Math.min(cfg.keepLastSections, sections.length));
      const boundary = sections.length - keep;
      const toSummarize = sections.slice(0, boundary);

      // 1. Collapse all old sections into one summary pair each (concurrent).
      await Promise.all(toSummarize.map((section) => summarizeSection(section, handler, cfg)));

      // 2. Preserve the newest section(s) with targeted compression.
      const lastSections = sections.slice(boundary);
      if (cfg.preserveLast) {
        for (const section of lastSections) {
          await preserveLastSection(section, handler, cfg);
        }
      }

      // 3. Optional QA rebuild.
      if (cfg.useQA && (sections.length > cfg.maxQASections || ast.size() > cfg.maxQABytes)) {
        await rebuildAsQA(ast, handler);
      }

      return ast.messages();
    },
  };
}

function resolveConfig(config?: SummarizerConfig) {
  return {
    preserveLast: config?.preserveLast ?? DEFAULTS.preserveLast,
    useQA: config?.useQA ?? DEFAULTS.useQA,
    lastSectionBytes: config?.lastSectionBytes ?? DEFAULTS.lastSectionBytes,
    maxBodyPairBytes: config?.maxBodyPairBytes ?? DEFAULTS.maxBodyPairBytes,
    maxQASections: config?.maxQASections ?? DEFAULTS.maxQASections,
    maxQABytes: config?.maxQABytes ?? DEFAULTS.maxQABytes,
    keepLastSections: config?.keepLastSections ?? DEFAULTS.keepLastSections,
  };
}

function pairBytes(pair: ChainBodyPair): number {
  let n = pair.assistant.content.length;
  if (pair.assistant.toolCalls) {
    for (const c of pair.assistant.toolCalls) n += JSON.stringify(c.arguments || {}).length;
  }
  for (const t of pair.toolMessages) n += t.content.length;
  return n;
}

function isSummarizationPair(pair: ChainBodyPair): boolean {
  return pair.type === 'summarization' && pair.toolMessages.length === 1;
}

/** Replace a section's body with one summary pair (skips already-summarized). */
async function summarizeSection(section: ChainSection, handler: SummarizeHandler, cfg: ReturnType<typeof resolveConfig>): Promise<void> {
  if (section.body.length === 1 && isSummarizationPair(section.body[0])) return;
  if (section.body.length === 0) return;

  const hadToolTraffic = section.body.some((p) => p.type !== 'completion');
  const prompt = messagesToPrompt(section);
  const summary = await handler(prompt);
  let pair: ChainBodyPair;
  if (hadToolTraffic) {
    const callId = `call_summarize_${Math.random().toString(16).slice(2)}`;
    pair = {
      type: 'summarization',
      assistant: {
        role: 'assistant',
        content: '',
        toolCalls: [{ id: callId, name: SUMMARIZATION_TOOL_NAME, arguments: { question: prompt.slice(0, 200) } }],
      },
      toolMessages: [{ role: 'tool', content: summary, toolCallId: callId, name: SUMMARIZATION_TOOL_NAME }],
    };
  } else {
    pair = {
      type: 'completion',
      assistant: { role: 'assistant', content: SUMMARIZED_CONTENT_PREFIX + summary },
      toolMessages: [],
    };
  }
  section.body = [pair];
  void cfg;
}

/** Compress the newest section in place: oversized pairs (except the newest), then overflow. */
async function preserveLastSection(section: ChainSection, handler: SummarizeHandler, cfg: ReturnType<typeof resolveConfig>): Promise<void> {
  if (section.body.length === 0) return;

  // 2a. Oversized pairs — summarize in place, never the newest pair.
  const newest = section.body.length - 1;
  for (let i = 0; i < newest; i++) {
    const pair = section.body[i];
    if (pairBytes(pair) <= cfg.maxBodyPairBytes || isSummarizationPair(pair)) continue;
    const summary = await handler(messagesToPrompt(section, [pair]));
    section.body[i] = {
      type: 'completion',
      assistant: { role: 'assistant', content: SUMMARIZED_CONTENT_PREFIX + summary },
      toolMessages: [],
    };
  }

  // 2b. Still oversized — keep the newest pairs under a 75% threshold, summarize the rest.
  if (sectionSize(section) <= cfg.lastSectionBytes) return;
  const threshold = Math.floor(cfg.lastSectionBytes * 75) / 100;
  const kept: ChainBodyPair[] = [];
  let keptBytes = 0;
  const cutoff = Math.max(0, section.body.length - 1); // always keep the newest pair
  let firstKept = section.body.length;
  for (let i = section.body.length - 1; i >= cutoff; i--) {
    const size = pairBytes(section.body[i]);
    if (keptBytes + size > threshold && kept.length > 0) break;
    kept.unshift(section.body[i]);
    keptBytes += size;
    firstKept = i;
  }
  const toSummarize = section.body.slice(0, firstKept).filter((p) => !isSummarizationPair(p));
  if (toSummarize.length > 0) {
    const summary = await handler(messagesToPrompt(section, toSummarize));
    const head: ChainBodyPair = {
      type: 'completion',
      assistant: { role: 'assistant', content: SUMMARIZED_CONTENT_PREFIX + summary },
      toolMessages: [],
    };
    section.body = [head, ...kept];
  } else {
    section.body = kept;
  }
}

/** QA rebuild: one summary section up front, then the newest sections that fit. */
async function rebuildAsQA(ast: ChainAST, handler: SummarizeHandler): Promise<void> {
  const sections = ast.sections;
  if (sections.length === 0) return;
  const buffer = 1000;
  let budget = buffer;
  let firstKept = sections.length;
  for (let i = sections.length - 1; i >= 1; i--) {
    const size = sectionSize(sections[i]);
    if (budget + size > buffer * 64) break; // heuristic cap on the preserved tail
    budget += size;
    firstKept = i;
  }
  const toSummarize = sections.slice(0, firstKept);
  if (toSummarize.length === 0) return;
  const summary = await handler(messagesToPromptSections(toSummarize));
  const system = toSummarize.map((s) => s.header.system).find(Boolean);
  const human = toSummarize.map((s) => s.header.human).find(Boolean);
  const summarySection = ast.addSection({
    ...(system ? { system } : {}),
    ...(human ? { human } : {}),
  });
  summarySection.body.push({
    type: 'completion',
    assistant: { role: 'assistant', content: SUMMARIZED_CONTENT_PREFIX + summary },
    toolMessages: [],
  });
  // Drop the summarized sections from the front (addSection appended at the end).
  ast.sections.splice(0, firstKept);
}

// =============================================================================
// PROMPT RENDERING (pentagi messagesToPrompt shape)
// =============================================================================

function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function renderMessage(id: number, msg: LLMMessage, includeToolCalls: boolean): string {
  const parts: string[] = [`<message id="${id}" role="${msg.role}">`];
  if (msg.content) parts.push(`<content>${escapeXml(msg.content)}</content>`);
  if (includeToolCalls && msg.toolCalls?.length) {
    for (const call of msg.toolCalls) {
      parts.push(`<tool_call name="${escapeXml(call.name)}">${escapeXml(JSON.stringify(call.arguments || {}))}</tool_call>`);
    }
  }
  if (msg.role === 'tool' && msg.name) {
    parts.push(`<tool_call_response name="${escapeXml(msg.name)}">${escapeXml(msg.content)}</tool_call_response>`);
  }
  parts.push('</message>');
  return parts.join('');
}

function renderPairs(pairs: ChainBodyPair[]): string {
  let id = 0;
  const out: string[] = [];
  for (const pair of pairs) {
    out.push(renderMessage(++id, pair.assistant, true));
    for (const tool of pair.toolMessages) out.push(renderMessage(++id, tool, false));
  }
  return out.join('\n');
}

function instructionsFor(hasHuman: boolean, hasAI: boolean): string {
  const subject = hasHuman && hasAI ? 'the conversation between the human operator and the AI agent' : hasAI ? 'the AI agent messages' : 'the human operator messages';
  return (
    `Summarize ${subject} for an autonomous security-assessment agent about to continue working. ` +
    `Preserve: the mission objective, confirmed findings with their evidence, targets and ports already tested, ` +
    `dead ends, and any pending next steps. Drop boilerplate tool noise. ` +
    `Content already carrying the "${SUMMARIZATION_TOOL_NAME}" marker is a prior summary — keep its substance. ` +
    `Reply with a dense plain-text summary only.`
  );
}

/** Render a full section (header + body) as a summarizer prompt. */
function messagesToPrompt(section: ChainSection, only?: ChainBodyPair[]): string {
  const pairs = only || section.body;
  const human = section.header.human?.content || '';
  const tasks = human
    ? `<tasks>\n<task id="1">${escapeXml(human)}</task>\n</tasks>\n\n`
    : '';
  const hasHuman = Boolean(human);
  const hasAI = pairs.length > 0;
  return `<instructions>${instructionsFor(hasHuman, hasAI)}</instructions>\n\n${tasks}<messages>\n${renderPairs(pairs)}\n</messages>`;
}

function messagesToPromptSections(sections: ChainSection[]): string {
  const human = sections.map((s) => s.header.human?.content || '').filter(Boolean).join('\n');
  const tasks = human ? `<tasks>\n<task id="1">${escapeXml(human)}</task>\n</tasks>\n\n` : '';
  const body = sections.map((s) => renderPairs(s.body)).filter(Boolean).join('\n');
  return `<instructions>${instructionsFor(Boolean(human), body.length > 0)}</instructions>\n\n${tasks}<messages>\n${body}\n</messages>`;
}

// =============================================================================
// CONVENIENCE — one-shot summary + backbone-backed handler
// =============================================================================

/**
 * Pentagi GenerateSummary: summarize a flat list of human + AI messages into a
 * single string via the handler.
 */
export async function generateSummary(handler: SummarizeHandler, humanMessages: string[], aiMessages: string[]): Promise<string> {
  const human = humanMessages.filter(Boolean);
  const ai = aiMessages.filter(Boolean);
  const tasks = human.length
    ? `<tasks>\n${human.map((h, i) => `<task id="${i + 1}">${escapeXml(h)}</task>`).join('\n')}\n</tasks>\n\n`
    : '';
  let id = 0;
  const body = [
    ...human.map((h) => renderMessage(++id, { role: 'user', content: h }, false)),
    ...ai.map((a) => renderMessage(++id, { role: 'assistant', content: a }, false)),
  ].join('\n');
  const prompt = `<instructions>${instructionsFor(human.length > 0, ai.length > 0)}</instructions>\n\n${tasks}<messages>\n${body}\n</messages>`;
  return handler(prompt);
}
