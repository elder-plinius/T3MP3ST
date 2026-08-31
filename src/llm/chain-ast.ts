/**
 * ChainAST — structural parse of an LLM message chain
 *
 * TypeScript port of Pentagi's pkg/cast (backend/pkg/cast/chain_ast.go), adapted
 * to T3MP3ST's flat LLMMessage shape (string content, no multimodal parts).
 *
 * Structure:
 *   Chain -> Section[]            (a section starts at a system/human boundary)
 *   Section -> Header + BodyPair[]
 *   Header -> system message (first section only) + human message
 *   BodyPair -> one assistant turn + its tool results
 *     type: 'request-response' | 'completion' | 'summarization'
 *
 * `force = true` repairs a broken chain (pending tool calls, unmatched tool
 * results, stray messages) so the result is always a valid, replayable chain.
 */

import type { LLMMessage, LLMToolCall } from '../types/index.js';

/** Synthetic tool name marking an already-summarized section (pentagi parity). */
export const SUMMARIZATION_TOOL_NAME = 'execute_task_and_return_summary';
export const FALLBACK_RESPONSE_CONTENT = 'the call was not handled, please try again';
export const SUMMARIZED_CONTENT_PREFIX = '**summarized content:**\n';

export type BodyPairType = 'request-response' | 'completion' | 'summarization';

export interface ChainHeader {
  system?: LLMMessage;
  human?: LLMMessage;
}

export interface ChainBodyPair {
  type: BodyPairType;
  /** The assistant turn that opened this pair */
  assistant: LLMMessage;
  /** Tool result messages attached to this pair */
  toolMessages: LLMMessage[];
}

export interface ChainSection {
  header: ChainHeader;
  body: ChainBodyPair[];
}

interface PendingCall {
  call: LLMToolCall;
  responded: boolean;
}

export class ChainAST {
  readonly sections: ChainSection[] = [];

  /** Byte size of the whole chain (content + tool-call arguments). */
  size(): number {
    return this.sections.reduce((sum, s) => sum + sectionSize(s), 0);
  }

  /** Round-trip back to a flat message array. */
  messages(): LLMMessage[] {
    const out: LLMMessage[] = [];
    for (const section of this.sections) {
      if (section.header.system) out.push(section.header.system);
      if (section.header.human) out.push(section.header.human);
      for (const pair of section.body) {
        out.push(pair.assistant);
        for (const tool of pair.toolMessages) out.push(tool);
      }
    }
    return out;
  }

  addSection(header: ChainHeader = {}): ChainSection {
    const section: ChainSection = { header, body: [] };
    this.sections.push(section);
    return section;
  }

  appendHumanMessage(content: string): void {
    const last = this.sections[this.sections.length - 1];
    if (last && last.body.length === 0 && !last.header.human) {
      last.header.human = { role: 'user', content };
      return;
    }
    this.addSection({ human: { role: 'user', content } });
  }

  /** All tool-call/response match info for one pair (pending/unmatched diagnostics). */
  getToolCallsInfo(pair: ChainBodyPair): {
    pendingIds: string[];
    unmatchedIds: string[];
  } {
    const calls = pair.assistant.toolCalls || [];
    const responded = new Set(pair.toolMessages.map((m) => m.toolCallId));
    const pendingIds = calls.filter((c) => !responded.has(c.id)).map((c) => c.id);
    const callIds = new Set(calls.map((c) => c.id));
    const unmatchedIds = pair.toolMessages.filter((m) => !m.toolCallId || !callIds.has(m.toolCallId)).map((m) => m.toolCallId || '');
    return { pendingIds, unmatchedIds };
  }

  findToolCallResponses(callId: string): LLMMessage[] {
    const out: LLMMessage[] = [];
    for (const section of this.sections) {
      for (const pair of section.body) {
        for (const tool of pair.toolMessages) {
          if (tool.toolCallId === callId) out.push(tool);
        }
      }
    }
    return out;
  }

  /**
   * Regenerate tool-call IDs (calls + their responses stay paired) using
   * `template` with a `{n}` placeholder — used when resuming chains whose IDs
   * came from a different provider session.
   */
  normalizeToolCallIDs(template = 'call_{n}'): void {
    let n = 0;
    for (const section of this.sections) {
      for (const pair of section.body) {
        const calls = pair.assistant.toolCalls;
        if (!calls?.length) continue;
        const remap = new Map<string, string>();
        pair.assistant.toolCalls = calls.map((call) => {
          const id = template.replace('{n}', String(++n));
          remap.set(call.id, id);
          return { ...call, id };
        });
        pair.toolMessages = pair.toolMessages.map((tool) => {
          const mapped = tool.toolCallId ? remap.get(tool.toolCallId) : undefined;
          return mapped ? { ...tool, toolCallId: mapped } : tool;
        });
      }
    }
  }

  /** Strip control characters that break JSON parsing from tool-call arguments. */
  sanitizeToolCallArguments(): void {
    for (const section of this.sections) {
      for (const pair of section.body) {
        if (!pair.assistant.toolCalls) continue;
        pair.assistant.toolCalls = pair.assistant.toolCalls.map((call) => ({
          ...call,
          arguments: JSON.parse(JSON.stringify(call.arguments, (_k, v) => (typeof v === 'string' ? sanitizeJSONControlChars(v) : v))),
        }));
      }
    }
  }
}

export function sanitizeJSONControlChars(s: string): string {
  // Keep \n (\u000A), \t (\u0009), \r (\u000D); strip the rest of C0 range.
  return s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');
}

function messageSize(m: LLMMessage): number {
  let n = m.content.length + (m.name?.length || 0) + (m.toolCallId?.length || 0);
  if (m.toolCalls) {
    for (const c of m.toolCalls) n += c.id.length + c.name.length + JSON.stringify(c.arguments || {}).length;
  }
  return n;
}

export function sectionSize(s: ChainSection): number {
  let n = (s.header.system ? messageSize(s.header.system) : 0) + (s.header.human ? messageSize(s.header.human) : 0);
  for (const pair of s.body) n += messageSize(pair.assistant) + pair.toolMessages.reduce((x, t) => x + messageSize(t), 0);
  return n;
}

function pairTypeFor(assistant: LLMMessage): BodyPairType {
  const calls = assistant.toolCalls || [];
  if (calls.length === 0) return 'completion';
  if (calls.every((c) => c.name === SUMMARIZATION_TOOL_NAME)) return 'summarization';
  return 'request-response';
}

function emptyPair(assistant: LLMMessage): ChainBodyPair {
  return { type: pairTypeFor(assistant), assistant, toolMessages: [] };
}

/**
 * Parse a flat message chain into sections. With `force`, repairs every
 * structural defect found instead of throwing:
 *  - message[0] must be system/user (stray tool/assistant messages before any
 *    header are dropped)
 *  - system only allowed as the very first message (later ones are demoted to
 *    human)
 *  - assistant opens a BodyPair; tool results attach to the open pair
 *  - pending tool calls (no response) get a fallback tool message
 *  - unmatched tool responses get a fallback assistant tool call
 *  - consecutive human messages merge into the section header
 */
export function newChainAST(chain: LLMMessage[], force = false): ChainAST {
  const ast = new ChainAST();
  let section: ChainSection | null = null;
  let openPair: ChainBodyPair | null = null;
  const pending: PendingCall[] = [];

  const ensureSection = () => {
    if (!section) section = ast.addSection();
    return section;
  };

  const closePair = () => {
    if (!openPair) return;
    if (force) {
      for (const p of pending) {
        if (!p.responded) {
          openPair.toolMessages.push({
            role: 'tool',
            content: FALLBACK_RESPONSE_CONTENT,
            toolCallId: p.call.id,
            name: p.call.name,
          });
        }
      }
    }
    pending.length = 0;
    openPair = null;
  };

  for (let i = 0; i < chain.length; i++) {
    const msg = chain[i];

    if (msg.role === 'system') {
      if (i === 0) {
        section = ast.addSection({ system: msg });
      } else if (force) {
        // demote a mid-chain system message to human context
        const sec = ensureSection();
        closePair();
        if (sec.header.human) {
          sec.header.human = { role: 'user', content: `${sec.header.human.content}\n${msg.content}` };
        } else {
          sec.header.human = { role: 'user', content: msg.content };
        }
      }
      continue;
    }

    if (msg.role === 'user') {
      closePair();
      if (section?.header.human && section.body.length === 0) {
        // double human message before any assistant turn — merge
        section.header.human = { role: 'user', content: `${section.header.human.content}\n${msg.content}` };
      } else if (section && section.body.length > 0) {
        // human after assistant turns starts a new section
        section = ast.addSection({ human: msg });
      } else {
        ensureSection().header.human = msg;
      }
      continue;
    }

    if (msg.role === 'assistant') {
      const sec = ensureSection();
      closePair();
      openPair = emptyPair(msg);
      sec.body.push(openPair);
      for (const call of msg.toolCalls || []) pending.push({ call, responded: false });
      continue;
    }

    if (msg.role === 'tool') {
      if (openPair) {
        openPair.toolMessages.push(msg);
        const match = pending.find((p) => p.call.id === msg.toolCallId);
        if (match) match.responded = true;
      } else if (force) {
        // stray tool result with no owning assistant turn — fabricate the call
        const sec = ensureSection();
        const call: LLMToolCall = { id: msg.toolCallId || `call_fabricated_${i}`, name: msg.name || 'unknown_tool', arguments: {} };
        openPair = emptyPair({ role: 'assistant', content: '', toolCalls: [call] });
        sec.body.push(openPair);
        pending.push({ call, responded: true });
        openPair.toolMessages.push(msg);
      }
      continue;
    }
  }
  closePair();

  if (force && ast.sections.length === 0) {
    ast.addSection();
  }
  return ast;
}
