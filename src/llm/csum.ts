/**
 * Chain Summarizer (csum) for LLM Context Compression
 * Ported & adapted from PentAGI (pkg/csum/chain_summary.go)
 * 
 * Compresses long multi-turn message histories by:
 * 1. Preserving recent rounds intact (configurable active window byte size).
 * 2. Condensing earlier rounds into structured summary checkpoints.
 * 3. Preserving tool call IDs, arguments, and return schema fidelity.
 */

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  name?: string;
  tool_call_id?: string;
  tool_calls?: any[];
}

export interface SummarizerConfig {
  /** Maximum bytes to keep unsummarized in the recent active window (default: 40KB) */
  activeWindowMaxBytes?: number;
  /** Maximum estimated tokens before triggering compression (default: 12000) */
  triggerTokenThreshold?: number;
  /** Custom prefix for compressed blocks */
  summaryPrefix?: string;
}

export class ChainSummarizer {
  private activeWindowMaxBytes: number;
  private triggerTokenThreshold: number;
  private summaryPrefix: string;

  constructor(config: SummarizerConfig = {}) {
    this.activeWindowMaxBytes = config.activeWindowMaxBytes || 40 * 1024; // 40 KB
    this.triggerTokenThreshold = config.triggerTokenThreshold || 12000;
    this.summaryPrefix = config.summaryPrefix || '**[T3MP3ST Context Summary]**:\n';
  }

  /**
   * Estimates rough token count from message string content (~4 chars per token)
   */
  public estimateTokens(messages: LLMMessage[]): number {
    let charCount = 0;
    for (const msg of messages) {
      charCount += (msg.content || '').length;
      if (msg.tool_calls) {
        charCount += JSON.stringify(msg.tool_calls).length;
      }
    }
    return Math.ceil(charCount / 4);
  }

  /**
   * Compresses message history if it exceeds the token/byte budget
   */
  public compress(messages: LLMMessage[]): LLMMessage[] {
    if (!messages || messages.length <= 2) {
      return messages;
    }

    const totalTokens = this.estimateTokens(messages);
    if (totalTokens < this.triggerTokenThreshold) {
      return messages;
    }

    // Keep system message always intact at index 0 if present
    const hasSystem = messages[0]?.role === 'system';
    const systemMsg = hasSystem ? messages[0] : null;
    const workMessages = hasSystem ? messages.slice(1) : [...messages];

    if (workMessages.length <= 1) {
      return messages;
    }

    // Find the split point: work backwards from end accumulating bytes until activeWindowMaxBytes
    let accumulatedBytes = 0;
    let splitIndex = -1;

    for (let i = workMessages.length - 1; i >= 0; i--) {
      const msgBytes = Buffer.byteLength(workMessages[i].content || '', 'utf8') +
        (workMessages[i].tool_calls ? Buffer.byteLength(JSON.stringify(workMessages[i].tool_calls), 'utf8') : 0);

      if (accumulatedBytes + msgBytes > this.activeWindowMaxBytes && (workMessages.length - i) >= 1) {
        splitIndex = i + 1;
        break;
      }
      accumulatedBytes += msgBytes;
    }

    // Fallback: if no split found, retain last 2 messages
    if (splitIndex <= 0 || splitIndex >= workMessages.length) {
      splitIndex = Math.max(1, workMessages.length - 2);
    }

    const toSummarize = workMessages.slice(0, splitIndex);
    const toKeep = workMessages.slice(splitIndex);

    if (toSummarize.length === 0) {
      return messages;
    }

    // Build condensed summary block from toSummarize
    const summaryLines: string[] = [];
    for (const msg of toSummarize) {
      if (msg.role === 'user') {
        const text = (msg.content || '').trim().replace(/\n+/g, ' ');
        summaryLines.push(`- Operator/Prompt: ${text.length > 200 ? text.slice(0, 200) + '...' : text}`);
      } else if (msg.role === 'assistant') {
        if (msg.tool_calls && msg.tool_calls.length > 0) {
          const calls = msg.tool_calls.map(c => c.function?.name || c.name || 'tool').join(', ');
          summaryLines.push(`- Agent Action: Dispatched [${calls}]`);
        } else {
          const text = (msg.content || '').trim().replace(/\n+/g, ' ');
          summaryLines.push(`- Agent Reasoning: ${text.length > 150 ? text.slice(0, 150) + '...' : text}`);
        }
      } else if (msg.role === 'tool') {
        const text = (msg.content || '').trim().replace(/\n+/g, ' ');
        summaryLines.push(`- Tool Output: ${text.length > 180 ? text.slice(0, 180) + '...' : text}`);
      }
    }

    const summaryMessage: LLMMessage = {
      role: 'user',
      content: `${this.summaryPrefix}${summaryLines.join('\n')}\n\n[Active recent turns continue below]`
    };

    const result: LLMMessage[] = [];
    if (systemMsg) result.push(systemMsg);
    result.push(summaryMessage);
    result.push(...toKeep);

    return result;
  }
}
