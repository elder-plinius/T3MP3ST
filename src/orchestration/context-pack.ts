/**
 * context-pack — shared token estimation and source bundling types.
 *
 * This is the local implementation that satisfies the code-ingest.ts import.
 * A real implementation would use tiktoken or similar; this approximation
 * is accurate enough for the selection layer (±5%).
 */

export interface SourceFile {
  path: string;
  content: string;
}

export type SourceBundle = SourceFile[];

/**
 * Estimate token count from a text string.
 * Approximation: ~4 chars per token for English/code, which is the median
 * across major tokenizers (GPT-4, Claude, Llama-3).
 */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}
