/**
 * Execution Monitor + Mentor + Arg-Reflector
 *
 * Ported from Pentagi's execution-monitor pattern (backend/pkg/providers/helpers.go):
 * - ExecutionMonitor counts consecutive same-tool calls and total calls; past a
 *   threshold it asks the LLM to act as a "mentor" that reviews the tool result
 *   in context and steers the operator back on track.
 * - The mentor analysis is wrapped around the original tool result so the model
 *   sees both (`<original_result>` + `<mentor_analysis>`).
 * - fixToolCallArgs is the JSON arg repair reflector: on validation failures it
 *   asks the model to emit corrected single-line JSON args (bounded retries).
 *
 * All LLM interactions are failure-soft by design: callers log and continue with
 * the raw result when the mentor/reflector itself errors.
 */

import type { LLMBackbone } from '../llm/index.js';
import type { LLMToolDefinition } from '../types/index.js';

// =============================================================================
// EXECUTION MONITOR
// =============================================================================

export interface ExecutionMonitorOptions {
  /** Consecutive calls to the same tool before invoking the mentor (default: 5) */
  sameToolLimit?: number;
  /** Total tool calls before invoking the mentor (default: 10) */
  totalToolLimit?: number;
}

export class ExecutionMonitor {
  private sameToolCount = 0;
  private totalCallCount = 0;
  private lastToolName = '';
  private readonly sameLimit: number;
  private readonly totalLimit: number;

  constructor(options?: ExecutionMonitorOptions) {
    this.sameLimit = Math.max(1, options?.sameToolLimit ?? 5);
    this.totalLimit = Math.max(1, options?.totalToolLimit ?? 10);
  }

  /**
   * Record a tool call and decide whether the mentor should review this result.
   * Mirrors pentagi semantics: total count never resets on tool change; the
   * same-tool streak resets when the tool name changes.
   */
  shouldInvokeMentor(toolName: string): boolean {
    this.totalCallCount += 1;
    if (toolName === this.lastToolName) {
      this.sameToolCount += 1;
    } else {
      this.sameToolCount = 1;
      this.lastToolName = toolName;
    }
    return this.sameToolCount >= this.sameLimit || this.totalCallCount >= this.totalLimit;
  }

  /** Zero the counters after a successful mentor intervention (pentagi parity). */
  reset(): void {
    this.sameToolCount = 0;
    this.totalCallCount = 0;
    this.lastToolName = '';
  }

  get calls(): { sameToolCount: number; totalCallCount: number; lastToolName: string } {
    return { sameToolCount: this.sameToolCount, totalCallCount: this.totalCallCount, lastToolName: this.lastToolName };
  }
}

// =============================================================================
// MENTOR WRAP + PROMPT
// =============================================================================

/**
 * Exact pentagi wrap format (helpers.go formatEnhancedToolResponse):
 * empty mentor analysis returns the original result untouched.
 */
export function formatEnhancedToolResponse(originalResult: string, mentorAnalysis: string): string {
  if (!mentorAnalysis) return originalResult;
  return [
    '<enhanced_response>',
    '<original_result>',
    originalResult,
    '</original_result>',
    '',
    '<mentor_analysis>',
    mentorAnalysis,
    '</mentor_analysis>',
    '</enhanced_response>',
  ].join('\n');
}

export interface MentorContext {
  taskDescription: string;
  toolName: string;
  toolArgs?: Record<string, unknown>;
  toolResult: string;
  recentMessages?: string[];
}

/**
 * Ask the LLM (via the backbone's failover ladder) to review a tool result as a
 * mentor. Returns the analysis text, or throws — callers are expected to catch
 * and continue with the raw result.
 */
export async function performMentor(llm: LLMBackbone, ctx: MentorContext): Promise<string> {
  const system =
    'You are the Execution Monitor mentor for an autonomous security-assessment agent. ' +
    'Review the latest tool result in the context of the task. Be concise and concrete: ' +
    'state whether the result is sufficient evidence, whether the agent is stuck in a loop, ' +
    'and the single best next action (different tool, different arguments, or move to reporting). ' +
    'Never invent tool output that is not present. Reply with 3-6 sentences max.';
  const recent = (ctx.recentMessages || []).slice(-4).map((m) => `- ${m}`).join('\n');
  const user = [
    `## Task`,
    ctx.taskDescription,
    `## Executed tool call`,
    `Tool: ${ctx.toolName}`,
    ctx.toolArgs ? `Arguments: ${JSON.stringify(ctx.toolArgs).slice(0, 2000)}` : '',
    `## Tool result`,
    ctx.toolResult.slice(0, 4096),
    recent ? `## Recent activity\n${recent}` : '',
  ].filter(Boolean).join('\n\n');

  const response = await llm.chat(
    [
      { role: 'system', content: system },
      { role: 'user', content: user },
    ],
    { maxTokens: 512, temperature: 0.2 }
  );
  return response.content.trim();
}

// =============================================================================
// ARG REFLECTOR — bounded JSON repair for validation failures
// =============================================================================

export interface ArgFixRequest {
  toolName: string;
  /** The failed arguments as a JSON string */
  argsJson: string;
  /** JSON-schema of the tool parameters, when available */
  schema?: LLMToolDefinition['parameters'];
  /** The validation error the tool threw */
  error: string;
}

/** Extract the first balanced JSON object from model prose (handles fences). */
function extractJsonObject(text: string): unknown | undefined {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidates = fenced ? [fenced[1], text] : [text];
  for (const candidate of candidates) {
    const start = candidate.indexOf('{');
    const end = candidate.lastIndexOf('}');
    if (start === -1 || end <= start) continue;
    try {
      const parsed = JSON.parse(candidate.slice(start, end + 1));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    } catch {
      // try the next candidate
    }
  }
  return undefined;
}

/**
 * Pentagi's fixToolCallArgs: after a validation failure, ask the model to emit
 * corrected arguments as single-line JSON. Up to `maxRetries` attempts
 * (pentagi: 3). Returns the repaired arguments object, or null if every
 * attempt failed to produce parseable JSON.
 */
export async function fixToolCallArgs(
  llm: LLMBackbone,
  req: ArgFixRequest,
  maxRetries = 3
): Promise<Record<string, unknown> | null> {
  const system =
    'You are a tool-call argument repair specialist. You fix malformed or invalid JSON ' +
    'arguments so a tool call passes schema validation. Output ONLY a single line of ' +
    'minified JSON — the corrected arguments object. No prose, no markdown fences, no explanations.';
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const user = [
      `Tool: ${req.toolName}`,
      req.schema ? `Parameter schema: ${JSON.stringify(req.schema).slice(0, 4000)}` : '',
      `Failed arguments: ${req.argsJson.slice(0, 4000)}`,
      `Validation error: ${req.error.slice(0, 1000)}`,
      'Return the corrected arguments as a single line of JSON.',
    ].filter(Boolean).join('\n');
    try {
      const response = await llm.chat(
        [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
        { maxTokens: 1024, temperature: 0 }
      );
      const repaired = extractJsonObject(response.content);
      if (repaired) return repaired as Record<string, unknown>;
    } catch {
      // backbone failure — fall through to the next attempt
    }
  }
  return null;
}
