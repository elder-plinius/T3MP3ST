/**
 * T3MP3ST Agent Loop
 *
 * ReAct (Reason + Act) agent that connects LLM tool calling to Arsenal execution.
 * This is the core autonomous loop: the LLM decides which tool to use,
 * Arsenal executes it, and results are fed back for the next decision.
 */

import { EventEmitter } from 'eventemitter3';
import type { LLMBackbone } from '../llm/index.js';
import type { Arsenal } from '../arsenal/index.js';
import type {
  LLMMessage,
  LLMToolDefinition,
  LLMToolCall,
  ToolResult,
  ToolFinding,
  Severity,
  Target,
  Task,
} from '../types/index.js';

// =============================================================================
// TYPES
// =============================================================================

export interface AgentLoopOptions {
  /** Max ReAct iterations before forcing a conclusion (default: 15) */
  maxIterations?: number;
  /** Max total tokens to spend (default: 50000) */
  maxTokens?: number;
  /** Tool categories to expose (default: all) */
  toolCategories?: string[];
  /** Explicit tool-NAME allowlist — the operator's role toolkit. Overrides toolCategories. */
  tools?: string[];
  /** Whether to include detailed tool output in context (default: true) */
  verboseToolOutput?: boolean;
  /** Max characters per tool result before truncation (default: 4000) */
  maxToolOutputLength?: number;
}

export interface AgentStep {
  iteration: number;
  type: 'tool_call' | 'observation' | 'reasoning';
  toolName?: string;
  toolArgs?: Record<string, unknown>;
  toolResult?: ToolResult;
  content?: string;
  timestamp: number;
}

export interface AgentResult {
  success: boolean;
  /** Final summary from the LLM */
  summary: string;
  /** All steps taken during execution */
  steps: AgentStep[];
  /** Findings extracted from tool results */
  findings: ToolFinding[];
  /** Total iterations used */
  iterations: number;
  /** Total tokens consumed */
  tokensUsed: number;
  /** Duration in ms */
  durationMs: number;
  /** Whether the agent hit the iteration limit */
  hitLimit: boolean;
  /** Error from the forced final-summary call after hitting limits, if any */
  finalSummaryError?: string;
}

export interface AgentEvents {
  'agent:step': AgentStep;
  'agent:tool_call': { name: string; args: Record<string, unknown> };
  'agent:tool_result': { name: string; result: ToolResult };
  'agent:thinking': { content: string };
  'agent:complete': AgentResult;
  'agent:error': { error: Error; step: number };
}

// =============================================================================
// AGENT LOOP
// =============================================================================

export class AgentLoop extends EventEmitter<AgentEvents> {
  private llm: LLMBackbone;
  private arsenal: Arsenal;
  private options: Required<AgentLoopOptions>;

  constructor(llm: LLMBackbone, arsenal: Arsenal, options?: AgentLoopOptions) {
    super();
    this.llm = llm;
    this.arsenal = arsenal;
    this.options = {
      maxIterations: options?.maxIterations ?? 15,
      maxTokens: options?.maxTokens ?? 50000,
      toolCategories: options?.toolCategories ?? [],
      tools: options?.tools ?? [],
      verboseToolOutput: options?.verboseToolOutput ?? true,
      maxToolOutputLength: options?.maxToolOutputLength ?? 4000,
    };
  }

  /**
   * Run the ReAct loop for a task
   */
  async run(
    task: Task,
    systemPrompt: string,
    target?: Target,
    sourceContext?: string,
    sharedContext?: string
  ): Promise<AgentResult> {
    const startTime = Date.now();
    const steps: AgentStep[] = [];
    const allFindings: ToolFinding[] = [];
    let tokensUsed = 0;
    let hitLimit = false;
    // anti-stall: dedup identical tool calls + detect runs of no-new-findings (ported from the hunter)
    const seenCalls = new Map<string, string>();
    let noProgress = 0;

    // Get tool definitions from Arsenal (the operator's role toolkit: name allowlist wins,
    // then category filter, then all).
    const toolDefs = this.arsenal.getToolDefinitions(
      this.options.toolCategories.length > 0 ? this.options.toolCategories : undefined,
      this.options.tools.length > 0 ? this.options.tools : undefined
    );

    // Build initial messages
    const messages: LLMMessage[] = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: this.buildTaskPrompt(task, target, toolDefs, sourceContext, sharedContext) },
    ];

    for (let i = 0; i < this.options.maxIterations; i++) {
      try {
        // Ask the LLM what to do next
        const response = await this.llm.chatWithTools(messages, toolDefs, {
          maxTokens: 4096,
          temperature: 0.3, // Lower temperature for tool-using tasks
        });

        tokensUsed += response.usage?.totalTokens || 0;

        // If the LLM wants to call tools
        if (response.toolCalls?.length) {
          // Record the assistant's reasoning
          if (response.content) {
            const thinkStep: AgentStep = {
              iteration: i,
              type: 'reasoning',
              content: response.content,
              timestamp: Date.now(),
            };
            steps.push(thinkStep);
            this.emit('agent:thinking', { content: response.content });
          }

          // Add assistant message to context (with tool calls)
          messages.push({
            role: 'assistant',
            content: response.content || '',
            toolCalls: response.toolCalls,
          });

          // Execute each tool call
          const findingsBefore = allFindings.length;
          for (const toolCall of response.toolCalls) {
            // ANTI-STALL: a byte-identical repeat is almost always wasted — steer instead of re-running.
            const callHash = `${toolCall.name}:${JSON.stringify(toolCall.arguments || {})}`;
            let toolStep: AgentStep;
            if (seenCalls.has(callHash)) {
              const dup: ToolResult = {
                success: false,
                error: `Duplicate call — you already ran ${toolCall.name} with these exact arguments. ` +
                  `Prior result: ${seenCalls.get(callHash)}. Do NOT repeat it — change the arguments, pick a different tool, or move to your final debrief.`,
              };
              toolStep = { iteration: i, type: 'tool_call', toolName: toolCall.name, toolArgs: toolCall.arguments, toolResult: dup, timestamp: Date.now() };
            } else {
              toolStep = await this.executeTool(toolCall, target, i);
              seenCalls.set(callHash, String(toolStep.toolResult?.output || toolStep.toolResult?.error || 'no output').replace(/\s+/g, ' ').slice(0, 160));
            }
            steps.push(toolStep);

            // Collect findings — tag with REAL tool provenance (the output that backs them)
            if (toolStep.toolResult?.findings) {
              const out = String(toolStep.toolResult.output ?? '').slice(0, 4000);
              for (const tf of toolStep.toolResult.findings) {
                allFindings.push({ ...tf, provenance: 'tool', toolName: toolCall.name, toolOutput: out || tf.details });
              }
            }

            // Build tool result content
            const resultContent = this.formatToolResult(toolStep.toolResult);

            // Add tool result to context
            messages.push({
              role: 'tool',
              content: resultContent,
              toolCallId: toolCall.id,
              name: toolCall.name,
            });
          }

          // ANTI-STALL: after a run of iterations with no new findings, steer (once) toward a new
          // vector or a final debrief — don't let the agent grind the budget on a dead approach.
          noProgress = allFindings.length > findingsBefore ? 0 : noProgress + 1;
          if (noProgress >= 4 && i < this.options.maxIterations - 2) {
            messages.push({
              role: 'user',
              content: '[System: 4 iterations with no new findings. Either pursue a GENUINELY different vector/tool/argument now, or produce your final debrief if the surface is exhausted. Do not keep repeating the current approach.]',
            });
            noProgress = 0;
          }
        } else {
          // LLM finished reasoning — this is the final answer.
          const finalStep: AgentStep = {
            iteration: i,
            type: 'reasoning',
            content: response.content,
            timestamp: Date.now(),
          };
          steps.push(finalStep);

          // Parse the structured debrief block so the model's OWN analysis is captured —
          // previously only tool-emitted findings were kept and the final report was dropped.
          for (const f of this.parseFinalFindings(response.content || '')) {
            if (!allFindings.some((x) => x.title === f.title)) allFindings.push(f);
          }

          const result: AgentResult = {
            success: true,
            summary: response.content,
            steps,
            findings: allFindings,
            iterations: i + 1,
            tokensUsed,
            durationMs: Date.now() - startTime,
            hitLimit: false,
          };

          this.emit('agent:complete', result);
          return result;
        }

        // Check token budget
        if (tokensUsed >= this.options.maxTokens) {
          hitLimit = true;
          break;
        }
      } catch (error) {
        this.emit('agent:error', { error: error as Error, step: i });

        // On error, try to continue with a reduced context
        const errMsg = error instanceof Error ? error.message : String(error);
        messages.push({
          role: 'user',
          content: `[System: Tool execution error: ${errMsg}. Please continue with available information or try a different approach.]`,
        });
      }
    }

    // Hit iteration or token limit — ask LLM for a final summary
    hitLimit = true;
    messages.push({
      role: 'user',
      content: 'You have reached the maximum number of steps. Please provide a final summary of everything you discovered, including all findings and recommendations.',
    });

    let summary = 'Agent reached iteration limit without producing a final summary.';
    let finalSummaryError: string | undefined;
    try {
      const finalResponse = await this.llm.chat(messages, { maxTokens: 2048 });
      summary = finalResponse.content;
      tokensUsed += finalResponse.usage?.totalTokens || 0;
      // capture the structured debrief from the limit-summary too (same contract as the clean finish)
      for (const f of this.parseFinalFindings(summary)) {
        if (!allFindings.some((x) => x.title === f.title)) allFindings.push(f);
      }
    } catch (error) {
      finalSummaryError = error instanceof Error ? error.message : String(error);
    }

    const result: AgentResult = {
      success: allFindings.length > 0 || steps.some(s => s.toolResult?.success),
      summary,
      steps,
      findings: allFindings,
      iterations: this.options.maxIterations,
      tokensUsed,
      durationMs: Date.now() - startTime,
      hitLimit,
      finalSummaryError,
    };

    this.emit('agent:complete', result);
    return result;
  }

  /**
   * Execute a single tool call via the Arsenal
   */
  private async executeTool(
    toolCall: LLMToolCall,
    target: Target | undefined,
    iteration: number
  ): Promise<AgentStep> {
    this.emit('agent:tool_call', { name: toolCall.name, args: toolCall.arguments });

    let toolResult: ToolResult;
    try {
      toolResult = await this.arsenal.execute(toolCall.name, {
        target,
        parameters: toolCall.arguments,
      });
    } catch (err) {
      // A bad/hallucinated tool name must NOT crash the loop. Return the callable set so the
      // model self-corrects in-place instead of dying or looping on a tool that doesn't exist.
      const available = this.arsenal
        .getToolDefinitions(
          this.options.toolCategories.length ? this.options.toolCategories : undefined,
          this.options.tools.length ? this.options.tools : undefined
        )
        .map((t) => t.name);
      toolResult = {
        success: false,
        error: `Tool "${toolCall.name}" is not available. Callable tools this run: ${available.join(', ') || '(none)'}. ` +
          `Use one of these EXACT names — do not invent tools; if none fit, describe the capability you need in prose.`,
      };
    }

    this.emit('agent:tool_result', { name: toolCall.name, result: toolResult });

    return {
      iteration,
      type: 'tool_call',
      toolName: toolCall.name,
      toolArgs: toolCall.arguments,
      toolResult,
      timestamp: Date.now(),
    };
  }

  /**
   * Build the initial task prompt with target context and prior intel
   */
  private buildTaskPrompt(task: Task, target?: Target, tools?: LLMToolDefinition[], sourceContext?: string, sharedContext?: string): string {
    const parts: string[] = [];

    parts.push(`## MISSION TASK: ${task.name}`);
    parts.push(`**Phase**: ${task.phase} | **Priority**: ${task.priority}/10`);
    parts.push(`\n### Objective`);
    parts.push(task.description);

    // White-box source excerpt (security-prioritized) — provided by the large-repo
    // analysis pipeline. Optional + backward-compatible: absent/empty keeps the
    // original black-box prompt. When present, give the model the real source so it
    // can ground findings in code rather than probing blind.
    if (sourceContext && sourceContext.trim().length > 0) {
      parts.push(`\n### White-box source (security-prioritized excerpt)`);
      parts.push(`The following is a security-prioritized excerpt of the target's own source code. Use it to locate and confirm vulnerabilities against the actual implementation — but only report a finding as verified when a tool result backs it.`);
      parts.push(sourceContext);
    }

    // Shared intel from the pack board (Phase-2 coordination): what sibling operators have already
    // found/claimed on this mission. Lets this operator build on tool-verified leads and NOT re-tread
    // surface a teammate already owns. Absent/empty keeps the solo-operator prompt (the baseline).
    if (sharedContext && sharedContext.trim().length > 0) {
      parts.push(`\n### Shared intel from the pack (your teammates' live board)`);
      parts.push(`Other operators are working this same target in parallel. Below is the current lead-board — tool-verified leads, who has claimed what, and open surface. Build on verified leads, do not duplicate a teammate's claimed work, and chase the hottest UNCLAIMED lead that fits your role.`);
      parts.push(sharedContext);
    }

    if (target) {
      parts.push(`\n### Target Intelligence`);
      parts.push(`- **Address**: ${target.address}`);
      parts.push(`- **Type**: ${target.type} | **Zone**: ${target.zone} | **Status**: ${target.status}`);

      // Prior recon intel: discovered services
      if (target.services?.length) {
        parts.push(`\n**Discovered Services** (from prior recon):`);
        for (const svc of target.services) {
          const version = svc.version ? ` v${svc.version}` : '';
          const banner = svc.banner ? ` [${svc.banner.slice(0, 60)}]` : '';
          parts.push(`  - ${svc.port}/${svc.protocol}: ${svc.name}${version}${banner}`);
        }
        parts.push(`Use this intel to focus your efforts. These are confirmed services.`);
      }

      // Prior vuln intel: discovered vulnerabilities
      if (target.vulnerabilities?.length) {
        parts.push(`\n**Known Vulnerabilities** (from prior scanning):`);
        for (const vuln of target.vulnerabilities.slice(0, 10)) {
          const cves = vuln.cve?.length ? ` (${vuln.cve.join(', ')})` : '';
          parts.push(`  - [${vuln.severity.toUpperCase()}] ${vuln.name}${cves}`);
          if (vuln.description) parts.push(`    ${vuln.description.slice(0, 200)}`);
        }
        if (target.vulnerabilities.length > 10) {
          parts.push(`  ... and ${target.vulnerabilities.length - 10} more`);
        }
        parts.push(`Use this intel to prioritize your testing.`);
      }

      // Prior credential intel
      if (target.credentials?.length) {
        parts.push(`\n**Harvested Credentials** (from prior phases):`);
        for (const cred of target.credentials.slice(0, 5)) {
          parts.push(`  - ${cred.username || 'unknown'}:*** (${cred.type}) via ${cred.source}`);
        }
      }
    }

    if (tools?.length) {
      parts.push(`\n### Arsenal (${tools.length} tools available)`);
      parts.push(`You have the following tools available via function calling. Select the most effective tool for each step of your assessment:`);
      // Group tools by rough function
      const toolList = tools.map(t => `  - **${t.name}**: ${t.description}`);
      parts.push(toolList.join('\n'));
      parts.push(`\n### Standing Orders`);
      parts.push(`1. Call tools via function calling — do NOT fabricate results`);
      parts.push(`2. Analyze each result before deciding the next action`);
      parts.push(`3. Report findings immediately as you discover them`);
      parts.push(`4. When finished, END your final message with a single fenced \`\`\`json block:\n` +
        `   {"findings":[{"title":"…","severity":"critical|high|medium|low|info","details":"… cite the tool output that evidences it …","cvss":0.0,"cve":["…"],"remediation":"…"}],"abstained":false}\n` +
        `   This block is the ONLY finding channel the harness records — anything described only in prose is dropped. Emit [] findings + "abstained":true if you found nothing real.`);
    }

    return parts.join('\n');
  }

  /**
   * Format a tool result for the LLM context
   */
  private formatToolResult(result?: ToolResult): string {
    if (!result) return 'No result returned.';

    const parts: string[] = [];
    parts.push(`Success: ${result.success}`);

    if (result.output) {
      let output = result.output;
      // ALWAYS cap tool output (verbose just gets a larger budget). Previously this was gated on
      // !verboseToolOutput, which defaults TRUE — so by default nothing was capped and large tool
      // results flooded the context window. Keep HEAD+TAIL: flags/results often land at the end.
      const cap = this.options.verboseToolOutput ? this.options.maxToolOutputLength * 4 : this.options.maxToolOutputLength;
      if (output.length > cap) {
        const head = Math.floor(cap * 0.7);
        const tail = cap - head;
        output = output.slice(0, head) + `\n… (truncated ${output.length - cap} chars) …\n` + output.slice(-tail);
      }
      parts.push(output);
    }

    if (result.error) {
      parts.push(`Error: ${result.error}`);
    }

    if (result.findings?.length) {
      parts.push('\nFindings:');
      for (const f of result.findings) {
        parts.push(`  - [${f.severity.toUpperCase()}] ${f.title}: ${f.details}`);
      }
    }

    return parts.join('\n');
  }

  /**
   * Parse the model's final debrief block into structured findings. The operator is told to
   * end its last message with a fenced ```json {findings:[…]} block; this is the ONLY prose→data
   * channel the harness honors (no substring guessing). Returns [] if there's no valid block.
   */
  private parseFinalFindings(content: string): ToolFinding[] {
    if (!content) return [];
    const SEV = new Set(['critical', 'high', 'medium', 'low', 'info']);
    const blocks = [...content.matchAll(/```(?:json)?\s*([\s\S]*?)```/g)].map((m) => m[1]);
    const candidates = blocks.length ? blocks.reverse() : [content];
    for (const c of candidates) {
      const start = c.indexOf('{');
      const end = c.lastIndexOf('}');
      if (start === -1 || end <= start) continue;
      try {
        const obj = JSON.parse(c.slice(start, end + 1));
        if (!obj || !Array.isArray(obj.findings)) continue;
        return obj.findings.filter((f: any) => f && f.title).map((f: any) => ({
          title: String(f.title).slice(0, 200),
          severity: (SEV.has(String(f.severity).toLowerCase()) ? String(f.severity).toLowerCase() : 'info') as Severity,
          details: String(f.details ?? f.evidence ?? f.evidence_ref ?? '').slice(0, 4000),
          cvss: typeof f.cvss === 'number' ? f.cvss : undefined,
          cve: Array.isArray(f.cve) ? f.cve.map(String) : undefined,
          remediation: f.remediation ? String(f.remediation) : undefined,
          // Model-asserted in the debrief — NO tool provenance. The gate downgrades these.
          provenance: 'model' as const,
        }));
      } catch { /* try the next candidate block */ }
    }
    return [];
  }
}

// =============================================================================
// FACTORY
// =============================================================================

export function createAgentLoop(
  llm: LLMBackbone,
  arsenal: Arsenal,
  options?: AgentLoopOptions
): AgentLoop {
  return new AgentLoop(llm, arsenal, options);
}

/**
 * Run a one-shot agent task — convenience function
 */
export async function runAgentTask(
  llm: LLMBackbone,
  arsenal: Arsenal,
  task: Task,
  systemPrompt: string,
  target?: Target,
  options?: AgentLoopOptions
): Promise<AgentResult> {
  const agent = createAgentLoop(llm, arsenal, options);
  return agent.run(task, systemPrompt, target);
}
