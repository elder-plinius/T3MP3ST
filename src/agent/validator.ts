/**
 * FindingValidator — second-pass LLM skeptic for code_supply_chain missions.
 *
 * LLM 1 (scanner/analyst) finds vulnerabilities using tools.
 * LLM 2 (this) takes those findings and independently confirms or rejects each one.
 * A finding that doesn't survive skeptical review gets validationResult.confirmed = false
 * and the gate will block it from being marked verified.
 */

import type { LLMBackbone } from '../llm/index.js';
import type { ToolFinding, ValidationResult } from '../types/index.js';

export interface ValidationVerdict {
  findingTitle: string;
  confirmed: boolean;
  confidence: number;
  reasoning: string;
  suggestedSeverity?: string;
}

export interface ValidatorResult {
  verdicts: ValidationVerdict[];
  confirmedCount: number;
  rejectedCount: number;
  durationMs: number;
}

const VALIDATOR_SYSTEM_PROMPT = `You are an independent security finding validator — a skeptical second reviewer.

Your job is NOT to find new vulnerabilities. Your job is to CONFIRM or REJECT findings that a first-pass scanner reported. You are the quality gate.

For each finding you receive:
1. Examine the cited evidence (tool output, code snippet, file path + line number)
2. Ask: does this evidence actually PROVE this vulnerability is exploitable, or does it only show the pattern exists?
3. A finding is CONFIRMED only if there is a clear, specific attack path with attacker-controlled input reaching the vulnerable sink
4. A finding is REJECTED if: evidence only shows the pattern exists without proving exploitability, the tool output is ambiguous or generic, severity is overclaimed, or it requires unproven assumptions

Be specific. Reference the actual evidence. Be skeptical of high/critical severity claims.

Respond with ONLY a JSON array (no surrounding text):
[
  {
    "findingTitle": "exact title from the finding",
    "confirmed": true or false,
    "confidence": 0.0 to 1.0,
    "reasoning": "Specific reason referencing the evidence — cite file paths, line numbers, or tool output",
    "suggestedSeverity": "lower to medium" (optional, only if overclaimed)
  }
]`;

export class FindingValidator {
  private llm: LLMBackbone;

  constructor(llm: LLMBackbone) {
    this.llm = llm;
  }

  async validate(findings: ToolFinding[], context?: string): Promise<ValidatorResult> {
    const startTime = Date.now();

    if (findings.length === 0) {
      return { verdicts: [], confirmedCount: 0, rejectedCount: 0, durationMs: 0 };
    }

    const findingsSummary = findings.map((f, i) =>
      [
        `Finding ${i + 1}: ${f.title} [severity: ${f.severity}]`,
        `Details: ${f.details}`,
        `Tool evidence: ${f.toolOutput ? f.toolOutput.slice(0, 800) : '(none — model assertion only)'}`,
        `Provenance: ${f.provenance || 'unknown'}`,
        f.cve?.length ? `CVEs: ${f.cve.join(', ')}` : '',
      ].filter(Boolean).join('\n')
    ).join('\n\n---\n\n');

    const userPrompt = [
      context ? `Target context: ${context}\n` : '',
      `Review these ${findings.length} findings and validate each one:\n\n${findingsSummary}`,
    ].join('');

    try {
      const response = await this.llm.chat([
        { role: 'system', content: VALIDATOR_SYSTEM_PROMPT },
        { role: 'user', content: userPrompt },
      ], { maxTokens: 4096, temperature: 0.1 });

      const verdicts = this.parseVerdicts(response.content, findings);
      const confirmedCount = verdicts.filter(v => v.confirmed).length;

      return {
        verdicts,
        confirmedCount,
        rejectedCount: verdicts.length - confirmedCount,
        durationMs: Date.now() - startTime,
      };
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      return {
        verdicts: findings.map(f => ({
          findingTitle: f.title,
          confirmed: false,
          confidence: 0,
          reasoning: `Validator failed — manual review required: ${errorMsg}`,
        })),
        confirmedCount: 0,
        rejectedCount: findings.length,
        durationMs: Date.now() - startTime,
      };
    }
  }

  /** Convert a ValidationVerdict into the Finding.validationResult shape */
  static toValidationResult(verdict: ValidationVerdict): ValidationResult {
    return {
      confirmed: verdict.confirmed,
      confidence: verdict.confidence,
      reasoning: verdict.reasoning,
      validatedAt: Date.now(),
    };
  }

  private parseVerdicts(content: string, findings: ToolFinding[]): ValidationVerdict[] {
    // Try JSON array directly or inside a code fence
    const attempts = [
      content.trim(),
      (content.match(/```(?:json)?\s*([\s\S]*?)```/)?.[1] || '').trim(),
    ];

    for (const attempt of attempts) {
      if (!attempt) continue;
      try {
        const parsed = JSON.parse(attempt);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed as ValidationVerdict[];
        }
      } catch {
        // try next
      }
    }

    // Fallback: return unconfirmed for all — manual review needed
    return findings.map(f => ({
      findingTitle: f.title,
      confirmed: false,
      confidence: 0,
      reasoning: 'Validator could not parse verdict — manual review required',
    }));
  }
}
