/**
 * DecompositionOrchestrator — the master builder.
 *
 * The orchestrator (running on a capable, unrestricted model like opus) holds
 * the full offensive objective. It decomposes that objective into innocuous
 * analytical queries, dispatches them to a worker model (which can be a more
 * powerful but more restricted model like fable-5), collects the answers, and
 * synthesizes them into exploit intelligence.
 *
 * The worker never sees the offensive framing — only benign code-analysis
 * questions, each accompanied by the source under analysis. The orchestrator
 * does all the offensive reasoning. Only the master builder knows the plan.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import { LLMBackbone } from '../llm/index.js';
import type {
  DecompositionConfig,
  DecompositionResult,
  DecompositionRound,
  DecomposedQuery,
  QueryResult,
  SynthesisResult,
  ExtractedFact,
  DecompositionEvents,
} from './types.js';
import {
  ORCHESTRATOR_DECOMPOSE_PROMPT,
  ORCHESTRATOR_SYNTHESIZE_PROMPT,
  ORCHESTRATOR_FINAL_PROMPT,
  WORKER_SYSTEM_PROMPT,
} from './prompts.js';

// =============================================================================
// ROBUST JSON EXTRACTION
//
// Reasoning/chat models wrap answers in ``` fences, emit prose with stray
// braces, or add a sentence after the JSON. Strategy: try a direct parse of the
// (de-fenced) text first — the happy path when the model obeys "output ONLY
// JSON" — then fall back to scanning every balanced bracket span and taking the
// LAST one that parses to the expected shape (the model's final answer).
// Mirrors the proven parser in scripts/refute-finding.mjs.
// =============================================================================

function stripFences(s: string): string {
  return String(s).replace(/```(?:json)?/gi, '');
}

function balancedSpans(s: string, open: string, close: string): string[] {
  const spans: string[] = [];
  let depth = 0, start = -1;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === open) { if (depth === 0) start = i; depth++; }
    else if (c === close) { if (depth > 0 && --depth === 0 && start >= 0) { spans.push(s.slice(start, i + 1)); start = -1; } }
  }
  return spans;
}

function parseLastArray(text: string): unknown[] | null {
  const s = stripFences(text);
  try { const d = JSON.parse(s.trim()); if (Array.isArray(d)) return d; } catch { /* fall through */ }
  const spans = balancedSpans(s, '[', ']');
  for (let i = spans.length - 1; i >= 0; i--) {
    try { const d = JSON.parse(spans[i]); if (Array.isArray(d)) return d; } catch { /* keep scanning */ }
  }
  return null;
}

function parseLastObject(text: string): Record<string, unknown> | null {
  const s = stripFences(text);
  try { const d = JSON.parse(s.trim()); if (d && typeof d === 'object' && !Array.isArray(d)) return d as Record<string, unknown>; } catch { /* fall through */ }
  const spans = balancedSpans(s, '{', '}');
  for (let i = spans.length - 1; i >= 0; i--) {
    try { const d = JSON.parse(spans[i]); if (d && typeof d === 'object' && !Array.isArray(d)) return d as Record<string, unknown>; } catch { /* keep scanning */ }
  }
  return null;
}

// =============================================================================
// ORCHESTRATOR
// =============================================================================

export class DecompositionOrchestrator extends EventEmitter<DecompositionEvents> {
  private config: Required<Omit<DecompositionConfig, 'orchestratorModel' | 'workerModel'>> & Pick<DecompositionConfig, 'orchestratorModel' | 'workerModel'>;
  private orchestrator: LLMBackbone;
  private worker: LLMBackbone;

  // per-run state (reset in run())
  private orchestratorTokensUsed = 0;
  private fullSourceContext = '';

  constructor(config: DecompositionConfig) {
    super();
    this.config = {
      maxQueriesPerRound: 8,
      maxRounds: 5,
      workerMaxTokens: 4096,
      orchestratorMaxTokens: 8192,
      workerTemperature: 0.2,
      parallelWorkers: true,
      maxConcurrency: 4,
      attachSourceToWorker: true,
      verbose: false,
      ...config,
    };
    this.orchestrator = new LLMBackbone(config.orchestratorModel);
    this.worker = new LLMBackbone(config.workerModel);
  }

  /**
   * Run the full decomposition loop against an objective.
   *
   * @param objective  The full offensive objective (only the orchestrator sees this).
   * @param sourceContext  Relevant source code, file listings, or repo context.
   * @param priorIntel  Any intelligence from previous runs (findings, known guards, etc.).
   */
  async run(
    objective: string,
    sourceContext: string,
    priorIntel?: string,
  ): Promise<DecompositionResult> {
    const t0 = this.now();
    this.orchestratorTokensUsed = 0;
    this.fullSourceContext = sourceContext || '';
    this.emit('decomposition:start', { objective, config: this.config });

    const rounds: DecompositionRound[] = [];
    let accumulatedKnowledge = priorIntel || '';
    let totalWorkerTokens = 0;

    for (let round = 1; round <= this.config.maxRounds; round++) {
      const rt0 = this.now();
      this.emit('decomposition:round_start', { round });

      // ── STEP 1: orchestrator decomposes the objective into innocuous queries ──
      const queries = await this.decompose(objective, sourceContext, accumulatedKnowledge, round);
      this.emit('decomposition:queries_planned', { round, queries });
      if (queries.length === 0) break;

      // ── STEP 2: dispatch innocuous queries to the worker model ──
      const results = await this.dispatchQueries(queries, round);
      totalWorkerTokens += results.reduce(
        (sum, r) => sum + (r.usage?.promptTokens || 0) + (r.usage?.completionTokens || 0), 0,
      );

      // ── STEP 3: orchestrator synthesizes the analytical answers ──
      const synthesis = await this.synthesize(objective, accumulatedKnowledge, queries, results, round);
      this.emit('decomposition:synthesis', { round, synthesis });

      // accumulate knowledge for the next round
      accumulatedKnowledge += `\n\n--- ROUND ${round} FINDINGS ---\n${synthesis.attackSurfaceModel}\n`;
      for (const f of synthesis.findings) {
        accumulatedKnowledge += `- [${f.type}/${f.severity || 'n/a'}] ${f.title}: ${f.description}\n`;
      }

      const roundResult: DecompositionRound = {
        roundNumber: round,
        queries,
        results,
        synthesis,
        durationMs: this.now() - rt0,
      };
      rounds.push(roundResult);
      this.emit('decomposition:round_complete', { round, durationMs: roundResult.durationMs });

      if (!synthesis.continueDecomposition) break;
    }

    // ── STEP 4: final synthesis across all rounds ──
    const finalSynthesis = await this.finalSynthesize(objective, rounds);

    const totalQueries = rounds.reduce((s, r) => s + r.queries.length, 0);
    const answeredQueries = rounds.reduce((s, r) => s + r.results.filter(q => q.status === 'answered').length, 0);
    const refusedQueries = rounds.reduce((s, r) => s + r.results.filter(q => q.status === 'refused').length, 0);

    const result: DecompositionResult = {
      rounds,
      finalSynthesis,
      totalQueries,
      answeredQueries,
      refusedQueries,
      totalDurationMs: this.now() - t0,
      totalUsage: {
        orchestratorTokens: this.orchestratorTokensUsed,
        workerTokens: totalWorkerTokens,
      },
    };

    this.emit('decomposition:complete', { result });
    return result;
  }

  // ===========================================================================
  // ORCHESTRATOR CALL — captures token usage (prompt() throws it away)
  // ===========================================================================

  private async askOrchestrator(prompt: string, temperature: number): Promise<string> {
    const res = await this.orchestrator.chat(
      [{ role: 'user', content: prompt }],
      { maxTokens: this.config.orchestratorMaxTokens, temperature },
    );
    this.orchestratorTokensUsed += (res.usage?.promptTokens || 0) + (res.usage?.completionTokens || 0);
    return res.content || '';
  }

  // ===========================================================================
  // DECOMPOSE — orchestrator breaks the objective into innocuous queries
  // ===========================================================================

  private async decompose(
    objective: string,
    sourceContext: string,
    accumulatedKnowledge: string,
    round: number,
  ): Promise<DecomposedQuery[]> {
    const prompt = ORCHESTRATOR_DECOMPOSE_PROMPT(
      objective, sourceContext, accumulatedKnowledge, round, this.config.maxQueriesPerRound,
    );
    const response = await this.askOrchestrator(prompt, 0.4);
    return this.parseQueries(response);
  }

  // ===========================================================================
  // DISPATCH — send innocuous queries to the worker model
  // ===========================================================================

  private async dispatchQueries(queries: DecomposedQuery[], round: number): Promise<QueryResult[]> {
    if (!this.config.parallelWorkers) {
      const results: QueryResult[] = [];
      for (const query of queries) results.push(await this.executeQuery(query, round));
      return results;
    }
    // bounded-concurrency parallel dispatch
    const concurrency = Math.max(1, this.config.maxConcurrency);
    const results: QueryResult[] = [];
    for (let i = 0; i < queries.length; i += concurrency) {
      const batch = queries.slice(i, i + concurrency);
      results.push(...await Promise.all(batch.map(q => this.executeQuery(q, round))));
    }
    return results;
  }

  private async executeQuery(query: DecomposedQuery, round: number): Promise<QueryResult> {
    const t0 = this.now();
    this.emit('decomposition:query_sent', { round, query });

    try {
      // The worker is stateless and blind to the objective. It needs the source
      // to analyze: prefer a focused snippet the orchestrator attached, else the
      // full source context (so the orchestrator never has to copy-paste code).
      const source = query.context || (this.config.attachSourceToWorker ? this.fullSourceContext : '');
      const userMessage = source
        ? `${query.query}\n\n--- SOURCE UNDER ANALYSIS ---\n${source}`
        : query.query;

      const response = await this.worker.chat(
        [
          { role: 'system', content: WORKER_SYSTEM_PROMPT },
          { role: 'user', content: userMessage },
        ],
        { maxTokens: this.config.workerMaxTokens, temperature: this.config.workerTemperature },
      );

      const durationMs = this.now() - t0;
      const content = response.content || '';
      const isEmpty = content.trim().length < 10;
      const isRefusal = isEmpty || this.looksLikeRefusal(content);

      if (isRefusal) {
        this.emit('decomposition:query_refused', { round, queryId: query.id, preview: content.slice(0, 200) });
      }

      const result: QueryResult = {
        queryId: query.id,
        rawResponse: content,
        extractedFacts: isRefusal ? [] : this.extractFacts(content),
        status: isRefusal ? 'refused' : 'answered',
        usage: response.usage
          ? { promptTokens: response.usage.promptTokens, completionTokens: response.usage.completionTokens }
          : undefined,
        durationMs,
      };
      this.emit('decomposition:query_result', { round, result });
      return result;
    } catch (error) {
      return {
        queryId: query.id,
        rawResponse: `ERROR: ${(error as Error).message}`,
        extractedFacts: [],
        status: 'error',
        durationMs: this.now() - t0,
      };
    }
  }

  // ===========================================================================
  // SYNTHESIZE — orchestrator reassembles the analytical answers
  // ===========================================================================

  private async synthesize(
    objective: string,
    accumulatedKnowledge: string,
    queries: DecomposedQuery[],
    results: QueryResult[],
    round: number,
  ): Promise<SynthesisResult> {
    const queryResultPairs = queries.map((q, i) => ({
      id: q.id,
      question: q.query,
      purpose: q.purpose,
      category: q.category,
      answer: results[i]?.rawResponse || '(no response)',
      status: results[i]?.status || 'error',
    }));
    const prompt = ORCHESTRATOR_SYNTHESIZE_PROMPT(objective, accumulatedKnowledge, queryResultPairs, round);
    const response = await this.askOrchestrator(prompt, 0.3);
    return this.parseSynthesis(response);
  }

  private async finalSynthesize(objective: string, rounds: DecompositionRound[]): Promise<SynthesisResult> {
    // edge case: nothing ran (every round produced 0 queries)
    if (rounds.length === 0) {
      return { findings: [], gaps: ['no queries were generated'], continueDecomposition: false, attackSurfaceModel: '', confidence: 0 };
    }
    const roundSummaries = rounds.map(r => ({
      round: r.roundNumber,
      queriesAsked: r.queries.length,
      answered: r.results.filter(q => q.status === 'answered').length,
      refused: r.results.filter(q => q.status === 'refused').length,
      findings: r.synthesis.findings,
      gaps: r.synthesis.gaps,
      attackSurface: r.synthesis.attackSurfaceModel,
    }));
    const prompt = ORCHESTRATOR_FINAL_PROMPT(objective, roundSummaries);
    const response = await this.askOrchestrator(prompt, 0.3);
    return this.parseSynthesis(response);
  }

  // ===========================================================================
  // PARSING HELPERS
  // ===========================================================================

  private parseQueries(response: string): DecomposedQuery[] {
    const queries: DecomposedQuery[] = [];
    const parsed = parseLastArray(response);
    if (!parsed) return queries;

    for (const raw of parsed) {
      const item = raw as Record<string, unknown>;
      if (!item || typeof item.query !== 'string' || item.query.trim().length < 8) continue;
      queries.push({
        id: `q_${randomUUID().slice(0, 8)}`,
        query: item.query as string,
        purpose: typeof item.purpose === 'string' ? item.purpose : '',
        category: this.normalizeCategory(item.category),
        priority: typeof item.priority === 'number' ? item.priority : queries.length + 1,
        focusTargets: Array.isArray(item.focusTargets) ? (item.focusTargets as string[]) : undefined,
        context: typeof item.context === 'string' ? item.context : undefined,
      });
    }
    return queries.slice(0, this.config.maxQueriesPerRound);
  }

  private normalizeCategory(c: unknown): DecomposedQuery['category'] {
    const valid = ['data_flow', 'bounds_check', 'type_analysis', 'reachability', 'auth_check', 'config_analysis', 'call_graph', 'side_effect', 'protocol', 'general'];
    return (typeof c === 'string' && valid.includes(c)) ? c as DecomposedQuery['category'] : 'general';
  }

  private parseSynthesis(response: string): SynthesisResult {
    const parsed = parseLastObject(response);
    if (parsed && (parsed.findings || parsed.gaps || parsed.attackSurfaceModel)) {
      return {
        findings: (Array.isArray(parsed.findings) ? parsed.findings : []).map((f: Record<string, unknown>) => ({
          type: (f.type as SynthesisResult['findings'][number]['type']) || 'observation',
          title: (f.title as string) || 'untitled',
          description: (f.description as string) || '',
          sourceQueryIds: Array.isArray(f.sourceQueryIds) ? (f.sourceQueryIds as string[]) : [],
          severity: f.severity as SynthesisResult['findings'][number]['severity'],
          nextAction: f.nextAction as string | undefined,
        })),
        gaps: Array.isArray(parsed.gaps) ? (parsed.gaps as string[]) : [],
        continueDecomposition: parsed.continueDecomposition === true,
        attackSurfaceModel: (parsed.attackSurfaceModel as string) || '',
        confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.5,
      };
    }
    // unstructured fallback — keep the prose, stop the loop (fail-safe)
    return {
      findings: [],
      gaps: [],
      continueDecomposition: false,
      attackSurfaceModel: response,
      confidence: 0.3,
    };
  }

  private extractFacts(text: string): ExtractedFact[] {
    const facts: ExtractedFact[] = [];
    const sentences = text.split(/[.!]\s+/).filter(s => s.length > 30);
    for (const s of sentences.slice(0, 10)) {
      const locationMatch = s.match(/(?:at |in |@\s*|file\s+)([^\s:]+\.\w+(?::\d+)?)/);
      facts.push({
        summary: s.slice(0, 120).trim(),
        evidence: s.trim(),
        confidence: 'medium',
        location: locationMatch?.[1],
      });
    }
    return facts;
  }

  private looksLikeRefusal(content: string): boolean {
    if (!content || content.trim().length < 10) return true;
    const lower = content.toLowerCase();
    const refusalPatterns = [
      "i can't assist", "i cannot assist", "i'm not able to", "i am not able to",
      "i can't help with", "i cannot help with", "against my guidelines",
      "i must decline", "i'm unable to", "i am unable to", "i won't be able to",
      "i can't provide", "i cannot provide",
    ];
    // Only treat as a refusal if the message is SHORT and refusal-y — a long
    // analysis that happens to contain "i cannot determine X from the code" is a
    // legitimate answer, not a decline.
    return content.trim().length < 400 && refusalPatterns.some(p => lower.includes(p));
  }

  /** Indirection so tests/mocks can stamp time; real impl uses wall clock. */
  private now(): number {
    return Date.now();
  }
}
