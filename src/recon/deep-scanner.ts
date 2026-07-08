/**
 * T3MP3ST Deep Scanner
 *
 * Multi-phase security scanner that connects the code ingestion pipeline
 * to the decomposition orchestrator with:
 *
 * 1. Cross-batch reasoning — findings reference related code across the repo
 * 2. Follow-up investigation — traces whether patterns lead to exploitable behavior
 * 3. Verification — adversarial pass refutes weak findings
 * 4. Deep reasoning — multi-round decomposition instead of single-pass pattern matching
 *
 * Pipeline:
 *   Phase 1: Ingest + Classify (code-ingest.ts)
 *   Phase 2: Broad sweep — quick single-pass to surface candidates
 *   Phase 3: Cross-reference — pull related blocks for each candidate
 *   Phase 4: Deep analysis — multi-round decomposition on high-value targets
 *   Phase 5: Adversarial verification — try to REFUTE each finding
 *   Phase 6: Synthesis — final report with confidence scores
 */
import { resolve } from 'path';
import { EventEmitter } from 'eventemitter3';
import { LLMBackbone } from '../llm/index.js';
import {
  type AnalysisUnit,
  type Exposure,
  ingestRepository,
  createPythonIngestConfig,
  formatUnitForLLM,
} from './code-ingest.js';

// =============================================================================
// LOCAL BATCH HELPERS (batchAnalysisUnits + formatBatchForLLM were removed from
// code-ingest in a later refactor — keep them here so deep-scanner stays self-contained)
// =============================================================================

function batchAnalysisUnits(units: AnalysisUnit[], maxCharsPerBatch: number): AnalysisUnit[][] {
  const batches: AnalysisUnit[][] = [];
  let current: AnalysisUnit[] = [];
  let currentSize = 0;
  for (const unit of units) {
    const unitSize = formatUnitForLLM(unit).length;
    if (currentSize + unitSize > maxCharsPerBatch && current.length > 0) {
      batches.push(current);
      current = [];
      currentSize = 0;
    }
    current.push(unit);
    currentSize += unitSize;
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

function formatBatchForLLM(units: AnalysisUnit[]): string {
  return units.map(u => formatUnitForLLM(u)).join('\n\n---\n\n');
}

// =============================================================================
// DEFAULT CONFIG
// =============================================================================

const DEFAULT_CONFIG = {
  broadSweepLimit: 80,
  crossRefLimit: 20,
  deepAnalysisLimit: 10,
  verificationLimit: 15,
  concurrency: 3,
  batchSize: 14000,
  verbose: true,
};

// =============================================================================
// TYPES
// =============================================================================

export interface DeepScanConfig {
  scanDirs: string[];
  language: 'python' | 'typescript' | 'go';
  exclude?: string[];
  /** Max targets for broad sweep (default: 80) */
  broadSweepLimit: number;
  /** Max findings to cross-reference (default: 20) */
  crossRefLimit: number;
  /** Max findings for deep analysis (default: 10) */
  deepAnalysisLimit: number;
  /** Max findings for verification (default: 15) */
  verificationLimit: number;
  /** Concurrent LLM calls (default: 3) */
  concurrency: number;
  /** Chars per LLM batch (default: 14000) */
  batchSize: number;
  /** LLM config */
  llmProvider: 'bedrock' | 'openrouter' | 'anthropic';
  llmModel: string;
  llmRegion?: string;
  llmApiKey?: string;
  verbose: boolean;
}

export interface CandidateFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  file: string;
  description: string;
  category: string;
  sourceBlockId: string;
  classification: Exposure;
  riskSignals: string[];
  phase: 'broad_sweep' | 'cross_ref' | 'deep_analysis';
}

export interface VerifiedFinding extends CandidateFinding {
  verified: boolean;
  confidence: number;
  verificationNotes: string;
  relatedBlocks: string[];
  exploitChain: string[];
  refutationAttempt: string;
}

export interface DeepScanResult {
  config: DeepScanConfig;
  ingestion: {
    totalFiles: number;
    totalBlocks: number;
    totalEdges: number;
    entryPoints: number;
    classifications: Record<Exposure, number>;
    durationMs: number;
  };
  broadSweep: {
    candidatesFound: number;
    durationMs: number;
    tokensUsed: number;
  };
  crossRef: {
    findingsEnriched: number;
    newFindingsFromContext: number;
    durationMs: number;
  };
  deepAnalysis: {
    rounds: number;
    findingsRefined: number;
    durationMs: number;
  };
  verification: {
    verified: number;
    refuted: number;
    uncertain: number;
    durationMs: number;
  };
  findings: VerifiedFinding[];
  totalDurationMs: number;
  totalCostEstimate: number;
}

export interface DeepScanEvents {
  'phase:start': { phase: string; detail: string };
  'phase:complete': { phase: string; durationMs: number };
  'finding:candidate': CandidateFinding;
  'finding:verified': VerifiedFinding;
  'finding:refuted': { id: string; reason: string };
  'progress': { message: string };
}

// =============================================================================
// DEEP SCANNER
// =============================================================================

export class DeepScanner extends EventEmitter<DeepScanEvents> {
  private config: DeepScanConfig;
  private llm: LLMBackbone;
  private allUnits: AnalysisUnit[] = [];
  private unitIndex: Map<string, AnalysisUnit> = new Map();
  private inputTokens = 0;
  private outputTokens = 0;

  constructor(config: DeepScanConfig) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.llm = this.createLLM();
  }

  private createLLM(): LLMBackbone {
    return new LLMBackbone({
      provider: this.config.llmProvider,
      model: this.config.llmModel,
      baseUrl: this.config.llmRegion,
      apiKey: this.config.llmApiKey,
      maxTokens: 4096,
      temperature: 0.2,
    });
  }

  private log(msg: string): void {
    if (this.config.verbose) console.log(msg);
    this.emit('progress', { message: msg });
  }

  // ===========================================================================
  // MAIN ENTRY
  // ===========================================================================

  async scan(): Promise<DeepScanResult> {
    const t0 = Date.now();
    const ingestionResult = this.runIngestion();
    const broadResult = await this.runBroadSweep();
    const crossRefResult = await this.runCrossReference(broadResult.candidates);
    const deepResult = await this.runDeepAnalysis(crossRefResult.enrichedFindings);
    const verifiedResult = await this.runVerification(deepResult.findings);
    const totalDuration = Date.now() - t0;
    const costEstimate = this.estimateCost();
    return {
      config: this.config,
      ingestion: ingestionResult,
      broadSweep: broadResult.stats,
      crossRef: crossRefResult.stats,
      deepAnalysis: deepResult.stats,
      verification: verifiedResult.stats,
      findings: verifiedResult.findings,
      totalDurationMs: totalDuration,
      totalCostEstimate: costEstimate,
    };
  }

  // ===========================================================================
  // PHASE 1: INGEST
  // ===========================================================================

  private validateScanDirs(): void {
    const scanRoot = process.env.T3MP3ST_SCAN_ROOT ? resolve(process.env.T3MP3ST_SCAN_ROOT) : null;
    for (const dir of this.config.scanDirs) {
      if (dir.includes('..')) throw new Error(`scanDir "${dir}" contains path traversal`);
      const abs = resolve(dir);
      if (scanRoot && abs !== scanRoot && !abs.startsWith(scanRoot + '/')) {
        throw new Error(`scanDir "${abs}" is outside T3MP3ST_SCAN_ROOT (${scanRoot})`);
      }
    }
  }

  private runIngestion() {
    this.validateScanDirs();
    const t0 = Date.now();
    this.emit('phase:start', { phase: 'ingest', detail: `${this.config.scanDirs.length} directories` });
    this.log('\n[PHASE 1] Code Ingestion');

    let totalFiles = 0, totalBlocks = 0;
    const allEntryPoints: string[] = [];

    for (const dir of this.config.scanDirs) {
      const config = createPythonIngestConfig(dir);
      config.excludeGlobs = [...(config.excludeGlobs ?? []), ...(this.config.exclude ?? []), 'tests', '__init__.py'];
      try {
        const result = ingestRepository(config);
        this.allUnits.push(...result.analysisUnits);
        totalFiles += result.stats.files;
        totalBlocks += result.stats.blocks;
        allEntryPoints.push(...result.entryPoints);
        const dirName = dir.split('/').pop();
        this.log(`  ${dirName}: ${result.stats.files} files, ${result.stats.blocks} blocks, ${result.entryPoints.length} entry points`);
      } catch {
        this.log(`  ${dir.split('/').pop()}: SKIPPED`);
      }
    }

    // Sort and index by block id
    this.allUnits.sort((a, b) => b.priority - a.priority);
    for (const u of this.allUnits) {
      this.unitIndex.set(u.block.id, u);
    }

    const classifications: Record<Exposure, number> = {
      exposed_externally: 0,
      exposed_internally: 0,
      attack_surface: 0,
      security_control: 0,
      neutral: 0,
    };
    for (const u of this.allUnits) classifications[u.exposure]++;

    const duration = Date.now() - t0;
    this.log(`\n  TOTAL: ${totalFiles} files, ${totalBlocks} blocks, ${allEntryPoints.length} entry points (${duration}ms)`);
    this.emit('phase:complete', { phase: 'ingest', durationMs: duration });
    return {
      totalFiles,
      totalBlocks,
      totalEdges: 0,
      entryPoints: allEntryPoints.length,
      classifications,
      durationMs: duration,
    };
  }

  // ===========================================================================
  // PHASE 2: BROAD SWEEP
  // ===========================================================================

  private async runBroadSweep() {
    const t0 = Date.now();
    this.emit('phase:start', { phase: 'broad_sweep', detail: `Top ${this.config.broadSweepLimit} targets` });
    this.log('\n[PHASE 2] Broad Sweep\n');

    const targets = this.allUnits
      .filter(u => u.exposure !== 'neutral')
      .slice(0, this.config.broadSweepLimit);

    const batches = batchAnalysisUnits(targets, this.config.batchSize);
    this.log(`  ${targets.length} targets → ${batches.length} batches`);

    const candidates: CandidateFinding[] = [];

    for (let i = 0; i < batches.length; i += this.config.concurrency) {
      const chunk = batches.slice(i, i + this.config.concurrency);
      const promises = chunk.map(async (batch, j) => {
        const batchNum = i + j + 1;
        return this.analyzeBatch(batch, batchNum, batches.length);
      });
      const results = await Promise.all(promises);
      for (const findings of results) candidates.push(...findings);
      this.log(`  [${Math.min(i + chunk.length, batches.length)}/${batches.length}] ${candidates.length} candidates`);
    }

    const duration = Date.now() - t0;
    this.emit('phase:complete', { phase: 'broad_sweep', durationMs: duration });
    return {
      candidates,
      stats: {
        candidatesFound: candidates.length,
        durationMs: duration,
        tokensUsed: this.inputTokens + this.outputTokens,
      },
    };
  }

  private async analyzeBatch(batch: AnalysisUnit[], batchNum: number, totalBatches: number): Promise<CandidateFinding[]> {
    const code = formatBatchForLLM(batch);
    const prompt = `Analyze these code blocks for security vulnerabilities. Each block includes metadata showing its classification, callers, callees, and risk signals.

IMPORTANT: Only report findings you are >70% confident are REAL and EXPLOITABLE — not code smells or theoretical concerns.
A "Context.TODO()" is only a finding if you can explain the specific bypass it enables.
An "open redirect" is only a finding if the URL is actually user-controlled (not a hardcoded internal path).
An "IDOR" is only a finding if there's NO authorization check visible in the block or its callers.

Return ONLY a JSON array (no markdown):
[{"severity": "critical|high|medium|low", "title": "...", "file": "...", "description": "Specific exploit path — what input, what happens, what the attacker gains", "category": "ssrf|auth|idor|redirect|injection|logic|crypto|disclosure"}]
Empty if nothing real: []

CODE (batch ${batchNum}/${totalBatches}):
${code}`;

    const response = await this.llmCall(prompt, 'Expert AppSec researcher. High-confidence findings only. JSON array output.');

    try {
      const match = response.match(/\[[\s\S]*\]/);
      if (!match) return [];
      const raw = JSON.parse(match[0]) as Array<{
        severity: string;
        title: string;
        file: string;
        description: string;
        category: string;
      }>;
      return raw.map((f, idx) => ({
        id: `sweep-${batchNum}-${idx}`,
        severity: f.severity as CandidateFinding['severity'],
        title: f.title,
        file: f.file,
        description: f.description,
        category: f.category,
        sourceBlockId: batch[0]?.block.id ?? '',
        classification: batch[0]?.exposure ?? 'neutral',
        riskSignals: batch[0]?.riskSignals ?? [],
        phase: 'broad_sweep' as const,
      }));
    } catch {
      return [];
    }
  }

  // ===========================================================================
  // PHASE 3: CROSS-REFERENCE
  // ===========================================================================

  private async runCrossReference(candidates: CandidateFinding[]) {
    const t0 = Date.now();
    this.emit('phase:start', { phase: 'cross_ref', detail: `${Math.min(candidates.length, this.config.crossRefLimit)} findings` });
    this.log('\n[PHASE 3] Cross-Reference Analysis\n');

    const sorted = [...candidates].sort((a, b) => {
      const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
    });
    const topCandidates = sorted.slice(0, this.config.crossRefLimit);

    const enriched: CandidateFinding[] = [];
    let newFindings = 0;

    for (let i = 0; i < topCandidates.length; i += this.config.concurrency) {
      const chunk = topCandidates.slice(i, i + this.config.concurrency);
      const promises = chunk.map(candidate => this.crossReferenceFinding(candidate));
      const results = await Promise.all(promises);
      for (const result of results) {
        enriched.push(result.finding);
        newFindings += result.newFindings.length;
        enriched.push(...result.newFindings);
      }
      this.log(`  [${Math.min(i + chunk.length, topCandidates.length)}/${topCandidates.length}] ${enriched.length} findings (+${newFindings} from context)`);
    }

    const duration = Date.now() - t0;
    this.emit('phase:complete', { phase: 'cross_ref', durationMs: duration });
    return {
      enrichedFindings: enriched,
      stats: {
        findingsEnriched: topCandidates.length,
        newFindingsFromContext: newFindings,
        durationMs: duration,
      },
    };
  }

  private async crossReferenceFinding(candidate: CandidateFinding): Promise<{ finding: CandidateFinding; newFindings: CandidateFinding[] }> {
    const relatedBlocks = this.findRelatedBlocks(candidate);
    if (relatedBlocks.length === 0) return { finding: candidate, newFindings: [] };

    const relatedContext = relatedBlocks
      .slice(0, 5)
      .map(u => formatUnitForLLM(u))
      .join('\n\n---\n\n');

    const prompt = `You previously identified this potential vulnerability:

FINDING: [${candidate.severity.toUpperCase()}] ${candidate.title}
FILE: ${candidate.file}
DESCRIPTION: ${candidate.description}

Here is RELATED code — callers, callees, and same-module functions that interact with the vulnerable code:

${relatedContext}

Based on this additional context:
1. Is the original finding CONFIRMED, UPGRADED, DOWNGRADED, or REFUTED?
2. Does the related code reveal additional vulnerabilities in the same flow?
3. What is the full exploit chain from entry point to impact?

Return JSON:
{
  "status": "confirmed|upgraded|downgraded|refuted",
  "updated_severity": "critical|high|medium|low",
  "updated_description": "refined description with full chain",
  "exploit_chain": ["step1", "step2", ...],
  "new_findings": [{"severity": "...", "title": "...", "file": "...", "description": "...", "category": "..."}]
}`;

    const response = await this.llmCall(prompt, 'Security analyst performing cross-reference verification. JSON output only.');

    try {
      const match = response.match(/\{[\s\S]*\}/);
      if (!match) return { finding: candidate, newFindings: [] };
      const result = JSON.parse(match[0]) as {
        status: string;
        updated_severity?: string;
        updated_description?: string;
        new_findings?: Array<{ severity: string; title: string; file: string; description: string; category: string }>;
      };

      if (result.status === 'refuted') {
        candidate.severity = 'low';
        candidate.description = `[REFUTED] ${result.updated_description ?? candidate.description}`;
      } else if (result.updated_severity) {
        candidate.severity = result.updated_severity as CandidateFinding['severity'];
      }
      if (result.updated_description) candidate.description = result.updated_description;

      const newFindings: CandidateFinding[] = (result.new_findings ?? []).map((f, idx) => ({
        id: `crossref-${candidate.id}-${idx}`,
        severity: f.severity as CandidateFinding['severity'],
        title: f.title,
        file: f.file,
        description: f.description,
        category: f.category,
        sourceBlockId: candidate.sourceBlockId,
        classification: candidate.classification,
        riskSignals: candidate.riskSignals,
        phase: 'cross_ref' as const,
      }));

      return { finding: candidate, newFindings };
    } catch {
      return { finding: candidate, newFindings: [] };
    }
  }

  private findRelatedBlocks(candidate: CandidateFinding): AnalysisUnit[] {
    const related: AnalysisUnit[] = [];
    const candidateFile = candidate.file;

    for (const unit of this.allUnits) {
      if (related.length >= 8) break;

      if (unit.block.path === candidateFile && unit.block.id !== candidate.sourceBlockId) {
        related.push(unit);
        continue;
      }

      const fileBase = candidate.file.split('/').pop()?.replace('.py', '') ?? '';
      if (unit.callees.some(c => c.includes(fileBase))) {
        related.push(unit);
        continue;
      }

      const sourceUnit = this.unitIndex.get(candidate.sourceBlockId);
      if (sourceUnit && sourceUnit.callees.includes(unit.block.id)) {
        related.push(unit);
        continue;
      }

      if (sourceUnit && unit.riskSignals.some(s => sourceUnit.riskSignals.includes(s) && s !== 'handles_identifiers')) {
        if (unit.exposure !== 'neutral' && unit.block.path !== candidateFile) {
          related.push(unit);
        }
      }
    }

    return related;
  }

  // ===========================================================================
  // PHASE 4: DEEP ANALYSIS (multi-round decomposition)
  // ===========================================================================

  private async runDeepAnalysis(candidates: CandidateFinding[]) {
    const t0 = Date.now();
    this.emit('phase:start', { phase: 'deep_analysis', detail: `Top ${this.config.deepAnalysisLimit} findings` });
    this.log('\n[PHASE 4] Deep Analysis (multi-round)\n');

    const highValue = candidates
      .filter(c => c.severity === 'critical' || c.severity === 'high')
      .slice(0, this.config.deepAnalysisLimit);

    let rounds = 0;
    for (let i = 0; i < highValue.length; i += this.config.concurrency) {
      const chunk = highValue.slice(i, i + this.config.concurrency);
      const promises = chunk.map(candidate => this.deepAnalyze(candidate));
      const results = await Promise.all(promises);
      rounds += results.reduce((s, r) => s + r.rounds, 0);
      this.log(`  [${Math.min(i + chunk.length, highValue.length)}/${highValue.length}] deep-analyzed (${rounds} total rounds)`);
    }

    const duration = Date.now() - t0;
    this.emit('phase:complete', { phase: 'deep_analysis', durationMs: duration });
    return {
      findings: candidates,
      stats: { rounds, findingsRefined: highValue.length, durationMs: duration },
    };
  }

  private async deepAnalyze(candidate: CandidateFinding): Promise<{ rounds: number }> {
    const related = this.findRelatedBlocks(candidate);
    const relatedContext = related
      .slice(0, 3)
      .map(u => formatUnitForLLM(u))
      .join('\n\n');

    const r1 = await this.llmCall(
      `Trace the COMPLETE data flow for this vulnerability:

FINDING: [${candidate.severity.toUpperCase()}] ${candidate.title}
FILE: ${candidate.file}
DESCRIPTION: ${candidate.description}

RELATED CODE:
${relatedContext}

Questions to answer:
1. Where does the user-controlled input ORIGINATE? (HTTP param, form field, header, etc.)
2. What TRANSFORMATIONS does it undergo before reaching the sink?
3. Is there ANY validation, sanitization, or allowlist applied?
4. What is the EXACT sink where the dangerous operation happens?
5. What does a successful exploit LOOK LIKE? (specific request/response)

Be precise. If you can't trace the full path from input to sink, say so.`,
      'Data flow analyst. Precise, evidence-based. Cite specific function names and parameters.',
    );

    const r2 = await this.llmCall(
      `Given this data flow analysis:

${r1}

Now answer:
1. What PRECONDITIONS must be met for exploitation? (auth level, feature flags, account type)
2. Are there any BYPASSES for the protections identified?
3. What is the MINIMUM privilege level needed to trigger this?
4. Is there a SIMPLER path to the same sink that avoids the protections?
5. Rate exploitability: TRIVIAL / MODERATE / COMPLEX / THEORETICAL

Be adversarial — look for the path of least resistance.`,
      'Offensive security specialist. Find the path of least resistance.',
    );

    candidate.description = `${candidate.description}\n\n[DEEP ANALYSIS]\nData flow: ${r1.substring(0, 300)}\nExploitability: ${r2.substring(0, 300)}`;
    return { rounds: 2 };
  }

  // ===========================================================================
  // PHASE 5: ADVERSARIAL VERIFICATION
  // ===========================================================================

  private async runVerification(candidates: CandidateFinding[]) {
    const t0 = Date.now();
    this.emit('phase:start', { phase: 'verification', detail: `${Math.min(candidates.length, this.config.verificationLimit)} findings` });
    this.log('\n[PHASE 5] Adversarial Verification\n');

    const toVerify = candidates
      .filter(c => c.severity === 'critical' || c.severity === 'high' || c.severity === 'medium')
      .slice(0, this.config.verificationLimit);

    const verified: VerifiedFinding[] = [];
    let verifiedCount = 0, refutedCount = 0, uncertainCount = 0;

    for (let i = 0; i < toVerify.length; i += this.config.concurrency) {
      const chunk = toVerify.slice(i, i + this.config.concurrency);
      const promises = chunk.map(candidate => this.verifySingle(candidate));
      const results = await Promise.all(promises);
      for (const result of results) {
        verified.push(result);
        if (result.verified) verifiedCount++;
        else if (result.confidence < 0.3) refutedCount++;
        else uncertainCount++;
      }
      this.log(`  [${Math.min(i + chunk.length, toVerify.length)}/${toVerify.length}] verified:${verifiedCount} refuted:${refutedCount} uncertain:${uncertainCount}`);
    }

    const lowFindings: VerifiedFinding[] = candidates
      .filter(c => c.severity === 'low')
      .map(c => ({
        ...c,
        verified: false,
        confidence: 0.4,
        verificationNotes: 'Low severity — not verified',
        relatedBlocks: [],
        exploitChain: [],
        refutationAttempt: '',
      }));

    const allVerified = [
      ...verified.filter(f => f.verified || f.confidence >= 0.5),
      ...lowFindings,
    ].sort((a, b) => {
      const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
    });

    const duration = Date.now() - t0;
    this.emit('phase:complete', { phase: 'verification', durationMs: duration });
    return {
      findings: allVerified,
      stats: { verified: verifiedCount, refuted: refutedCount, uncertain: uncertainCount, durationMs: duration },
    };
  }

  private async verifySingle(candidate: CandidateFinding): Promise<VerifiedFinding> {
    const related = this.findRelatedBlocks(candidate);
    const relatedContext = related
      .slice(0, 3)
      .map(u => `${u.block.path}::${u.block.name}:\n${u.block.body.substring(0, 500)}`)
      .join('\n\n');

    const prompt = `You are a SKEPTICAL security reviewer. Your job is to try to REFUTE this finding. Default to refuted=true if uncertain.

FINDING: [${candidate.severity.toUpperCase()}] ${candidate.title}
FILE: ${candidate.file}
CATEGORY: ${candidate.category}
DESCRIPTION: ${candidate.description}

RELATED CODE FOR CONTEXT:
${relatedContext}

Try to REFUTE this finding by answering:
1. Is there ALREADY a protection that the original analysis missed? (auth check, validation, allowlist, WAF, etc.)
2. Is the "user-controlled" input actually user-controlled, or is it from a trusted internal source?
3. Does exploitation require unrealistic preconditions? (e.g., admin access to exploit admin-only features)
4. Is the impact overstated? (e.g., "open redirect" to a hardcoded internal path isn't really exploitable)
5. Could this be a FALSE POSITIVE from pattern matching rather than real analysis?

Return JSON:
{
  "verdict": "CONFIRMED|REFUTED|UNCERTAIN",
  "confidence": 0.0,
  "reasoning": "Why you believe this verdict",
  "refutation_attempt": "Your best argument for why this ISN'T a real vulnerability",
  "exploit_chain": ["step1", "step2"],
  "related_blocks": ["file::function"]
}`;

    const response = await this.llmCall(prompt, 'Adversarial security reviewer. Default skeptical. JSON output.');

    try {
      const match = response.match(/\{[\s\S]*\}/);
      if (!match) {
        return {
          ...candidate,
          verified: false,
          confidence: 0.5,
          verificationNotes: 'Parse error',
          relatedBlocks: [],
          exploitChain: [],
          refutationAttempt: '',
        };
      }
      const result = JSON.parse(match[0]) as {
        verdict: string;
        confidence?: number;
        reasoning?: string;
        refutation_attempt?: string;
        exploit_chain?: string[];
        related_blocks?: string[];
      };
      const isVerified = result.verdict === 'CONFIRMED';
      const confidence = result.confidence ?? 0.5;
      if (!isVerified) {
        this.emit('finding:refuted', { id: candidate.id, reason: result.reasoning ?? '' });
      }
      return {
        ...candidate,
        verified: isVerified,
        confidence,
        verificationNotes: result.reasoning ?? '',
        relatedBlocks: result.related_blocks ?? [],
        exploitChain: result.exploit_chain ?? [],
        refutationAttempt: result.refutation_attempt ?? '',
      };
    } catch {
      return {
        ...candidate,
        verified: false,
        confidence: 0.5,
        verificationNotes: 'Parse error',
        relatedBlocks: [],
        exploitChain: [],
        refutationAttempt: '',
      };
    }
  }

  // ===========================================================================
  // UTILITIES
  // ===========================================================================

  private async llmCall(userPrompt: string, systemPrompt: string): Promise<string> {
    const response = await this.llm.chat(
      [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      { maxTokens: 4096, temperature: 0.2 },
    );
    if (response.usage) {
      this.inputTokens += response.usage.promptTokens;
      this.outputTokens += response.usage.completionTokens;
    }
    return response.content;
  }

  private estimateCost(): number {
    const inputCost = (this.inputTokens / 1_000_000) * 3;
    const outputCost = (this.outputTokens / 1_000_000) * 15;
    return inputCost + outputCost;
  }
}

// =============================================================================
// FACTORY
// =============================================================================

export function createDeepScanner(config: DeepScanConfig): DeepScanner {
  return new DeepScanner(config);
}
