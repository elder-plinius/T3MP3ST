/**
 * T3MP3ST (TEMPEST)
 * Tactical Execution Multi-agent Platform for Elite Security Testing
 *
 * A sophisticated multi-agent framework for penetration testing and red team operations.
 *
 * @example
 * ```typescript
 * import { createTempest } from 't3mp3st';
 *
 * const tempest = createTempest({
 *   name: 'Operation Midnight',
 *   llm: { provider: 'openrouter', model: 'anthropic/claude-opus-4-6' },
 *   opsec: { level: 'covert' },
 * });
 *
 * // Spawn operators
 * const recon = tempest.cell.spawnOperator('Ghost-1', 'recon');
 *
 * // Start operations
 * tempest.command.start();
 * ```
 */

import { EventEmitter } from 'eventemitter3';

// =============================================================================
// TYPE EXPORTS
// =============================================================================

export * from './types/index.js';

// =============================================================================
// MODULE EXPORTS
// =============================================================================

// Configuration
export { config, getApiKey, setApiKey, hasApiKey, getLLMConfig, getConfiguredProviders, AVAILABLE_MODELS } from './config/index.js';
export type { TempestSettings, ModelInfo } from './config/index.js';

// LLM
export {
  LLMBackbone,
  createAnthropicBackbone,
  createOpenRouterBackbone,
  createOpenAIBackbone,
  createMockBackbone,
  createLocalBackbone,
  createBestAvailableBackbone,
} from './llm/index.js';
export type { LLMEvents, LLMProviderAdapter, ChatOptions } from './llm/index.js';

// Operators
export {
  OperatorAgent,
  OperatorCell,
  createOperator,
  createBalancedTeam,
  createStealthTeam,
  createBreachTeam,
  ARCHETYPE_PROFILES,
  ARCHETYPE_CAPABILITIES,
  ARCHETYPE_TECHNIQUES,
  PHASE_ARCHETYPES,
  KILL_CHAIN_ORDER,
  PHASE_DESCRIPTIONS,
  FAMILY_PHASES,
  FAMILY_ARCHETYPES,
  getPhasesForFamily,
  getArchetypesForFamily,
} from './operators/index.js';
export type { OperatorEvents, CellEvents, ArchetypeProfile } from './operators/index.js';

// Mission
export {
  MissionControl,
  TaskQueue,
  createDefaultRoE,
  createStrictRoE,
  createReconTasks,
  createVulnScanTasks,
  createCodeScanTasks,
  createFindingValidationTasks,
} from './mission/index.js';
export type { MissionEvents, TaskQueueEvents } from './mission/index.js';

// Validator
export { FindingValidator } from './agent/validator.js';
export type { ValidatorResult, ValidationVerdict } from './agent/validator.js';

// Target
export {
  TargetEnvironment,
  createTargetFromUrl,
  createTargetFromIP,
  createDMZArchitecture,
} from './target/index.js';
export type { TargetEvents } from './target/index.js';

// Evidence
export {
  EvidenceVault,
  createFindingFromVuln,
  createMisconfigFinding,
  SEVERITY_SCORES,
  cvssToSeverity,
} from './evidence/index.js';
export type { EvidenceVaultEvents } from './evidence/index.js';

// Arsenal
export { Arsenal, successResult, failResult, createToolContext, BUILTIN_TOOLS, EXTERNAL_TOOLS, isToolAvailable, runSubprocess } from './arsenal/index.js';
export type { ArsenalEvents, ToolExecution } from './arsenal/index.js';

// Agent Loop
export { AgentLoop, createAgentLoop, runAgentTask } from './agent/index.js';
export type { AgentLoopOptions, AgentStep, AgentResult, AgentEvents } from './agent/index.js';

// OPSEC
export {
  OpsecController,
  createSilentOpsecConfig,
  createAggressiveOpsecConfig,
  createBalancedOpsecConfig,
} from './opsec/index.js';
export type { OpsecEvents, IOC } from './opsec/index.js';

// Comms
export {
  CommsChannel,
  createMissionComms,
  initializeTeamChannels,
  MESSAGE_FORMATS,
  PRIORITY_INDICATORS,
} from './comms/index.js';
export type { CommsEvents, Channel } from './comms/index.js';

// Analysis
export { AnalysisEngine, createAnalysisEngine } from './analysis/index.js';

// Benchmark
export {
  Benchmark,
  createBenchmark,
  scoreBenchmark,
  matchFinding,
  aggregateMetrics,
  BENCHMARK_CHALLENGES,
} from './benchmark/index.js';
export type {
  BenchmarkChallenge,
  BenchmarkMetrics,
  BenchmarkRunResult,
  BenchmarkSuiteResult,
  BenchmarkEvents,
  GroundTruthVuln,
} from './benchmark/index.js';

// Prompts
export {
  OPERATOR_SYSTEM_PROMPTS,
  COGNITION_PROMPTS,
  REASONING_PROMPTS,
  WORKFLOW_PROMPTS,
  SPECIALIZED_PROMPTS,
  PROMPT_TEMPLATES,
  GENERAL_SYSTEM_PROMPT,
  GENERAL_REPLAN_PROMPT,
} from './prompts/index.js';

// General (Autonomous Op Orchestrator)
export { OpGeneral } from './general/index.js';
export type {
  Directive,
  OpPlan,
  OpPlanTarget,
  OpPlanObjective,
  OpPlanOperator,
  OpPlanPhaseStrategy,
  OpPlanRoE,
  OpPlanContingency,
  OpPlanHuntLane,
  OpPlanAuthorityReceipt,
  OpPlanEvidenceContract,
  OpPlanWorkOrder,
  OpPlanToolPlan,
  OpPlanCritique,
  OpPlanMissionGate,
  OpPlanLearningDirective,
  GeneralPlanReview,
  GeneralSitrep,
  StrategicAssessment,
  GeneralEvents,
} from './general/index.js';

// Decomposition Orchestrator (multi-model task decomposition)
export { DecompositionOrchestrator } from './orchestration/index.js';
export type {
  DecompositionConfig,
  DecompositionResult,
  DecomposedQuery,
  QueryResult,
  SynthesisResult,
  DecompositionEvents,
} from './orchestration/index.js';

// Stubs (advanced modules)
export * from './stubs/index.js';

// =============================================================================
// TYPE IMPORTS
// =============================================================================

import {
  KillChainPhase,
} from './types/index.js';

import type {
  TempestConfig,
  LLMConfig,
  RuntimeHooks,
  OperatorArchetype,
  CommandEvents,
  Finding,
} from './types/index.js';

// Re-export commonly used types
export { KillChainPhase } from './types/index.js';
export type { OpsecConfig, Finding, Credential, Target, DetectionEvent } from './types/index.js';

import { OperatorCell, OperatorAgent, ARCHETYPE_PROFILES, getArchetypesForFamily } from './operators/index.js';
import { MissionControl } from './mission/index.js';
import { TargetEnvironment } from './target/index.js';
import { EvidenceVault } from './evidence/index.js';
import { Arsenal, BUILTIN_TOOLS, EXTERNAL_TOOLS } from './arsenal/index.js';
import { OpsecController, createBalancedOpsecConfig } from './opsec/index.js';
import { CommsChannel } from './comms/index.js';
import { AnalysisEngine } from './analysis/index.js';
import { LLMBackbone } from './llm/index.js';
import { getLLMConfig } from './config/index.js';
import { AgentLoop } from './agent/index.js';
import { OpGeneral } from './general/index.js';

// Stubs for advanced modules
import {
  ExploitEngine,
  ScannerOrchestrator,
  BrowserAutomation,
  BenchmarkRunner,
  ReasoningEngine,
  CognitionEngine,
  SwarmController,
  CloudSecurityEngine,
  PersistenceController,
  LearningEngine,
  KnowledgeBase,
  ProtocolHandler,
  EvasionEngine,
  ReportingEngine,
  WorkflowOrchestrator,
} from './stubs/index.js';

// =============================================================================
// TEMPEST COMMAND
// =============================================================================

/**
 * TEMPEST Command - Main orchestration controller
 */
export class TempestCommand extends EventEmitter<CommandEvents> {
  public readonly name: string;
  public missionFamily: import('./types/index.js').MissionFamily | undefined;
  public scanOptions: { spiderScope?: string; spiderDepth?: number; spiderMaxPages?: number } = {};
  public sandboxOptions: { networkMode?: string; durationSec?: number; alias?: string } = {};
  /** Per-tool parameter defaults injected at execution time — credentials never enter the LLM prompt */
  public toolDefaults: Record<string, Record<string, unknown>> = {};
  public readonly cell: OperatorCell;
  public readonly mission: MissionControl;
  public readonly targetEnv: TargetEnvironment;
  public readonly vault: EvidenceVault;
  public readonly arsenal: Arsenal;
  public readonly opsec: OpsecController;
  public readonly comms: CommsChannel;
  public readonly analysis: AnalysisEngine;
  public readonly llm: LLMBackbone;

  // Advanced modules
  public readonly exploit: ExploitEngine;
  public readonly scanner: ScannerOrchestrator;
  public readonly browser: BrowserAutomation;
  public readonly benchmark: BenchmarkRunner;
  public readonly reasoning: ReasoningEngine;

  // Elite modules
  public readonly cognition: CognitionEngine;
  public readonly swarm: SwarmController;
  public readonly cloud: CloudSecurityEngine;
  public readonly persistence: PersistenceController;
  public readonly learning: LearningEngine;

  // Foundational modules
  public readonly knowledge: KnowledgeBase;
  public readonly protocols: ProtocolHandler;
  public readonly evasion: EvasionEngine;
  public readonly reporting: ReportingEngine;
  public readonly workflow: WorkflowOrchestrator;

  // Autonomous Op General
  public readonly general: OpGeneral;

  private running: boolean = false;
  private paused: boolean = false;
  private stallReason: string | null = null;
  private tickInterval: NodeJS.Timeout | null = null;
  private tickCount: number = 0;
  private hooks: RuntimeHooks;
  /** Mission-level abort controller — aborted on stop() to cancel all sidecar HTTP calls */
  private missionController: AbortController = new AbortController();
  /** Tracks when each task dispatch started, for backstop timeout detection */
  private dispatchStartTime: Map<string, number> = new Map();

  constructor(config: TempestConfig) {
    super();
    this.name = config.name;
    this.missionFamily = config.missionFamily;
    this.hooks = config.hooks || {};

    // Initialize LLM backbone
    this.llm = new LLMBackbone(config.llm);

    // Initialize core subsystems
    this.cell = new OperatorCell(config.operators?.maxConcurrent || 10, this.llm);
    this.mission = new MissionControl();
    this.targetEnv = new TargetEnvironment();
    this.vault = new EvidenceVault();
    this.arsenal = new Arsenal();
    this.opsec = new OpsecController(config.opsec);
    this.comms = new CommsChannel();

    // Register built-in tools and external CLI wrappers
    this.arsenal.registerMany(BUILTIN_TOOLS);
    this.arsenal.registerMany(EXTERNAL_TOOLS);

    // Inject LLM backbone so tools like llm_code_review and llm_validate_finding can call it
    this.arsenal.setLLM(this.llm);

    // Advanced modules
    this.exploit = new ExploitEngine();
    this.scanner = new ScannerOrchestrator();
    this.browser = new BrowserAutomation();
    this.benchmark = new BenchmarkRunner();
    this.reasoning = new ReasoningEngine(this.llm);

    // Elite modules
    this.cognition = new CognitionEngine(this.llm);
    this.swarm = new SwarmController();
    this.cloud = new CloudSecurityEngine();
    this.persistence = new PersistenceController();
    this.learning = new LearningEngine();

    // Foundational modules
    this.knowledge = new KnowledgeBase();
    this.protocols = new ProtocolHandler();
    this.evasion = new EvasionEngine();
    this.reporting = new ReportingEngine();
    this.workflow = new WorkflowOrchestrator(this.llm.getClient());

    // Autonomous Op General
    this.general = new OpGeneral(this.llm);

    // Analysis depends on other subsystems
    this.analysis = new AnalysisEngine(
      this.vault,
      this.targetEnv,
      this.mission,
      this.opsec
    );

    // Wire up events
    this.setupEventForwarding();

    // Register custom tools
    if (config.tools) {
      for (const tool of config.tools) {
        this.arsenal.register(tool);
      }
    }
  }

  /**
   * Setup event forwarding from subsystems
   */
  private setupEventForwarding(): void {
    // Forward operator events
    this.cell.on('operator:spawned', (op) => {
      this.emit('operator:spawned', { id: op.id, archetype: op.archetype });
      this.hooks.onOperatorSpawned?.({ id: op.id, archetype: op.archetype });
    });

    this.cell.on('operator:burned', (op) => {
      this.emit('operator:burned', { id: op.id });
    });

    // Forward detection events
    this.opsec.on('detection:triggered', (event) => {
      this.emit('detection:triggered', event);
      this.hooks.onDetectionEvent?.(event);
    });

    this.opsec.on('opsec:abort_recommended', ({ reason }) => {
      this.emit('abort:recommended', reason);
    });

    // Forward mission events
    this.mission.on('mission:completed', () => {
      this.stop();
    });

    this.mission.on('mission:aborted', () => {
      this.stop();
    });

    this.mission.on('mission:phase_changed', ({ mission, newPhase }) => {
      this.emit('mission:phase_changed', { missionId: mission.id, phase: newPhase });
      this.hooks.onMissionPhaseChange?.(mission.id, newPhase);
    });

    // Auto-generate tasks when a target is added to an active mission.
    // Only mark "seeded" if a mission actually exists — otherwise generateTasksForTarget
    // no-ops and we'd falsely suppress the tick-loop seeding (leaving operators idle).
    this.targetEnv.on('target:added', (target) => {
      if (this.mission.getActiveMission()) {
        this.mission.generateTasksForTarget(target.address, this.scanOptions);
        this.taskSeeded = true;
      }
    });
  }

  /**
   * Setup event forwarding for an operator
   */
  private setupOperatorEvents(operator: OperatorAgent): void {
    operator.on('finding:discovered', ({ finding }) => {
      const activeMission = this.mission.getActiveMission();
      if (activeMission) {
        finding.missionId = activeMission.id;
        finding.missionName = activeMission.name;
      }
      this.vault.addFinding(finding);
      this.emit('finding:discovered', { finding, operatorId: operator.id });
      this.hooks.onFindingDiscovered?.(finding, { id: operator.id });

      // Sync finding intelligence back to the target object
      this.syncFindingToTarget(finding);
    });

    operator.on('credential:harvested', ({ credential }) => {
      this.vault.addCredential(credential);
      this.emit('credential:harvested', { credential, operatorId: operator.id });
      this.hooks.onCredentialHarvested?.(credential, { id: operator.id });

      // Sync credential to the target
      if (credential.targetId) {
        const target = this.targetEnv.getTarget(credential.targetId);
        if (target) {
          target.credentials = target.credentials || [];
          target.credentials.push(credential);
        }
      }
    });

    operator.on('status:changed', ({ oldStatus: _oldStatus }) => {
      this.hooks.onOperatorStateChange?.({ id: operator.id }, operator.state);
    });
  }

  /**
   * Parse a finding and update the target's services/vulnerabilities.
   * This is the intelligence pipeline that feeds data between phases.
   */
  private syncFindingToTarget(finding: Finding): void {
    // Find the target this finding belongs to
    let target = this.targetEnv.getTarget(finding.targetId);
    if (!target) {
      // Try to match by scanning all targets
      const allTargets = this.targetEnv.getAllTargets();
      target = allTargets.find(t => finding.description.includes(t.address)) || allTargets[0] || null;
    }
    if (!target) return;

    const desc = finding.description.toLowerCase();
    const title = finding.title.toLowerCase();

    // Detect service-related findings and add to target.services
    if (title.includes('open port') || title.includes('service') || desc.includes('open port')) {
      this.extractServicesFromFinding(target.id, finding);
    }

    // Detect vulnerability findings and add to target.vulnerabilities
    if (finding.severity !== 'info' || title.includes('vuln') || title.includes('cve') ||
        title.includes('injection') || title.includes('xss') || title.includes('ssrf')) {
      this.targetEnv.addVulnerability(target.id, {
        id: finding.id,
        name: finding.title,
        description: finding.description,
        severity: finding.severity,
        cvss: finding.cvss,
        cve: finding.cve,
        cwe: finding.cwe,
        exploitAvailable: finding.exploitedAt != null,
        references: finding.references,
      });
    }

    // Update target status based on severity
    if (finding.severity === 'critical' || finding.severity === 'high') {
      this.targetEnv.setStatus(target.id, 'vulnerable');
    }
    if (finding.exploitedAt) {
      this.targetEnv.setStatus(target.id, 'exploited');
    }
  }

  /**
   * Extract service info from port/service findings and add to target
   */
  private extractServicesFromFinding(targetId: string, finding: Finding): void {
    // Try to parse port numbers from the finding description
    const portMatches = finding.description.matchAll(/(\d+)\/(tcp|udp)\s+(open)\s+(\S+)/gi);
    for (const match of portMatches) {
      const port = parseInt(match[1], 10);
      const protocol = match[2];
      const name = match[4];
      this.targetEnv.addService(targetId, { name, port, protocol });
    }

    // Also try simpler pattern: "port 80", "port 443 open"
    const simpleMatches = finding.description.matchAll(/port[s]?\s*[:=]?\s*(\d+(?:\s*,\s*\d+)*)/gi);
    for (const match of simpleMatches) {
      const ports = match[1].split(',').map(p => parseInt(p.trim(), 10));
      for (const port of ports) {
        if (!isNaN(port)) {
          const existing = this.targetEnv.getTarget(targetId);
          const alreadyHas = existing?.services?.some(s => s.port === port);
          if (!alreadyHas) {
            const knownServices: Record<number, string> = {
              21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
              80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
              3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 6379: 'redis',
              8080: 'http-proxy', 8443: 'https-alt', 27017: 'mongodb',
            };
            this.targetEnv.addService(targetId, {
              name: knownServices[port] || 'unknown',
              port,
              protocol: 'tcp',
            });
          }
        }
      }
    }
  }

  // ===========================================================================
  // LIFECYCLE
  // ===========================================================================

  /** Set the mission family before start() — controls phases and task factories. */
  public setMissionFamily(family: import('./types/index.js').MissionFamily): void {
    this.missionFamily = family;
  }

  /** Set spider/crawl options that are threaded into RECON task descriptions. */
  public setScanOptions(opts: { spiderScope?: string; spiderDepth?: number; spiderMaxPages?: number }): void {
    this.scanOptions = { ...this.scanOptions, ...opts };
  }

  /** Set dynamic sandbox execution options threaded into WEAPONIZE binary task descriptions. */
  public setSandboxOptions(opts: { networkMode?: string; durationSec?: number; alias?: string }): void {
    this.sandboxOptions = { ...this.sandboxOptions, ...opts };
  }

  /**
   * Infer the best mission family from a raw target string.
   * Mirrors the detectTargetFamily() logic in the frontend so API callers
   * get the same routing without going through the UI.
   */
  public static detectMissionFamily(target: string): import('./types/index.js').MissionFamily {
    if (!target) return 'web_api';
    const h = target.trim().toLowerCase().replace(/^https?:\/\//, '');

    // Code / Supply Chain
    if (/^(www\.)?(github|gitlab|bitbucket)\.com\/[^\/\s]+\/[^\/\s]/.test(h)) return 'code_supply_chain';
    if (/^git@/.test(target.trim()) || h.endsWith('.git')) return 'code_supply_chain';
    if (/codeberg\.org\/[^\/]+\/[^\/]/.test(h)) return 'code_supply_chain';

    // Smart Contract
    if (/^0x[0-9a-f]{40}$/i.test(h) || h.endsWith('.eth')) return 'smart_contract';
    if (/etherscan\.io|bscscan\.com|polygonscan\.com/.test(h)) return 'smart_contract';

    // Cloud Infra
    if (/\.amazonaws\.com|\.cloudfront\.net|\.elasticbeanstalk\.com/.test(h)) return 'cloud_infra';
    if (/\.googleapis\.com|\.appspot\.com|\.run\.app|\.cloudfunctions\.net/.test(h)) return 'cloud_infra';
    if (/\.azure\.com|\.azurewebsites\.net|\.windows\.net/.test(h)) return 'cloud_infra';

    // AI Red Team
    if (/api\.openai\.com|platform\.openai\.com|api\.anthropic\.com/.test(h)) return 'ai_red_team';
    if (/\.huggingface\.co|api\.together\.xyz|api\.replicate\.com|api\.mistral\.ai|api\.groq\.com/.test(h)) return 'ai_red_team';

    // Raw IPs / CIDRs / localhost → web_api (nmap-first recon handles the rest)
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/.test(h)) return 'web_api';
    if (/^[0-9a-f:]+$/.test(h) && h.includes(':')) return 'web_api';

    return 'web_api';
  }

  /**
   * Start command operations.
   * Automatically creates and starts a mission if none is active.
   */
  public start(): void {
    if (this.running) return;

    // Auto-create a mission if none exists
    this.ensureMission();

    // Reset the seed flag so the first tick generates tasks for targets added
    // BEFORE start(). A pre-mission target:added event leaves taskSeeded stale-true
    // (generateTasksForTarget no-ops with no active mission), which would otherwise
    // skip seeding forever and leave every operator idle.
    this.taskSeeded = false;

    // Fresh abort controller for this mission — propagated to sidecar calls via arsenal
    this.missionController = new AbortController();
    this.arsenal.setAbortSignal(this.missionController.signal);

    this.running = true;
    this.paused = false;
    this.stallReason = null;
    this.emit('command:started');

    // Start tick loop (1 second interval). Catch any tick error so a single bad tick
    // (e.g. a spawn hitting the pool cap) can never take down the whole server process.
    this.tickInterval = setInterval(() => {
      this.tick().catch(err => console.error('[T3MP3ST] tick error (mission continues):', err instanceof Error ? err.message : err));
    }, 1000);
  }

  /**
   * Ensure an active mission exists. Creates and starts one if needed.
   */
  private ensureMission(): void {
    if (this.mission.getActiveMission()) return;

    const targets = this.targetEnv.getAllTargets();
    const targetNames = targets.map(t => t.address).join(', ') || 'pending targets';

    const mission = this.mission.createMission({
      name: `${this.name} — Auto Mission`,
      description: `Automated mission for ${targetNames}`,
      objectives: ['Enumerate attack surface', 'Identify vulnerabilities', 'Validate findings'],
      family: this.missionFamily,
    });
    this.mission.startMission(mission.id);
  }

  /**
   * Stop command operations
   */
  public stop(): void {
    if (!this.running) return;

    this.running = false;
    this.taskSeeded = false;
    if (this.tickInterval) {
      clearInterval(this.tickInterval);
      this.tickInterval = null;
    }
    // Abort all in-flight operator tasks (stops LLM fetch calls and local agent child processes)
    for (const controller of this.activeControllers.values()) {
      try { controller.abort(); } catch { /* noop */ }
    }
    this.activeControllers.clear();
    this.activeDispatches.clear();
    this.dispatchStartTime.clear();
    // Abort all in-flight sidecar HTTPS calls (binary/sandbox/cloud containers)
    try { this.missionController.abort(); } catch { /* noop */ }
    this.arsenal.setAbortSignal(null);
    this.emit('command:stopped');
  }

  /**
   * Pause operations, optionally recording the reason for the stall.
   */
  public pause(reason?: string): void {
    if (!this.running || this.paused) return;
    this.paused = true;
    if (reason) this.stallReason = reason;
    this.emit('command:paused');
  }

  /**
   * Resume operations
   */
  public resume(): void {
    if (!this.running || !this.paused) return;
    this.paused = false;
    this.emit('command:resumed');
  }

  /**
   * Check if running
   */
  public isRunning(): boolean {
    return this.running && !this.paused;
  }

  /** Track in-flight task promises so we don't double-dispatch */
  private activeDispatches: Set<string> = new Set();

  /** AbortControllers for in-flight operator tasks — aborted on stop() */
  private activeControllers: Map<string, AbortController> = new Map();

  /** Track whether we've seeded initial tasks for the current mission */
  private taskSeeded: boolean = false;

  /** Returns the task-dispatch timeout in ms, configurable via T3MP3ST_TASK_TIMEOUT_MS. */
  private resolveTaskTimeoutMs(): number {
    const envVal = process.env.T3MP3ST_TASK_TIMEOUT_MS;
    if (envVal) {
      const parsed = parseInt(envVal, 10);
      if (!isNaN(parsed) && parsed > 0) return parsed;
    }
    return 5 * 60 * 1000; // 5 minutes default
  }

  /**
   * Main tick loop — seeds tasks, dispatches to operators, advances phases
   */
  private async tick(): Promise<void> {
    if (this.paused) return;

    this.tickCount++;
    this.emit('tick', this.tickCount);

    // Check OPSEC status
    if (this.opsec.isAbortRecommended()) {
      this.pause();
      return;
    }

    // Get active mission
    const mission = this.mission.getActiveMission();
    if (!mission) return;

    // Get the task queue
    const taskQueue = this.mission.getTaskQueue();
    if (!taskQueue) return;

    // ── Auto-seed tasks from targets if queue is empty ──
    if (!this.taskSeeded) {
      const targets = this.targetEnv.getAllTargets();
      if (targets.length > 0) {
        for (const target of targets) {
          this.mission.generateTasksForTarget(target.address, this.scanOptions);
        }
        this.taskSeeded = true;

        // Auto-spawn the right operator for the initial RECON phase, scoped to the
        // mission family. Families without a recon archetype (e.g. code_supply_chain
        // uses code_scanner to clone the repo) fall back to the first family archetype.
        const activeMission = this.mission.getActiveMission();
        const familyArchetypes = getArchetypesForFamily(activeMission?.family);
        const reconArchetype = familyArchetypes.includes('recon') ? 'recon' : familyArchetypes[0] ?? 'recon';
        if (!this.cell.getAvailableOperator(reconArchetype)) {
          const callsign = `${reconArchetype.charAt(0).toUpperCase() + reconArchetype.slice(1)}-Auto`;
          try { this.spawnOperator(callsign, reconArchetype); } catch { /* pool full */ }
        }
      }
    }

    // ── Backstop: abort dispatches that have been in-flight past the task timeout ──
    const timeoutMs = this.resolveTaskTimeoutMs();
    for (const taskId of [...this.activeDispatches]) {
      const startTime = this.dispatchStartTime.get(taskId);
      if (!startTime || Date.now() - startTime <= timeoutMs) continue;

      const task = taskQueue.getTask(taskId);
      const operator = this.cell.getAllOperators().find((op) => op.state.currentTask === taskId);

      this.activeDispatches.delete(taskId);
      this.dispatchStartTime.delete(taskId);
      const controller = this.activeControllers.get(taskId);
      if (controller) { controller.abort(); this.activeControllers.delete(taskId); }
      if (operator) operator.abortActiveTask(`dispatch timeout after ${timeoutMs}ms`);

      try { taskQueue.fail(taskId, `dispatch timed out after ${timeoutMs}ms`); } catch { /* already terminal */ }

      // Required recon work timing out → stall the mission rather than silently advancing
      if (task?.phase === KillChainPhase.RECON && mission.currentPhase === KillChainPhase.RECON) {
        this.pause(`stalled in reconnaissance: required dispatch timed out for task ${taskId}`);
        return;
      }
    }

    // ── Check for phase advancement ──
    const allMissionTasks = taskQueue.getForMission(mission.id);
    const pendingOrActive = allMissionTasks.filter(
      t => t.status === 'pending' || t.status === 'assigned' || t.status === 'in_progress'
    );
    const inFlight = allMissionTasks.filter(t => this.activeDispatches.has(t.id));

    // If we have tasks, all are done, and nothing is in-flight → advance phase
    if (allMissionTasks.length > 0 && pendingOrActive.length === 0 && inFlight.length === 0) {
      const phaseIndex = mission.phases.indexOf(mission.currentPhase);
      if (phaseIndex === -1) return; // Guard: phase not found (race condition)
      if (phaseIndex < mission.phases.length - 1) {
        // Advance to next phase and generate tasks
        this.mission.advancePhase(mission.id);
        const targets = this.targetEnv.getAllTargets();
        const currentFindings = this.vault.getAllFindings();
        for (const target of targets) {
          this.mission.generateNextPhaseTasks(target.address, currentFindings, this.sandboxOptions);
        }

        // Auto-spawn operators for the new phase
        const nextPhase = mission.currentPhase;
        this.autoSpawnForPhase(nextPhase);
      } else {
        // All phases complete — finish the mission
        this.mission.completeMission(mission.id);
        return;
      }
    }

    // ── Dispatch pending tasks to idle operators ──
    const pendingTasks = taskQueue.getPending();
    if (pendingTasks.length === 0) return;

    for (const task of pendingTasks) {
      // Skip if already being dispatched
      if (this.activeDispatches.has(task.id)) continue;

      // Find ALL idle operators matching the task's archetype, pick the first unused
      const availableOps = this.cell.getAllOperators()
        .filter(op => op.archetype === task.operatorType && op.isAvailable());
      let operator = availableOps[0];

      // Auto-spawn an operator if none exists for this archetype
      if (!operator) {
        const allOps = this.cell.getAllOperators();
        const archetypeCount = allOps.filter(op => op.archetype === task.operatorType).length;
        // Spawn up to 3 operators per archetype for parallelism
        if (archetypeCount < 3) {
          const callsign = `${task.operatorType.charAt(0).toUpperCase() + task.operatorType.slice(1)}-${archetypeCount + 1}`;
          // spawnOperator throws when the pool is at capacity or the callsign collides —
          // treat that as "no operator available right now" and defer (operator stays unset),
          // never crash the tick.
          try { operator = this.spawnOperator(callsign, task.operatorType); }
          catch { /* pool full / dup callsign — dispatch skipped by the !operator guard below */ }
        }
        if (!operator) continue;
      }

      // Check task dependencies are met
      if (task.dependencies.length > 0) {
        const allDepsComplete = task.dependencies.every(depId => {
          const dep = taskQueue.getTask(depId);
          return dep?.status === 'completed';
        });
        if (!allDepsComplete) continue;
      }

      // Dispatch task (fire and forget — don't block the tick loop)
      this.activeDispatches.add(task.id);
      this.dispatchStartTime.set(task.id, Date.now());
      taskQueue.assign(task.id, operator.id);

      // Match task to target by address in the task description
      const allTargets = this.targetEnv.getAllTargets();
      const target = allTargets.find(t => task.description.includes(t.address)) || allTargets[0];
      if (!target) continue; // No targets available — skip dispatch

      // Execute asynchronously; create an AbortController so stop() can cancel in-flight work
      const controller = new AbortController();
      this.activeControllers.set(task.id, controller);
      operator.assignTask(task, target, controller.signal).then((result) => {
        this.activeDispatches.delete(task.id);
        this.dispatchStartTime.delete(task.id);
        this.activeControllers.delete(task.id);
        taskQueue.complete(task.id, result);
        this.hooks.onTaskCompleted?.(task);
      }).catch((_error) => {
        this.activeDispatches.delete(task.id);
        this.dispatchStartTime.delete(task.id);
        this.activeControllers.delete(task.id);
        try {
          taskQueue.fail(task.id, _error instanceof Error ? _error.message : String(_error));
        } catch (failErr) {
          // Swallow — task may already be in a terminal state
        }
      });
    }
  }

  /**
   * Auto-spawn operators needed for a given kill chain phase.
   * Intersects the phase's typical archetypes with what the mission family actually
   * uses — so a code_supply_chain scan never spawns an exploiter or infiltrator.
   */
  private autoSpawnForPhase(phase: KillChainPhase): void {
    const phaseOperators: Record<string, OperatorArchetype[]> = {
      [KillChainPhase.RECON]:     ['recon', 'code_scanner'],
      [KillChainPhase.WEAPONIZE]: ['code_scanner', 'web_scanner', 'analyst'],
      [KillChainPhase.DELIVER]:   ['exploiter'],
      [KillChainPhase.EXPLOIT]:   ['exploiter'],
      [KillChainPhase.INSTALL]:   ['infiltrator', 'ghost'],
      [KillChainPhase.C2]:        ['ghost', 'coordinator'],
      [KillChainPhase.ACTIONS]:   ['analyst'],
    };

    const activeMission = this.mission.getActiveMission();
    const familyArchetypes = getArchetypesForFamily(activeMission?.family);
    const phaseNeeded = phaseOperators[phase] || [];
    // Only spawn archetypes the family actually uses — skip everything else
    const needed = phaseNeeded.filter(a => familyArchetypes.includes(a));

    for (const archetype of needed) {
      const existing = this.cell.getAvailableOperator(archetype);
      if (!existing) {
        const allOps = this.cell.getAllOperators();
        const hasArchetype = allOps.some(op => op.archetype === archetype);
        if (!hasArchetype) {
          const callsign = `${archetype.charAt(0).toUpperCase() + archetype.slice(1)}-Auto`;
          try { this.spawnOperator(callsign, archetype); } catch { /* pool full */ }
        }
      }
    }
  }

  // ===========================================================================
  // SSE BROADCAST
  // ===========================================================================

  /**
   * Connect a broadcast function (e.g., from the server's SSE endpoint)
   * so all events stream to the web UI in real-time.
   */
  public connectBroadcast(broadcast: (event: string, data: Record<string, unknown>) => void): void {
    this.on('finding:discovered', (data) => broadcast('finding', data));
    this.on('operator:spawned', (data) => broadcast('operator:spawned', data));
    this.on('operator:burned', (data) => broadcast('operator:burned', data));
    this.on('operator:error', (data) => broadcast('operator:error', data));
    this.on('credential:harvested', (data) => broadcast('credential', data));
    this.on('detection:triggered', (data) => broadcast('detection', data));
    this.on('mission:phase_changed', (data) => broadcast('phase_changed', data));
    this.on('tick', (count) => {
      // Broadcast status every 5 ticks to avoid flooding
      if (typeof count === 'number' && count % 5 === 0) {
        broadcast('status', this.getStatus());
      }
    });
  }

  // ===========================================================================
  // CONVENIENCE METHODS
  // ===========================================================================

  /**
   * Spawn an operator with forwarding setup and agent loop
   */
  public spawnOperator(
    callsign: string,
    archetype: OperatorArchetype
  ): OperatorAgent {
    const operator = this.cell.spawnOperator(callsign, archetype);
    this.setupOperatorEvents(operator);

    // Attach the agent loop scoped to this archetype's tool categories
    const profile = ARCHETYPE_PROFILES[archetype];
    const agentLoop = new AgentLoop(this.llm, this.arsenal, {
      maxIterations: 25,
      maxTokens: 50000,
      toolCategories: profile.toolCategories,
      toolDefaults: Object.keys(this.toolDefaults).length > 0 ? this.toolDefaults : undefined,
    });
    operator.attachArsenal(this.arsenal, agentLoop);

    // Surface LLM/tool errors to the operator so they reach the frontend via SSE.
    // Without this, API key errors, 401s, and bad model names are silently swallowed.
    agentLoop.on('agent:error', ({ error, step }) => {
      this.emit('operator:error', {
        operatorId: operator.id,
        callsign: operator.callsign,
        archetype: operator.archetype,
        error: error.message,
        step,
      });
    });

    // Surface tool-level failures (timeout, not installed, repo not found, etc.)
    agentLoop.on('agent:tool_result', ({ name, result }) => {
      if (!result.success && result.error) {
        this.emit('operator:error', {
          operatorId: operator.id,
          callsign: operator.callsign,
          archetype: operator.archetype,
          error: `[${name}] ${result.error}`,
          step: -1,
        });
      }
    });

    return operator;
  }

  /**
   * Get command status
   */
  public getStatus(): {
    name: string;
    running: boolean;
    paused: boolean;
    stallReason: string | null;
    tickCount: number;
    operators: ReturnType<OperatorCell['getStatus']>;
    targets: ReturnType<TargetEnvironment['getStats']>;
    vault: ReturnType<EvidenceVault['getStats']>;
    opsec: ReturnType<OpsecController['getStats']>;
    activeMission: string | null;
  } {
    const activeMission = this.mission.getActiveMission();

    return {
      name: this.name,
      running: this.running,
      paused: this.paused,
      stallReason: this.stallReason,
      tickCount: this.tickCount,
      operators: this.cell.getStatus(),
      targets: this.targetEnv.getStats(),
      vault: this.vault.getStats(),
      opsec: this.opsec.getStats(),
      activeMission: activeMission?.id || null,
    };
  }

  /**
   * Generate engagement report
   */
  public generateReport(missionId?: string): string {
    const mission = missionId
      ? this.mission.getMission(missionId)
      : this.mission.getActiveMission();

    if (!mission) {
      throw new Error('No mission found for reporting');
    }

    const report = this.analysis.generateReport(mission.id, 'full_report');
    return this.analysis.exportToMarkdown(report);
  }
}

// =============================================================================
// TEMPEST INSTANCE
// =============================================================================

/**
 * Full T3MP3ST instance with all components
 */
export interface Tempest {
  command: TempestCommand;
  cell: OperatorCell;
  mission: MissionControl;
  targetEnv: TargetEnvironment;
  vault: EvidenceVault;
  arsenal: Arsenal;
  opsec: OpsecController;
  comms: CommsChannel;
  analysis: AnalysisEngine;
  llm: LLMBackbone;
  // Autonomous Op General
  general: OpGeneral;
  // Advanced modules
  exploit: ExploitEngine;
  scanner: ScannerOrchestrator;
  browser: BrowserAutomation;
  benchmark: BenchmarkRunner;
  reasoning: ReasoningEngine;
  // Elite modules
  cognition: CognitionEngine;
  swarm: SwarmController;
  cloud: CloudSecurityEngine;
  persistence: PersistenceController;
  learning: LearningEngine;
  // Foundational modules
  knowledge: KnowledgeBase;
  protocols: ProtocolHandler;
  evasion: EvasionEngine;
  reporting: ReportingEngine;
  workflow: WorkflowOrchestrator;
}

// =============================================================================
// FACTORY FUNCTIONS
// =============================================================================

/**
 * Create a TEMPEST instance
 */
export function createTempest(config: TempestConfig): Tempest {
  const command = new TempestCommand(config);

  return {
    command,
    cell: command.cell,
    mission: command.mission,
    targetEnv: command.targetEnv,
    vault: command.vault,
    arsenal: command.arsenal,
    opsec: command.opsec,
    comms: command.comms,
    analysis: command.analysis,
    llm: command.llm,
    // Autonomous Op General
    general: command.general,
    // Advanced modules
    exploit: command.exploit,
    scanner: command.scanner,
    browser: command.browser,
    benchmark: command.benchmark,
    reasoning: command.reasoning,
    // Elite modules
    cognition: command.cognition,
    swarm: command.swarm,
    cloud: command.cloud,
    persistence: command.persistence,
    learning: command.learning,
    // Foundational modules
    knowledge: command.knowledge,
    protocols: command.protocols,
    evasion: command.evasion,
    reporting: command.reporting,
    workflow: command.workflow,
  };
}

/**
 * Create a minimal TEMPEST instance for testing
 */
export function createTestTempest(name: string = 'Test Operation'): Tempest {
  return createTempest({
    name,
    llm: {
      provider: 'mock',
      model: 'mock-model',
      maxTokens: 4096,
      temperature: 0.7,
    },
    opsec: createBalancedOpsecConfig(),
    operators: {
      maxConcurrent: 10,
      defaultConfig: {
        maxDetectionRisk: 0.8,
        cooldownMs: 5000,
        maxRetries: 3,
        preferredTechniques: [],
        avoidTechniques: [],
        toolPreferences: [],
      },
    },
    targets: {
      maxConcurrent: 20,
    },
  });
}

/**
 * Create a TEMPEST instance with the best available LLM provider
 */
export function createAutoTempest(name: string = 'Auto Operation'): Tempest {
  const llmConfig = getLLMConfig();

  return createTempest({
    name,
    llm: llmConfig,
    opsec: createBalancedOpsecConfig(),
  });
}

/**
 * Quick start for a stealth operation
 */
export function createStealthOperation(name: string, llmConfig?: LLMConfig): Tempest {
  const config = llmConfig || getLLMConfig();

  return createTempest({
    name,
    llm: config,
    opsec: {
      level: 'silent',
      maxDetectionEvents: 1,
      cooldownAfterDetection: 300000,
      cleanupOnComplete: true,
      avoidDetection: true,
      jitterRange: [5000, 15000],
      trafficBlending: true,
      loggingSanitization: true,
    },
    operators: {
      maxConcurrent: 5,
      defaultConfig: {
        maxDetectionRisk: 0.3,
        cooldownMs: 30000,
        maxRetries: 2,
        preferredTechniques: [],
        avoidTechniques: [],
        toolPreferences: [],
      },
    },
    targets: {
      maxConcurrent: 10,
    },
  });
}

/**
 * Quick start for an aggressive operation
 */
export function createAggressiveOperation(name: string, llmConfig?: LLMConfig): Tempest {
  const config = llmConfig || getLLMConfig();

  return createTempest({
    name,
    llm: config,
    opsec: {
      level: 'loud',
      maxDetectionEvents: 20,
      cooldownAfterDetection: 2000,
      cleanupOnComplete: false,
      avoidDetection: false,
      jitterRange: [100, 500],
      trafficBlending: false,
      loggingSanitization: false,
    },
    operators: {
      maxConcurrent: 15,
      defaultConfig: {
        maxDetectionRisk: 0.95,
        cooldownMs: 1000,
        maxRetries: 5,
        preferredTechniques: [],
        avoidTechniques: [],
        toolPreferences: [],
      },
    },
    targets: {
      maxConcurrent: 50,
    },
  });
}

// =============================================================================
// BANNER
// =============================================================================

/**
 * Get ASCII banner
 */
export function getBanner(): string {
  return `
 ▄▄▄█████▓▓█████  ███▄ ▄███▓ ██▓███  ▓█████   ██████ ▄▄▄█████▓
 ▓  ██▒ ▓▒▓█   ▀ ▓██▒▀█▀ ██▒▓██░  ██▒▓█   ▀ ▒██    ▒ ▓  ██▒ ▓▒
 ▒ ▓██░ ▒░▒███   ▓██    ▓██░▓██░ ██▓▒▒███   ░ ▓██▄   ▒ ▓██░ ▒░
 ░ ▓██▓ ░ ▒▓█  ▄ ▒██    ▒██ ▒██▄█▓▒ ▒▒▓█  ▄   ▒   ██▒░ ▓██▓ ░
   ▒██▒ ░ ░▒████▒▒██▒   ░██▒▒██▒ ░  ░░▒████▒▒██████▒▒  ▒██▒ ░
   ▒ ░░   ░░ ▒░ ░░ ▒░   ░  ░▒▓▒░ ░  ░░░ ▒░ ░▒ ▒▓▒ ▒ ░  ▒ ░░
     ░     ░ ░  ░░  ░      ░░▒ ░      ░ ░  ░░ ░▒  ░ ░    ░
   ░         ░   ░      ░   ░░          ░   ░  ░  ░    ░
             ░  ░       ░               ░  ░      ░

  T3MP3ST - Tactical Execution Multi-agent Platform
            for Elite Security Testing

  Multi-Agent Red Team / Penetration Testing Framework
`;
}

// Default export
export default createTempest;
