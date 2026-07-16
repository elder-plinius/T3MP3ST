/**
 * T3MP3ST Operators Module
 *
 * Agent system for penetration testing operations.
 * Each operator is specialized for a specific phase of the kill chain.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import type { PackBoard } from '../pack/board.js';
import {
  KillChainPhase,
  type OperatorArchetype,
  type OperatorStatus,
  type OperatorState,
  type OperatorConfig,
  type Finding,
  type Credential,
  type Task,
  type TaskResult,
} from '../types/index.js';
import type { LLMBackbone } from '../llm/index.js';
import type { Arsenal } from '../arsenal/index.js';
import type { AgentLoop } from '../agent/index.js';
import type { ToolResult } from '../types/index.js';
import type { Target } from '../types/index.js';
import { OPERATOR_SYSTEM_PROMPTS } from '../prompts/index.js';
import { gateLiveFinding } from '../evidence/gate.js';

// =============================================================================
// OPERATOR EVENTS
// =============================================================================

export interface OperatorEvents {
  'status:changed': { oldStatus: OperatorStatus; newStatus: OperatorStatus };
  'task:started': { task: Task };
  'task:completed': { task: Task; result: TaskResult };
  'task:failed': { task: Task; error: string };
  'task:decomposed': { parent: Task; subtasks: Task[]; reason: string };
  'agent:thinking': { task: Task; content: string };
  'agent:tool_call': { task: Task; name: string; args: Record<string, unknown>; source?: 'agent' | 'backend_seeded' };
  'agent:tool_result': { task: Task; name: string; result: ToolResult; source?: 'agent' | 'backend_seeded' };
  'finding:discovered': { finding: Finding };
  'finding:gate-blocked': { finding: Finding; reasons: string[] };
  'credential:harvested': { credential: Credential };
  'detection:risk_increased': { newRisk: number };
  'cooldown:started': { durationMs: number };
  'cooldown:ended': void;
}

export interface CellEvents {
  'operator:spawned': OperatorAgent;
  'operator:burned': OperatorAgent;
  'operator:status_changed': { operator: OperatorAgent; oldStatus: OperatorStatus };
  'cell:capacity_warning': { current: number; max: number };
}

// =============================================================================
// ARCHETYPE PROFILES
// =============================================================================

export interface ArchetypeProfile {
  name: string;
  description: string;
  mitreTactics: string[];
  primaryPhases: KillChainPhase[];
  defaultTools: string[];
  /** Arsenal tool categories this archetype should have access to */
  toolCategories: string[];
  systemPrompt: string;
  capabilities: string[];
  techniques: string[];
}

export const ARCHETYPE_PROFILES: Record<OperatorArchetype, ArchetypeProfile> = {
  recon: {
    name: 'Reconnaissance Operator',
    description: 'Specialized in OSINT, network discovery, and asset enumeration',
    mitreTactics: ['TA0043'],
    primaryPhases: [KillChainPhase.RECON],
    defaultTools: ['dns_lookup', 'reverse_dns', 'whois_lookup', 'subdomain_enum', 'nmap_scan', 'port_scan', 'network_trace', 'version_detect', 'robots_txt_fetch', 'cidr_expand', 'technology_detect', 'http_request', 'curl_request', 'header_analysis', 'api_endpoint_discovery'],
    toolCategories: ['recon', 'web'],
    capabilities: ['osint', 'dns_enum', 'subdomain_discovery', 'port_scanning', 'service_detection'],
    techniques: ['T1595', 'T1592', 'T1589', 'T1590', 'T1591'],
    systemPrompt: OPERATOR_SYSTEM_PROMPTS.recon,
  },
  scanner: {
    name: 'Vulnerability Scanner',
    description: 'Identifies vulnerabilities and security misconfigurations',
    mitreTactics: ['TA0007'],
    primaryPhases: [KillChainPhase.WEAPONIZE],
    defaultTools: ['nuclei_scan', 'ssl_scan', 'cors_check', 'csp_analysis', 'clickjacking_test', 'cookie_analysis', 'http_methods_test', 'open_redirect_test', 'port_scan', 'version_detect', 'technology_detect', 'api_endpoint_discovery', 'header_analysis', 'http_request', 'curl_request'],
    toolCategories: ['vuln', 'web', 'recon'],
    capabilities: ['vuln_scanning', 'web_scanning', 'service_enum', 'config_audit'],
    techniques: ['T1046', 'T1082', 'T1083', 'T1087'],
    systemPrompt: OPERATOR_SYSTEM_PROMPTS.scanner,
  },
  exploiter: {
    name: 'Exploitation Specialist',
    description: 'Executes exploits and achieves initial access',
    mitreTactics: ['TA0001', 'TA0002'],
    primaryPhases: [KillChainPhase.DELIVER, KillChainPhase.EXPLOIT],
    defaultTools: ['sqli_scan', 'xss_scan', 'ssti_test', 'lfi_test', 'open_redirect_test', 'nuclei_scan', 'ffuf_fuzz', 'dir_bruteforce', 'api_endpoint_discovery', 'http_methods_test', 'password_spray', 'hash_crack', 'base64_decode', 'url_encode', 'jwt_decode', 'http_request', 'curl_request', 'technology_detect', 'header_analysis'],
    toolCategories: ['vuln', 'web', 'auth', 'util'],
    capabilities: ['exploit_dev', 'payload_delivery', 'initial_access', 'code_execution'],
    techniques: ['T1190', 'T1133', 'T1078', 'T1059'],
    systemPrompt: OPERATOR_SYSTEM_PROMPTS.exploiter,
  },
  infiltrator: {
    name: 'Lateral Movement Specialist',
    description: 'Moves through networks and escalates privileges',
    mitreTactics: ['TA0008', 'TA0004'],
    primaryPhases: [KillChainPhase.INSTALL],
    defaultTools: ['hash_crack', 'password_spray', 'jwt_decode', 'cookie_analysis', 'dns_lookup', 'port_scan', 'subdomain_enum', 'network_trace', 'nmap_scan', 'sqli_scan', 'lfi_test', 'cve_lookup', 'base64_decode', 'http_request', 'curl_request', 'technology_detect'],
    toolCategories: ['recon', 'web', 'auth', 'vuln'],
    capabilities: ['priv_esc', 'lateral_movement', 'credential_access', 'domain_enum'],
    techniques: ['T1021', 'T1078', 'T1068', 'T1548'],
    systemPrompt: OPERATOR_SYSTEM_PROMPTS.infiltrator,
  },
  exfiltrator: {
    name: 'Data Exfiltration Specialist',
    description: 'Collects and extracts sensitive data',
    mitreTactics: ['TA0009', 'TA0010'],
    primaryPhases: [KillChainPhase.ACTIONS],
    defaultTools: ['http_request', 'curl_request', 'api_endpoint_discovery', 'dir_bruteforce', 'base64_decode', 'url_encode', 'jwt_decode', 'cookie_analysis', 'subdomain_enum', 'robots_txt_fetch', 'technology_detect', 'lfi_test', 'sqli_scan', 'header_analysis', 'cve_lookup'],
    toolCategories: ['web', 'recon', 'util'],
    capabilities: ['data_collection', 'exfiltration', 'staging', 'compression'],
    techniques: ['T1041', 'T1048', 'T1567', 'T1560'],
    systemPrompt: OPERATOR_SYSTEM_PROMPTS.exfiltrator,
  },
  ghost: {
    name: 'Persistence Specialist',
    description: 'Establishes persistence and covers tracks',
    mitreTactics: ['TA0003', 'TA0005'],
    primaryPhases: [KillChainPhase.INSTALL, KillChainPhase.C2],
    defaultTools: ['http_request', 'curl_request', 'cookie_analysis', 'header_analysis', 'csp_analysis', 'clickjacking_test', 'technology_detect', 'http_methods_test', 'jwt_decode', 'base64_decode', 'url_encode', 'robots_txt_fetch', 'subdomain_enum', 'open_redirect_test', 'ssl_scan'],
    toolCategories: ['web', 'recon', 'vuln'],
    capabilities: ['persistence', 'evasion', 'cleanup', 'anti_forensics'],
    techniques: ['T1547', 'T1053', 'T1136', 'T1070'],
    systemPrompt: OPERATOR_SYSTEM_PROMPTS.ghost,
  },
  coordinator: {
    name: 'Mission Coordinator',
    description: 'Orchestrates operations and manages agents',
    mitreTactics: ['TA0011'],
    primaryPhases: [KillChainPhase.C2],
    defaultTools: ['cve_lookup', 'technology_detect', 'http_request', 'curl_request', 'header_analysis', 'nmap_scan', 'port_scan', 'dns_lookup', 'subdomain_enum', 'nuclei_scan', 'sqli_scan', 'api_endpoint_discovery', 'version_detect', 'ssl_scan'],
    toolCategories: ['recon', 'web', 'vuln'],
    capabilities: ['orchestration', 'task_management', 'communication', 'decision_making'],
    techniques: ['T1071', 'T1095', 'T1573', 'T1132'],
    systemPrompt: OPERATOR_SYSTEM_PROMPTS.coordinator,
  },
  analyst: {
    name: 'Security Analyst',
    description: 'Analyzes findings and generates reports',
    mitreTactics: [],
    primaryPhases: [KillChainPhase.ACTIONS],
    defaultTools: ['cve_lookup', 'jwt_decode', 'hash_crack', 'base64_decode', 'url_encode', 'technology_detect', 'ssl_scan', 'header_analysis', 'cors_check', 'csp_analysis', 'cookie_analysis', 'whois_lookup', 'dns_lookup', 'http_request', 'curl_request'],
    toolCategories: ['web', 'vuln', 'recon', 'util'],
    capabilities: ['analysis', 'reporting', 'recommendations', 'risk_assessment'],
    techniques: [],
    systemPrompt: OPERATOR_SYSTEM_PROMPTS.analyst,
  },
};

// ── Runtime operator overrides (set via the Operatives tab / Admiral advisor) ─────────────
// Edit an operator's system prompt + sampling params at RUN TIME without touching the source
// constants. Applied at operator construction (resolveProfile, below) so every spawned operator
// picks them up; ARCHETYPE_PROFILES stays immutable as the default to reset back to.
export interface OperatorParams { temperature: number; maxTokens: number; topP: number; }
export interface OperatorOverride { systemPrompt?: string; params?: Partial<OperatorParams>; }
const DEFAULT_OPERATOR_PARAMS: OperatorParams = { temperature: 0.4, maxTokens: 4096, topP: 1.0 };
const OPERATOR_OVERRIDES: Partial<Record<OperatorArchetype, OperatorOverride>> = {};

export function setOperatorOverride(archetype: OperatorArchetype, override: OperatorOverride): void {
  const cur = OPERATOR_OVERRIDES[archetype] || {};
  OPERATOR_OVERRIDES[archetype] = {
    systemPrompt: override.systemPrompt !== undefined ? override.systemPrompt : cur.systemPrompt,
    params: { ...(cur.params || {}), ...(override.params || {}) },
  };
}
export function resetOperatorOverride(archetype: OperatorArchetype): void { delete OPERATOR_OVERRIDES[archetype]; }
export function getOperatorParams(archetype: OperatorArchetype): OperatorParams {
  return { ...DEFAULT_OPERATOR_PARAMS, ...(OPERATOR_OVERRIDES[archetype]?.params || {}) };
}
/** Resolve an archetype's profile with any runtime systemPrompt override applied. */
export function resolveProfile(archetype: OperatorArchetype): ArchetypeProfile {
  const base = ARCHETYPE_PROFILES[archetype];
  const ov = OPERATOR_OVERRIDES[archetype];
  return (ov && ov.systemPrompt) ? { ...base, systemPrompt: ov.systemPrompt } : base;
}
/** Override-aware read view of every archetype, for the Operatives tab. */
export function listOperatorPrompts() {
  return (Object.keys(ARCHETYPE_PROFILES) as OperatorArchetype[]).map((a) => {
    const base = ARCHETYPE_PROFILES[a];
    const ov = OPERATOR_OVERRIDES[a];
    return {
      archetype: a,
      name: base.name,
      description: base.description,
      defaultTools: base.defaultTools,
      toolCategories: base.toolCategories,
      capabilities: base.capabilities,
      techniques: base.techniques,
      systemPrompt: (ov && ov.systemPrompt) || base.systemPrompt,
      defaultSystemPrompt: base.systemPrompt,
      params: getOperatorParams(a),
      overridden: !!(ov && (ov.systemPrompt || (ov.params && Object.keys(ov.params).length))),
    };
  });
}

export const ARCHETYPE_CAPABILITIES = Object.fromEntries(
  Object.entries(ARCHETYPE_PROFILES).map(([k, v]) => [k, v.capabilities])
);

export const ARCHETYPE_TECHNIQUES = Object.fromEntries(
  Object.entries(ARCHETYPE_PROFILES).map(([k, v]) => [k, v.techniques])
);

export const PHASE_ARCHETYPES: Record<KillChainPhase, OperatorArchetype[]> = {
  [KillChainPhase.RECON]: ['recon'],
  [KillChainPhase.WEAPONIZE]: ['scanner', 'exploiter'],
  [KillChainPhase.DELIVER]: ['exploiter'],
  [KillChainPhase.EXPLOIT]: ['exploiter'],
  [KillChainPhase.INSTALL]: ['infiltrator', 'ghost'],
  [KillChainPhase.C2]: ['coordinator', 'ghost'],
  [KillChainPhase.ACTIONS]: ['exfiltrator', 'analyst'],
};

export const KILL_CHAIN_ORDER: KillChainPhase[] = [
  KillChainPhase.RECON,
  KillChainPhase.WEAPONIZE,
  KillChainPhase.DELIVER,
  KillChainPhase.EXPLOIT,
  KillChainPhase.INSTALL,
  KillChainPhase.C2,
  KillChainPhase.ACTIONS,
];

export const PHASE_DESCRIPTIONS: Record<KillChainPhase, string> = {
  [KillChainPhase.RECON]: 'Gathering intelligence about the target',
  [KillChainPhase.WEAPONIZE]: 'Preparing exploits and payloads',
  [KillChainPhase.DELIVER]: 'Delivering exploits to targets',
  [KillChainPhase.EXPLOIT]: 'Executing exploits to gain access',
  [KillChainPhase.INSTALL]: 'Establishing persistence and expanding access',
  [KillChainPhase.C2]: 'Setting up command and control',
  [KillChainPhase.ACTIONS]: 'Achieving objectives and extracting data',
};

// =============================================================================
// DEFAULT OPERATOR CONFIG
// =============================================================================

const DEFAULT_OPERATOR_CONFIG: OperatorConfig = {
  maxDetectionRisk: 0.8,
  cooldownMs: 5000,
  maxRetries: 3,
  preferredTechniques: [],
  avoidTechniques: [],
  toolPreferences: [],
};

// =============================================================================
// OPERATOR AGENT
// =============================================================================

export class OperatorAgent extends EventEmitter<OperatorEvents> {
  public readonly id: string;
  public readonly callsign: string;
  public readonly archetype: OperatorArchetype;
  public readonly profile: ArchetypeProfile;
  public readonly config: OperatorConfig;

  private _state: OperatorState;
  private llm?: LLMBackbone;
  private agentLoop?: AgentLoop;
  /** Shared pack board (Phase-2). Attached only when swarm coordination is on; absent = solo baseline. */
  private board?: PackBoard;
  private cooldownTimer: NodeJS.Timeout | null = null;
  private findings: Finding[] = [];
  private credentials: Credential[] = [];
  /** White-box source excerpt (security-prioritized), set by TempestCommand.setWhiteboxSource */
  private whiteboxSource: string = '';

  constructor(
    callsign: string,
    archetype: OperatorArchetype,
    config?: Partial<OperatorConfig>,
    llm?: LLMBackbone
  ) {
    super();
    this.id = randomUUID();
    this.callsign = callsign;
    this.archetype = archetype;
    this.profile = resolveProfile(archetype);
    this.config = { ...DEFAULT_OPERATOR_CONFIG, ...config };
    this.llm = llm;

    this._state = {
      status: 'idle',
      currentTask: null,
      completedTasks: 0,
      failedTasks: 0,
      findingsCount: 0,
      credentialsCount: 0,
      detectionRisk: 0,
      lastActivityTime: Date.now(),
    };
  }

  /**
   * Get the current state
   */
  get state(): OperatorState {
    return { ...this._state };
  }

  /**
   * Get the current status
   */
  get status(): OperatorStatus {
    return this._state.status;
  }

  /**
   * Check if the operator is available for tasks
   */
  isAvailable(): boolean {
    return this._state.status === 'idle';
  }

  /**
   * Check if the operator is burned (compromised)
   */
  isBurned(): boolean {
    return this._state.status === 'burned';
  }

  /**
   * Assign a task to the operator
   */
  async assignTask(task: Task, target?: Target): Promise<TaskResult> {
    if (!this.isAvailable()) {
      throw new Error(`Operator ${this.callsign} is not available (status: ${this._state.status})`);
    }

    this.setStatus('tasked');
    this._state.currentTask = task.id;
    this._state.lastActivityTime = Date.now();

    this.emit('task:started', { task });

    try {
      this.setStatus('executing');
      const result = await this.executeTask(task, target);

      this._state.completedTasks++;
      this._state.currentTask = null;

      this.emit('task:completed', { task, result });

      // Apply cooldown after task
      await this.applyCooldown();

      return result;
    } catch (error) {
      this._state.failedTasks++;
      this._state.currentTask = null;

      const errorMessage = error instanceof Error ? error.message : String(error);

      // Decompose fallback: if we have an LLM and retries left, break the
      // failed task into smaller subtasks instead of giving up.
      const attempt = (task as any)._decomposeAttempt || 0;
      if (this.llm && attempt < this.config.maxRetries) {
        const subtasks = await this.decomposeTask(task, errorMessage);
        if (subtasks.length > 0) {
          this.emit('task:decomposed', { parent: task, subtasks, reason: errorMessage });
          this.setStatus('idle');

          const subResults: TaskResult[] = [];
          for (const sub of subtasks) {
            (sub as any)._decomposeAttempt = attempt + 1;
            const r = await this.assignTask(sub, target);
            subResults.push(r);
          }

          const anySuccess = subResults.some(r => r.success);
          return {
            success: anySuccess,
            output: subResults.map(r => r.output || r.error || '').join('\n---\n'),
            findings: subResults.flatMap(r => r.findings || []),
          };
        }
      }

      this.emit('task:failed', { task, error: errorMessage });
      this.increaseDetectionRisk(0.1);
      this.setStatus('idle');

      return {
        success: false,
        error: errorMessage,
      };
    }
  }

  /**
   * Attach an Arsenal and AgentLoop for autonomous tool-using execution
   */
  attachArsenal(_arsenal: Arsenal, agentLoop: AgentLoop): void {
    this.agentLoop = agentLoop;
  }

  /** Attach the shared pack board so this operator sees the swarm's live lead-board (Phase-2). */
  attachBoard(board: PackBoard): void {
    this.board = board;
  }

  /**
   * Execute a task with an optional target context
   */
  async executeTask(task: Task, target?: Target): Promise<TaskResult> {
    // If we have an agent loop (LLM + Arsenal), use autonomous ReAct execution.
    // Pass the white-box source excerpt (if any) so the model sees the target's
    // real source alongside the task; empty string keeps black-box behavior.
    if (this.agentLoop && this.llm) {
      const onThinking = ({ content }: { content: string }): void => {
        this.emit('agent:thinking', { task, content });
      };
      const onToolCall = ({ name, args, source }: { name: string; args: Record<string, unknown>; source?: 'agent' | 'backend_seeded' }): void => {
        this.emit('agent:tool_call', { task, name, args, source });
      };
      const onToolResult = ({ name, result, source }: { name: string; result: ToolResult; source?: 'agent' | 'backend_seeded' }): void => {
        this.emit('agent:tool_result', { task, name, result, source });
      };
      const canForwardAgentEvents =
        typeof this.agentLoop.on === 'function' &&
        typeof this.agentLoop.off === 'function';
      if (canForwardAgentEvents) {
        this.agentLoop.on('agent:thinking', onThinking);
        this.agentLoop.on('agent:tool_call', onToolCall);
        this.agentLoop.on('agent:tool_result', onToolResult);
      }

      let result;
      try {
        // [Phase-2] Register as live on the board and pull the shared situation report so this
        // operator sees teammates' verified leads/claims — it builds on them instead of running blind.
        this.board?.heartbeat(this.id, 'hunting', task.name);
        const sharedContext = this.board?.situationReport(this.id);
        result = await this.agentLoop.run(task, this.profile.systemPrompt, target, this.whiteboxSource, sharedContext);
      } finally {
        if (canForwardAgentEvents) {
          this.agentLoop.off('agent:thinking', onThinking);
          this.agentLoop.off('agent:tool_call', onToolCall);
          this.agentLoop.off('agent:tool_result', onToolResult);
        }
      }

      // Convert agent findings to operator findings.
      // PROVENANCE-HONEST: only a tool-backed finding gets tool-output evidence (the raw
      // output that produced it). A model-asserted finding carries NO fabricated evidence —
      // recordFinding's gate then refuses to mark it verified. The old code laundered the
      // model's prose summary as `type:'output'` for EVERY finding, which passed the gate.
      for (const finding of result.findings) {
        const toolBacked = finding.provenance === 'tool';
        this.recordFinding({
          id: `finding-${randomUUID()}`,
          title: finding.title,
          description: finding.details,
          severity: finding.severity,
          targetId: target?.id || 'unknown',
          operatorId: this.id,
          phase: task.phase as KillChainPhase,
          cvss: finding.cvss,
          cve: finding.cve,
          cwe: finding.cwe,
          evidence: toolBacked
            ? [{
                type: 'output',
                content: finding.toolOutput || finding.details || '',
                timestamp: Date.now(),
                metadata: { tool: finding.toolName },
              }]
            : [],
          remediation: finding.remediation,
          discoveredAt: Date.now(),
        });
      }

      return {
        success: result.success,
        output: result.summary,
        error: result.finalSummaryError
          ? `${result.summary} Final summary failed: ${result.finalSummaryError}`
          : undefined,
        findings: result.findings.map(f => f.title),
        nextTasks: undefined,
      };
    }

    // Fallback: LLM-only execution (no tool calling)
    if (this.llm) {
      const prompt = this.buildTaskPrompt(task);
      const _p = getOperatorParams(this.archetype);
      const response = await this.llm.prompt(prompt, this.profile.systemPrompt, { temperature: _p.temperature, maxTokens: _p.maxTokens });
      return this.parseTaskResponse(response, task);
    }

    // No LLM available
    return {
      success: false,
      error: `No LLM backbone configured. Operator "${this.callsign}" requires an LLM to execute task "${task.name}". ` +
             `Configure an LLM provider (OpenRouter, OpenAI, Anthropic) to enable intelligent task execution.`,
      output: `Task "${task.name}" cannot be executed without LLM backbone.\n` +
              `Operator: ${this.callsign} (${this.archetype})\n` +
              `Phase: ${task.phase}\n` +
              `Required capabilities: ${this.profile.capabilities.join(', ')}\n\n` +
              `To execute this task, configure an LLM provider in your T3MP3ST configuration.`,
    };
  }

  /**
   * Decompose a failed task into smaller, more tractable subtasks.
   * The operator asks its LLM to break the problem down — this is an
   * internal recovery strategy, never surfaced as a user-facing mode.
   */
  private async decomposeTask(task: Task, failureReason: string): Promise<Task[]> {
    if (!this.llm) return [];
    try {
      const prompt = `A task just FAILED. Your job is to decompose it into 2-4 smaller, independent subtasks that are each more likely to succeed.

FAILED TASK:
  Name: ${task.name}
  Description: ${task.description}
  Phase: ${task.phase}
  Error: ${failureReason}

Respond with ONLY a JSON array of subtask objects, each with "name" and "description" fields. Keep subtasks concrete and scoped — each should be completable on its own. Example:
[{"name":"enumerate endpoints","description":"Map all HTTP endpoints on the target before attempting exploitation"},{"name":"check auth bypass","description":"Test for authentication bypass on the discovered endpoints"}]`;

      const response = await this.llm.prompt(prompt, this.profile.systemPrompt, { maxTokens: 1024, temperature: 0.3 });
      const match = response.match(/\[[\s\S]*\]/);
      if (!match) return [];
      const parsed: Array<{ name: string; description: string }> = JSON.parse(match[0]);
      if (!Array.isArray(parsed) || parsed.length < 2 || parsed.length > 4) return [];

      return parsed.map((sub, i) => ({
        id: `${task.id}-decomp-${i}`,
        missionId: task.missionId,
        name: sub.name,
        description: sub.description,
        phase: task.phase,
        operatorType: task.operatorType,
        status: 'pending' as const,
        priority: task.priority,
        dependencies: [],
        createdAt: Date.now(),
      }));
    } catch {
      return [];
    }
  }

  /**
   * Build a prompt for task execution
   */
  private buildTaskPrompt(task: Task): string {
    return `Execute the following task:

Task: ${task.name}
Description: ${task.description}
Phase: ${task.phase}
Priority: ${task.priority}

Analyze the task requirements and provide:
1. Recommended approach
2. Required tools/techniques
3. Expected findings or results
4. Potential risks/detections
5. Next steps if successful

Respond in a structured format.`;
  }

  /**
   * Parse task response from LLM
   */
  private parseTaskResponse(response: string, _task: Task): TaskResult {
    // No tool ran in this fallback path, so it CANNOT produce a provenance-backed finding.
    // The old code inferred `findings` from prose keywords ('vulnerab'/'finding'/'discovered'),
    // which manufactured success from a description. We don't claim findings we can't back.
    return {
      success: true,
      output: response,
      findings: undefined,
      nextTasks: this.extractNextTasks(response),
    };
  }

  /**
   * Extract suggested next tasks from response
   */
  private extractNextTasks(response: string): string[] | undefined {
    const nextSteps: string[] = [];
    const lines = response.split('\n');

    let inNextSteps = false;
    for (const line of lines) {
      if (line.toLowerCase().includes('next step') || line.toLowerCase().includes('recommend')) {
        inNextSteps = true;
        continue;
      }
      if (inNextSteps && line.trim().startsWith('-')) {
        nextSteps.push(line.trim().substring(1).trim());
      }
    }

    return nextSteps.length > 0 ? nextSteps : undefined;
  }

  /**
   * Record a finding
   */
  recordFinding(finding: Finding): void {
    // HONESTY SPINE — load-bearing, IN the live path (not an opt-in verifyFinding call).
    // A finding is stamped verified ONLY if it passes the provenance gate (real tool
    // output). A model-asserted finding is still recorded — but left UNVERIFIED with the
    // gate's reasons attached. This enforces the invariant the project sells, at the point
    // of creation, so a model can no longer assert a "critical" into the record for free.
    const gate = gateLiveFinding(finding);
    finding.verifyGate = { passed: gate.passed, provenance: gate.provenance, reasons: gate.reasons, checkedAt: gate.checkedAt };
    if (gate.passed) {
      finding.verifiedAt = finding.verifiedAt ?? Date.now();
    } else {
      delete finding.verifiedAt;
    }
    this.findings.push(finding);
    this._state.findingsCount++;
    this.emit('finding:discovered', { finding });
    if (!gate.passed) this.emit('finding:gate-blocked', { finding, reasons: gate.reasons });
  }

  /**
   * Record a credential
   */
  recordCredential(credential: Credential): void {
    this.credentials.push(credential);
    this._state.credentialsCount++;
    this.emit('credential:harvested', { credential });
  }

  /**
   * Get all findings
   */
  getFindings(): Finding[] {
    return [...this.findings];
  }

  /**
   * Get all credentials
   */
  getCredentials(): Credential[] {
    return [...this.credentials];
  }

  /**
   * Apply cooldown after task
   */
  private async applyCooldown(): Promise<void> {
    this.setStatus('cooldown');
    this.emit('cooldown:started', { durationMs: this.config.cooldownMs });

    await new Promise<void>(resolve => {
      this.cooldownTimer = setTimeout(() => {
        this.setStatus('idle');
        this.emit('cooldown:ended');
        resolve();
      }, this.config.cooldownMs);
    });
  }

  /**
   * Increase detection risk
   */
  increaseDetectionRisk(amount: number): void {
    const newRisk = Math.min(1, this._state.detectionRisk + amount);
    this._state.detectionRisk = newRisk;
    this.emit('detection:risk_increased', { newRisk });

    // Check if operator should be burned
    if (newRisk >= this.config.maxDetectionRisk) {
      this.burn();
    }
  }

  /**
   * Burn the operator (mark as compromised)
   */
  burn(): void {
    if (this.cooldownTimer) {
      clearTimeout(this.cooldownTimer);
      this.cooldownTimer = null;
    }
    this.setStatus('burned');
  }

  /**
   * Exfiltrate the operator (successful extraction)
   */
  exfiltrate(): void {
    if (this.cooldownTimer) {
      clearTimeout(this.cooldownTimer);
      this.cooldownTimer = null;
    }
    this.setStatus('exfiltrated');
  }

  /**
   * Force-abort whatever this operator is doing and return it to idle.
   *
   * This is the recovery hatch for a WEDGED dispatch: the normal completion
   * path clears `currentTask` and sets status via assignTask()'s resolve/reject,
   * but if the underlying agent-loop promise never settles (a truly hung LLM
   * call, a stuck subprocess, etc.) the operator stays pinned in
   * `executing`/`tasked` forever and can never take new work. TempestCommand's
   * per-dispatch wall-clock backstop calls this to free the operator so the
   * mission can make progress.
   *
   * It does NOT touch the normal completion path — assignTask()'s own
   * resolve/reject still run if/when the wedged promise eventually settles;
   * they simply find the operator already idle (setStatus is idempotent) and
   * their taskQueue.complete/fail call is a no-op because the task is already
   * terminal. Only status-machine state is reset here; findings already
   * recorded are preserved.
   */
  abortActiveTask(reason: string): void {
    // Nothing to abort if the operator isn't holding a task.
    if (this._state.status === 'idle' || this._state.status === 'burned' || this._state.status === 'exfiltrated') {
      return;
    }
    if (this.cooldownTimer) {
      clearTimeout(this.cooldownTimer);
      this.cooldownTimer = null;
    }
    this._state.failedTasks++;
    this._state.currentTask = null;
    this._state.lastActivityTime = Date.now();
    this.emit('task:failed', {
      task: { id: 'unknown', name: reason } as unknown as Task,
      error: `aborted: ${reason}`,
    });
    this.setStatus('idle');
  }

  /**
   * Set status with event emission
   */
  private setStatus(newStatus: OperatorStatus): void {
    const oldStatus = this._state.status;
    this._state.status = newStatus;
    this.emit('status:changed', { oldStatus, newStatus });
  }

  /**
   * Set the LLM backbone
   */
  setLLM(llm: LLMBackbone): void {
    this.llm = llm;
  }

  /**
   * Set the white-box source context (security-prioritized code excerpt).
   * Passed through to the agent loop in executeTask so the model analyzes the
   * target against its real source. Empty string = black-box (unchanged).
   */
  setWhiteboxSource(s: string): void {
    this.whiteboxSource = s;
  }

  /**
   * Get operator summary
   */
  getSummary(): {
    id: string;
    callsign: string;
    archetype: OperatorArchetype;
    status: OperatorStatus;
    completedTasks: number;
    failedTasks: number;
    findings: number;
    credentials: number;
    detectionRisk: number;
  } {
    return {
      id: this.id,
      callsign: this.callsign,
      archetype: this.archetype,
      status: this._state.status,
      completedTasks: this._state.completedTasks,
      failedTasks: this._state.failedTasks,
      findings: this._state.findingsCount,
      credentials: this._state.credentialsCount,
      detectionRisk: this._state.detectionRisk,
    };
  }
}

// =============================================================================
// OPERATOR CELL (Pool of operators)
// =============================================================================

export class OperatorCell extends EventEmitter<CellEvents> {
  private operators: Map<string, OperatorAgent> = new Map();
  private maxOperators: number;
  private llm?: LLMBackbone;

  constructor(maxOperators: number = 10, llm?: LLMBackbone) {
    super();
    this.maxOperators = maxOperators;
    this.llm = llm;
  }

  /**
   * Set the LLM backbone for all operators
   */
  setLLM(llm: LLMBackbone): void {
    this.llm = llm;
    for (const operator of this.operators.values()) {
      operator.setLLM(llm);
    }
  }

  /**
   * Spawn a new operator
   */
  spawnOperator(
    callsign: string,
    archetype: OperatorArchetype,
    config?: Partial<OperatorConfig>
  ): OperatorAgent {
    if (this.operators.size >= this.maxOperators) {
      this.emit('cell:capacity_warning', {
        current: this.operators.size,
        max: this.maxOperators,
      });
      throw new Error(`Operator cell at capacity (${this.maxOperators})`);
    }

    // Check for duplicate callsign
    for (const op of this.operators.values()) {
      if (op.callsign === callsign) {
        throw new Error(`Operator with callsign "${callsign}" already exists`);
      }
    }

    const operator = new OperatorAgent(callsign, archetype, config, this.llm);

    // Forward operator events
    operator.on('status:changed', ({ oldStatus }) => {
      this.emit('operator:status_changed', { operator, oldStatus });

      if (operator.status === 'burned') {
        this.emit('operator:burned', operator);
      }
    });

    this.operators.set(operator.id, operator);
    this.emit('operator:spawned', operator);

    return operator;
  }

  /**
   * Get an operator by ID
   */
  getOperator(id: string): OperatorAgent | undefined {
    return this.operators.get(id);
  }

  /**
   * Get an operator by callsign
   */
  getOperatorByCallsign(callsign: string): OperatorAgent | undefined {
    for (const operator of this.operators.values()) {
      if (operator.callsign === callsign) {
        return operator;
      }
    }
    return undefined;
  }

  /**
   * Get all operators
   */
  getAllOperators(): OperatorAgent[] {
    return Array.from(this.operators.values());
  }

  /**
   * Get available operators
   */
  getAvailableOperators(): OperatorAgent[] {
    return this.getAllOperators().filter(op => op.isAvailable());
  }

  /**
   * Get a single available operator matching an archetype (for task dispatch)
   */
  getAvailableOperator(archetype: OperatorArchetype): OperatorAgent | undefined {
    return this.getAllOperators().find(op => op.archetype === archetype && op.isAvailable());
  }

  /**
   * Get operators by archetype
   */
  getOperatorsByArchetype(archetype: OperatorArchetype): OperatorAgent[] {
    return this.getAllOperators().filter(op => op.archetype === archetype);
  }

  /**
   * Get operators by phase
   */
  getOperatorsForPhase(phase: KillChainPhase): OperatorAgent[] {
    const archetypes = PHASE_ARCHETYPES[phase];
    return this.getAllOperators().filter(op => archetypes.includes(op.archetype));
  }

  /**
   * Remove an operator
   */
  removeOperator(id: string): boolean {
    const operator = this.operators.get(id);
    if (operator) {
      operator.removeAllListeners();
      this.operators.delete(id);
      return true;
    }
    return false;
  }

  /**
   * Remove burned operators
   */
  purgeBurned(): number {
    let count = 0;
    for (const [id, operator] of this.operators.entries()) {
      if (operator.isBurned()) {
        operator.removeAllListeners();
        this.operators.delete(id);
        count++;
      }
    }
    return count;
  }

  /**
   * Get cell status
   */
  getStatus(): {
    total: number;
    available: number;
    busy: number;
    cooldown: number;
    burned: number;
    byArchetype: Record<OperatorArchetype, number>;
  } {
    const operators = this.getAllOperators();

    const byArchetype: Partial<Record<OperatorArchetype, number>> = {};
    for (const archetype of Object.keys(ARCHETYPE_PROFILES) as OperatorArchetype[]) {
      byArchetype[archetype] = 0;
    }

    let available = 0;
    let busy = 0;
    let cooldown = 0;
    let burned = 0;

    for (const op of operators) {
      byArchetype[op.archetype] = (byArchetype[op.archetype] || 0) + 1;

      switch (op.status) {
        case 'idle':
          available++;
          break;
        case 'tasked':
        case 'executing':
          busy++;
          break;
        case 'cooldown':
          cooldown++;
          break;
        case 'burned':
          burned++;
          break;
      }
    }

    return {
      total: operators.length,
      available,
      busy,
      cooldown,
      burned,
      byArchetype: byArchetype as Record<OperatorArchetype, number>,
    };
  }

  /**
   * Get all findings from all operators
   */
  getAllFindings(): Finding[] {
    const findings: Finding[] = [];
    for (const operator of this.operators.values()) {
      findings.push(...operator.getFindings());
    }
    return findings;
  }

  /**
   * Get all credentials from all operators
   */
  getAllCredentials(): Credential[] {
    const credentials: Credential[] = [];
    for (const operator of this.operators.values()) {
      credentials.push(...operator.getCredentials());
    }
    return credentials;
  }
}

// =============================================================================
// FACTORY FUNCTIONS
// =============================================================================

export function createOperator(
  callsign: string,
  archetype: OperatorArchetype,
  config?: Partial<OperatorConfig>,
  llm?: LLMBackbone
): OperatorAgent {
  return new OperatorAgent(callsign, archetype, config, llm);
}

export function createBalancedTeam(llm?: LLMBackbone): OperatorCell {
  const cell = new OperatorCell(10, llm);

  cell.spawnOperator('Ghost-1', 'recon');
  cell.spawnOperator('Wraith-1', 'scanner');
  cell.spawnOperator('Phantom-1', 'exploiter');
  cell.spawnOperator('Shadow-1', 'infiltrator');
  cell.spawnOperator('Specter-1', 'exfiltrator');
  cell.spawnOperator('Shade-1', 'ghost');
  cell.spawnOperator('Oracle-1', 'coordinator');
  cell.spawnOperator('Sage-1', 'analyst');

  return cell;
}

export function createStealthTeam(llm?: LLMBackbone): OperatorCell {
  const cell = new OperatorCell(5, llm);
  const stealthConfig: Partial<OperatorConfig> = {
    maxDetectionRisk: 0.3,
    cooldownMs: 30000,
    maxRetries: 2,
  };

  cell.spawnOperator('Whisper-1', 'recon', stealthConfig);
  cell.spawnOperator('Silence-1', 'scanner', stealthConfig);
  cell.spawnOperator('Void-1', 'ghost', stealthConfig);

  return cell;
}

export function createBreachTeam(llm?: LLMBackbone): OperatorCell {
  const cell = new OperatorCell(8, llm);
  const aggressiveConfig: Partial<OperatorConfig> = {
    maxDetectionRisk: 0.95,
    cooldownMs: 1000,
    maxRetries: 5,
  };

  cell.spawnOperator('Hammer-1', 'exploiter', aggressiveConfig);
  cell.spawnOperator('Hammer-2', 'exploiter', aggressiveConfig);
  cell.spawnOperator('Drill-1', 'infiltrator', aggressiveConfig);
  cell.spawnOperator('Grab-1', 'exfiltrator', aggressiveConfig);

  return cell;
}
