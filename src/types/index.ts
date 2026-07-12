/**
 * T3MP3ST Core Type Definitions
 */

// =============================================================================
// LLM CONFIGURATION
// =============================================================================

export type LLMProvider = 'openrouter' | 'venice' | 'anthropic' | 'openai' | 'xai' | 'gemini' | 'codex' | 'mock' | 'local' | 'local-agent';

export interface LLMConfig {
  provider: LLMProvider;
  model: string;
  apiKey?: string;
  baseUrl?: string;
  maxTokens?: number;
  temperature?: number;
  timeout?: number;
  /**
   * Ordered model/provider ladder to fall back to when the PRIMARY model fails for
   * ANY reason it can't self-recover from — hard errors after same-model retries
   * (rate-limit, 5xx, timeout, auth, unavailable model, context-length) AND soft
   * failures (a refusal, or an empty/contentless 200). Empty/unset = no fallback.
   * Each entry overrides the primary config's matching fields.
   *
   * On a *refusal* specifically, the operation's REAL authorization context (scope
   * + human-approved gate + responsible disclosure) is restated before the next
   * model is tried — honest escalation, NO jailbreak / guardrail-bypass prompts.
   * A refusal that survives honest context + a model swap is respected.
   */
  fallbackChain?: FallbackEntry[];
}

/** One hop in an LLMConfig.fallbackChain ladder. */
export interface FallbackEntry {
  provider: LLMProvider;
  model: string;
  apiKey?: string;
  baseUrl?: string;
}

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  /** Tool calls requested by the assistant */
  toolCalls?: LLMToolCall[];
  /** ID of the tool call this message is a result for (role=tool) */
  toolCallId?: string;
  /** Tool name for tool result messages */
  name?: string;
}

export interface LLMResponse {
  content: string;
  model: string;
  /** Tool calls the model wants to make */
  toolCalls?: LLMToolCall[];
  usage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  finishReason?: string;
}

// =============================================================================
// LLM TOOL CALLING
// =============================================================================

/** Definition of a tool the LLM can invoke */
export interface LLMToolDefinition {
  name: string;
  description: string;
  parameters: {
    type: 'object';
    properties: Record<string, {
      type: string;
      description?: string;
      enum?: string[];
      items?: { type: string };
      default?: unknown;
    }>;
    required?: string[];
  };
}

/** A tool call from the LLM response */
export interface LLMToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

// =============================================================================
// OPERATOR TYPES
// =============================================================================

export type OperatorArchetype =
  | 'recon'
  | 'scanner'
  | 'exploiter'
  | 'infiltrator'
  | 'exfiltrator'
  | 'ghost'
  | 'coordinator'
  | 'analyst';

export type OperatorStatus =
  | 'idle'
  | 'tasked'
  | 'executing'
  | 'cooldown'
  | 'burned'
  | 'exfiltrated';

export interface OperatorState {
  status: OperatorStatus;
  currentTask: string | null;
  completedTasks: number;
  failedTasks: number;
  findingsCount: number;
  credentialsCount: number;
  detectionRisk: number;
  lastActivityTime: number;
}

export interface OperatorConfig {
  maxDetectionRisk: number;
  cooldownMs: number;
  maxRetries: number;
  preferredTechniques: string[];
  avoidTechniques: string[];
  toolPreferences: string[];
}

// =============================================================================
// KILL CHAIN PHASES
// =============================================================================

export enum KillChainPhase {
  RECON = 'reconnaissance',
  WEAPONIZE = 'weaponization',
  DELIVER = 'delivery',
  EXPLOIT = 'exploitation',
  INSTALL = 'installation',
  C2 = 'command_and_control',
  ACTIONS = 'actions_on_objectives',
}

// =============================================================================
// TARGET TYPES
// =============================================================================

export type TargetType =
  | 'web_application'
  | 'api'
  | 'network'
  | 'host'
  | 'database'
  | 'cloud'
  | 'mobile'
  | 'iot'
  | 'container';

export type TargetZone =
  | 'external'
  | 'dmz'
  | 'internal'
  | 'restricted'
  | 'airgapped';

export type TargetStatus =
  | 'discovered'
  | 'scanning'
  | 'vulnerable'
  | 'exploited'
  | 'owned'
  | 'exfiltrated';

export interface Target {
  id: string;
  name: string;
  type: TargetType;
  zone: TargetZone;
  status: TargetStatus;
  address: string;
  port?: number;
  protocol?: string;
  services?: Service[];
  vulnerabilities?: Vulnerability[];
  credentials?: Credential[];
  metadata?: Record<string, unknown>;
  discoveredAt: number;
  lastScannedAt?: number;
  ownedAt?: number;
}

export interface Service {
  name: string;
  port: number;
  protocol: string;
  version?: string;
  banner?: string;
  vulnerabilities?: string[];
}

// =============================================================================
// FINDING TYPES
// =============================================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  targetId: string;
  operatorId: string;
  phase: KillChainPhase;
  cvss?: number;
  cve?: string[];
  cwe?: string[];
  evidence: Evidence[];
  remediation?: string;
  references?: string[];
  discoveredAt: number;
  verifiedAt?: number;
  exploitedAt?: number;
  /** Result of the live verification gate — present once verifyFinding() has run. */
  verifyGate?: { passed: boolean; provenance: 'none' | 'context' | 'tool'; reasons: string[]; checkedAt: number };
}

export interface Evidence {
  type: 'screenshot' | 'log' | 'request' | 'response' | 'file' | 'command' | 'output';
  content: string;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

// =============================================================================
// VULNERABILITY TYPES
// =============================================================================

export interface Vulnerability {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  cvss?: number;
  cve?: string[];
  cwe?: string[];
  affected?: string;
  exploitAvailable?: boolean;
  patchAvailable?: boolean;
  references?: string[];
}

// =============================================================================
// CREDENTIAL TYPES
// =============================================================================

export type CredentialType =
  | 'password'
  | 'hash'
  | 'token'
  | 'api_key'
  | 'ssh_key'
  | 'certificate'
  | 'session'
  | 'cookie';

export interface Credential {
  id: string;
  type: CredentialType;
  username?: string;
  secret: string;
  domain?: string;
  targetId?: string;
  source: string;
  discoveredAt: number;
  validatedAt?: number;
  privilegeLevel?: 'user' | 'admin' | 'system' | 'root';
}

// =============================================================================
// MISSION TYPES
// =============================================================================

export interface Mission {
  id: string;
  name: string;
  description?: string;
  objectives: string[];
  phases: KillChainPhase[];
  rules: RulesOfEngagement;
  status: 'planning' | 'active' | 'paused' | 'completed' | 'aborted';
  startedAt?: number;
  completedAt?: number;
  currentPhase: KillChainPhase;
  progress: number;
}

export interface RulesOfEngagement {
  scope: string[];
  excludedTargets: string[];
  allowedTechniques: string[];
  forbiddenTechniques: string[];
  maxDetectionEvents: number;
  requireManualApproval: string[];
  timeWindow?: { start: number; end: number };
}

export interface Task {
  id: string;
  missionId: string;
  name: string;
  description: string;
  phase: KillChainPhase;
  operatorType: OperatorArchetype;
  status: 'pending' | 'assigned' | 'in_progress' | 'completed' | 'failed' | 'skipped';
  priority: number;
  dependencies: string[];
  assignedTo?: string;
  result?: TaskResult;
  createdAt: number;
  startedAt?: number;
  completedAt?: number;
}

export interface TaskResult {
  success: boolean;
  output?: string;
  findings?: string[];
  credentials?: string[];
  nextTasks?: string[];
  error?: string;
}

// =============================================================================
// OPSEC TYPES
// =============================================================================

export type OpsecLevel = 'silent' | 'covert' | 'loud';

export interface OpsecConfig {
  level: OpsecLevel;
  maxDetectionEvents: number;
  cooldownAfterDetection: number;
  cleanupOnComplete: boolean;
  avoidDetection: boolean;
  jitterRange: [number, number];
  trafficBlending: boolean;
  loggingSanitization: boolean;
}

export interface DetectionEvent {
  id: string;
  type: 'waf' | 'ids' | 'edr' | 'siem' | 'honeypot' | 'manual' | 'unknown';
  severity: Severity;
  source: string;
  description: string;
  operatorId?: string;
  targetId?: string;
  timestamp: number;
  mitigated: boolean;
}

// =============================================================================
// COMMS TYPES
// =============================================================================

export interface Message {
  id: string;
  from: string;
  to: string | string[];
  channel: string;
  type: 'intel' | 'task' | 'alert' | 'status' | 'finding' | 'coordination';
  priority: 'low' | 'normal' | 'high' | 'critical';
  content: string;
  metadata?: Record<string, unknown>;
  timestamp: number;
}

// =============================================================================
// TOOL TYPES
// =============================================================================

/** A tool's risk tier — the catalog's `risk` vocabulary. Drives the approval + spicy-warning gate
 *  (see src/arsenal/approval.ts): intrusive/credential/dangerous require approval; credential/dangerous
 *  additionally fire a loud warning. Absent/safe/active tools are ungated. */
export type RiskTier = 'local_read' | 'passive' | 'active' | 'intrusive' | 'credential' | 'dangerous';

export interface CustomTool {
  name: string;
  description: string;
  category: string;
  handler: (context: ToolContext) => Promise<ToolResult>;
  parameters?: ToolParameter[];
  requiredPermissions?: string[];
  /** Risk tier carried from the catalog when the tool is a minted adapter — gates approval. */
  riskTier?: RiskTier;
}

export interface ToolParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  description: string;
  required: boolean;
  default?: unknown;
}

export interface ToolContext {
  target?: Target;
  operator?: string;
  mission?: string;
  parameters: Record<string, unknown>;
}

/**
 * Simplified finding for tool results (tools don't have full context)
 */
export interface ToolFinding {
  title: string;
  severity: Severity;
  details: string;
  cvss?: number;
  cve?: string[];
  remediation?: string;
  /**
   * How this finding was produced — the provenance flag the honesty gate keys on:
   *  'tool'  = parsed from real tool output (has provenance, can be verified)
   *  'model' = asserted by the model in its debrief prose (NO provenance — the gate
   *            records it but refuses to mark it verified; prose is not evidence).
   */
  provenance?: 'tool' | 'model';
  /** For 'tool' provenance: the tool that produced it + the raw output backing the claim. */
  toolName?: string;
  toolOutput?: string;
}

export interface ToolResult {
  success: boolean;
  output?: string;
  findings?: ToolFinding[];
  credentials?: Credential[];
  error?: string;
  duration?: number;
}

// =============================================================================
// CONFIG TYPES
// =============================================================================

export interface TempestConfig {
  name: string;
  llm: LLMConfig;
  opsec?: Partial<OpsecConfig>;
  operators?: {
    maxConcurrent?: number;
    defaultConfig?: Partial<OperatorConfig>;
  };
  targets?: {
    maxConcurrent?: number;
  };
  tools?: CustomTool[];
  hooks?: RuntimeHooks;
}

export interface RuntimeHooks {
  onOperatorSpawned?: (operator: { id: string; archetype: OperatorArchetype }) => void;
  onOperatorStateChange?: (operator: { id: string }, newState: OperatorState) => void;
  onFindingDiscovered?: (finding: Finding, operator: { id: string }) => void;
  onCredentialHarvested?: (credential: Credential, operator: { id: string }) => void;
  onDetectionEvent?: (event: DetectionEvent) => void;
  onMissionPhaseChange?: (missionId: string, phase: KillChainPhase) => void;
  onTaskCompleted?: (task: Task) => void;
}

// =============================================================================
// REPORT TYPES
// =============================================================================

export interface Report {
  id: string;
  missionId: string;
  type: 'executive' | 'technical' | 'full_report' | 'findings_only';
  generatedAt: number;
  summary: ExecutiveSummary;
  findings: Finding[];
  attackPaths: AttackPath[];
  recommendations: Recommendation[];
  appendices?: Appendix[];
}

export interface ExecutiveSummary {
  overview: string;
  riskRating: Severity;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  infoFindings: number;
  successfulExploits: number;
  credentialsHarvested: number;
  systemsCompromised: number;
}

export interface AttackPath {
  id: string;
  name: string;
  description: string;
  steps: string[];
  findings: string[];
  impactLevel: Severity;
}

export interface Recommendation {
  id: string;
  findingId?: string;
  priority: 'immediate' | 'short_term' | 'long_term';
  title: string;
  description: string;
  effort: 'low' | 'medium' | 'high';
  impact: 'low' | 'medium' | 'high';
}

export interface Appendix {
  title: string;
  content: string;
}

// =============================================================================
// EVENT TYPES
// =============================================================================

export interface ScanProgressEvent {
  id: string;
  timestamp: number;
  kind: 'task_started' | 'thinking' | 'tool_call' | 'tool_result' | 'task_completed' | 'task_failed';
  operatorId: string;
  callsign: string;
  archetype: OperatorArchetype;
  taskId?: string;
  taskName?: string;
  toolName?: string;
  source?: 'agent' | 'backend_seeded';
  detail: string;
  success?: boolean;
}

export interface CommandEvents {
  'command:started': void;
  'command:stopped': void;
  'command:paused': void;
  'command:resumed': void;
  'tick': number;
  'operator:spawned': { id: string; archetype: OperatorArchetype };
  'operator:burned': { id: string };
  'finding:discovered': { finding: Finding; operatorId: string };
  'credential:harvested': { credential: Credential; operatorId: string };
  'target:owned': { target: Target; operatorId: string };
  'detection:triggered': DetectionEvent;
  'mission:phase_changed': { missionId: string; phase: KillChainPhase };
  'scan:progress': ScanProgressEvent;
  'abort:recommended': string;
  /** A capability-approval gate decision (allowed/denied) on an intrusive/dangerous tool — bridged to
   *  the dashboard's live approval/audit feed. Structural match for arsenal/approval.ts ApprovalRecord. */
  'approval:decision': {
    tool: string;
    risk: RiskTier;
    operator?: string;
    target?: string;
    action: string;
    outcome: string;
    spicy: boolean;
    at: number;
  };
}

// =============================================================================
// UTILITY TYPES
// =============================================================================

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export type RequireAtLeastOne<T, Keys extends keyof T = keyof T> =
  Pick<T, Exclude<keyof T, Keys>> &
  { [K in Keys]-?: Required<Pick<T, K>> & Partial<Pick<T, Exclude<Keys, K>>> }[Keys];
