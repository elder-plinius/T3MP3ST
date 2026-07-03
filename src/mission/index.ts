/**
 * T3MP3ST Mission Control
 *
 * Manages missions, tasks, and rules of engagement.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import {
  KillChainPhase,
  type Mission,
  type Task,
  type TaskResult,
  type RulesOfEngagement,
  type OperatorArchetype,
} from '../types/index.js';
import { KILL_CHAIN_ORDER } from '../operators/index.js';

// =============================================================================
// EVENTS
// =============================================================================

export interface MissionEvents {
  'mission:created': Mission;
  'mission:started': Mission;
  'mission:paused': Mission;
  'mission:resumed': Mission;
  'mission:completed': Mission;
  'mission:aborted': { mission: Mission; reason: string };
  'mission:phase_changed': { mission: Mission; oldPhase: KillChainPhase; newPhase: KillChainPhase };
  'task:created': Task;
  'task:assigned': { task: Task; operatorId: string };
  'task:completed': { task: Task; result: TaskResult };
  'task:failed': { task: Task; error: string };
}

export interface TaskQueueEvents {
  'task:added': Task;
  'task:removed': Task;
  'queue:empty': void;
}

// =============================================================================
// RULES OF ENGAGEMENT
// =============================================================================

export function createDefaultRoE(): RulesOfEngagement {
  return {
    scope: [],
    excludedTargets: [],
    allowedTechniques: [],
    forbiddenTechniques: [],
    maxDetectionEvents: 5,
    requireManualApproval: ['T1078', 'T1059', 'T1548'], // Credential use, command exec, privilege escalation
  };
}

export function createStrictRoE(): RulesOfEngagement {
  return {
    scope: [],
    excludedTargets: [],
    allowedTechniques: [],
    forbiddenTechniques: [
      'T1485', // Data Destruction
      'T1489', // Service Stop
      'T1490', // Inhibit System Recovery
      'T1499', // Endpoint DoS
    ],
    maxDetectionEvents: 2,
    requireManualApproval: ['T1078', 'T1059', 'T1548', 'T1055', 'T1134'],
  };
}

// =============================================================================
// TASK QUEUE
// =============================================================================

export class TaskQueue extends EventEmitter<TaskQueueEvents> {
  private tasks: Task[] = [];

  /**
   * Add a task to the queue
   */
  add(task: Task): void {
    this.tasks.push(task);
    this.sortByPriority();
    this.emit('task:added', task);
  }

  /**
   * Add multiple tasks
   */
  addMany(tasks: Task[]): void {
    for (const task of tasks) {
      this.add(task);
    }
  }

  /**
   * Get the next pending task
   */
  getNext(): Task | undefined {
    return this.tasks.find(t => t.status === 'pending');
  }

  /**
   * Get the next pending task for a specific operator type
   */
  getNextForArchetype(archetype: OperatorArchetype): Task | undefined {
    return this.tasks.find(t => t.status === 'pending' && t.operatorType === archetype);
  }

  /**
   * Get all pending tasks
   */
  getPending(): Task[] {
    return this.tasks.filter(t => t.status === 'pending');
  }

  /**
   * Get all tasks for a mission
   */
  getForMission(missionId: string): Task[] {
    return this.tasks.filter(t => t.missionId === missionId);
  }

  /**
   * Update a task's status
   */
  updateStatus(taskId: string, status: Task['status'], result?: TaskResult): Task | undefined {
    const task = this.tasks.find(t => t.id === taskId);
    if (task) {
      task.status = status;
      if (result) task.result = result;
      if (status === 'in_progress') task.startedAt = Date.now();
      if (status === 'completed' || status === 'failed') task.completedAt = Date.now();
    }
    return task;
  }

  /**
   * Get a task by ID
   */
  getTask(taskId: string): Task | undefined {
    return this.tasks.find(t => t.id === taskId);
  }

  /**
   * Mark a task as assigned to an operator
   */
  assign(taskId: string, operatorId: string): void {
    const task = this.tasks.find(t => t.id === taskId);
    if (task) {
      task.status = 'assigned';
      task.assignedTo = operatorId;
      task.startedAt = Date.now();
    }
  }

  /**
   * Mark a task as completed with result
   */
  complete(taskId: string, result: TaskResult): void {
    this.updateStatus(taskId, 'completed', result);
  }

  /**
   * Mark a task as failed with error message
   */
  fail(taskId: string, error: string): void {
    this.updateStatus(taskId, 'failed', { success: false, error });
  }

  /**
   * Remove a task
   */
  remove(taskId: string): Task | undefined {
    const index = this.tasks.findIndex(t => t.id === taskId);
    if (index !== -1) {
      const [task] = this.tasks.splice(index, 1);
      this.emit('task:removed', task);
      if (this.tasks.length === 0) {
        this.emit('queue:empty');
      }
      return task;
    }
    return undefined;
  }

  /**
   * Sort tasks by priority
   */
  private sortByPriority(): void {
    this.tasks.sort((a, b) => b.priority - a.priority);
  }

  /**
   * Get queue size
   */
  get size(): number {
    return this.tasks.length;
  }

  /**
   * Get pending count
   */
  get pendingCount(): number {
    return this.tasks.filter(t => t.status === 'pending').length;
  }

  /**
   * Clear the queue
   */
  clear(): void {
    this.tasks = [];
  }
}

// =============================================================================
// MISSION CONTROL
// =============================================================================

export class MissionControl extends EventEmitter<MissionEvents> {
  private missions: Map<string, Mission> = new Map();
  private taskQueue: TaskQueue;
  private activeMissionId: string | null = null;

  constructor() {
    super();
    this.taskQueue = new TaskQueue();

    // Forward task queue events
    this.taskQueue.on('task:added', task => this.emit('task:created', task));
  }

  /**
   * Create a new mission
   */
  createMission(params: {
    name: string;
    description?: string;
    objectives: string[];
    phases?: KillChainPhase[];
    rules?: RulesOfEngagement;
  }): Mission {
    const mission: Mission = {
      id: randomUUID(),
      name: params.name,
      description: params.description,
      objectives: params.objectives,
      phases: params.phases || KILL_CHAIN_ORDER,
      rules: params.rules || createDefaultRoE(),
      status: 'planning',
      currentPhase: params.phases?.[0] || KillChainPhase.RECON,
      progress: 0,
    };

    this.missions.set(mission.id, mission);
    this.emit('mission:created', mission);

    return mission;
  }

  /**
   * Start a mission
   */
  startMission(missionId: string): Mission {
    const mission = this.missions.get(missionId);
    if (!mission) {
      throw new Error(`Mission ${missionId} not found`);
    }

    if (mission.status !== 'planning' && mission.status !== 'paused') {
      throw new Error(`Cannot start mission in ${mission.status} status`);
    }

    mission.status = 'active';
    mission.startedAt = Date.now();
    this.activeMissionId = missionId;

    this.emit('mission:started', mission);

    return mission;
  }

  /**
   * Generate initial tasks for a target under the active mission.
   * Called when a target is added or when a mission starts with existing targets.
   */
  generateTasksForTarget(targetAddress: string): void {
    const mission = this.getActiveMission();
    if (!mission) return;

    // Check if we already have tasks for this target (avoid duplicates)
    const existingTasks = this.taskQueue.getForMission(mission.id);
    const alreadyHasTasksForTarget = existingTasks.some(t =>
      t.description.includes(targetAddress)
    );
    if (alreadyHasTasksForTarget) return;

    // Always start with recon tasks
    const reconTasks = createReconTasks(mission.id, targetAddress);
    this.taskQueue.addMany(reconTasks);
  }

  /**
   * Generate next-phase tasks based on the current mission phase and target.
   * Called by the tick loop when current phase tasks are all done.
   */
  generateNextPhaseTasks(targetAddress: string): void {
    const mission = this.getActiveMission();
    if (!mission) return;

    const phase = mission.currentPhase;
    let tasks: Task[] = [];

    switch (phase) {
      case KillChainPhase.WEAPONIZE:
        tasks = createVulnScanTasks(mission.id, targetAddress);
        break;
      case KillChainPhase.DELIVER:
        tasks = createExploitTasks(mission.id, targetAddress);
        break;
      case KillChainPhase.ACTIONS:
        tasks = createAnalysisTasks(mission.id, targetAddress);
        break;
    }

    if (tasks.length > 0) {
      this.taskQueue.addMany(tasks);
    }
  }

  /**
   * Pause a mission
   */
  pauseMission(missionId: string): Mission {
    const mission = this.missions.get(missionId);
    if (!mission) {
      throw new Error(`Mission ${missionId} not found`);
    }

    if (mission.status !== 'active') {
      throw new Error(`Cannot pause mission in ${mission.status} status`);
    }

    mission.status = 'paused';
    this.emit('mission:paused', mission);

    return mission;
  }

  /**
   * Resume a mission
   */
  resumeMission(missionId: string): Mission {
    const mission = this.missions.get(missionId);
    if (!mission) {
      throw new Error(`Mission ${missionId} not found`);
    }

    if (mission.status !== 'paused') {
      throw new Error(`Cannot resume mission in ${mission.status} status`);
    }

    mission.status = 'active';
    this.emit('mission:resumed', mission);

    return mission;
  }

  /**
   * Complete a mission
   */
  completeMission(missionId: string): Mission {
    const mission = this.missions.get(missionId);
    if (!mission) {
      throw new Error(`Mission ${missionId} not found`);
    }

    mission.status = 'completed';
    mission.completedAt = Date.now();
    mission.progress = 100;

    if (this.activeMissionId === missionId) {
      this.activeMissionId = null;
    }

    this.emit('mission:completed', mission);

    return mission;
  }

  /**
   * Abort a mission
   */
  abortMission(missionId: string, reason: string): Mission {
    const mission = this.missions.get(missionId);
    if (!mission) {
      throw new Error(`Mission ${missionId} not found`);
    }

    mission.status = 'aborted';
    mission.completedAt = Date.now();

    if (this.activeMissionId === missionId) {
      this.activeMissionId = null;
    }

    this.emit('mission:aborted', { mission, reason });

    return mission;
  }

  /**
   * Advance to the next phase
   */
  advancePhase(missionId: string): Mission {
    const mission = this.missions.get(missionId);
    if (!mission) {
      throw new Error(`Mission ${missionId} not found`);
    }

    const currentIndex = mission.phases.indexOf(mission.currentPhase);
    if (currentIndex === -1 || currentIndex >= mission.phases.length - 1) {
      throw new Error('No more phases to advance to');
    }

    const oldPhase = mission.currentPhase;
    mission.currentPhase = mission.phases[currentIndex + 1];
    mission.progress = ((currentIndex + 1) / mission.phases.length) * 100;

    this.emit('mission:phase_changed', { mission, oldPhase, newPhase: mission.currentPhase });

    return mission;
  }

  /**
   * Get a mission by ID
   */
  getMission(missionId: string): Mission | undefined {
    return this.missions.get(missionId);
  }

  /**
   * Get the active mission
   */
  getActiveMission(): Mission | undefined {
    return this.activeMissionId ? this.missions.get(this.activeMissionId) : undefined;
  }

  /**
   * Get all missions
   */
  getAllMissions(): Mission[] {
    return Array.from(this.missions.values());
  }

  /**
   * Create a task for a mission
   */
  createTask(params: {
    missionId: string;
    name: string;
    description: string;
    phase: KillChainPhase;
    operatorType: OperatorArchetype;
    priority?: number;
    dependencies?: string[];
  }): Task {
    const task: Task = {
      id: randomUUID(),
      missionId: params.missionId,
      name: params.name,
      description: params.description,
      phase: params.phase,
      operatorType: params.operatorType,
      status: 'pending',
      priority: params.priority || 5,
      dependencies: params.dependencies || [],
      createdAt: Date.now(),
    };

    this.taskQueue.add(task);

    return task;
  }

  /**
   * Get the task queue
   */
  getTaskQueue(): TaskQueue {
    return this.taskQueue;
  }

  /**
   * Check if a technique is allowed by the RoE
   */
  isTechniqueAllowed(missionId: string, technique: string): boolean {
    const mission = this.missions.get(missionId);
    if (!mission) return false;

    const { rules } = mission;

    // Check if explicitly forbidden
    if (rules.forbiddenTechniques.includes(technique)) {
      return false;
    }

    // If allowedTechniques is specified and not empty, technique must be in it
    if (rules.allowedTechniques.length > 0 && !rules.allowedTechniques.includes(technique)) {
      return false;
    }

    return true;
  }

  /**
   * Check if a technique requires manual approval
   */
  requiresApproval(missionId: string, technique: string): boolean {
    const mission = this.missions.get(missionId);
    if (!mission) return true;

    return mission.rules.requireManualApproval.includes(technique);
  }

  /**
   * Get mission statistics
   */
  getStats(): {
    total: number;
    active: number;
    completed: number;
    aborted: number;
    planning: number;
    paused: number;
  } {
    const missions = this.getAllMissions();

    return {
      total: missions.length,
      active: missions.filter(m => m.status === 'active').length,
      completed: missions.filter(m => m.status === 'completed').length,
      aborted: missions.filter(m => m.status === 'aborted').length,
      planning: missions.filter(m => m.status === 'planning').length,
      paused: missions.filter(m => m.status === 'paused').length,
    };
  }
}

// =============================================================================
// TASK FACTORIES
// =============================================================================

export function createReconTasks(missionId: string, targetAddress: string): Task[] {
  const tasks: Task[] = [];

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'DNS Enumeration',
    description: `Enumerate all DNS record types (A, AAAA, MX, TXT, NS, SOA, CNAME) for ${targetAddress}. Identify hosting providers, mail servers, SPF/DKIM/DMARC configuration, and any related domains.`,
    phase: KillChainPhase.RECON,
    operatorType: 'recon',
    status: 'pending',
    priority: 10,
    dependencies: [],
    createdAt: Date.now(),
  });

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Port Scanning & Service Detection',
    description: `Scan ${targetAddress} for open ports and detect running services with version information. Start with top 1000 ports, then expand if significant results are found. Identify the full attack surface.`,
    phase: KillChainPhase.RECON,
    operatorType: 'recon',
    status: 'pending',
    priority: 9,
    dependencies: [],
    createdAt: Date.now(),
  });

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Web Probing & Technology Fingerprinting',
    description: `Probe all HTTP/HTTPS services on ${targetAddress}. Check response headers, server banners, technology stack, CMS detection, security headers, robots.txt, sitemap.xml, and common paths. Identify frameworks, libraries, and potential misconfigurations.`,
    phase: KillChainPhase.RECON,
    operatorType: 'recon',
    status: 'pending',
    priority: 8,
    dependencies: [],
    createdAt: Date.now(),
  });

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Content Discovery',
    description: `Discover hidden directories, files, API endpoints, admin panels, and backup files on ${targetAddress} using directory brute-forcing and common path checks.`,
    phase: KillChainPhase.RECON,
    operatorType: 'recon',
    status: 'pending',
    priority: 7,
    dependencies: [],
    createdAt: Date.now(),
  });

  return tasks;
}

export function createVulnScanTasks(missionId: string, targetAddress: string): Task[] {
  const tasks: Task[] = [];

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Automated Vulnerability Scan',
    description: `Run automated vulnerability scanning against ${targetAddress}. Check for known CVEs, common misconfigurations, and security issues. Start with critical/high severity checks, then medium/low.`,
    phase: KillChainPhase.WEAPONIZE,
    operatorType: 'scanner',
    status: 'pending',
    priority: 10,
    dependencies: [],
    createdAt: Date.now(),
  });

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Web Application Security Testing',
    description: `Test ${targetAddress} for OWASP Top 10 vulnerabilities: SQL injection, XSS, SSRF, broken authentication, access control issues, security misconfigurations. Validate all findings with manual confirmation.`,
    phase: KillChainPhase.WEAPONIZE,
    operatorType: 'scanner',
    status: 'pending',
    priority: 9,
    dependencies: [],
    createdAt: Date.now(),
  });

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Network Service Vulnerability Assessment',
    description: `Assess network services on ${targetAddress} for vulnerabilities: default credentials, known CVEs for detected versions, protocol weaknesses, and misconfigurations.`,
    phase: KillChainPhase.WEAPONIZE,
    operatorType: 'scanner',
    status: 'pending',
    priority: 8,
    dependencies: [],
    createdAt: Date.now(),
  });

  return tasks;
}

export function createExploitTasks(missionId: string, targetAddress: string): Task[] {
  const tasks: Task[] = [];

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Exploit Confirmed Vulnerabilities',
    description: `Review confirmed vulnerability findings for ${targetAddress} and exploit the highest-severity issues to demonstrate real-world impact. Prove code execution, data access, or authentication bypass with minimal-impact payloads. Document full evidence chain.`,
    phase: KillChainPhase.DELIVER,
    operatorType: 'exploiter',
    status: 'pending',
    priority: 10,
    dependencies: [],
    createdAt: Date.now(),
  });

  return tasks;
}

export function createAnalysisTasks(missionId: string, targetAddress: string): Task[] {
  const tasks: Task[] = [];

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Finding Analysis & Report Generation',
    description: `Analyze all findings from the assessment of ${targetAddress}. Validate severity ratings, identify attack chains, calculate CVSS scores, prioritize remediation recommendations, and produce a comprehensive security report.`,
    phase: KillChainPhase.ACTIONS,
    operatorType: 'analyst',
    status: 'pending',
    priority: 10,
    dependencies: [],
    createdAt: Date.now(),
  });

  return tasks;
}
