/**
 * T3MP3ST Mission Control
 *
 * Manages missions, tasks, and rules of engagement.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import {
  KillChainPhase,
  type MissionFamily,
  type Mission,
  type Task,
  type TaskResult,
  type RulesOfEngagement,
  type OperatorArchetype,
  type Finding,
} from '../types/index.js';
import { getPhasesForFamily } from '../operators/index.js';

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
    family?: MissionFamily;
  }): Mission {
    const phases = params.phases || getPhasesForFamily(params.family);
    const mission: Mission = {
      id: randomUUID(),
      name: params.name,
      description: params.description,
      objectives: params.objectives,
      phases,
      rules: params.rules || createDefaultRoE(),
      status: 'planning',
      currentPhase: phases[0] || KillChainPhase.RECON,
      progress: 0,
      family: params.family,
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
  generateTasksForTarget(targetAddress: string, scanOptions?: { spiderScope?: string; spiderDepth?: number; spiderMaxPages?: number }): void {
    const mission = this.getActiveMission();
    if (!mission) return;

    // Check if we already have tasks for this target (avoid duplicates)
    const existingTasks = this.taskQueue.getForMission(mission.id);
    const alreadyHasTasksForTarget = existingTasks.some(t =>
      t.description.includes(targetAddress)
    );
    if (alreadyHasTasksForTarget) return;

    // Seed initial tasks based on mission family — no port scans for code repos
    const initialTasks = mission.family === 'code_supply_chain'
      ? createCodeScanTasks(mission.id, targetAddress).slice(0, 1)       // start with enumeration only
      : mission.family === 'local_code_scan'
      ? createLocalScanTasks(mission.id, targetAddress).slice(0, 1)      // start with local enumeration only
      : mission.family === 'cloud_infra'
      ? createCloudInfraTasks(mission.id, targetAddress).slice(0, 1)     // start with cloud asset discovery
      : mission.family === 'reverse_binary'
      ? createBinaryAnalysisTasks(mission.id, targetAddress).slice(0, 1) // start with binary identification
      : createReconTasks(mission.id, targetAddress, scanOptions);
    this.taskQueue.addMany(initialTasks);
  }

  /**
   * Generate next-phase tasks based on the current mission phase, family, and target.
   * Called by the tick loop when current phase tasks are all done.
   */
  generateNextPhaseTasks(targetAddress: string, findings?: Finding[], sandboxOptions?: { networkMode?: string; durationSec?: number; alias?: string }): void {
    const mission = this.getActiveMission();
    if (!mission) return;

    const phase = mission.currentPhase;
    let tasks: Task[] = [];

    if (mission.family === 'code_supply_chain' || mission.family === 'local_code_scan') {
      const isLocal = mission.family === 'local_code_scan';
      switch (phase) {
        case KillChainPhase.WEAPONIZE:
          // Static scan, secrets, deps, and LLM review — full scan suite minus enumeration
          tasks = isLocal
            ? createLocalScanTasks(mission.id, targetAddress).slice(1)
            : createCodeScanTasks(mission.id, targetAddress).slice(1);
          break;
        case KillChainPhase.ACTIONS:
          // Validation only — no web probe tools against a code target
          tasks = createFindingValidationTasks(mission.id, targetAddress, findings ?? []);
          break;
      }
    } else if (mission.family === 'cloud_infra') {
      switch (phase) {
        case KillChainPhase.WEAPONIZE:
          // Config scan (idx 1) + IAM LLM review (idx 2)
          tasks = createCloudInfraTasks(mission.id, targetAddress).slice(1, 3);
          break;
        case KillChainPhase.EXPLOIT:
          // Misconfiguration exploitation probe (idx 3)
          tasks = createCloudInfraTasks(mission.id, targetAddress).slice(3, 4);
          break;
        case KillChainPhase.ACTIONS:
          tasks = createFindingValidationTasks(mission.id, targetAddress, findings ?? []);
          break;
      }
    } else if (mission.family === 'reverse_binary') {
      switch (phase) {
        case KillChainPhase.WEAPONIZE:
          // Deep disassembly + decompilation + ROP + XOR decode (idx 1)
          tasks = createBinaryAnalysisTasks(mission.id, targetAddress, sandboxOptions).slice(1, 2);
          break;
        case KillChainPhase.EXPLOIT:
          // LLM vulnerability pattern hunting (idx 2)
          tasks = createBinaryAnalysisTasks(mission.id, targetAddress, sandboxOptions).slice(2, 3);
          break;
        case KillChainPhase.ACTIONS:
          // Binary-specific deep validation — decompiles each suspect function for confirmation
          tasks = createBinaryValidationTasks(mission.id, targetAddress, findings ?? []);
          if (tasks.length === 0) tasks = createFindingValidationTasks(mission.id, targetAddress, findings ?? []);
          break;
      }
    } else {
      switch (phase) {
        case KillChainPhase.WEAPONIZE:
          tasks = createVulnScanTasks(mission.id, targetAddress);
          break;
        case KillChainPhase.DELIVER:
          tasks = createExploitTasks(mission.id, targetAddress);
          break;
        case KillChainPhase.ACTIONS:
          tasks = createFindingValidationTasks(mission.id, targetAddress, findings ?? []);
          break;
      }
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

export function createReconTasks(
  missionId: string,
  targetAddress: string,
  scanOptions?: { spiderScope?: string; spiderDepth?: number; spiderMaxPages?: number },
): Task[] {
  const spiderScope = scanOptions?.spiderScope ?? 'strict';
  const spiderDepth = scanOptions?.spiderDepth ?? 2;
  const spiderMaxPages = scanOptions?.spiderMaxPages ?? 50;
  const tasks: Task[] = [];

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'DNS & OSINT Enumeration',
    description: `Enumerate all DNS and registration data for ${targetAddress}. YOUR tool sequence — call each in order:\n1. dns_lookup with domain="${targetAddress}" — get A, AAAA, MX, TXT, NS, SOA, CNAME records\n2. whois_lookup with domain="${targetAddress}" — registrar, creation date, nameservers\n3. subdomain_enum with domain="${targetAddress}" — discover related subdomains\n4. reverse_dns on each IP returned from A records\n5. cert_transparency with domain="${targetAddress}" — query CT logs for subdomains that wordlist enumeration misses\n\nSkip steps 1/2/3 if ${targetAddress} is a bare IP address — start at step 4 in that case.\nRecord every IP, mail server, nameserver, SPF/DKIM/DMARC policy, hosting provider, and registrar.`,
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
    description: `Map every exposed service on ${targetAddress}. YOUR tool sequence — call each in order:\n1. port_scan with target="${targetAddress}" — scan top 1000 ports\n2. version_detect on every open port found — get service name, version, and banner\n3. nmap_scan with target="${targetAddress}" — deeper fingerprinting and OS detection if nmap is available\n\nReport every open port, protocol, service name, version string, and any banner text captured.`,
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
    description: `Fingerprint all web-facing services on ${targetAddress}. YOUR tool sequence — call each in order:\n1. http_request on http://${targetAddress}/ — capture status code, headers, and body snippet\n2. http_request on https://${targetAddress}/ — confirm HTTPS availability\n3. technology_detect with url="${targetAddress}" — identify frameworks, CMS, CDN, JS libraries\n4. header_analysis with url="${targetAddress}" — audit HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer-Policy, Permissions-Policy\n5. robots_txt_fetch with url="${targetAddress}" — surface disallowed paths and sitemaps\n6. ssl_scan with url="${targetAddress}" — TLS versions, certificate validity, weak ciphers (skip if no HTTPS)\n\nSkip all steps if no web ports are open. Report every identified technology, version, and security header gap.`,
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
    description: `Discover hidden attack surface on ${targetAddress}. YOUR tool sequence — call each in order:\n1. dir_bruteforce with url="${targetAddress}" — enumerate common directories, admin panels, backup files, config files (.env, .git, web.config, .htaccess)\n2. api_endpoint_discovery with url="${targetAddress}" — find REST endpoints, GraphQL, undocumented APIs, OpenAPI/Swagger specs\n3. http_request on the most interesting paths found (/.git/HEAD, /.env, /admin, /api/v1, /swagger, /graphql, /actuator, /metrics, /debug)\n\nSkip if no web ports are open. Report all discovered paths with HTTP status codes and content-type headers.`,
    phase: KillChainPhase.RECON,
    operatorType: 'recon',
    status: 'pending',
    priority: 7,
    dependencies: [],
    createdAt: Date.now(),
  });

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'WAF Detection & Technology Audit',
    description: `Detect WAF presence and fingerprint infrastructure for ${targetAddress}. YOUR tool sequence:\n1. waf_detect with url="${targetAddress}" — fingerprint WAF vendor (informs payload encoding for all subsequent scans)\n2. site_spider with url="${targetAddress}", depth=${spiderDepth}, max_pages=${spiderMaxPages}, scope="${spiderScope}" — crawl all reachable pages, extract forms and URL parameters for fuzzing\n3. Note: spider results (URL params, forms) are critical inputs for WEAPONIZE phase param_fuzz calls`,
    phase: KillChainPhase.RECON,
    operatorType: 'recon',
    status: 'pending',
    priority: 6,
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
    name: 'SSL/TLS, Headers & Configuration Audit',
    description: `Audit ${targetAddress} for configuration-level and infrastructure vulnerabilities. YOUR tool sequence — call each in order:\n1. ssl_scan with url="${targetAddress}" — TLS version support, certificate validity/expiry, weak ciphers (BEAST, POODLE, ROBOT, RC4)\n2. header_analysis with url="${targetAddress}" — missing/misconfigured HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy\n3. cors_check with url="${targetAddress}" — wildcard origins, credentialed cross-origin exposure, CORS bypass\n4. cookie_analysis with url="${targetAddress}" — missing Secure, SameSite, or HttpOnly flags on session cookies\n5. clickjacking_test with url="${targetAddress}" — X-Frame-Options absent or bypassable\n6. csp_analysis with url="${targetAddress}" — unsafe-inline, unsafe-eval, wildcard sources, missing directives\n7. nuclei_scan with url="${targetAddress}" — template-based CVE checks, exposed panels, known misconfigurations\n\nSkip SSL steps if no HTTPS. Report ALL confirmed issues with severity rating and full HTTP evidence.`,
    phase: KillChainPhase.WEAPONIZE,
    operatorType: 'web_scanner',
    status: 'pending',
    priority: 10,
    dependencies: [],
    createdAt: Date.now(),
  });

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Web Application Vulnerability Testing',
    description: `Test ${targetAddress} for exploitable OWASP Top 10 vulnerabilities. YOUR tool sequence — call each in order:\n1. xss_scan with url="${targetAddress}" — reflected XSS, stored XSS, DOM XSS payloads\n2. sqli_scan with url="${targetAddress}" — error-based, boolean-blind, time-based SQLi\n3. lfi_test with url="${targetAddress}" — local file inclusion (../../../etc/passwd, php://filter, /proc/self/environ)\n4. open_redirect_test with url="${targetAddress}" — open redirect via URL parameters and headers\n5. ssti_test with url="${targetAddress}" — Jinja2/Twig/ERB/Mako server-side template injection\n6. api_endpoint_discovery with url="${targetAddress}" — surface undocumented endpoints and APIs, then probe each for auth bypass and injection\n7. param_fuzz with url="<URL-with-params-from-spider>" and mode="all" — dynamically fuzz all parameters discovered by site_spider\n8. host_header_injection with url="${targetAddress}" — test Host/X-Forwarded-Host for cache poisoning\n9. ssrf_test with url="${targetAddress}" — test URL params and headers for SSRF\n10. xxe_test with url="${targetAddress}" — test XML/SVG endpoints for XXE\n11. graphql_probe with url="${targetAddress}" — discover and test GraphQL endpoints\n12. oauth_probe with url="${targetAddress}" — test OAuth flows if present\n\nDo NOT report potential issues — only confirmed findings with reproduction steps.`,
    phase: KillChainPhase.WEAPONIZE,
    operatorType: 'web_scanner',
    status: 'pending',
    priority: 9,
    dependencies: [],
    createdAt: Date.now(),
  });

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Advanced Client-Side & Injection Testing',
    description: `Perform advanced injection and client-side vulnerability testing on ${targetAddress}. YOUR tool sequence — call each in order:\n1. js_analysis with url="${targetAddress}" — extract and analyse all linked JavaScript files for hardcoded secrets (AWS keys, GitHub tokens, JWTs, API keys), internal API endpoints, and sensitive patterns; report every finding\n2. nosql_injection with url="${targetAddress}" — test URL params and JSON POST bodies for MongoDB/NoSQL operator injection ($ne, $gt, $regex, $where); probe both GET bracket-notation variants and JSON POST auth-bypass payloads\n3. command_injection with url="${targetAddress}" — test all URL parameters for OS command injection using output-based (echo marker) and time-based blind (sleep) payloads; report any confirmed RCE\n4. http_param_pollution with url="${targetAddress}" — send duplicate parameters with safe+malicious ordering to test WAF bypass and server-side parser differential; flag any malicious param reflection\n5. web_cache_poisoning with url="${targetAddress}" — inject canary values via X-Forwarded-Host, X-Host, X-Forwarded-Server, X-Original-URL and check if they are reflected in cached responses\n6. prototype_pollution with url="${targetAddress}" — test __proto__ and constructor.prototype injection via GET params and JSON POST bodies; detect via error markers and behavioral response changes\n7. For any paths that returned 403 during reconnaissance, call bypass_403 with url="<403-path>" — test X-Original-URL, X-Rewrite-URL, IP spoofing headers, and path variants (/., //, %2F) for access control bypass\n\nDo NOT report theoretical issues — only confirmed findings with HTTP evidence (request + response).`,
    phase: KillChainPhase.WEAPONIZE,
    operatorType: 'web_scanner',
    status: 'pending',
    priority: 8,
    dependencies: [],
    createdAt: Date.now(),
  });

  tasks.push({
    id: randomUUID(),
    missionId,
    name: 'Network Service & Credential Assessment',
    description: `Assess exposed network services on ${targetAddress} for exploitable weaknesses. YOUR tool sequence — call each in order:\n1. port_scan with target="${targetAddress}" — confirm all open ports (cross-check RECON findings)\n2. http_methods_test with url="${targetAddress}" — detect dangerous HTTP methods (PUT, DELETE, TRACE, CONNECT, PATCH on sensitive paths)\n3. password_spray with url="${targetAddress}" — test default/common credentials against login forms, admin panels, and any SSH/FTP/RDP ports found\n4. jwt_decode on any JWT tokens found in responses or cookies — flag alg:none, expired tokens, weak signing keys\n5. cve_lookup for every service version identified in RECON — retrieve CVE IDs, CVSS scores, and exploit availability\n6. cloud_storage_check with domain="${targetAddress}" — check for public S3/GCS/Azure buckets\n7. cloud_metadata — probe IMDS endpoints (relevant if scanner is on same cloud network)\n8. subdomain_takeover with domain="${targetAddress}" — check for dangling DNS entries pointing to claimable services\n9. rate_limit_check with url="${targetAddress}" — verify rate limiting on auth endpoints\n10. http_smuggling with url="${targetAddress}" — timing-based CL.TE detection\n\nReport default credentials found, unpatched CVEs with CVSS ≥ 7.0, dangerous HTTP method exposures, JWT weaknesses, and any cloud misconfigurations.`,
    phase: KillChainPhase.WEAPONIZE,
    operatorType: 'web_scanner',
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

// =============================================================================
// CODE SUPPLY CHAIN TASK FACTORIES
// For git repos: enumerate → static scan → secrets → deps → validate.
// No port scanning. No C2. No persistence.
// =============================================================================

export function createCodeScanTasks(missionId: string, repoUrl: string): Task[] {
  const reconId = randomUUID();
  const fullScanId = randomUUID();
  const llmReviewId = randomUUID();

  return [
    {
      id: reconId,
      missionId,
      name: 'Repository Enumeration',
      description: `Clone and enumerate the repository at ${repoUrl}. YOUR ONLY TOOL CALL for this task is git_clone_analyze — call it with url="${repoUrl}". Do NOT call semgrep_scan, gitleaks_scan, trivy_scan, or llm_code_review. Those tools run in the WEAPONIZE phase. Report the clone path, detected languages, source file counts, and any CI/CD or dependency manifest files present.`,
      phase: KillChainPhase.RECON,
      operatorType: 'code_scanner',
      status: 'pending',
      priority: 10,
      dependencies: [],
      createdAt: Date.now(),
    },
    {
      id: fullScanId,
      missionId,
      name: 'Full Code Security Scan',
      description: `CODE REPOSITORY TASK — NOT a web application. DO NOT use nuclei_scan, nmap_scan, http_request, or any network/web probing tool.\n\nThe repository at ${repoUrl} has already been cloned locally by the RECON phase. Run ALL THREE scan tools IN SEQUENCE — do not skip any:\n\n1. Call semgrep_scan with url="${repoUrl}" — static analysis for injection sinks (SQLi, command injection, SSTI, path traversal), insecure deserialization, hardcoded credentials, dangerous calls (eval, exec, pickle.loads), weak cryptography, OWASP Top 10 patterns.\n\n2. Call gitleaks_scan with url="${repoUrl}" — scans current files AND full git history for leaked secrets: API keys, tokens, passwords, private keys, connection strings, cloud credentials.\n\n3. Call trivy_scan with url="${repoUrl}" — audits direct and transitive dependencies for known CVEs and supply-chain risk. Reports CVE ID, severity, installed version, and whether a patch is available.\n\nAfter all three tools return, produce your final debrief with ALL findings from all three tools combined.`,
      phase: KillChainPhase.WEAPONIZE,
      operatorType: 'code_scanner',
      status: 'pending',
      priority: 10,
      dependencies: [],
      createdAt: Date.now(),
    },
    {
      id: llmReviewId,
      missionId,
      name: 'LLM Semantic Code Review',
      description: `The repository at ${repoUrl} has already been cloned locally by the RECON phase. Call llm_code_review FOUR TIMES with different focus areas to maximize coverage — each call analyzes different high-risk files based on the focus parameter:\n\n1. Call llm_code_review with url="${repoUrl}", focus="injection" — finds SQL injection, XSS, command injection, SSTI, path traversal, eval/exec sinks with user input\n2. Call llm_code_review with url="${repoUrl}", focus="auth" — finds broken access control, missing auth checks, IDOR, JWT weaknesses, privilege escalation, session fixation\n3. Call llm_code_review with url="${repoUrl}", focus="logic" — finds race conditions, mass assignment, missing ownership checks, insecure redirects, business logic flaws\n4. Call llm_code_review with url="${repoUrl}", focus="secrets" — finds hardcoded API keys, passwords, tokens, private keys, connection strings\n\nDO NOT call technology_detect, http_methods_test, security_headers, or any web probe tool — this is a code repo, not a web target.`,
      phase: KillChainPhase.WEAPONIZE,
      operatorType: 'analyst',
      status: 'pending',
      priority: 9,
      dependencies: [],
      createdAt: Date.now(),
    },
  ];
}

/**
 * Create tasks for scanning a local ZIP or pre-extracted folder (local:// targets).
 * Mirrors createCodeScanTasks but uses local_code_scan instead of git_clone_analyze.
 */
export function createLocalScanTasks(missionId: string, localRef: string): Task[] {
  const reconId = randomUUID();
  const fullScanId = randomUUID();
  const llmReviewId = randomUUID();

  // Normalise: ensure we always work with a local:// URL
  const ref = localRef.startsWith('local://') ? localRef : `local://${localRef}`;

  return [
    {
      id: reconId,
      missionId,
      name: 'Local Target Enumeration',
      description: `Enumerate the local code target: ${ref}. YOUR ONLY TOOL CALL for this task is local_code_scan — call it with path="${ref}". Do NOT call semgrep_scan, gitleaks_scan, trivy_scan, or llm_code_review yet. Report the scan path, detected languages, source file counts, and any CI/CD or dependency manifest files present.`,
      phase: KillChainPhase.RECON,
      operatorType: 'code_scanner',
      status: 'pending',
      priority: 10,
      dependencies: [],
      createdAt: Date.now(),
    },
    {
      id: fullScanId,
      missionId,
      name: 'Full Code Security Scan',
      description: `LOCAL CODE REPOSITORY TASK — NOT a web application. DO NOT use nuclei_scan, nmap_scan, http_request, or any network/web probing tool.\n\nThe local target ${ref} has already been enumerated by the RECON phase. Run ALL THREE scan tools IN SEQUENCE:\n\n1. Call semgrep_scan with url="${ref}" — static analysis for injection sinks (SQLi, command injection, SSTI, path traversal), insecure deserialization, hardcoded credentials, dangerous calls (eval, exec, pickle.loads), weak cryptography, OWASP Top 10 patterns.\n\n2. Call gitleaks_scan with url="${ref}" — scans files for leaked secrets: API keys, tokens, passwords, private keys, connection strings, cloud credentials. If a .git directory is present, gitleaks will also scan the full commit history for secrets that were added and later removed.\n\n3. Call trivy_scan with url="${ref}" — audits dependencies for known CVEs. Reports CVE ID, severity, installed version, and patch availability.\n\nAfter all three tools return, produce your final debrief with ALL findings combined.`,
      phase: KillChainPhase.WEAPONIZE,
      operatorType: 'code_scanner',
      status: 'pending',
      priority: 10,
      dependencies: [],
      createdAt: Date.now(),
    },
    {
      id: llmReviewId,
      missionId,
      name: 'LLM Semantic Code Review',
      description: `The local target ${ref} has already been enumerated by the RECON phase. Call llm_code_review FOUR TIMES with different focus areas:\n\n1. Call llm_code_review with url="${ref}", focus="injection"\n2. Call llm_code_review with url="${ref}", focus="auth"\n3. Call llm_code_review with url="${ref}", focus="logic"\n4. Call llm_code_review with url="${ref}", focus="secrets"\n\nDO NOT call technology_detect, http_methods_test, security_headers, or any web probe tool — this is a local code target, not a web application.`,
      phase: KillChainPhase.WEAPONIZE,
      operatorType: 'analyst',
      status: 'pending',
      priority: 9,
      dependencies: [],
      createdAt: Date.now(),
    },
  ];
}

/**
 * Create tasks for cloud infrastructure scanning (cloud_infra family).
 * Phases: RECON → WEAPONIZE → EXPLOIT
 * ACTIONS is handled separately by createFindingValidationTasks.
 */
export function createCloudInfraTasks(missionId: string, targetAddress: string): Task[] {
  const reconId      = randomUUID();
  const configScanId = randomUUID();
  const iamReviewId  = randomUUID();
  const exploitId    = randomUUID();

  return [
    {
      id: reconId,
      missionId,
      name: 'Cloud Asset Discovery',
      description: `Cloud infrastructure reconnaissance for ${targetAddress}.\n\nCLOUD SCAN TASK — use cloud-specific tools, not generic web probes.\n\nTool sequence:\n1. dns_lookup with target="${targetAddress}" — resolve IP, check cloud provider PTR records\n2. subdomain_enum with target="${targetAddress}" — enumerate subdomains; cloud services often expose regional endpoints\n3. port_scan with target="${targetAddress}", ports="443,8443,6443,2375,2376,5000,9200,9300,27017,6379" — identify exposed cloud management / data ports\n4. cloud_metadata_probe with target="${targetAddress}", provider="auto" — probe AWS IMDS, GCP metadata, Azure IMDS both directly and via target\n5. nuclei_scan with target="${targetAddress}", tags="cloud-metadata,cloud-enum,cloud-detect" — detect cloud provider fingerprints\n\nReport: cloud provider identification, exposed services and ports, metadata service accessibility, discovered subdomains.`,
      phase: KillChainPhase.RECON,
      operatorType: 'recon',
      status: 'pending',
      priority: 10,
      dependencies: [],
      createdAt: Date.now(),
    },
    {
      id: configScanId,
      missionId,
      name: 'Cloud Configuration & Compliance Scan',
      description: `Cloud misconfiguration and storage exposure scan for ${targetAddress}.\n\nTool sequence:\n1. nuclei_scan with target="${targetAddress}", tags="cloud-misconfig,cloud-storage,cloud-takeover" — detect storage, IAM, and service misconfigurations\n2. s3_bucket_check with target="${targetAddress}" — enumerate public S3, GCS, and Azure Blob buckets using domain permutations\n3. cloud_metadata_probe with target="${targetAddress}", provider="aws" — check for AWS user-data leakage (credentials often stored here)\n4. header_analysis with target="https://${targetAddress}" — check for cloud provider headers leaking account IDs or internal resource paths\n5. cors_check with target="https://${targetAddress}" — misconfigured CORS on cloud APIs can expose data cross-origin\n\nReport: publicly accessible storage buckets, metadata credential exposure, header leakage, CORS misconfigurations.`,
      phase: KillChainPhase.WEAPONIZE,
      operatorType: 'web_scanner',
      status: 'pending',
      priority: 10,
      dependencies: [],
      createdAt: Date.now(),
    },
    {
      id: iamReviewId,
      missionId,
      name: 'IAM & Secrets Exposure Assessment',
      description: `LLM-driven cloud IAM and secrets exposure assessment for ${targetAddress}.\n\nCall llm_cloud_review FOUR TIMES with the context from RECON and config scan findings:\n\n1. llm_cloud_review with target="${targetAddress}", focus="iam_misconfig" — analyze IAM policy gaps, role chaining, and over-privilege\n2. llm_cloud_review with target="${targetAddress}", focus="exposed_endpoints" — assess unauthenticated endpoints, open management interfaces\n3. llm_cloud_review with target="${targetAddress}", focus="credential_leakage" — check for keys in headers, metadata responses, public storage\n4. llm_cloud_review with target="${targetAddress}", focus="network_exposure" — review security group logic, exposed ports, DMZ breakout paths\n\nFor each call, pass prior scan output as the context parameter. Conclude with a severity-ranked list of cloud attack paths.`,
      phase: KillChainPhase.WEAPONIZE,
      operatorType: 'analyst',
      status: 'pending',
      priority: 9,
      dependencies: [],
      createdAt: Date.now(),
    },
    {
      id: exploitId,
      missionId,
      name: 'Cloud Misconfiguration Exploitation',
      description: `Probe confirmed misconfigurations in ${targetAddress} for exploitability.\n\nBased on WEAPONIZE findings, attempt to confirm impact:\n1. http_request with url of any open S3/GCS/Azure Blob endpoints found — test for public LIST and GET access (enumerate bucket contents if listable)\n2. cloud_metadata_probe with target="${targetAddress}", provider="aws" and path="/latest/user-data" — extract credentials from EC2 user-data if accessible\n3. subdomain_takeover check — identify dangling CNAME records pointing to decommissioned cloud services\n4. cve_lookup for cloud-adjacent services found (kubernetes, docker, elasticsearch, redis) — check for known unauthenticated RCE CVEs\n5. password_spray if any cloud login portals were identified — test for weak/default credentials\n\nReport: confirmed data exposures, exploitable credential paths, pivot opportunities, and business impact assessment.`,
      phase: KillChainPhase.EXPLOIT,
      operatorType: 'exploiter',
      status: 'pending',
      priority: 10,
      dependencies: [],
      createdAt: Date.now(),
    },
  ];
}

/**
 * Create tasks for binary / firmware reverse engineering (reverse_binary family).
 * Phases: RECON → WEAPONIZE → EXPLOIT
 * ACTIONS is handled separately by createFindingValidationTasks.
 */
export function createBinaryAnalysisTasks(missionId: string, localRef: string, sandboxOptions?: { networkMode?: string; durationSec?: number; alias?: string }): Task[] {
  // Normalise: ensure we always work with a local:// reference
  const ref = localRef.startsWith('local://') ? localRef : `local://${localRef}`;
  const sbxNetwork  = sandboxOptions?.networkMode  ?? 'none';
  const sbxDuration = sandboxOptions?.durationSec  ?? 30;
  const sbxAlias    = sandboxOptions?.alias         ? `, alias="${sandboxOptions.alias}"` : '';

  const reconId    = randomUUID();
  const analysisId = randomUUID();
  const vulnHuntId = randomUUID();

  return [
    {
      id: reconId,
      missionId,
      name: 'Binary Surface Analysis',
      description: `Surface analysis of ${ref}. Run these six tools in order. Each one's output will be stored automatically.\n\nStep 1: binary_recon(binary_path="${ref}")\nStep 2: binary_strings(binary_path="${ref}", min_length=8)\nStep 3: binary_entropy(binary_path="${ref}")\nStep 4: binary_symbols(binary_path="${ref}")\nStep 5: binary_rop_gadgets(binary_path="${ref}", focus="rop")\nStep 6: binary_yara(binary_path="${ref}")\n\nRead each tool's output carefully. Note the file type, architecture, any credentials or dangerous imports in the strings/symbols, ROP gadget count and quality, and any YARA signature matches. Once all six tools have run and you have read their output, your task is complete. Do NOT call llm_binary_review here — that happens in the exploit phase.`,
      phase: KillChainPhase.RECON,
      operatorType: 'code_scanner',
      status: 'pending',
      priority: 10,
      dependencies: [],
      createdAt: Date.now(),
    },
    {
      id: analysisId,
      missionId,
      name: 'Dynamic Deep Reverse Engineering',
      description: `Goal: full dynamic + static deep-dive on ${ref}. DO NOT call llm_binary_review here — that is the EXPLOIT phase.\n\nAll steps are MANDATORY — do not skip any:\n\nStep 1: binary_functions(binary_path="${ref}", sort_by="size", limit=40)\n  → note the top functions by size; these inform Step 7 drill-down targets.\n\nStep 2: binary_xor_decode(binary_path="${ref}")\n  → recover any XOR-obfuscated strings, keys, or payloads.\n\nStep 3: sandbox_execute(binary_path="${ref}", network_mode="${sbxNetwork}"${sbxAlias})\n  → run the binary and capture stdout/stderr/exit code; note any decrypted output or runtime secrets.\n\nStep 4: sandbox_trace(binary_path="${ref}", tracer="strace"${sbxAlias})\n  → syscall trace — reveals file access, network calls (connect/send/recv), memory allocation patterns, and exec() chains. This is mandatory regardless of sandbox_execute output.\n\nStep 5: sandbox_network(binary_path="${ref}", duration_sec=${sbxDuration})\n  → live network capture — confirms C2 beacons, DNS lookups, remote IPs contacted, and protocol used. Run this even if no obvious C2 strings were found; beacons often use obfuscated addresses.\n\nStep 6: binary_full_decompile(binary_path="${ref}")\n  → decompiles ALL user-defined functions (up to 40 largest) using r2ghidra/pdc/pdf in fallback order, extracts the full call graph, then produces an LLM narrative: binary purpose, execution flow, function inventory, security findings. This is the primary static analysis step — read the flow report carefully before Step 7.\n\nStep 7: For any suspicious addresses, functions, or call paths identified in steps 1–6, call binary_investigate to trace the full call flow:\n  binary_investigate(binary_path="${ref}", target="<address_or_name>", hypothesis="<what_you_suspect>")\n  Keep drilling into suggested next targets — follow callers of dangerous functions, XOR callers, and any function that reads external input.\n\nFor PE binaries: also call sandbox_wine(binary_path="${ref}", alias="svchost.exe")\nFor packed binaries (high entropy found in RECON): also call sandbox_unpack(binary_path="${ref}") to dump the decrypted payload from memory.`,
      phase: KillChainPhase.WEAPONIZE,
      operatorType: 'code_scanner',
      status: 'pending',
      priority: 10,
      dependencies: [],
      createdAt: Date.now(),
    },
    {
      id: vulnHuntId,
      missionId,
      name: 'Vulnerability Assessment & Exploit Synthesis',
      description: `Deep vulnerability synthesis for ${ref}. Run all steps in order.\n\nIMPORTANT CONTEXT: binary_full_decompile already ran in WEAPONIZE and decompiled ALL user-defined functions — that decompiled code is already in your conversation context. Do NOT call binary_functions, binary_full_decompile, or ghidra_decompile for any function that binary_full_decompile already covered. Only call ghidra_decompile for specific raw addresses (e.g. from sandbox_trace output) that binary_full_decompile did not include.\n\nStep 1: llm_binary_review(binary_path="${ref}", focus="backdoor_indicators")\n  → hardcoded credentials, hidden trigger strings, anti-debug checks, covert channels, C2 callbacks — use the binary_full_decompile output from WEAPONIZE as your primary context\n\nStep 2: llm_binary_review(binary_path="${ref}", focus="memory_corruption")\n  → buffer overflows, UAF, integer overflows, ROP gadget viability given mitigations — cite exact function names and addresses from binary_full_decompile output\n\nStep 3: llm_binary_review(binary_path="${ref}", focus="crypto_weakness")\n  → weak ciphers, hardcoded keys/IVs, XOR obfuscation, insecure RNG\n\nStep 4: llm_binary_review(binary_path="${ref}", focus="report_synthesis")\n  → comprehensive report combining ALL findings from RECON, WEAPONIZE, and steps 1–3 above\n\nDo NOT call binary_recon, binary_symbols, binary_functions, binary_full_decompile, or sandbox_execute here — those ran in earlier phases. Do NOT call ghidra_decompile for functions already in the binary_full_decompile output.`,
      phase: KillChainPhase.EXPLOIT,
      operatorType: 'code_scanner',
      status: 'pending',
      priority: 10,
      dependencies: [],
      createdAt: Date.now(),
    },
  ];
}

/**
 * Binary-specific ACTIONS validation.
 * Unlike the generic web/code validator (llm_validate_finding), this asks the analyst to
 * decompile the exact functions mentioned in each finding, then use that code as evidence.
 * This resolves NEEDS_MORE_INFO verdicts for UAF, integer overflow, IOCTL, backdoor, etc.
 */
export function createBinaryValidationTasks(missionId: string, targetRef: string, findings: Finding[]): Task[] {
  const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const validatable = findings
    .filter(f => f.severity !== 'info')
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));

  if (validatable.length === 0) return [];

  const ref = targetRef.startsWith('local://') ? targetRef : `local://${targetRef.replace(/^.*\//, '')}`;

  // Extract function name from finding title/details (e.g. "UAF in destroy_session" → "destroy_session")
  const FUNC_PATTERNS = [
    /\bin\s+(\w+)\b/i,
    /\bfunction\s+(\w+)\b/i,
    /\b(sym\.\w+|\w+_\w+)\s*\(/,
    /\b(main|decode_cred|process_username|authenticate|configure_crypto_device|parse_data|run_diagnostic|reload_config|handle_packet|read_log|generate_token|parse_field|create_session|destroy_session|send_beacon|check_backdoor)\b/i,
  ];

  const functionsToDecompile = [...new Set(
    validatable.flatMap(f => {
      const text = `${f.title} ${f.description ?? ''}`;
      return FUNC_PATTERNS.flatMap(p => {
        const m = text.match(p);
        return m ? [m[1]] : [];
      });
    }).filter(Boolean)
  )].slice(0, 10);

  const findingsSummary = validatable.map((f, i) =>
    `${i + 1}. [${f.severity.toUpperCase()}] "${f.title}"\n   Evidence: ${(f.description ?? '').slice(0, 300)}`
  ).join('\n\n');

  const decompileInstructions = functionsToDecompile.length > 0
    ? `\nStep 1 — decompile the functions that are mentioned in the findings above:\n${
        functionsToDecompile.map(fn => `  ghidra_decompile(binary_path="${ref}", function_name="${fn}")`).join('\n')
      }\n\nStep 2 — if XOR obfuscation or credential findings exist, run:\n  binary_xor_decode(binary_path="${ref}")\n\n`
    : `\nStep 1 — run ghidra_decompile on the top suspicious functions from the function list.\n\n`;

  return [{
    id: randomUUID(),
    missionId,
    name: 'Binary Finding Deep Validation',
    description: `You are a second, independent binary security reviewer for ${ref}. Your task is to CONFIRM or DENY the ${validatable.length} findings listed below by examining the actual decompiled code — do NOT create new findings.\n\nFindings to validate:\n${findingsSummary}\n\n${decompileInstructions}Step 3 — for each finding numbered above, determine: CONFIRMED, NEEDS_MORE_INFO, or FALSE_POSITIVE based on the decompiled code.\n- CONFIRMED: the code clearly shows the vulnerability\n- NEEDS_MORE_INFO: code suggests it but more context needed\n- FALSE_POSITIVE: code does NOT show the vulnerability\n\nFor XOR/credential findings: include the actual decoded value in your reasoning.\nFor UAF findings: trace alloc → free → use in the decompiled code.\nFor integer overflow: show the multiplication/addition that overflows.\nFor command injection: quote the unsanitized argument in the system()/snprintf() call.\n\nAfter all decompilation and analysis is done, output ONLY this JSON:\n{ "verdicts": [{ "title": "<exact finding title>", "verdict": "CONFIRMED|NEEDS_MORE_INFO|FALSE_POSITIVE", "confidence": 0-100, "reasoning": "<cite function name + specific line/pattern from decompiled code>" }] }`,
    phase: KillChainPhase.ACTIONS,
    operatorType: 'analyst',
    status: 'pending',
    priority: 9,
    dependencies: [],
    createdAt: Date.now(),
  }];
}

/**
 * Extract a "file:line" location string from a finding's evidence or description.
 * Handles both LLM findings (description starts with "File: path:line") and semgrep/
 * gitleaks findings (evidence[0].content is "path:line — message").
 */
function extractFileInfo(f: Finding): { file: string; line: number } | null {
  // LLM findings: description = "File: routes/api.ts:42\n<details>"
  const descMatch = (f.description ?? '').match(/^File:\s*([^\n:]+):(\d+)/);
  if (descMatch) return { file: descMatch[1].trim(), line: Number(descMatch[2]) };

  // Scan findings: evidence[0].content = "routes/api.ts:42 — message" or "path:line:"
  const evidContent = f.evidence?.[0]?.content ?? '';
  const evMatch = evidContent.match(/^([^\s]+\.[a-z]{1,6}):(\d+)/i);
  if (evMatch) return { file: evMatch[1], line: Number(evMatch[2]) };

  return null;
}

/**
 * Second-pass validation task — a skeptic LLM that independently reviews each
 * finding from the first pass and rejects anything not backed by specific evidence.
 * Called when the ACTIONS phase starts, so the vault snapshot includes ALL WEAPONIZE
 * findings (semgrep, gitleaks, trivy, and all 4 LLM code-review passes).
 */
const VALIDATION_BATCH_SIZE = 12;

function buildValidationTask(
  missionId: string,
  targetAddress: string,
  batch: Finding[],
  batchIndex: number,
  totalBatches: number,
): Task {
  const batchLabel = totalBatches > 1 ? ` (batch ${batchIndex + 1}/${totalBatches})` : '';

  // Determine whether this is a code-scan batch (findings have file locations) or
  // a web/network batch (findings are backed by HTTP evidence, no source file paths).
  const isCodeBatch = batch.some(f => !!extractFileInfo(f));
  // Web findings carry richer evidence text (HTTP responses) — give them more room.
  const evidenceMaxLen = isCodeBatch ? 200 : 400;

  const findingsBlock = batch.length > 0
    ? `\n\nFindings to validate${batchLabel} (${batch.length} findings, sorted by severity):\n` +
      batch.map((f, i) => {
        const loc = extractFileInfo(f);
        const locStr = loc ? `\n   Location: ${loc.file}:${loc.line}` : '';
        // Surface all useful evidence types: output (toolOutput), request, response
        const outputEv = f.evidence?.find(e => e.type === 'output');
        const requestEv = f.evidence?.find(e => e.type === 'request');
        const responseEv = f.evidence?.find(e => e.type === 'response');
        const primaryCtx = (outputEv?.content ?? f.description ?? '').slice(0, evidenceMaxLen).replace(/\n/g, ' ');
        const reqCtx = requestEv ? `\n   Request: ${requestEv.content.slice(0, 300).replace(/\n/g, ' ')}` : '';
        const respCtx = responseEv ? `\n   Response: ${responseEv.content.slice(0, 300).replace(/\n/g, ' ')}` : '';
        return `${i + 1}. [${f.severity.toUpperCase()}] "${f.title}"${locStr}\n   Evidence: ${primaryCtx}${reqCtx}${respCtx}`;
      }).join('\n\n')
    : '';

  const validateInstructions = batch.length > 0
    ? isCodeBatch
      ? `For EACH finding numbered above, call llm_validate_finding with: url="${targetAddress}", the file path and line number from "Location:" (if present), the finding title, and a brief description from "Evidence:". Work through them in order — do NOT skip findings due to time or repetition.\n\nFor LLM code review findings (title starts with "LLM:"), the Location field gives an exact file:line — use it directly.\nFor semgrep/gitleaks findings, parse the file:line from the Evidence field (format is "path/file.ts:42 — message").\nIf a finding has no file path, call llm_validate_finding with file="" and line=0.\n\nAfter ALL llm_validate_finding calls are done, output ONLY a JSON block with key "verdicts" (not "findings"): { "verdicts": [{ "title": "<exact title>", "verdict": "CONFIRMED|NEEDS_EVIDENCE|FALSE_POSITIVE", "confidence": 0-100, "reasoning": "..." }] }`
      : `For EACH finding numbered above, call llm_validate_finding with: url="${targetAddress}", file="", line=0, the finding title, and the full "Evidence:" content as the description. The evidence contains HTTP response data, headers, payloads, or test output — include it verbatim so the validator can assess real exploitability. Work through them in order — do NOT skip findings.\n\nAfter ALL llm_validate_finding calls are done, output ONLY a JSON block with key "verdicts" (not "findings"): { "verdicts": [{ "title": "<exact title>", "verdict": "CONFIRMED|NEEDS_EVIDENCE|FALSE_POSITIVE", "confidence": 0-100, "reasoning": "..." }] }`
    : `Output ONLY a JSON block with key "verdicts" (not "findings"): { "verdicts": [] }`;

  return {
    id: randomUUID(),
    missionId,
    name: totalBatches > 1 ? `Independent Finding Validation${batchLabel}` : 'Independent Finding Validation',
    description: `You are a second, independent security reviewer for ${targetAddress}. Your ONLY job is to validate the existing findings listed below — DO NOT create new findings, DO NOT emit a "findings" JSON block.${findingsBlock}\n\n${validateInstructions}`,
    phase: KillChainPhase.ACTIONS,
    operatorType: 'analyst',
    status: 'pending',
    priority: 9,
    dependencies: [],
    createdAt: Date.now(),
  };
}

/**
 * Create one validation task per batch of VALIDATION_BATCH_SIZE findings.
 * Batching keeps each task's initial LLM call under the 60-second HTTP timeout
 * while still validating all findings across as many tasks as needed.
 */
export function createFindingValidationTasks(missionId: string, targetAddress: string, findings: Finding[] = []): Task[] {
  const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  const sorted = findings
    .filter(f => f.evidence && f.evidence.length > 0 && f.phase !== KillChainPhase.RECON && f.severity !== 'info')
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));

  if (sorted.length === 0) {
    return [buildValidationTask(missionId, targetAddress, [], 0, 1)];
  }

  const batches: Finding[][] = [];
  for (let i = 0; i < sorted.length; i += VALIDATION_BATCH_SIZE) {
    batches.push(sorted.slice(i, i + VALIDATION_BATCH_SIZE));
  }

  return batches.map((batch, idx) => buildValidationTask(missionId, targetAddress, batch, idx, batches.length));
}
