/**
 * T3MP3ST Core Tests
 *
 * Basic test suite for core functionality.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { Arsenal, BUILTIN_TOOLS, successResult, failResult, createToolContext } from '../arsenal/index.js';
import { FRONTIER_ARSENAL_MILESTONE, SAFE_COMMANDS, TOOL_ADAPTERS, adaptersForFamily, summarizeToolCatalog } from '../arsenal/catalog.js';
import { createKnowledgeBase, createEvasionEngine, CVE_DATABASE, MITRE_TECHNIQUES } from '../stubs/index.js';
import { AGENT_PROMPT_PACKS, FOREFRONT_PRESSURE_LANES, OPERATOR_RUNBOOKS, forefrontPressureForFamily, promptPacksForFamily, runbookForFamily } from '../resources/index.js';
import { OpGeneral } from '../general/index.js';
import { LLMBackbone } from '../llm/index.js';

describe('Arsenal', () => {
  let arsenal: Arsenal;

  beforeEach(() => {
    arsenal = new Arsenal();
  });

  describe('Tool Registration', () => {
    it('should register built-in tools', () => {
      arsenal.registerMany(BUILTIN_TOOLS);
      expect(arsenal.getAllTools().length).toBe(BUILTIN_TOOLS.length);
    });

    it('should get tool by name', () => {
      arsenal.registerMany(BUILTIN_TOOLS);
      const tool = arsenal.getTool('dns_lookup');
      expect(tool).toBeDefined();
      expect(tool?.name).toBe('dns_lookup');
    });

    it('should filter tools by category', () => {
      arsenal.registerMany(BUILTIN_TOOLS);
      const reconTools = arsenal.getToolsByCategory('recon');
      expect(reconTools.length).toBeGreaterThan(0);
      reconTools.forEach(tool => expect(tool.category).toBe('recon'));
    });

    it('should return undefined for unknown tool', () => {
      const tool = arsenal.getTool('nonexistent');
      expect(tool).toBeUndefined();
    });
  });

  describe('Tool Execution', () => {
    it('should execute dns_lookup tool (may fail if no network)', async () => {
      arsenal.registerMany(BUILTIN_TOOLS);
      const result = await arsenal.execute('dns_lookup', createToolContext(undefined, { domain: 'example.com' }));
      // DNS lookup now does real network requests - may succeed or fail depending on network
      expect(result.output || result.error).toContain('example.com');
    });

    it('should execute base64_decode tool', async () => {
      arsenal.registerMany(BUILTIN_TOOLS);
      const result = await arsenal.execute('base64_decode', createToolContext(undefined, { data: 'SGVsbG8gV29ybGQ=' }));
      expect(result.success).toBe(true);
      expect(result.output).toContain('Hello World');
    });

    it('should execute jwt_decode tool', async () => {
      arsenal.registerMany(BUILTIN_TOOLS);
      // Valid JWT token structure (header.payload.signature)
      const testJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      const result = await arsenal.execute('jwt_decode', createToolContext(undefined, { token: testJwt }));
      expect(result.success).toBe(true);
      expect(result.output).toContain('HS256');
    });

    it('should throw for unknown tool', async () => {
      await expect(arsenal.execute('nonexistent', createToolContext())).rejects.toThrow();
    });
  });

  describe('Helper Functions', () => {
    it('should create success result', () => {
      const result = successResult('Test output');
      expect(result.success).toBe(true);
      expect(result.output).toBe('Test output');
    });

    it('should create fail result', () => {
      const result = failResult('Test error');
      expect(result.success).toBe(false);
      expect(result.error).toBe('Test error');
    });
  });
});

describe('KnowledgeBase', () => {
  const kb = createKnowledgeBase();

  describe('CVE Database', () => {
    it('should have CVE entries', () => {
      expect(CVE_DATABASE.length).toBeGreaterThan(0);
    });

    it('should query CVEs by ID', () => {
      const result = kb.query({ type: 'cve', query: 'Log4Shell' });
      expect(result.results.length).toBeGreaterThan(0);
    });

    it('should get CVE by exact ID', () => {
      const cve = kb.getCVE('CVE-2021-44228');
      expect(cve).toBeDefined();
      expect(cve?.description).toContain('Log4Shell');
    });

    it('should filter critical CVEs by CVSS', () => {
      const critical = kb.getCriticalCVEs(9.0);
      expect(critical.length).toBeGreaterThan(0);
      critical.forEach(c => expect(c.cvss).toBeGreaterThanOrEqual(9.0));
    });
  });

  describe('MITRE Techniques', () => {
    it('should have MITRE techniques', () => {
      expect(MITRE_TECHNIQUES.length).toBeGreaterThan(0);
    });

    it('should get technique by ID', () => {
      const technique = kb.getTechnique('T1190');
      expect(technique).toBeDefined();
      expect(technique?.name).toBe('Exploit Public-Facing Application');
    });

    it('should filter techniques by tactic', () => {
      const initialAccess = kb.getTechniquesByTactic('initial-access');
      expect(initialAccess.length).toBeGreaterThan(0);
      initialAccess.forEach(t => expect(t.tactic).toBe('initial-access'));
    });
  });

  describe('Pattern Matching', () => {
    it('should detect SQL injection patterns', () => {
      const matches = kb.matchPatterns("SELECT * FROM users WHERE id = '1' OR '1'='1'");
      expect(matches.some(m => m.type === 'sqli')).toBe(true);
    });

    it('should detect XSS patterns', () => {
      const matches = kb.matchPatterns('<script>alert(1)</script>');
      expect(matches.some(m => m.type === 'xss')).toBe(true);
    });

    it('should detect path traversal patterns', () => {
      const matches = kb.matchPatterns('../../etc/passwd');
      expect(matches.some(m => m.type === 'path-traversal')).toBe(true);
    });
  });
});

describe('EvasionEngine', () => {
  const evasion = createEvasionEngine();

  describe('Encoding', () => {
    it('should encode to base64', () => {
      const result = evasion.encode('hello', 'base64');
      expect(result.encoded).toBe('aGVsbG8=');
      expect(result.encoding).toBe('base64');
    });

    it('should encode to hex', () => {
      const result = evasion.encode('AB', 'hex');
      expect(result.encoded).toBe('4142');
    });

    it('should encode to URL', () => {
      const result = evasion.encode('<script>', 'url');
      expect(result.encoded).toBe('%3Cscript%3E');
    });

    it('should handle unknown encoding', () => {
      const result = evasion.encode('test', 'unknown');
      expect(result.encoded).toBe('test');
      expect(result.encoding).toBe('none');
    });
  });

  describe('Multi-layer Encoding', () => {
    it('should apply multiple encodings', () => {
      const result = evasion.multiEncode('test', ['base64', 'url']);
      expect(result.encoding).toBe('base64+url');
      expect(result.encoded).not.toBe('test');
    });
  });

  describe('Polymorphic Generation', () => {
    it('should generate multiple payload variants', () => {
      const variants = evasion.generatePolymorphic('<script>alert(1)</script>');
      expect(variants.length).toBeGreaterThan(3);
      // All variants should be different
      const uniqueEncoded = new Set(variants.map(v => v.encoded));
      expect(uniqueEncoded.size).toBe(variants.length);
    });
  });

  describe('WAF Bypass', () => {
    it('should generate WAF bypass variants', () => {
      const variants = evasion.getWAFBypassVariants('SELECT * FROM users');
      expect(variants.length).toBeGreaterThan(5);
      expect(variants).toContain('SELECT * FROM users'); // Original included
    });
  });

  describe('Code Obfuscation', () => {
    it('should obfuscate strings', () => {
      const result = evasion.obfuscate("var x = 'hello'", 'string_split');
      expect(result.obfuscated).toContain('String.fromCharCode');
    });
  });
});

describe('Operator Contracts', () => {
  it('should expose family-specific prompt packs with evidence contracts', () => {
    expect(AGENT_PROMPT_PACKS.length).toBeGreaterThanOrEqual(5);
    for (const pack of AGENT_PROMPT_PACKS) {
      expect(pack.roleFrame.length).toBeGreaterThan(20);
      expect(pack.evidenceContract.length).toBeGreaterThanOrEqual(3);
      expect(pack.escalationRules.length).toBeGreaterThan(0);
    }
  });

  it('should return the AI boundary prompt pack for AI red-team missions', () => {
    const packs = promptPacksForFamily('ai_red_team');
    expect(packs.map(pack => pack.id)).toContain('prompt-ai-boundary-cartographer');
  });

  it('should expose operator runbooks with phase risks and exit criteria', () => {
    expect(OPERATOR_RUNBOOKS.length).toBeGreaterThanOrEqual(5);
    for (const runbook of OPERATOR_RUNBOOKS) {
      expect(runbook.operatorPromise.length).toBeGreaterThan(30);
      expect(runbook.phases.length).toBeGreaterThanOrEqual(3);
      for (const phase of runbook.phases) {
        expect(phase.riskIfSkipped.length).toBeGreaterThan(20);
        expect(phase.exitCriteria.length).toBeGreaterThan(0);
      }
    }
  });

  it('should return a runbook for the core routed mission families', () => {
    expect(runbookForFamily('ai_red_team')?.title).toContain('AI Agent Boundary');
    expect(runbookForFamily('web_api')?.title).toContain('Web/API');
    expect(runbookForFamily('code_supply_chain')?.title).toContain('Repository Trust');
  });

  it('should expose forefront pressure lanes with defensive conversion artifacts', () => {
    expect(FOREFRONT_PRESSURE_LANES.length).toBeGreaterThanOrEqual(6);
    for (const lane of FOREFRONT_PRESSURE_LANES) {
      expect(lane.frontierSignal.length).toBeGreaterThan(40);
      expect(lane.pressureQuestion).toMatch(/\?$/);
      expect(lane.operatorMove.length).toBeGreaterThan(40);
      expect(lane.defensiveArtifact.length).toBeGreaterThan(30);
      expect(lane.containment.length).toBeGreaterThan(30);
      expect(lane.recommendedResources.length).toBeGreaterThan(0);
    }
  });

  it('should return forefront lanes by mission family', () => {
    expect(forefrontPressureForFamily('ai_red_team').map(lane => lane.id)).toContain('frontier-browser-tool-privilege');
    expect(forefrontPressureForFamily('agent_warfare').map(lane => lane.id)).toContain('frontier-agent-command-injection');
  });
});

describe('Tool Adapter Catalog', () => {
  it('should expose a broad command-ready and catalog-only arsenal', () => {
    const summary = summarizeToolCatalog();
    expect(TOOL_ADAPTERS.length).toBeGreaterThanOrEqual(30);
    expect(summary.commandReady).toBeGreaterThanOrEqual(20);
    expect(summary.catalogOnly).toBeGreaterThanOrEqual(2);
    expect(summary.unmodeled).toBe(false);
    expect(TOOL_ADAPTERS.length).toBeLessThanOrEqual(FRONTIER_ARSENAL_MILESTONE);
    expect(SAFE_COMMANDS).toContain('nuclei');
    expect(SAFE_COMMANDS).toContain('semgrep');
    expect(SAFE_COMMANDS).not.toContain('msfconsole');
  });

  it('should give core mission families first-class adapter coverage', () => {
    expect(adaptersForFamily('web_api').map(adapter => adapter.id)).toEqual(expect.arrayContaining(['nmap', 'nuclei', 'ffuf', 'katana']));
    expect(adaptersForFamily('code_supply_chain').map(adapter => adapter.id)).toEqual(expect.arrayContaining(['semgrep', 'gitleaks', 'trivy', 'syft']));
    expect(adaptersForFamily('ai_red_team').map(adapter => adapter.id)).toEqual(expect.arrayContaining(['garak', 'promptfoo']));
    expect(adaptersForFamily('smart_contract').map(adapter => adapter.id)).toEqual(expect.arrayContaining(['slither', 'mythril', 'foundry-forge', 'solhint']));
    expect(adaptersForFamily('crypto_secrets').map(adapter => adapter.id)).toEqual(expect.arrayContaining(['openssl', 'john', 'hashcat', 'foundry-cast']));
    expect(adaptersForFamily('reverse_binary').map(adapter => adapter.id)).toEqual(expect.arrayContaining(['binwalk', 'radare2', 'apktool', 'jadx']));
  });
});

describe('OpGeneral v2 Campaign Control', () => {
  function generalWithResponse(payload: Record<string, unknown>): OpGeneral {
    const llm = {
      prompt: async () => `\`\`\`json\n${JSON.stringify(payload)}\n\`\`\``,
    } as unknown as LLMBackbone;
    return new OpGeneral(llm);
  }

  it('should enrich sparse plans with hunt lanes, work orders, evidence contracts, and review gates', async () => {
    const general = generalWithResponse({
      codename: 'IRON CURRENT',
      summary: 'Authorized local web/API weird-machine hunt.',
      targets: [{ address: 'http://127.0.0.1:3333/ui/', expectedType: 'web_application', priority: 1, rationale: 'Local T3MP3ST UI' }],
      objectives: [{ description: 'Find boundary failures in the local control plane', priority: 1, successCriteria: 'Evidence-backed hypotheses and retests', phase: 'reconnaissance' }],
      operators: [{ archetype: 'scanner', count: 2, deployPhase: 'reconnaissance', briefing: 'Probe local UI/API edges safely' }],
      roe: { scope: ['http://127.0.0.1:3333/ui/'], exclusions: ['external targets'], maxDetections: 1, destructiveAllowed: false, requireApproval: [] },
      complexity: 'moderate',
      rationale: 'Start local, preserve evidence, and require receipts before active external action.',
    });

    const plan = await general.planOperation({ objective: 'Run an authorized local web/API zero-day hunt against http://127.0.0.1:3333/ui/' });
    const review = general.reviewPlan(plan);

    expect(plan.missionFamily).toBe('web_api');
    expect(plan.huntLanes.length).toBeGreaterThan(0);
    expect(plan.workOrders.length).toBeGreaterThanOrEqual(2);
    expect(plan.evidenceContract.requiredArtifacts.length).toBeGreaterThan(2);
    expect(plan.authorityReceipts.map(receipt => receipt.action)).toContain('mission_execution');
    expect(plan.missionGate.status).not.toBe('hold');
    expect(review.score).toBeGreaterThanOrEqual(70);
  });

  it('should hold the gate when a directive has no explicit target or scope', async () => {
    const general = generalWithResponse({
      codename: 'VAGUE THUNDER',
      summary: 'Interesting but under-scoped operation.',
      objectives: [{ description: 'Hunt something somewhere', priority: 1, successCriteria: 'Unknown', phase: 'reconnaissance' }],
      operators: [{ archetype: 'analyst', count: 1, deployPhase: 'reconnaissance', briefing: 'Clarify scope' }],
      roe: { scope: [], exclusions: [], maxDetections: 0, destructiveAllowed: false, requireApproval: [] },
      complexity: 'high',
      rationale: 'Scope is not explicit enough for execution.',
    });

    const plan = await general.planOperation({ objective: 'Find weird machines wherever they may be' });
    const review = general.reviewPlan(plan);

    expect(review.status).toBe('hold');
    expect(review.blockers.join(' ')).toMatch(/target|scope/i);
    expect(plan.missionGate.status).toBe('hold');
  });

  it('should preserve specialist multiplicity and expose work-order assignments for execution', async () => {
    const general = generalWithResponse({
      codename: 'DOUBLE SCANNER',
      summary: 'Authorized local scanner-heavy review.',
      targets: [{ address: 'localhost', expectedType: 'web_application', priority: 1, rationale: 'Local lab' }],
      objectives: [{ description: 'Compare two scanner routes', priority: 1, successCriteria: 'Two independent evidence paths', phase: 'reconnaissance' }],
      operators: [
        { archetype: 'scanner', count: 2, deployPhase: 'reconnaissance', briefing: 'Route A and Route B scanner comparison' },
        { archetype: 'analyst', count: 1, deployPhase: 'actions_on_objectives', briefing: 'Synthesize proof and falsifiers' },
      ],
      roe: { scope: ['localhost'], exclusions: ['external targets'], maxDetections: 1, destructiveAllowed: false, requireApproval: [] },
      complexity: 'moderate',
      rationale: 'Multiplicity matters for independent route comparison.',
    });

    const plan = await general.planOperation({ objective: 'Authorized local route comparison against localhost' });
    const execConfig = general.executePlan(plan);

    expect(execConfig.operators.filter(archetype => archetype === 'scanner').length).toBeGreaterThanOrEqual(2);
    expect(execConfig.operatorAssignments.some(assignment => assignment.workOrderIds.length > 0)).toBe(true);
    expect(execConfig.workOrders.every(order => order.falsifier && order.retest)).toBe(true);
  });
});

describe('Wedged-dispatch timeout backstop', () => {
  // A fake AgentLoop whose run() never settles — simulates a truly-hung LLM call
  // (the wedge symptom: operator pinned in `executing` forever).
  const makeWedgingLoop = () =>
    ({ run: () => new Promise(() => { /* never resolves */ }) } as unknown as import('../agent/index.js').AgentLoop);

  it('OperatorAgent.abortActiveTask returns a wedged operator to idle so it can take new work', async () => {
    const { createOperator } = await import('../operators/index.js');
    const { LLMBackbone } = await import('../llm/index.js');
    const { Arsenal } = await import('../arsenal/index.js');

    const op = createOperator('Wedge-1', 'recon', undefined, new LLMBackbone({ provider: 'mock', model: 'mock-model' }));
    op.attachArsenal(new Arsenal(), makeWedgingLoop());

    const task = {
      id: 't-wedge', missionId: 'm1', name: 'recon', description: 'scan example.com',
      phase: 'reconnaissance' as any, operatorType: 'recon' as const, status: 'pending' as const,
      priority: 1, dependencies: [], createdAt: Date.now(),
    };

    // Fire the task but DON'T await — the promise never settles (wedge).
    void op.assignTask(task as any);
    // Let the microtasks run so assignTask advances to 'executing'.
    await Promise.resolve();
    await Promise.resolve();
    expect(op.status).toBe('executing');
    expect(op.isAvailable()).toBe(false);

    // Backstop reset.
    op.abortActiveTask('test timeout');
    expect(op.status).toBe('idle');
    expect(op.isAvailable()).toBe(true);
    expect(op.state.currentTask).toBeNull();
    expect(op.getSummary().failedTasks).toBe(1);
  });

  it('mission completion stops the command loop so status/timer do not stay active', async () => {
    const mod = await import('../index.js');
    const command = new mod.TempestCommand({
      name: 'Lifecycle Op',
      llm: { provider: 'mock', model: 'mock-model' },
    });

    let stopped = false;
    command.on('command:stopped', () => { stopped = true; });
    command.start();

    const mission = command.mission.getActiveMission();
    expect(mission).toBeDefined();
    expect(command.getStatus().running).toBe(true);

    command.mission.completeMission(mission!.id);

    expect(command.getStatus().running).toBe(false);
    expect(command.mission.getActiveMission()).toBeUndefined();
    expect(stopped).toBe(true);
  });

  it('a wedged mission reaches phase advancement once the per-dispatch backstop fires', async () => {
    // Tiny backstop so the test is fast and deterministic.
    const prev = process.env.T3MP3ST_TASK_TIMEOUT_MS;
    process.env.T3MP3ST_TASK_TIMEOUT_MS = '30';
    try {
      // Re-import with the env override in place so resolveTaskTimeoutMs() reads it.
      const mod = await import('../index.js');
      const command = new mod.TempestCommand({
        name: 'Wedge Op',
        llm: { provider: 'mock', model: 'mock-model' },
      });

      // A target + a recon operator whose agent loop wedges forever.
      command.targetEnv.addTarget({ name: 'example.com', address: 'example.com', type: 'web_application', zone: 'external' });
      const op = command.spawnOperator('Recon-Wedge', 'recon');
      op.attachArsenal(command.arsenal, makeWedgingLoop());

      let phaseAdvanced = false;
      command.on('mission:phase_changed', () => { phaseAdvanced = true; });

      command.start();

      // Poll (real timers): the 1s tick loop must dispatch, wedge, then reap the
      // dispatch via the backstop and advance past RECON.
      const deadline = Date.now() + 8000;
      while (Date.now() < deadline && !phaseAdvanced) {
        await new Promise(r => setTimeout(r, 100));
      }
      command.stop();

      expect(phaseAdvanced).toBe(true);
      // The wedged operator was reset back to idle (or re-tasked in a later phase),
      // never left stuck in 'executing' with no current task.
      const stuck = command.cell.getAllOperators().some(
        o => (o.status === 'executing' || o.status === 'tasked') && !o.state.currentTask
      );
      expect(stuck).toBe(false);
    } finally {
      if (prev === undefined) delete process.env.T3MP3ST_TASK_TIMEOUT_MS;
      else process.env.T3MP3ST_TASK_TIMEOUT_MS = prev;
    }
  }, 15000);
});

describe('Codex account provider', () => {
  it('should expose Codex as an API-keyless planning backend', () => {
    const llm = new LLMBackbone({
      provider: 'codex',
      model: 'codex-default',
    });

    expect(llm.getProvider()).toBe('codex');
    expect(llm.getModel()).toBe('codex-default');
    expect(llm.validateConfig()).toEqual({ valid: true });
  });
});
