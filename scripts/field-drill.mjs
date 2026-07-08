#!/usr/bin/env node
import process from 'node:process';

const baseUrl = (process.env.T3MP3ST_API_URL || 'http://127.0.0.1:3333').replace(/\/$/, '');
const scenarioArg = process.argv.find(arg => arg.startsWith('--scenario='))?.split('=')[1] || 'all';
const checks = [];
const warnings = [];

const SCENARIOS = {
  'ai-agent-boundary': {
    family: 'ai_red_team',
    title: 'Field Drill: AI Agent Boundary Probe',
    objective: 'Authorized local field drill. Test an AI agent boundary workflow, preserve evidence, and do not touch external targets.',
    expectedResources: ['mitre-atlas', 'owasp-llm-top10', 'nist-ai-rmf'],
    expectedPromptPack: 'prompt-ai-boundary-cartographer',
  },
  'repo-supply-chain': {
    family: 'code_supply_chain',
    title: 'Field Drill: Repo Supply Chain Hardening',
    objective: 'Authorized local repo hardening drill. Review repository trust, dependencies, provenance, and fix readiness.',
    expectedResources: ['openssf-scorecard', 'slsa-framework', 'first-epss'],
    expectedPromptPack: 'prompt-repo-supply-chain-sentinel',
  },
  'local-web-api': {
    family: 'web_api',
    title: 'Field Drill: Owned Local Web/API',
    objective: 'Authorized owned web API drill. Map local app surface, OWASP categories, evidence, and remediation.',
    expectedResources: ['owasp-wstg', 'owasp-api-top10-2023', 'cwe-top25-2025'],
    expectedPromptPack: 'prompt-web-api-operator',
  },
};

function record(name, passed, detail = '', evidence = undefined) {
  checks.push({ name, passed: Boolean(passed), detail, evidence });
}

function warn(message) {
  warnings.push(message);
}

async function request(method, path, body) {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }
  return { status: response.status, ok: response.ok, data };
}

const get = path => request('GET', path);
const post = (path, body) => request('POST', path, body);
const patch = (path, body) => request('PATCH', path, body);

function selectedScenarios() {
  if (scenarioArg === 'all') return Object.entries(SCENARIOS);
  const scenario = SCENARIOS[scenarioArg];
  if (!scenario) {
    throw new Error(`Unknown scenario: ${scenarioArg}. Available: all, ${Object.keys(SCENARIOS).join(', ')}`);
  }
  return [[scenarioArg, scenario]];
}

async function runScenario(name, scenario) {
  const agentContext = await get(`/api/agent-context/${scenario.family}`);
  const resourceIds = (agentContext.data.resources || []).map(resource => resource.id);
  record(`[${name}] agent context has expected sources`, scenario.expectedResources.every(id => resourceIds.includes(id)), resourceIds.join(', '));
  const promptPacks = agentContext.data.promptPacks || [];
  const promptPackIds = promptPacks.map(pack => pack.id);
  record(`[${name}] agent context has expected prompt pack`, promptPackIds.includes(scenario.expectedPromptPack) && promptPacks.every(pack => pack.evidenceContract?.length), promptPackIds.join(', '));
  record(`[${name}] agent context has operator runbook`, agentContext.data.runbook?.family === scenario.family && agentContext.data.runbook?.phases?.length >= 3, agentContext.data.runbook?.title || agentContext.data.error);

  const runbook = await get(`/api/operator-runbooks/${scenario.family}`);
  record(`[${name}] runbook endpoint returns next actions`, runbook.ok && runbook.data.family === scenario.family && runbook.data.nextBestActions?.length, runbook.data.title || runbook.data.error);

  const missionDraft = await post('/api/mission-drafts', {
    title: scenario.title,
    objective: scenario.objective,
    scope: ['local-lab'],
    constraints: 'Local loopback only. No production writes. No third-party targets.',
    source: 'human',
  });
  record(`[${name}] mission draft created`, missionDraft.status === 201 && missionDraft.data.id, missionDraft.data.id || missionDraft.data.error);

  const routePreview = await post('/api/route-preview', { draftId: missionDraft.data.id });
  record(`[${name}] route family classified`, routePreview.ok && routePreview.data.route?.family === scenario.family, routePreview.data.route?.family || routePreview.data.error);
  record(`[${name}] operation contract emitted`, routePreview.data.operationDraft?.schema_version === 'plinyos.t3mp3st_operation/v1', routePreview.data.operationDraft?.schema_version || 'missing schema');
  record(`[${name}] operation contract carries runbook context`, Boolean(routePreview.data.operationDraft?.knowledge_context?.operator_runbook), routePreview.data.operationDraft?.knowledge_context?.operator_runbook || 'missing runbook context');

  const evidence = await post('/api/evidence', {
    missionId: missionDraft.data.id,
    operationId: routePreview.data.operationDraft?.operation_id,
    type: 'note',
    title: `${name} drill evidence`,
    summary: `Scenario ${name} validated resource context and route contract.`,
    source: 'system',
    resourceIds: scenario.expectedResources,
  });
  record(`[${name}] evidence ledger accepts entry`, evidence.status === 201 && evidence.data.id, evidence.data.id || evidence.data.error);

  const finding = await post('/api/findings', {
    missionId: missionDraft.data.id,
    operationId: routePreview.data.operationDraft?.operation_id,
    family: scenario.family,
    title: `${name} drill finding`,
    target: 'local-lab',
    claim: 'Field drill finding proves evidence, finding, and retest records can stay linked.',
    impact: 'Operators get traceable proof and retest state instead of free-floating claims.',
    severity: scenario.family === 'ai_red_team' ? 'high' : 'medium',
    confidence: 0.72,
    evidenceIds: evidence.data.id ? [evidence.data.id] : [],
    resourceIds: scenario.expectedResources,
    recommendedFix: 'Keep the finding bound to evidence and retest before report promotion.',
    acceptanceCriteria: ['Evidence is linked', 'Retest is queued', 'Retest completion updates finding state'],
  });
  record(`[${name}] finding ledger accepts claim`, finding.status === 201 && finding.data.id, finding.data.id || finding.data.error);

  const retest = finding.data.id
    ? await post(`/api/findings/${finding.data.id}/retest`, {
        method: `${name} retest validates linked evidence and acceptance criteria.`,
        acceptanceCriteria: ['Evidence is linked', 'Retest is queued', 'Retest completion updates finding state'],
      })
    : { status: 0, data: {} };
  record(`[${name}] retest can be queued`, retest.status === 201 && retest.data.id, retest.data.id || retest.data.error);

  const completedRetest = retest.data.id
    ? await patch(`/api/retests/${retest.data.id}`, { status: 'passed', resultSummary: `${name} retest completed in local field drill.` })
    : { status: 0, data: {} };
  record(`[${name}] retest can complete`, completedRetest.ok && completedRetest.data.status === 'passed', completedRetest.data.status || completedRetest.data.error);

  const bundle = await post('/api/mission-bundles', { operationDraft: routePreview.data.operationDraft });
  record(`[${name}] mission bundle exports handoff`, bundle.ok && bundle.data.schema_version === 'plinyos.t3mp3st_mission_bundle/v1' && bundle.data.runbook?.family === scenario.family && bundle.data.promptPacks?.some(pack => pack.id === scenario.expectedPromptPack), bundle.data.handoff?.humanSummary || bundle.data.error);

  const gate = await post('/api/mission-gate', { operationDraft: routePreview.data.operationDraft });
  record(`[${name}] mission gate reports launch status`, gate.ok && gate.data.schema_version === 'plinyos.t3mp3st_mission_gate/v1' && ['hold', 'ready'].includes(gate.data.status), `${gate.data.status || 'unknown'} ${gate.data.score ?? 'n/a'}/100`);

  return { missionDraft, routePreview, evidence, finding, retest };
}

async function runGuardrailChecks(operationDraft) {
  const privateRecon = await post('/api/tools/recon', { target: '192.168.0.1', scan_type: 'quick' });
  record('Private LAN recon blocks without scope receipt', privateRecon.status === 403 && privateRecon.data.approval?.status === 'pending', privateRecon.data.error || JSON.stringify(privateRecon.data.approval || {}));

  const shellMeta = await post('/api/tools/execute', { command: 'file package.json; whoami', target: 'local-host' });
  record('Shell metacharacters are rejected', shellMeta.status === 400 && /Shell control/.test(shellMeta.data.error || ''), shellMeta.data.error || '');

  const unapprovedCommand = await post('/api/tools/execute', { command: 'file package.json', target: 'local-host' });
  record('Local command execution asks for a receipt first', unapprovedCommand.status === 403 && unapprovedCommand.data.approval?.status === 'pending', unapprovedCommand.data.error || '');

  const approvalRequest = await post('/api/approvals/request', {
    action: 'command_execution',
    target: 'local-host',
    reason: 'Field drill receipt for harmless local file command.',
    operationDraft,
    source: 'human',
  });
  record('Operator can request a receipt', approvalRequest.status === 201 && approvalRequest.data.status === 'pending', approvalRequest.data.id || approvalRequest.data.error);

  const approval = approvalRequest.data.id
    ? await post(`/api/approvals/${approvalRequest.data.id}/approve`, { approvedBy: 'field-drill', ttlMinutes: 5 })
    : { status: 0, data: {} };
  record('Receipt can be approved with short TTL', approval.ok && approval.data.status === 'approved', approval.data.id || approval.data.error);

  const approvedCommand = await post('/api/tools/execute', {
    command: 'file package.json',
    target: 'local-host',
    approvalId: approval.data.id,
  });
  record('Approved local command executes', approvedCommand.ok && approvedCommand.data.success === true, (approvedCommand.data.output || approvedCommand.data.error || '').trim().slice(0, 120));

  const loopbackRecon = await post('/api/tools/recon', { target: '127.0.0.1', scan_type: 'quick' });
  record('Loopback recon path runs without external target', loopbackRecon.ok && loopbackRecon.data.success === true && loopbackRecon.data.target === '127.0.0.1', loopbackRecon.data.error || loopbackRecon.data.target || '');
  if (loopbackRecon.ok && loopbackRecon.data.results?.ports?.success === false) {
    warn(`Loopback recon endpoint worked, but local port scanner returned: ${loopbackRecon.data.results.ports.error}`);
  }

  const approvals = await get('/api/approvals');
  const approvedIds = (approvals.data.approvals || []).filter(item => item.status === 'approved').map(item => item.id);
  record('Approval ledger records approved receipt', approvals.ok && approvedIds.includes(approval.data.id), approvedIds.join(', '));
}

async function main() {
  const startedAt = new Date().toISOString();

  const health = await get('/health');
  record('API health is operational', health.ok && health.data.status === 'operational', `${health.status} ${health.data.status || 'unknown'}`, {
    mode: health.data.mode,
    missionDispatch: health.data.missionDispatch,
  });
  record('Knowledge surface is exposed', health.data.resources?.packs >= 14 && health.data.resources?.workflowPresets >= 5 && health.data.resources?.forefrontPressureLanes >= 6, `${health.data.resources?.packs || 0} packs / ${health.data.resources?.workflowPresets || 0} presets / ${health.data.resources?.forefrontPressureLanes || 0} pressure lanes`);

  const preflight = await get('/api/preflight');
  record('Capability preflight reports readiness', preflight.ok && typeof preflight.data.score === 'number', `${preflight.data.score ?? 'n/a'}/100`);
  if (preflight.ok) {
    const missing = (preflight.data.tools || []).filter(tool => !tool.available && ['nmap', 'dig'].includes(tool.name)).map(tool => tool.name);
    if (missing.length) warn(`Preflight missing optional recon tools: ${missing.join(', ')}`);
  }

  const arsenalStatus = await get('/api/arsenal/status?family=web_api');
  record('Arsenal adapter status reports mission readiness', arsenalStatus.ok && arsenalStatus.data.schema_version === 'plinyos.t3mp3st_arsenal_status/v1' && typeof arsenalStatus.data.summary?.readiness === 'number', `${arsenalStatus.data.summary?.readiness ?? 'n/a'}% ready`);
  const arsenalPlan = await post('/api/arsenal/plan', {
    family: 'web_api',
    target: 'local-lab',
    objective: 'Field drill validates gated tool planning.',
  });
  record('Arsenal planner emits gated evidence steps', arsenalPlan.ok && arsenalPlan.data.schema_version === 'plinyos.t3mp3st_arsenal_plan/v1' && (arsenalPlan.data.steps || []).length >= 4 && (arsenalPlan.data.stopConditions || []).length >= 2, `${arsenalPlan.data.steps?.length || 0} steps / ${arsenalPlan.data.stopConditions?.length || 0} stops`);

  const doctrine = await get('/api/operator-doctrine');
  record('Operator doctrine exposes authority model', doctrine.ok && /scope receipts/.test(doctrine.data.doctrine || '') && doctrine.data.authorityModel?.claimHardening === 'hypothesis -> evidence -> finding -> fix -> retest', doctrine.data.authorityModel?.claimHardening || doctrine.data.error);

  const learningStatus = await get('/api/learning/status');
  record('Learning loop exposes explicit proposal policy', learningStatus.ok && learningStatus.data.schema_version === 'plinyos.t3mp3st_learning_status/v1' && learningStatus.data.policy?.silentLearning === false && learningStatus.data.policy?.acceptanceRequired === true, learningStatus.data.policy?.proposalFlow || learningStatus.data.error);
  record('Learning loop deduplicates repeated reviews', learningStatus.ok && learningStatus.data.dedupe?.enabled === true && /canonical content fingerprint/.test(learningStatus.data.dedupe?.strategy || ''), learningStatus.data.dedupe?.strategy || learningStatus.data.error);

  const runbooks = await get('/api/operator-runbooks');
  record('Operator runbooks are exposed', runbooks.ok && runbooks.data.runbooks?.length >= 5, `${runbooks.data.runbooks?.length || 0} runbooks`);

  const forefrontRadar = await get('/api/forefront-radar');
  const laneIds = (forefrontRadar.data.lanes || []).map(lane => lane.id);
  record('Forefront radar exposes pressure lanes', forefrontRadar.ok && forefrontRadar.data.schema_version === 'plinyos.t3mp3st_forefront_radar/v1' && laneIds.includes('frontier-agent-command-injection') && laneIds.includes('frontier-browser-tool-privilege'), laneIds.join(', '));

  const cveSearch = await post('/api/resource-packs/search', { query: 'CVE' });
  const cveResourceIds = (cveSearch.data.resources || []).map(resource => resource.id);
  record('CVE search returns prioritization data sources', cveSearch.ok && ['cisa-kev', 'nvd-cve-api', 'first-epss'].every(id => cveResourceIds.includes(id)), cveResourceIds.join(', '));

  let firstOperationDraft = null;
  for (const [name, scenario] of selectedScenarios()) {
    const result = await runScenario(name, scenario);
    if (!firstOperationDraft) firstOperationDraft = result.routePreview.data.operationDraft;
  }

  await runGuardrailChecks(firstOperationDraft || {});

  const evidence = await get('/api/evidence');
  record('Evidence ledger can be listed', evidence.ok && Array.isArray(evidence.data.evidence) && evidence.data.evidence.length >= selectedScenarios().length, `${evidence.data.evidence?.length || 0} entries`);
  const findings = await get('/api/findings');
  record('Finding ledger can be listed', findings.ok && Array.isArray(findings.data.findings) && findings.data.findings.length >= selectedScenarios().length, `${findings.data.findings?.length || 0} findings`);
  const retests = await get('/api/retests');
  record('Retest ledger can be listed', retests.ok && Array.isArray(retests.data.retests) && retests.data.retests.length >= selectedScenarios().length, `${retests.data.retests?.length || 0} retests`);

  const failed = checks.filter(check => !check.passed);
  const report = {
    drill: 't3mp3st-local-field-drill',
    scenario: scenarioArg,
    baseUrl,
    startedAt,
    finishedAt: new Date().toISOString(),
    passed: failed.length === 0,
    checks,
    warnings,
  };

  console.log(JSON.stringify(report, null, 2));
  if (failed.length) process.exit(1);
}

main().catch(error => {
  console.error(JSON.stringify({
    drill: 't3mp3st-local-field-drill',
    scenario: scenarioArg,
    baseUrl,
    passed: false,
    fatal: error instanceof Error ? error.message : String(error),
  }, null, 2));
  process.exit(1);
});
