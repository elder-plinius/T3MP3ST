#!/usr/bin/env node
import process from 'node:process';

const baseUrl = (process.env.T3MP3ST_API_URL || 'http://127.0.0.1:3333').replace(/\/$/, '');
const startedAt = new Date().toISOString();
const checks = [];
const warnings = [];

function record(name, passed, detail = '', evidence = undefined) {
  checks.push({ name, passed: Boolean(passed), detail, ...(evidence === undefined ? {} : { evidence }) });
}

function warn(message) {
  warnings.push(message);
}

function countItems(value) {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === 'object') return Object.keys(value).length;
  return 0;
}

function summarizeError(result) {
  return result.data?.error || result.data?.message || result.data?.raw || `status=${result.status}`;
}

async function request(method, path, body, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs || 10000);
  try {
    const response = await fetch(`${baseUrl}${path}`, {
      method,
      signal: controller.signal,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });

    if (options.stream) {
      clearTimeout(timeout);
      try { await response.body?.cancel(); } catch {}
      return {
        status: response.status,
        ok: response.ok,
        data: { contentType: response.headers.get('content-type') || '' },
      };
    }

    const text = await response.text();
    clearTimeout(timeout);
    let data;
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }
    return { status: response.status, ok: response.ok, data };
  } catch (error) {
    clearTimeout(timeout);
    return { status: 0, ok: false, data: { error: error.message || String(error) } };
  }
}

const get = (path, options) => request('GET', path, undefined, options);
const post = (path, body, options) => request('POST', path, body, options);
const patch = (path, body, options) => request('PATCH', path, body, options);
const del = (path, options) => request('DELETE', path, undefined, options);

const syntheticFindings = [
  {
    id: 'arsenal-sqli-entry',
    type: 'sqli',
    severity: 'critical',
    confidence: 95,
    target: 'http://127.0.0.1/lab/search',
    parameter: 'q',
    evidence: 'Synthetic boolean canary differs on true/false probes.',
    requires: ['web_access'],
    provides: ['db_access'],
  },
  {
    id: 'arsenal-ssrf-pivot',
    type: 'ssrf',
    severity: 'high',
    confidence: 85,
    target: 'http://127.0.0.1/lab/fetch',
    parameter: 'url',
    evidence: 'Synthetic callback canary reached loopback fixture.',
    requires: ['web_access'],
    provides: ['internal_access'],
  },
  {
    id: 'arsenal-lfi-config',
    type: 'lfi',
    severity: 'high',
    confidence: 93,
    target: 'http://127.0.0.1/lab/download',
    parameter: 'file',
    evidence: 'Synthetic file-read canary observed expected marker.',
    requires: ['internal_access'],
    provides: ['file_read'],
  },
  {
    id: 'arsenal-cmdi-rce',
    type: 'cmdi',
    severity: 'critical',
    confidence: 88,
    target: 'http://127.0.0.1/lab/ping',
    parameter: 'host',
    evidence: 'Synthetic command canary echoed bounded marker.',
    requires: ['db_access'],
    provides: ['code_execution'],
  },
  {
    id: 'arsenal-privilege',
    type: 'privilege_escalation',
    severity: 'high',
    confidence: 82,
    requires: ['code_execution'],
    provides: ['privilege_escalation'],
  },
  {
    id: 'arsenal-persistence',
    type: 'persistence',
    severity: 'medium',
    confidence: 76,
    requires: ['privilege_escalation'],
    provides: ['persistence'],
  },
];

async function smokeEventStream() {
  const events = await get('/api/events', { stream: true, timeoutMs: 3000 });
  record('SSE event stream opens', events.ok && /event-stream/.test(events.data.contentType), events.data.contentType || summarizeError(events));
}

async function smokeCoreSurfaces() {
  const health = await get('/health');
  record('Health endpoint is operational', health.ok && health.data.status === 'operational', `${health.data.mode || 'unknown'} / ${health.data.tools_available || 0} tools`);
  record('Health exposes arsenal summary', health.ok && health.data.arsenal?.total >= 30 && health.data.arsenal?.commandReady >= 20, `${health.data.arsenal?.total || 0} adapters / ${health.data.arsenal?.commandReady || 0} command-ready`);

  const apiHealth = await get('/api/health');
  record('API health mirror is operational', apiHealth.ok && apiHealth.data.status === 'operational', apiHealth.data.organ || summarizeError(apiHealth));

  const preflight = await get('/api/preflight');
  record('Capability preflight runs', preflight.ok && typeof preflight.data.score === 'number', `${preflight.data.score ?? 'n/a'}/100`);
  if (preflight.ok) {
    const missing = (preflight.data.tools || []).filter(tool => !tool.available && ['nmap', 'dig'].includes(tool.name)).map(tool => tool.name);
    if (missing.length) warn(`Optional recon tools missing: ${missing.join(', ')}`);
  }

  await smokeEventStream();
}

async function smokeArsenalCatalog() {
  const catalog = await get('/api/arsenal/catalog');
  const adapterIds = (catalog.data.adapters || []).map(adapter => adapter.id);
  record('Arsenal catalog exposes adapter spine', catalog.ok && catalog.data.schema_version === 'plinyos.t3mp3st_arsenal_catalog/v1' && adapterIds.includes('nuclei') && adapterIds.includes('semgrep') && adapterIds.includes('promptfoo'), `${adapterIds.length} adapters`);
  record('Arsenal safe commands exclude catalog-only heavy tools', catalog.ok && (catalog.data.safeCommands || []).includes('nuclei') && !(catalog.data.safeCommands || []).includes('msfconsole'), `${countItems(catalog.data.safeCommands)} safe commands`);

  const webCatalog = await get('/api/arsenal/catalog?family=web_api');
  const webIds = (webCatalog.data.adapters || []).map(adapter => adapter.id);
  record('Web/API arsenal includes modern recon chain', webCatalog.ok && ['subfinder', 'httpx', 'katana', 'nuclei', 'ffuf'].every(id => webIds.includes(id)), webIds.join(', '));

  const supplyCatalog = await get('/api/arsenal/catalog?family=code_supply_chain');
  const supplyIds = (supplyCatalog.data.adapters || []).map(adapter => adapter.id);
  record('Supply-chain arsenal includes evidence scanners', supplyCatalog.ok && ['semgrep', 'gitleaks', 'trivy', 'syft', 'grype'].every(id => supplyIds.includes(id)), supplyIds.join(', '));

  const status = await get('/api/arsenal/status?family=web_api');
  record('Arsenal status reports installed and missing adapters', status.ok && status.data.schema_version === 'plinyos.t3mp3st_arsenal_status/v1' && typeof status.data.summary?.readiness === 'number' && Array.isArray(status.data.missingCommandReady), `${status.data.summary?.installed || 0} installed / ${status.data.summary?.readiness ?? 'n/a'}%`);

  const plan = await post('/api/arsenal/plan', {
    family: 'web_api',
    target: '127.0.0.1',
    objective: 'Plan a local-only web/API smoke toolchain with evidence flow.',
  });
  const planIds = (plan.data.steps || []).map(step => step.adapterId);
  record('Arsenal planner turns adapters into gated evidence steps', plan.ok && plan.data.schema_version === 'plinyos.t3mp3st_arsenal_plan/v1' && planIds.includes('nuclei') && (plan.data.steps || []).every(step => step.gate && step.nextEvidenceMove), `${countItems(plan.data.steps)} planned steps`);
}

async function smokeKnowledgeAtlas() {
  const presets = await get('/api/workflow-presets');
  record('Workflow presets exposed', presets.ok && countItems(presets.data.presets) >= 5, `${countItems(presets.data.presets)} presets`);

  const resources = await get('/api/resource-packs');
  const resourceIds = (resources.data.resources || []).map(resource => resource.id);
  record('Resource packs exposed', resources.ok && resourceIds.includes('owasp-wstg') && resourceIds.includes('mitre-atlas'), `${resourceIds.length} packs`);

  const resource = await get('/api/resource-packs/owasp-wstg');
  record('Resource pack detail works', resource.ok && resource.data.id === 'owasp-wstg', resource.data.title || summarizeError(resource));

  const promptPacks = await get('/api/agent-prompt-packs');
  const promptPackIds = (promptPacks.data.promptPacks || []).map(pack => pack.id);
  record('Agent prompt packs exposed', promptPacks.ok && promptPackIds.includes('prompt-ai-boundary-cartographer'), promptPackIds.join(', '));

  const promptPack = await get('/api/agent-prompt-packs/prompt-ai-boundary-cartographer');
  record('Agent prompt pack detail works', promptPack.ok && promptPack.data.id === 'prompt-ai-boundary-cartographer' && countItems(promptPack.data.evidenceContract) >= 3, promptPack.data.title || summarizeError(promptPack));

  const runbooks = await get('/api/operator-runbooks');
  record('Operator runbooks exposed', runbooks.ok && countItems(runbooks.data.runbooks) >= 5, `${countItems(runbooks.data.runbooks)} runbooks`);

  const runbook = await get('/api/operator-runbooks/ai_red_team');
  record('Operator runbook detail works', runbook.ok && runbook.data.family === 'ai_red_team' && countItems(runbook.data.phases) >= 3, runbook.data.title || summarizeError(runbook));

  const radar = await get('/api/forefront-radar');
  const laneIds = (radar.data.lanes || []).map(lane => lane.id);
  record('Forefront radar exposed', radar.ok && laneIds.includes('frontier-agent-command-injection') && laneIds.length >= 6, laneIds.join(', '));

  const radarLane = await get('/api/forefront-radar/frontier-agent-command-injection');
  record('Forefront lane detail works', radarLane.ok && radarLane.data.id === 'frontier-agent-command-injection', radarLane.data.title || summarizeError(radarLane));

  const search = await post('/api/resource-packs/search', { query: 'CVE' });
  const searchIds = (search.data.resources || []).map(resource => resource.id);
  record('Resource search returns CVE sources', search.ok && ['cisa-kev', 'nvd-cve-api', 'first-epss'].every(id => searchIds.includes(id)), searchIds.join(', '));

  const context = await get('/api/agent-context/ai_red_team');
  record('Agent context bundles resources, prompts, runbook', context.ok && countItems(context.data.resources) >= 3 && countItems(context.data.promptPacks) >= 1 && context.data.runbook?.family === 'ai_red_team', `${countItems(context.data.resources)} refs / ${countItems(context.data.promptPacks)} prompts`);

  const doctrine = await get('/api/operator-doctrine');
  record('Operator doctrine exposed', doctrine.ok && /hypothesis -> evidence -> finding -> fix -> retest/.test(doctrine.data.authorityModel?.claimHardening || ''), doctrine.data.authorityModel?.claimHardening || summarizeError(doctrine));

  const scorecard = await get('/api/routes/web_api/scorecards');
  record('Route scorecard exposed', scorecard.ok && scorecard.data.scorecard?.protected_metric, scorecard.data.scorecard?.protected_metric || summarizeError(scorecard));
}

async function smokeContractsAndLedgers() {
  const draft = await post('/api/mission-drafts', {
    title: 'Arsenal Smoke: Owned Local Web/API',
    objective: 'Authorized local-only arsenal smoke. Exercise tools with synthetic evidence and no external targets.',
    scope: ['local-lab'],
    constraints: 'Local loopback only. No production writes. Synthetic evidence only.',
    source: 'human',
  });
  record('Mission draft can be created', draft.status === 201 && draft.data.id, draft.data.id || summarizeError(draft));

  const drafts = await get('/api/mission-drafts');
  record('Mission draft list includes draft', drafts.ok && (drafts.data.drafts || []).some(item => item.id === draft.data.id), `${countItems(drafts.data.drafts)} drafts`);

  const draftDetail = await get(`/api/mission-drafts/${draft.data.id}`);
  record('Mission draft detail works', draftDetail.ok && draftDetail.data.id === draft.data.id, draftDetail.data.title || summarizeError(draftDetail));

  const patchedDraft = await patch(`/api/mission-drafts/${draft.data.id}`, { status: 'queued', urgency: 'high' });
  record('Mission draft patch works', patchedDraft.ok && patchedDraft.data.status === 'queued' && patchedDraft.data.urgency === 'high', `${patchedDraft.data.status || 'unknown'} / ${patchedDraft.data.urgency || 'unknown'}`);

  const route = await post('/api/route-preview', { draftId: draft.data.id });
  const operationDraft = route.data.operationDraft || {};
  record('Route preview emits operation contract', route.ok && operationDraft.schema_version === 'plinyos.t3mp3st_operation/v1', operationDraft.schema_version || summarizeError(route));

  const missionApprovalRequest = await post('/api/approvals/request', {
    action: 'mission_execution',
    target: operationDraft.target?.locator || 'local-lab',
    reason: 'Arsenal smoke mission gate receipt for local synthetic operation.',
    operationDraft,
    source: 'system',
  });
  const missionApproval = missionApprovalRequest.data.id
    ? await post(`/api/approvals/${missionApprovalRequest.data.id}/approve`, { approvedBy: 'arsenal-smoke', ttlMinutes: 5 })
    : { ok: false, data: {} };
  record('Mission receipt can be requested and approved', missionApprovalRequest.status === 201 && missionApproval.ok && missionApproval.data.status === 'approved', missionApproval.data.id || summarizeError(missionApprovalRequest));

  const rejectRequest = await post('/api/approvals/request', {
    action: 'model_call',
    target: '*',
    reason: 'Arsenal smoke rejection path.',
    operationDraft,
    source: 'system',
  });
  const rejected = rejectRequest.data.id
    ? await post(`/api/approvals/${rejectRequest.data.id}/reject`, { rejectedBy: 'arsenal-smoke' })
    : { ok: false, data: {} };
  record('Approval rejection path works', rejected.ok && rejected.data.status === 'rejected', rejected.data.id || summarizeError(rejected));

  const approvals = await get('/api/approvals');
  record('Approval ledger lists receipts', approvals.ok && countItems(approvals.data.approvals) >= 2, `${countItems(approvals.data.approvals)} approvals`);

  const evidence = await post('/api/evidence', {
    missionId: draft.data.id,
    operationId: operationDraft.operation_id,
    type: 'note',
    title: 'Arsenal smoke evidence',
    summary: 'Synthetic local smoke exercised mission contracts, tools, and ledgers.',
    source: 'system',
    resourceIds: ['owasp-wstg', 'owasp-api-top10-2023', 'cwe-top25-2025'],
  });
  record('Evidence ledger accepts entry', evidence.status === 201 && evidence.data.id, evidence.data.id || summarizeError(evidence));
  record('Evidence ledger labels weak provenance', evidence.ok && evidence.data.provenanceStrength === 'weak', evidence.data.provenanceStrength || summarizeError(evidence));

  const strongEvidence = await post('/api/evidence', {
    missionId: draft.data.id,
    operationId: operationDraft.operation_id,
    type: 'command',
    title: 'Arsenal smoke strong evidence',
    summary: 'Synthetic local command evidence proves the mission can distinguish replayable/tool-backed proof from context notes.',
    source: 'tool',
    command: 'file package.json',
    resourceIds: ['cwe-top25-2025'],
  });
  record('Evidence ledger labels tool provenance', strongEvidence.status === 201 && strongEvidence.data.provenanceStrength === 'tool', strongEvidence.data.provenanceStrength || summarizeError(strongEvidence));

  const proofEvidenceIds = [evidence.data.id, strongEvidence.data.id].filter(Boolean);

  const hypothesis = await post('/api/hypotheses', {
    missionId: draft.data.id,
    operationId: operationDraft.operation_id,
    family: 'web_api',
    target: 'local-lab',
    claim: 'The local arsenal smoke route has enough proof wiring to harden claims before reporting.',
    rationale: 'Synthetic smoke should exercise hypothesis -> evidence -> finding -> retest before team preview.',
    status: 'testing',
    confidence: 0.62,
    evidenceForIds: proofEvidenceIds,
    nextTests: ['Evidence is linked', 'Retest can be queued', 'Graph exposes unsupported claims'],
  });
  record('Hypothesis ledger accepts claim', hypothesis.status === 201 && hypothesis.data.id, hypothesis.data.id || summarizeError(hypothesis));

  const hypothesisList = await get(`/api/hypotheses?missionId=${encodeURIComponent(draft.data.id)}`);
  record('Hypothesis ledger can be filtered by mission', hypothesisList.ok && (hypothesisList.data.hypotheses || []).some(item => item.id === hypothesis.data.id), `${countItems(hypothesisList.data.hypotheses)} hypotheses`);

  const evidenceGraph = await get(`/api/evidence-graph?missionId=${encodeURIComponent(draft.data.id)}&operationId=${encodeURIComponent(operationDraft.operation_id)}&family=web_api`);
  record('Evidence graph links hypotheses and proof', evidenceGraph.ok && evidenceGraph.data.schema_version === 'plinyos.t3mp3st_evidence_graph/v1' && countItems(evidenceGraph.data.nodes) >= 2 && countItems(evidenceGraph.data.edges) >= 1, `${countItems(evidenceGraph.data.nodes)} nodes / ${countItems(evidenceGraph.data.edges)} edges`);

  const crossFamilyHypothesis = await post('/api/hypotheses', {
    missionId: draft.data.id,
    operationId: operationDraft.operation_id,
    family: 'agent_warfare',
    target: 'local-lab',
    claim: 'A multi-domain hunt must keep agent/tool boundary hypotheses visible even when the route family is web_api.',
    rationale: 'The command center should count mission-wide specialist work and expose per-lane drilldowns.',
    status: 'testing',
    confidence: 0.6,
    evidenceForIds: proofEvidenceIds,
    nextTests: ['Mission gate counts cross-family hypotheses', 'Evidence graph exposes lane summary'],
  });
  record('Cross-family hypothesis can join same mission', crossFamilyHypothesis.status === 201 && crossFamilyHypothesis.data.family === 'agent_warfare', crossFamilyHypothesis.data.id || summarizeError(crossFamilyHypothesis));

  const missionWideGraph = await get(`/api/evidence-graph?missionId=${encodeURIComponent(draft.data.id)}&operationId=${encodeURIComponent(operationDraft.operation_id)}`);
  record('Mission-wide graph preserves specialist lane truth', missionWideGraph.ok && missionWideGraph.data.summary?.hypotheses >= 2 && missionWideGraph.data.summary?.activeLanes >= 2, `${missionWideGraph.data.summary?.hypotheses || 0} hypotheses / ${missionWideGraph.data.summary?.activeLanes || 0} lanes`);
  record('Evidence graph summarizes strong provenance', missionWideGraph.ok && (missionWideGraph.data.summary?.evidenceProvenance?.strong || 0) >= 1, `${missionWideGraph.data.summary?.evidenceProvenance?.strong || 0} strong`);

  const earlyGate = await post('/api/mission-gate', { operationDraft });
  record('Mission gate counts cross-family hypotheses', earlyGate.ok && earlyGate.data.missionSummary?.hypotheses >= 2 && earlyGate.data.missionSummary?.activeLanes >= 2 && earlyGate.data.missionSummary?.routeFamilyHypotheses >= 1, `${earlyGate.data.missionSummary?.hypotheses || 0} mission hypotheses / ${earlyGate.data.missionSummary?.activeLanes || 0} lanes`);
  record('Mission gate recognizes strong evidence', earlyGate.ok && (earlyGate.data.missionSummary?.evidenceProvenance?.strong || 0) >= 1, `${earlyGate.data.missionSummary?.evidenceProvenance?.strong || 0} strong`);

  const decomposition = hypothesis.data.id
    ? await post(`/api/hypotheses/${hypothesis.data.id}/decompose`, {})
    : { status: 0, data: {} };
  record('Hypothesis decomposes into specialist work orders', decomposition.status === 201 && decomposition.data.schema_version === 'plinyos.t3mp3st_work_order_decomposition/v1' && countItems(decomposition.data.workOrders) >= 5, `${countItems(decomposition.data.workOrders)} work orders`);

  const workOrderList = await get(`/api/work-orders?missionId=${encodeURIComponent(draft.data.id)}&operationId=${encodeURIComponent(operationDraft.operation_id)}&family=web_api`);
  record('Work order queue can be filtered by mission', workOrderList.ok && countItems(workOrderList.data.workOrders) >= 5, `${countItems(workOrderList.data.workOrders)} queued`);

  const workOrder = (workOrderList.data.workOrders || []).find(item => item.status !== 'needs_receipt') || (workOrderList.data.workOrders || [])[0] || {};
  const completedWorkOrder = workOrder.id
    ? await post(`/api/work-orders/${workOrder.id}/complete`, {
        disposition: workOrder.kind === 'disprove' ? 'against' : 'for',
        evidenceType: 'note',
        resultSummary: 'Arsenal smoke completed a decomposed local-safe work order and attached evidence.',
        source: 'system',
      })
    : { status: 0, data: {} };
  record('Work order completion auto-attaches evidence', completedWorkOrder.status === 201 && completedWorkOrder.data.workOrder?.status === 'completed' && countItems(completedWorkOrder.data.evidenceIds) > 0, completedWorkOrder.data.workOrder?.id || summarizeError(completedWorkOrder));

  const graphWithWork = await get(`/api/evidence-graph?missionId=${encodeURIComponent(draft.data.id)}&operationId=${encodeURIComponent(operationDraft.operation_id)}&family=web_api`);
  record('Evidence graph includes work-order nodes', graphWithWork.ok && graphWithWork.data.summary?.workOrders >= 5 && (graphWithWork.data.nodes || []).some(item => item.type === 'work_order'), `${graphWithWork.data.summary?.workOrders || 0} work orders`);

  const watchHypothesis = await post('/api/hypotheses', {
    missionId: draft.data.id,
    operationId: operationDraft.operation_id,
    family: 'web_api',
    target: 'local-lab',
    claim: 'The watch loop can notice an undecomposed local-safe hypothesis and convert it into specialist work orders.',
    rationale: 'Always-on hunting should surface stale reasoning and create the next concrete work queue when nudged.',
    status: 'testing',
    confidence: 0.58,
    nextTests: ['Watch loop emits signals', 'Nudge spawns work orders', 'Status recalls latest cycle'],
  });
  record('Watch-loop fixture hypothesis created', watchHypothesis.status === 201 && watchHypothesis.data.id, watchHypothesis.data.id || summarizeError(watchHypothesis));

  const watchPulse = await post('/api/watch-loop/run', {
    missionId: draft.data.id,
    operationId: operationDraft.operation_id,
    family: 'web_api',
    target: 'local-lab',
    spawnWorkOrders: false,
  });
  record('Watch loop emits scoped signals', watchPulse.status === 201 && watchPulse.data.schema_version === 'plinyos.t3mp3st_watch_loop_cycle/v1' && countItems(watchPulse.data.signals) >= 1, `${watchPulse.data.summary?.signals || 0} signals / ${watchPulse.data.summary?.actions || 0} actions`);

  const watchNudge = await post('/api/watch-loop/run', {
    missionId: draft.data.id,
    operationId: operationDraft.operation_id,
    family: 'web_api',
    target: 'local-lab',
    spawnWorkOrders: true,
  });
  record('Watch loop nudge spawns specialist work orders', watchNudge.status === 201 && watchNudge.data.schema_version === 'plinyos.t3mp3st_watch_loop_cycle/v1' && (watchNudge.data.summary?.spawnedWorkOrders || 0) >= 5, `${watchNudge.data.summary?.spawnedWorkOrders || 0} spawned`);

  const watchStatus = await get(`/api/watch-loop/status?missionId=${encodeURIComponent(draft.data.id)}&operationId=${encodeURIComponent(operationDraft.operation_id)}&family=web_api&target=local-lab`);
  const watchCycleIds = (watchStatus.data.cycles || []).map(cycle => cycle.id);
  record('Watch loop status recalls latest pulse', watchStatus.ok && watchStatus.data.schema_version === 'plinyos.t3mp3st_watch_loop_status/v1' && watchCycleIds.includes(watchNudge.data.id), `${watchStatus.data.latestCycle?.id || 'none'} latest / ${watchCycleIds.length} retained`);

  const selfHeal = await post('/api/self-heal/run', {
    missionId: draft.data.id,
    operationId: operationDraft.operation_id,
    family: 'web_api',
    target: 'local-lab',
    operationDraft,
    apply: true,
  });
  record('Self-heal diagnoses and safely applies watch repair', selfHeal.status === 201 && selfHeal.data.schema_version === 'plinyos.t3mp3st_self_heal/v1' && countItems(selfHeal.data.actions) >= 1 && typeof selfHeal.data.summary?.applied === 'number', `${selfHeal.data.health || 'unknown'} / ${selfHeal.data.summary?.applied || 0} applied`);

  const supportedHypothesis = hypothesis.data.id
    ? await patch(`/api/hypotheses/${hypothesis.data.id}`, { status: 'supported', confidence: 0.76 })
    : { ok: false, data: {} };
  record('Hypothesis patch path works', supportedHypothesis.ok && supportedHypothesis.data.status === 'supported', supportedHypothesis.data.status || summarizeError(supportedHypothesis));

  const promotedHypothesis = hypothesis.data.id
    ? await post(`/api/hypotheses/${hypothesis.data.id}/promote`, {
        severity: 'medium',
        confidence: 0.78,
        acceptanceCriteria: ['Evidence is linked', 'Retest can be queued', 'Graph exposes unsupported claims'],
      })
    : { status: 0, data: {} };
  record('Hypothesis can be promoted to finding', promotedHypothesis.status === 201 && promotedHypothesis.data.finding?.id && promotedHypothesis.data.hypothesis?.status === 'promoted', promotedHypothesis.data.finding?.id || summarizeError(promotedHypothesis));

  const finding = await post('/api/findings', {
    missionId: draft.data.id,
    operationId: operationDraft.operation_id,
    family: 'web_api',
    title: 'Arsenal smoke finding',
    target: 'local-lab',
    claim: 'The local arsenal smoke binds tool output, route context, and retest state.',
    impact: 'Operators can trust the cockpit wiring before real authorized work.',
    severity: 'medium',
    confidence: 0.83,
    status: 'validated',
    evidenceIds: strongEvidence.data.id ? [strongEvidence.data.id] : proofEvidenceIds,
    resourceIds: ['owasp-wstg', 'owasp-api-top10-2023'],
    recommendedFix: 'Keep arsenal smoke in the pre-release gate.',
    acceptanceCriteria: ['Evidence is linked', 'Retest passes', 'Learning review deduplicates'],
  });
  record('Finding ledger accepts claim', finding.status === 201 && finding.data.id, finding.data.id || summarizeError(finding));

  const patchedFinding = finding.data.id
    ? await patch(`/api/findings/${finding.data.id}`, { owner: 'arsenal-smoke', status: 'fix_ready' })
    : { ok: false, data: {} };
  record('Finding patch path works', patchedFinding.ok && patchedFinding.data.status === 'fix_ready', patchedFinding.data.status || summarizeError(patchedFinding));

  const retest = finding.data.id
    ? await post(`/api/findings/${finding.data.id}/retest`, {
        method: 'Run npm run arsenal:smoke and verify synthetic local-only checks pass.',
        acceptanceCriteria: ['Evidence is linked', 'Retest passes', 'Learning review deduplicates'],
      })
    : { status: 0, data: {} };
  record('Retest can be queued', retest.status === 201 && retest.data.id, retest.data.id || summarizeError(retest));

  const gateWithQueuedRetest = await post('/api/mission-gate', { operationDraft });
  record('Mission gate holds unresolved retest', gateWithQueuedRetest.ok && gateWithQueuedRetest.data.schema_version === 'plinyos.t3mp3st_mission_gate/v1' && gateWithQueuedRetest.data.status !== 'ready', `${gateWithQueuedRetest.data.status || 'unknown'} ${gateWithQueuedRetest.data.score ?? 'n/a'}/100`);

  const completedRetest = retest.data.id
    ? await patch(`/api/retests/${retest.data.id}`, { status: 'passed', resultSummary: 'Arsenal smoke retest passed.' })
    : { ok: false, data: {} };
  record('Retest can be completed', completedRetest.ok && completedRetest.data.status === 'passed', completedRetest.data.status || summarizeError(completedRetest));

  const reproPacks = await post('/api/repro-packs', { operationDraft });
  const readyReproPack = (reproPacks.data.packs || []).find(pack => pack.readiness === 'ready');
  record('Repro packs summarize replay readiness', reproPacks.ok && reproPacks.data.schema_version === 'plinyos.t3mp3st_repro_packs/v1' && (reproPacks.data.summary?.total || 0) >= 2 && (reproPacks.data.summary?.ready || 0) >= 1, `${reproPacks.data.summary?.ready || 0}/${reproPacks.data.summary?.total || 0} ready`);
  record('Repro pack includes safe replay contract', Boolean(readyReproPack && countItems(readyReproPack.replaySteps) >= 4 && countItems(readyReproPack.falsifiers) >= 3 && readyReproPack.safeProbe), readyReproPack?.id || summarizeError(reproPacks));

  const pressurePaths = await post('/api/pressure-paths', { operationDraft });
  const bestPressurePath = (pressurePaths.data.paths || [])[0];
  record('Pressure paths convert repro into gated offensive chain', pressurePaths.ok && pressurePaths.data.schema_version === 'plinyos.t3mp3st_pressure_paths/v1' && (pressurePaths.data.summary?.total || 0) >= 2 && (pressurePaths.data.summary?.maxOffensiveScore || 0) > 0, `${pressurePaths.data.summary?.armed || 0}/${pressurePaths.data.summary?.total || 0} armed, max ${pressurePaths.data.summary?.maxOffensiveScore || 0}`);
  record('Pressure path includes simulator and no-go gates', Boolean(bestPressurePath && bestPressurePath.safeSimulator?.mode === 'local_canary' && countItems(bestPressurePath.chainStages) >= 5 && countItems(bestPressurePath.noGo) >= 2), bestPressurePath?.id || summarizeError(pressurePaths));

  const pressureCanary = await post('/api/pressure-paths/canary', {
    operationDraft,
    pathId: bestPressurePath?.id,
    pressurePaths: pressurePaths.data,
  });
  record('Pressure canary rehearses top path locally', pressureCanary.ok && pressureCanary.data.schema_version === 'plinyos.t3mp3st_pressure_canary/v1' && pressureCanary.data.status === 'passed' && pressureCanary.data.canary?.mode === 'local_canary', pressureCanary.data.canary?.observedSignal || summarizeError(pressureCanary));
  record('Pressure canary writes replayable evidence and retest receipt', Boolean(pressureCanary.data.evidence?.id && pressureCanary.data.evidence?.provenanceStrength === 'replayable' && pressureCanary.data.retest?.status === 'passed'), `${pressureCanary.data.evidence?.id || 'no evidence'} / ${pressureCanary.data.retest?.id || 'no retest'}`);

  const pressureDuel = await post('/api/pressure-paths/duel', {
    operationDraft,
    pathId: bestPressurePath?.id,
    pressurePaths: pressurePaths.data,
    pressureCanary: pressureCanary.data,
  });
  record('Pressure duel survives only evidence-backed canary route', pressureDuel.ok && pressureDuel.data.schema_version === 'plinyos.t3mp3st_pressure_duel/v1' && pressureDuel.data.status === 'survived' && (pressureDuel.data.survivabilityScore || 0) >= 86, `${pressureDuel.data.status || 'unknown'} ${pressureDuel.data.survivabilityScore || 0}/100`);
  record('Pressure duel writes skeptic evidence and follow-up task', Boolean(pressureDuel.data.evidence?.id && pressureDuel.data.workOrder?.id && countItems(pressureDuel.data.duel?.rounds) >= 3), `${pressureDuel.data.evidence?.id || 'no evidence'} / ${pressureDuel.data.workOrder?.id || 'no work order'}`);

  const pressureMutations = await post('/api/pressure-paths/mutate', {
    operationDraft,
    pathId: bestPressurePath?.id,
    pressurePaths: pressurePaths.data,
    pressureDuel: pressureDuel.data,
  });
  record('Pressure mutation gauntlet forks survived route', pressureMutations.ok && pressureMutations.data.schema_version === 'plinyos.t3mp3st_pressure_mutations/v1' && pressureMutations.data.status === 'queued' && countItems(pressureMutations.data.mutations) >= 5 && (pressureMutations.data.summary?.maxFangScore || 0) >= 80, `${countItems(pressureMutations.data.mutations)} mutations / max ${pressureMutations.data.summary?.maxFangScore || 0}`);
  record('Pressure mutation gauntlet queues specialist work orders', Boolean(pressureMutations.data.evidence?.id && countItems(pressureMutations.data.workOrders) >= 3 && pressureMutations.data.workOrders.every(order => order.requiresReceipt === false)), `${pressureMutations.data.evidence?.id || 'no evidence'} / ${countItems(pressureMutations.data.workOrders)} work orders`);

  const pressureChains = await post('/api/pressure-paths/chains', {
    operationDraft,
    pathId: bestPressurePath?.id,
    pressurePaths: pressurePaths.data,
    pressureMutations: pressureMutations.data,
  });
  record('Pressure fang chains compose local weird-machine routes', pressureChains.ok && pressureChains.data.schema_version === 'plinyos.t3mp3st_pressure_chains/v1' && pressureChains.data.status === 'queued' && countItems(pressureChains.data.chains) >= 3 && (pressureChains.data.summary?.maxChainScore || 0) >= 80, `${countItems(pressureChains.data.chains)} chains / max ${pressureChains.data.summary?.maxChainScore || 0}`);
  record('Pressure fang chains queue staged specialist work orders', Boolean(pressureChains.data.evidence?.id && countItems(pressureChains.data.workOrders) >= 2 && pressureChains.data.workOrders.every(order => order.requiresReceipt === false)), `${pressureChains.data.evidence?.id || 'no evidence'} / ${countItems(pressureChains.data.workOrders)} work orders`);

  const evidenceList = await get(`/api/evidence?missionId=${encodeURIComponent(draft.data.id)}`);
  record('Evidence ledger can be filtered by mission', evidenceList.ok && (evidenceList.data.evidence || []).some(item => item.id === evidence.data.id), `${countItems(evidenceList.data.evidence)} evidence`);
  record('Evidence ledger includes pressure canary receipt', evidenceList.ok && (evidenceList.data.evidence || []).some(item => item.id === pressureCanary.data.evidence?.id), pressureCanary.data.evidence?.id || summarizeError(evidenceList));
  record('Evidence ledger includes pressure duel receipt', evidenceList.ok && (evidenceList.data.evidence || []).some(item => item.id === pressureDuel.data.evidence?.id), pressureDuel.data.evidence?.id || summarizeError(evidenceList));
  record('Evidence ledger includes pressure mutation receipt', evidenceList.ok && (evidenceList.data.evidence || []).some(item => item.id === pressureMutations.data.evidence?.id), pressureMutations.data.evidence?.id || summarizeError(evidenceList));
  record('Evidence ledger includes pressure fang-chain receipt', evidenceList.ok && (evidenceList.data.evidence || []).some(item => item.id === pressureChains.data.evidence?.id), pressureChains.data.evidence?.id || summarizeError(evidenceList));

  const findingList = await get(`/api/findings?missionId=${encodeURIComponent(draft.data.id)}`);
  record('Finding ledger can be filtered by mission', findingList.ok && (findingList.data.findings || []).some(item => item.id === finding.data.id), `${countItems(findingList.data.findings)} findings`);

  const retestList = await get('/api/retests');
  record('Retest ledger can be listed', retestList.ok && (retestList.data.retests || []).some(item => item.id === retest.data.id), `${countItems(retestList.data.retests)} retests`);

  const bundle = await post('/api/mission-bundles', { operationDraft });
  record('Mission bundle exports handoff', bundle.ok && bundle.data.schema_version === 'plinyos.t3mp3st_mission_bundle/v1', bundle.data.handoff?.humanSummary || summarizeError(bundle));
  record('Mission bundle carries repro packs', bundle.ok && bundle.data.reproPacks?.schema_version === 'plinyos.t3mp3st_repro_packs/v1' && (bundle.data.reproPacks.summary?.total || 0) >= 2, `${bundle.data.reproPacks?.summary?.ready || 0}/${bundle.data.reproPacks?.summary?.total || 0} ready`);
  record('Mission bundle carries pressure paths', bundle.ok && bundle.data.pressurePaths?.schema_version === 'plinyos.t3mp3st_pressure_paths/v1' && (bundle.data.pressurePaths.summary?.total || 0) >= 2, `${bundle.data.pressurePaths?.summary?.armed || 0}/${bundle.data.pressurePaths?.summary?.total || 0} armed`);

  const bundleByMission = await get(`/api/mission-bundles/${encodeURIComponent(draft.data.id)}`);
  record('Mission bundle can be rebuilt by mission id', bundleByMission.ok && bundleByMission.data.schema_version === 'plinyos.t3mp3st_mission_bundle/v1', bundleByMission.data.handoff?.humanSummary || summarizeError(bundleByMission));

  const gate = await post('/api/mission-gate', { operationDraft });
  record('Mission gate evaluates ledgers and receipts', gate.ok && gate.data.schema_version === 'plinyos.t3mp3st_mission_gate/v1' && ['hold', 'ready'].includes(gate.data.status), `${gate.data.status || 'unknown'} ${gate.data.score ?? 'n/a'}/100`);

  const tempDraft = await post('/api/mission-drafts', {
    title: 'Arsenal Smoke Delete Fixture',
    objective: 'Temporary draft for delete path.',
    scope: ['local-lab'],
    constraints: 'Delete fixture.',
    source: 'system',
  });
  const deleted = tempDraft.data.id ? await del(`/api/mission-drafts/${tempDraft.data.id}`) : { ok: false, data: {} };
  const deletedDetail = tempDraft.data.id ? await get(`/api/mission-drafts/${tempDraft.data.id}`) : { status: 0, data: {} };
  record('Mission draft delete path works', deleted.ok && deleted.data.success === true && deletedDetail.status === 404, tempDraft.data.id || summarizeError(tempDraft));

  return { draft, route, operationDraft, evidence, finding, retest, missionApproval };
}

async function smokeImprovementAndLearning(context) {
  const proposal = await post('/api/improvement/proposals', {
    routeId: 'web_api',
    baseConfigId: 'arsenal-smoke-baseline',
    rationale: 'Promote local arsenal smoke into the regression gate.',
    expectedMetrics: { route_delta: 1, replay_passed: 1, false_positive_rate: 0.02 },
    risks: ['fixture drift'],
    requiredReplaySuites: ['arsenal-smoke'],
    rollbackTarget: 'arsenal-smoke-baseline',
  });
  record('Improvement proposal can be created', proposal.status === 201 && proposal.data.id, proposal.data.id || summarizeError(proposal));

  const proposals = await get('/api/improvement/proposals');
  record('Improvement proposals can be listed', proposals.ok && (proposals.data.proposals || []).some(item => item.id === proposal.data.id), `${countItems(proposals.data.proposals)} proposals`);

  const promotion = await post('/api/promotion/evaluate', {
    proposalId: proposal.data.id,
    metrics: { replay_passed: 1, route_delta: 1, false_positive_rate: 0.02 },
    approvals: ['human'],
  });
  record('Promotion gate approves only evidence-backed proposal', promotion.ok && promotion.data.approved === true, promotion.data.action || summarizeError(promotion));

  const learningStatus = await get('/api/learning/status');
  record('Learning status exposes explicit proposal policy', learningStatus.ok && learningStatus.data.policy?.silentLearning === false && learningStatus.data.dedupe?.enabled === true, learningStatus.data.dedupe?.strategy || summarizeError(learningStatus));

  const learningReview = await post('/api/learning/run-review', {
    missionId: context.draft.data.id,
    operationId: context.operationDraft.operation_id,
    family: context.operationDraft.family,
  });
  record('Learning review proposes inspectable memory', learningReview.status === 201 && countItems(learningReview.data.proposals) > 0, `${countItems(learningReview.data.proposals)} proposals`);

  const manualMemory = await post('/api/memory/proposals', {
    type: 'procedure',
    content: 'Arsenal smoke should stay local-only and synthetic unless a human attaches explicit scope receipts.',
    confidence: 0.8,
    rationale: 'Manual smoke memory verifies proposal/reject path.',
    source: 'arsenal.smoke',
    sourceMissionId: context.draft.data.id,
    sourceOperationId: context.operationDraft.operation_id,
    sourceEvidenceIds: context.evidence.data.id ? [context.evidence.data.id] : [],
  });
  record('Manual memory proposal can be created', manualMemory.status === 201 && manualMemory.data.id, manualMemory.data.id || summarizeError(manualMemory));

  const rejectedMemory = manualMemory.data.id
    ? await post(`/api/memory/proposals/${manualMemory.data.id}/reject`, {})
    : { ok: false, data: {} };
  record('Memory proposal reject path works', rejectedMemory.ok && rejectedMemory.data.status === 'rejected', rejectedMemory.data.status || summarizeError(rejectedMemory));

  const proposalId = learningReview.data.proposals?.[0]?.id;
  const acceptedMemory = proposalId
    ? await post(`/api/memory/proposals/${proposalId}/accept`, {})
    : { ok: false, data: {} };
  record('Memory proposal accept path works', acceptedMemory.ok && acceptedMemory.data.entry?.id && acceptedMemory.data.proposal?.status === 'accepted', acceptedMemory.data.entry?.id || summarizeError(acceptedMemory));

  const before = await get('/api/memory/proposals');
  const beforeCount = countItems(before.data.proposals);
  const repeated = await post('/api/learning/run-review', {
    missionId: context.draft.data.id,
    operationId: context.operationDraft.operation_id,
    family: context.operationDraft.family,
  });
  const after = await get('/api/memory/proposals');
  const afterCount = countItems(after.data.proposals);
  const reinforced = (repeated.data.proposals || []).some(item => (item.observationCount || 1) > 1);
  record('Repeated learning review reinforces, not duplicates', repeated.status === 201 && beforeCount === afterCount && reinforced, `${afterCount} proposals / reinforced=${reinforced}`);

  const capsule = await get('/api/memory/capsule');
  record('Memory capsule exposes accepted entries only', capsule.ok && capsule.data.schema_version === 'plinyos.t3mp3st_memory_capsule/v1' && (capsule.data.entries || []).some(item => item.id === acceptedMemory.data.entry?.id), `${countItems(capsule.data.entries)} entries`);
}

async function smokePlinySpecials() {
  const localTarget = 'http://127.0.0.1/lab';

  const engagement = await post('/api/pliny/leviathan/engage', {
    target: '127.0.0.1',
    autonomy: 'GUIDED',
    objectives: ['arsenal_smoke'],
    opsec_level: 'contained',
  });
  record('LEVIATHAN builds kill-chain plan', engagement.ok && engagement.data.success === true && countItems(engagement.data.plan?.phases) >= 6, `${countItems(engagement.data.plan?.phases)} phases`);

  const validation = await post('/api/pliny/sphinx/validate', {
    findings: syntheticFindings.slice(0, 4),
    validation_depth: 'thorough',
  });
  record('SPHINX validates synthetic findings', validation.ok && validation.data.success === true && countItems(validation.data.confirmed_findings) >= 4, `${countItems(validation.data.confirmed_findings)} confirmed`);

  const strike = await post('/api/pliny/gorgon/strike', {
    target: localTarget,
    vulnerability: syntheticFindings[0],
    mode: 'surgical',
    objective: 'data_read',
  });
  record('GORGON returns strike plan without execution', strike.ok && strike.data.success === true && countItems(strike.data.strike_plan?.payloads) > 0, `${countItems(strike.data.strike_plan?.payloads)} payload candidates`);

  const escalation = await post('/api/pliny/cerberus/escalate', {
    platform: 'linux',
    current_privilege: 'synthetic-user',
    system_info: { sudo_permissions: ['/usr/bin/find'], suid_binaries: ['/usr/bin/bash'] },
  });
  record('CERBERUS ranks synthetic escalation vectors', escalation.ok && escalation.data.success === true && escalation.data.vectors_found > 0, `${escalation.data.vectors_found || 0} vectors`);

  const injector = await post('/api/pliny/typhon/inject', {
    payload: 'T3MP3ST_ARSENAL_CANARY',
    context: 'url',
    encodings: ['url', 'base64'],
    waf_bypass: ['double_encode'],
    generate_variants: true,
  });
  record('TYPHON encodes benign canary variants', injector.ok && injector.data.success === true && injector.data.encoded !== 'T3MP3ST_ARSENAL_CANARY' && injector.data.variants, `${Object.keys(injector.data.variants || {}).length} variants`);

  const fakeJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhcnNlbmFsIiwiaWF0IjoxNzAwMDAwMDAwfQ.signature';
  const harvesting = await post('/api/pliny/griffin/harvest', {
    content: [
      'Synthetic fixture only.',
      'aws=AKIA1111111111111111',
      'github=ghp_111111111111111111111111111111111111',
      `jwt=${fakeJwt}`,
    ].join('\n'),
    decode_tokens: true,
  });
  record('GRIFFIN detects synthetic secrets without real values', harvesting.ok && harvesting.data.success === true && harvesting.data.scan_stats?.total_secrets >= 2, `${harvesting.data.scan_stats?.total_secrets || 0} synthetic matches`);

  const research = await post('/api/pliny/simurgh/hunt', {
    target: 'synthetic-parser',
    vuln_classes: ['buffer_overflow', 'format_string'],
    protections: ['ASLR', 'NX', 'stack_canary'],
  });
  record('SIMURGH produces synthetic research map', research.ok && research.data.success === true && research.data.vulnerability_analysis?.buffer_overflow && research.data.vulnerability_analysis?.format_string, `difficulty=${research.data.difficulty || 'unknown'}`);

  const multiVector = await post('/api/pliny/hydra/orchestrate', {
    target: localTarget,
    vectors: ['sqli', 'xss', 'ssti', 'ssrf', 'lfi'],
    parallelism: 3,
    depth: 'standard',
  });
  record('HYDRA composes multi-vector plan', multiVector.ok && multiVector.data.success === true && countItems(multiVector.data.attacks) === 5, `${countItems(multiVector.data.attacks)} vectors`);

  const chain = await post('/api/pliny/arachne/chain', {
    vulnerabilities: syntheticFindings,
    objective: 'full_compromise',
    max_chain_length: 6,
    starting_capabilities: ['web_access'],
  });
  record('ARACHNE builds viable exploit chain', chain.ok && chain.data.success === true && chain.data.analysis?.chains_found > 0, `${chain.data.analysis?.chains_found || 0} chains`);
}

async function smokeToolsAndRuntime(context) {
  const tools = await get('/api/tools');
  record('Tool registry exposes safe command allowlist', tools.ok && tools.data.count >= 20 && (tools.data.tools || []).includes('file'), `${tools.data.count || 0} tools`);

  const commandMissing = await post('/api/tools/execute', {});
  record('Tool execution rejects missing command', commandMissing.status === 400 && /Command required/.test(commandMissing.data.error || ''), summarizeError(commandMissing));

  const shellMeta = await post('/api/tools/execute', { command: 'file package.json; whoami', target: 'local-host' });
  record('Tool execution rejects shell metacharacters', shellMeta.status === 400 && /Shell control/.test(shellMeta.data.error || ''), summarizeError(shellMeta));

  const deniedCommand = await post('/api/tools/execute', { command: 'file package.json', target: 'local-host' });
  record('Tool execution requires receipt before local command', deniedCommand.status === 403 && deniedCommand.data.approval?.status === 'pending', deniedCommand.data.approval?.id || summarizeError(deniedCommand));

  const forgedTarget = `forged-authority-${Date.now()}.local`;
  const forgedDraft = {
    ...context.operationDraft,
    operation_id: `op_forged_${Date.now()}`,
    mission_id: `mission_forged_${Date.now()}`,
    target: { locator: forgedTarget },
    scope: {
      authorized: true,
      allowed_actions: ['read_only_assessment', 'command_execution'],
    },
  };
  const forgedCommand = await post('/api/tools/execute', {
    command: 'file package.json',
    target: forgedTarget,
    operationDraft: forgedDraft,
  });
  record('Tool execution rejects forged client authority', forgedCommand.status === 403 && forgedCommand.data.approval?.status === 'pending', forgedCommand.data.approval?.id || summarizeError(forgedCommand));

  const wildcardCommandApproval = await post('/api/approvals/request', {
    action: 'command_execution',
    target: '*',
    reason: 'Arsenal smoke should reject wildcard receipts for active local commands.',
    operationDraft: context.operationDraft,
    source: 'system',
  });
  record('Wildcard command approvals are rejected', wildcardCommandApproval.status === 400 && /Wildcard approval target/.test(wildcardCommandApproval.data.error || ''), summarizeError(wildcardCommandApproval));

  const commandOnlyTarget = `command-only-${Date.now()}.local`;
  const commandOnlyDraft = {
    ...context.operationDraft,
    operation_id: `op_command_only_${Date.now()}`,
    mission_id: `mission_command_only_${Date.now()}`,
    target: { locator: commandOnlyTarget },
    scope: {
      authorized: true,
      allowed_actions: ['read_only_assessment'],
    },
  };
  const commandOnlyRequest = await post('/api/approvals/request', {
    action: 'command_execution',
    target: commandOnlyTarget,
    reason: 'Arsenal smoke proves command receipts cannot substitute for mission authority.',
    operationDraft: commandOnlyDraft,
    source: 'system',
  });
  const commandOnlyApproval = commandOnlyRequest.data.id
    ? await post(`/api/approvals/${commandOnlyRequest.data.id}/approve`, { approvedBy: 'arsenal-smoke', ttlMinutes: 5 })
    : { ok: false, data: {} };
  const commandOnlyGate = await post('/api/mission-gate', { operationDraft: commandOnlyDraft });
  record(
    'Command receipt cannot satisfy mission gate authority',
    commandOnlyApproval.ok && commandOnlyGate.ok && commandOnlyGate.data.missionSummary?.freshMissionApprovals === 0 && (commandOnlyGate.data.missionSummary?.freshCommandApprovals || 0) >= 1 && commandOnlyGate.data.status !== 'ready',
    `${commandOnlyGate.data.missionSummary?.freshMissionApprovals || 0} mission / ${commandOnlyGate.data.missionSummary?.freshCommandApprovals || 0} command`
  );

  const commandApprovalRequest = await post('/api/approvals/request', {
    action: 'command_execution',
    target: 'local-host',
    reason: 'Arsenal smoke receipt for harmless local file command.',
    operationDraft: context.operationDraft,
    source: 'system',
  });
  const commandApproval = commandApprovalRequest.data.id
    ? await post(`/api/approvals/${commandApprovalRequest.data.id}/approve`, { approvedBy: 'arsenal-smoke', ttlMinutes: 5 })
    : { ok: false, data: {} };
  const approvedCommand = commandApproval.data.id
    ? await post('/api/tools/execute', { command: 'file package.json', target: 'local-host', approvalId: commandApproval.data.id })
    : { ok: false, data: {} };
  record('Approved local command executes', approvedCommand.ok && approvedCommand.data.success === true && /JSON data/.test(approvedCommand.data.output || ''), (approvedCommand.data.output || approvedCommand.data.error || '').trim().slice(0, 120));

  const invalidRecon = await post('/api/tools/recon', { target: '127.0.0.1;whoami', scan_type: 'quick' });
  record('Recon rejects unsupported target characters', invalidRecon.status === 400 && /unsupported/.test(invalidRecon.data.error || ''), summarizeError(invalidRecon));

  const privateRecon = await post('/api/tools/recon', { target: '192.168.0.1', scan_type: 'quick' });
  record('Private LAN recon requires receipt', privateRecon.status === 403 && privateRecon.data.approval?.status === 'pending', privateRecon.data.approval?.id || summarizeError(privateRecon));

  const loopbackRecon = await post('/api/tools/recon', { target: '127.0.0.1', scan_type: 'quick' });
  record('Loopback recon path is callable without external target', loopbackRecon.ok && loopbackRecon.data.success === true && loopbackRecon.data.target === '127.0.0.1', loopbackRecon.data.results?.ports?.error || loopbackRecon.data.target || summarizeError(loopbackRecon));
  if (loopbackRecon.data.results?.ports?.error) warn(`Loopback recon endpoint worked, but local port scanner returned: ${loopbackRecon.data.results.ports.error}`);

  const llmStatus = await get('/api/llm/status');
  const llmConfigured = Boolean(llmStatus.data.connected && llmStatus.data.hasApiKey);
  record('LLM status endpoint responds', llmStatus.ok && typeof llmStatus.data.connected === 'boolean' && typeof llmStatus.data.hasApiKey === 'boolean', `connected=${llmStatus.data.connected} hasApiKey=${llmStatus.data.hasApiKey}`);

  const llmChat = await post('/api/llm/chat', { message: 'local smoke ping' });
  record('LLM chat fails closed when unconfigured', llmConfigured ? llmChat.ok : llmChat.status === 503, llmChat.data.error || 'configured');
}

async function smokeMissionAndGeneralControl() {
  const status = await get('/api/mission/status');
  record('Mission status endpoint responds', status.ok && typeof status.data.active === 'boolean', `active=${status.data.active}`);

  const startNoKey = await post('/api/mission/start', {
    name: 'Arsenal Smoke Mission',
    targets: [{ host: '127.0.0.1' }],
    operators: ['recon', 'analyst'],
  });
  record('Mission start requires configured key or supplied key', startNoKey.status === 400 && /API key required/.test(startNoKey.data.error || ''), summarizeError(startNoKey));

  const operators = await get('/api/operators/list');
  record('Operator list endpoint responds', operators.ok && Array.isArray(operators.data.operators), `${countItems(operators.data.operators)} operators`);

  const spawnNoMission = await post('/api/operators/spawn', { archetype: 'recon', callsign: 'Arsenal-Smoke' });
  record('Operator spawn fails closed without active mission', spawnNoMission.status === 400 && /No active mission/.test(spawnNoMission.data.error || ''), summarizeError(spawnNoMission));

  const taskNoMission = await post('/api/operators/no-such-operator/task', { taskName: 'Smoke task', taskDescription: 'Local no-op smoke.' });
  record('Operator task dispatch fails closed without active mission', taskNoMission.status === 400 && /No active mission/.test(taskNoMission.data.error || ''), summarizeError(taskNoMission));

  const terminateNoMission = await post('/api/operators/terminate', { operatorId: 'no-such-operator' });
  record('Operator terminate fails closed without active mission', terminateNoMission.status === 400 && /No active mission/.test(terminateNoMission.data.error || ''), summarizeError(terminateNoMission));

  const findings = await get('/api/mission/findings');
  record('Mission findings endpoint responds', findings.ok && Array.isArray(findings.data.findings), `${countItems(findings.data.findings)} findings`);

  const pauseNoMission = await post('/api/mission/pause', {});
  record('Mission pause reports no active mission', pauseNoMission.status === 404 && /No active mission/.test(pauseNoMission.data.error || ''), summarizeError(pauseNoMission));

  const resumeNoMission = await post('/api/mission/resume', {});
  record('Mission resume reports no active mission', resumeNoMission.status === 404 && /No active mission/.test(resumeNoMission.data.error || ''), summarizeError(resumeNoMission));

  const stopNoMission = await post('/api/mission/stop', {});
  record('Mission stop reports no active mission', stopNoMission.status === 404 && /No active mission/.test(stopNoMission.data.error || ''), summarizeError(stopNoMission));

  const generalPlanEmpty = await get('/api/general/plan');
  record('General plan endpoint responds without active General', generalPlanEmpty.ok && generalPlanEmpty.data.plan === null, 'plan=null');

  const generalSitreps = await get('/api/general/sitreps');
  record('General sitreps endpoint responds without active General', generalSitreps.ok && Array.isArray(generalSitreps.data.sitreps), `${countItems(generalSitreps.data.sitreps)} sitreps`);

  const generalPlanNoObjective = await post('/api/general/plan', {});
  record('General planner requires objective', generalPlanNoObjective.status === 400 && /Objective required/.test(generalPlanNoObjective.data.error || ''), summarizeError(generalPlanNoObjective));

  const generalPlanNoKey = await post('/api/general/plan', { objective: 'Local-only synthetic planning smoke.' });
  record('General planner requires key before model call', generalPlanNoKey.status === 400 && /API key required/.test(generalPlanNoKey.data.error || ''), summarizeError(generalPlanNoKey));

  const generalExecuteNoPlan = await post('/api/general/execute', {});
  record('General execute fails closed without plan', generalExecuteNoPlan.status === 400 && /No plan available|No General active/.test(generalExecuteNoPlan.data.error || ''), summarizeError(generalExecuteNoPlan));

  const generalAutoNoKey = await post('/api/general/auto', { objective: 'Local-only synthetic auto smoke.' });
  record('General auto requires key before execution', generalAutoNoKey.status === 400 && /API key required/.test(generalAutoNoKey.data.error || ''), summarizeError(generalAutoNoKey));

  const generalSitrepNoGeneral = await post('/api/general/sitrep', {});
  record('General sitrep fails closed without General', generalSitrepNoGeneral.status === 400 && /No active mission|No General active/.test(generalSitrepNoGeneral.data.error || ''), summarizeError(generalSitrepNoGeneral));

  const generalAssessNoGeneral = await post('/api/general/assess', {});
  record('General assess fails closed without General', generalAssessNoGeneral.status === 400 && /No active mission|No General active/.test(generalAssessNoGeneral.data.error || ''), summarizeError(generalAssessNoGeneral));
}

async function main() {
  await smokeCoreSurfaces();
  await smokeArsenalCatalog();
  await smokeKnowledgeAtlas();
  const context = await smokeContractsAndLedgers();
  await smokeImprovementAndLearning(context);
  await smokePlinySpecials();
  await smokeToolsAndRuntime(context);
  await smokeMissionAndGeneralControl();

  const failed = checks.filter(check => !check.passed);
  const byArea = {
    core: checks.filter(check => /^(Health endpoint|API health|Capability preflight|SSE)/.test(check.name)).length,
    arsenal: checks.filter(check => /^(Health exposes arsenal|Arsenal|Web\/API arsenal|Supply-chain arsenal)/.test(check.name)).length,
    knowledge: checks.filter(check => /^(Workflow|Resource|Agent|Operator runbook|Forefront|Operator doctrine|Route scorecard)/.test(check.name)).length,
    contracts: checks.filter(check => /^(Mission draft|Route preview|Mission receipt|Approval|Evidence|Finding|Retest|Repro pack|Pressure path|Pressure canary|Pressure duel|Pressure mutation|Pressure fang|Mission bundle|Mission gate)/.test(check.name)).length,
    learning: checks.filter(check => /^(Improvement|Promotion|Learning|Manual memory|Memory|Repeated)/.test(check.name)).length,
    pliny: checks.filter(check => /^(LEVIATHAN|SPHINX|GORGON|CERBERUS|TYPHON|GRIFFIN|SIMURGH|HYDRA|ARACHNE)/.test(check.name)).length,
    tools: checks.filter(check => /^(Tool|Approved local command|Recon|Private LAN recon|Loopback recon|LLM)/.test(check.name)).length,
    missionControl: checks.filter(check => /^(Mission status|Mission start|Operator|Mission findings|Mission pause|Mission resume|Mission stop|General)/.test(check.name)).length,
  };

  const report = {
    drill: 't3mp3st-full-arsenal-smoke',
    baseUrl,
    startedAt,
    finishedAt: new Date().toISOString(),
    passed: failed.length === 0,
    summary: {
      checks: checks.length,
      passed: checks.length - failed.length,
      failed: failed.length,
      byArea,
      warnings: warnings.length,
    },
    checks,
    warnings,
  };

  console.log(JSON.stringify(report, null, 2));
  if (failed.length) process.exit(1);
}

main().catch(error => {
  console.error(JSON.stringify({
    drill: 't3mp3st-full-arsenal-smoke',
    passed: false,
    error: error.message || String(error),
    checks,
    warnings,
  }, null, 2));
  process.exit(1);
});
