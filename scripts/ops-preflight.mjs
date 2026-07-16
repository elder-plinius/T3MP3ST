#!/usr/bin/env node
import { access, constants } from 'node:fs/promises';
import { posix, resolve, win32 } from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const rawBaseUrl = process.env.T3MP3ST_API_URL || 'http://127.0.0.1:3333';
const jsonMode = process.argv.includes('--json');
const strictMode = process.argv.includes('--strict');
const checks = [];

function check(name, passed, detail = '', severity = 'block') {
  checks.push({ name, passed: Boolean(passed), detail, severity });
}

export function validateBaseUrl(value) {
  try {
    const url = new URL(value);
    const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    const loopbackIpv4 = /^127(?:\.\d{1,3}){3}$/.test(hostname)
      && hostname.split('.').every(part => Number(part) <= 255);
    const loopback = hostname === 'localhost' || hostname === '::1' || loopbackIpv4;
    const rootPath = url.pathname === '' || url.pathname === '/';
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('protocol must be http or https');
    if (!loopback) throw new Error('host must be loopback (localhost, 127.0.0.0/8, or ::1)');
    if (url.username || url.password) throw new Error('credentials are not allowed in the API URL');
    if (!rootPath || url.search || url.hash) throw new Error('API URL must be an origin without a path, query, or fragment');
    return { ok: true, url: url.origin };
  } catch (error) {
    return { ok: false, url: value, error: error instanceof Error ? error.message : String(error) };
  }
}

function commandCandidates(binary, platform, env) {
  const windows = platform === 'win32';
  const pathApi = windows ? win32 : posix;
  const separator = windows ? ';' : ':';
  const pathValue = env.PATH || env.Path || env.path || '';
  const directories = pathValue.split(separator).map(item => item.trim().replace(/^"|"$/g, '')).filter(Boolean);
  const hasExtension = windows && win32.extname(binary) !== '';
  const extensions = windows && !hasExtension
    ? (env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean)
    : [''];
  return directories.flatMap(directory => extensions.map(extension => pathApi.join(directory, `${binary}${extension}`)));
}

export async function commandExists(binary, options = {}) {
  const platform = options.platform || process.platform;
  const env = options.env || process.env;
  const accessFn = options.accessFn || access;
  const mode = platform === 'win32' ? constants.F_OK : constants.X_OK;
  for (const candidate of commandCandidates(binary, platform, env)) {
    try {
      await accessFn(candidate, mode);
      return true;
    } catch {
      // Keep searching PATH candidates.
    }
  }
  return false;
}

async function apiGet(baseUrl, path) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    const response = await fetch(`${baseUrl}${path}`, {
      signal: controller.signal,
      redirect: 'error',
    });
    const text = await response.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }
    return { ok: response.ok, status: response.status, data };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      data: {},
      error: error instanceof Error ? error.message : String(error),
    };
  } finally {
    clearTimeout(timer);
  }
}

function apiFailure(result) {
  if (result.status) return `HTTP ${result.status}`;
  return result.error || 'request failed';
}

function finish(startedAt, baseUrl, forcedPass) {
  const blockers = checks.filter(item => !item.passed && item.severity === 'block');
  const warnings = checks.filter(item => !item.passed && item.severity === 'warn');
  const passed = forcedPass ?? (blockers.length === 0 && (!strictMode || warnings.length === 0));
  const result = {
    tool: 't3mp3st-ops-preflight',
    startedAt,
    finishedAt: new Date().toISOString(),
    baseUrl,
    passed,
    summary: {
      checks: checks.length,
      passed: checks.filter(item => item.passed).length,
      warnings: warnings.length,
      blockers: blockers.length,
      strict: strictMode,
    },
    checks,
  };

  if (jsonMode) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`T3MP3ST ops preflight: ${passed ? 'PASS' : 'FAIL'}`);
    console.log(`${result.summary.passed}/${result.summary.checks} checks passed, ${warnings.length} warning(s), ${blockers.length} blocker(s)`);
    for (const item of checks) {
      const marker = item.passed ? 'ok' : item.severity === 'warn' ? 'warn' : 'block';
      console.log(`- ${marker.padEnd(5)} ${item.name}${item.detail ? ` - ${item.detail}` : ''}`);
    }
  }

  process.exitCode = passed ? 0 : 1;
  return result;
}

export async function main() {
  const startedAt = new Date().toISOString();
  const baseUrlResult = validateBaseUrl(rawBaseUrl);
  check('Local API URL', baseUrlResult.ok, baseUrlResult.ok ? baseUrlResult.url : baseUrlResult.error, 'block');
  if (!baseUrlResult.ok) return finish(startedAt, rawBaseUrl, false);
  const baseUrl = baseUrlResult.url;

  const health = await apiGet(baseUrl, '/health');
  const apiReachable = health.ok;
  check('API health endpoint', apiReachable,
    apiReachable ? `HTTP ${health.status}` : `${apiFailure(health)} - run npm run server`, 'block');

  if (!apiReachable) {
    check('Node runtime', true, `${process.execPath} (${process.version})`, 'warn');
    const npmAvailable = Boolean(process.env.npm_execpath) || await commandExists('npm');
    check('npm available', npmAvailable, npmAvailable ? 'available' : 'not found on PATH', 'warn');
    return finish(startedAt, baseUrl, false);
  }

  check('API reports operational', health.data?.status === 'operational',
    `status: ${health.data?.status || 'unknown'}`, 'block');

  const mission = await apiGet(baseUrl, '/api/mission/status');
  const missionShapeValid = mission.ok && typeof mission.data?.active === 'boolean';
  check('Mission status available', missionShapeValid,
    missionShapeValid ? 'verified' : mission.ok ? 'invalid response shape' : apiFailure(mission), 'block');
  if (missionShapeValid) {
    const missionActive = mission.data.active === true;
    const activeMission = mission.data.mission || {};
    const activeDetail = [
      `mission ${activeMission.id || mission.data.name || 'unknown'}`,
      activeMission.currentPhase ? `phase ${activeMission.currentPhase}` : '',
    ].filter(Boolean).join(', ');
    check('No active mission in progress', !missionActive, missionActive ? activeDetail : 'idle', 'block');
  }

  const approvals = await apiGet(baseUrl, '/api/approvals?status=pending');
  const approvalsShapeValid = approvals.ok && Array.isArray(approvals.data?.approvals);
  check('Approval receipt status available', approvalsShapeValid,
    approvalsShapeValid ? 'verified' : approvals.ok ? 'invalid response shape' : apiFailure(approvals), 'block');
  if (approvalsShapeValid) {
    const pendingCount = approvals.data.approvals.length;
    check('No pending action receipts', pendingCount === 0,
      pendingCount > 0 ? `${pendingCount} pending approval(s) - review before launch` : 'none pending', 'warn');
  }

  const llmStatus = health.data?.llm;
  const serverBackendAvailable = llmStatus?.configured === true || llmStatus?.connected === true;
  const localAgent = await apiGet(baseUrl, '/api/agents/local/status');
  const localAgentShapeValid = localAgent.ok && Array.isArray(localAgent.data?.connected);
  const connectedAgents = localAgentShapeValid ? localAgent.data.connected : [];
  const backendAvailable = serverBackendAvailable || connectedAgents.length > 0;
  let backendDetail;
  if (serverBackendAvailable) {
    backendDetail = `${llmStatus.provider || 'server'} backend ${llmStatus.connected ? 'connected' : 'configured'}`;
  } else if (connectedAgents.length > 0) {
    const firstAgent = connectedAgents[0];
    backendDetail = `${firstAgent.name || firstAgent.id || 'local agent'} connected`;
  } else if (!localAgentShapeValid) {
    backendDetail = `server LLM unavailable; local-agent status ${localAgent.ok ? 'has invalid shape' : apiFailure(localAgent)}`;
  } else {
    backendDetail = 'no server LLM or connected local agent - configure War Room Settings';
  }
  check('LLM backend available', backendAvailable, backendDetail, 'warn');

  const arsenal = await apiGet(baseUrl, '/api/arsenal/status');
  const arsenalShapeValid = arsenal.ok
    && Number.isFinite(arsenal.data?.summary?.installedCommandReady)
    && Number.isFinite(arsenal.data?.summary?.commandReady);
  check('Arsenal status available', arsenalShapeValid,
    arsenalShapeValid ? 'verified' : arsenal.ok ? 'invalid response shape' : apiFailure(arsenal), 'warn');
  if (arsenalShapeValid) {
    const installed = arsenal.data.summary.installedCommandReady;
    const total = arsenal.data.summary.commandReady;
    check('Arsenal tools available', installed > 0,
      `${installed}/${total} command-ready tools installed`, 'warn');
  }

  return finish(startedAt, baseUrl);
}

const invokedAsScript = process.argv[1]
  && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invokedAsScript) {
  main().catch(error => {
    console.error(`ops-preflight failed: ${error?.stack || error?.message || error}`);
    process.exitCode = 1;
  });
}
