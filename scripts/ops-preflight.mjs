#!/usr/bin/env node
import process from 'node:process';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const baseUrl = (process.env.T3MP3ST_API_URL || 'http://127.0.0.1:3333').replace(/\/$/, '');
const jsonMode = process.argv.includes('--json');
const strictMode = process.argv.includes('--strict');
const checks = [];

function check(name, passed, detail = '', severity = 'block') {
  checks.push({ name, passed: Boolean(passed), detail, severity });
}

async function apiGet(path) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    const response = await fetch(`${baseUrl}${path}`, { signal: controller.signal });
    const text = await response.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }
    return { ok: response.ok, status: response.status, data };
  } catch (err) {
    return { ok: false, status: 0, data: {}, error: err.message };
  } finally {
    clearTimeout(timer);
  }
}

async function commandExists(binary) {
  try {
    await execFileAsync('which', [binary], { timeout: 1500 });
    return true;
  } catch {
    return false;
  }
}

async function main() {
  const startedAt = new Date().toISOString();

  // 1. War Room API health
  const health = await apiGet('/health');
  const apiReachable = health.ok;
  check('API health endpoint', apiReachable,
    apiReachable ? `${health.status} ${health.data.status || 'operational'}` : `offline - run npm run server`,
    apiReachable ? 'warn' : 'block');

  if (!apiReachable) {
    const hasDoctor = await commandExists('node');
    check('Node runtime', hasDoctor, hasDoctor ? 'available' : 'missing');
    const hasNpm = await commandExists('npm');
    check('npm available', hasNpm, hasNpm ? 'available' : 'missing');

    const result = {
      tool: 't3mp3st-ops-preflight',
      startedAt,
      finishedAt: new Date().toISOString(),
      baseUrl,
      passed: false,
      summary: {
        checks: checks.length,
        passed: checks.filter(c => c.passed).length,
        warnings: checks.filter(c => !c.passed && c.severity === 'warn').length,
        blockers: checks.filter(c => !c.passed && c.severity === 'block').length,
      },
      checks,
    };

    if (jsonMode) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(`T3MP3ST ops preflight: FAIL (API unreachable)`);
      for (const c of checks) {
        const m = c.passed ? 'ok' : c.severity === 'warn' ? 'warn' : 'block';
        console.log(`- ${m.padEnd(5)} ${c.name}${c.detail ? ` - ${c.detail}` : ''}`);
      }
    }
    process.exitCode = 1;
    return;
  }

  check('API reports operational', health.data.status === 'operational',
    `status: ${health.data.status || 'unknown'}`, 'block');

  // 2. Mission status — fail if a mission is already active
  const mission = await apiGet('/api/mission/status');
  const missionActive = mission.ok && mission.data?.phase && mission.data.phase !== 'idle' && mission.data.phase !== 'completed';
  check('No active mission in progress', !missionActive,
    missionActive ? `mission ${mission.data.id || 'unknown'} in phase: ${mission.data.phase}` : 'idle',
    'block');

  // 3. Pending approvals — warn if pending receipts exist
  const approvals = await apiGet('/api/approvals?status=pending');
  let pendingCount = 0;
  if (approvals.ok) {
    pendingCount = Array.isArray(approvals.data) ? approvals.data.length : approvals.data?.total || 0;
  }
  check('No pending action receipts', pendingCount === 0,
    pendingCount > 0 ? `${pendingCount} pending approval(s) — review before launch` : 'none pending',
    pendingCount > 0 ? 'warn' : 'warn');

  // 4. Local agent / API provider availability
  if (process.env.OPENROUTER_API_KEY || process.env.ANTHROPIC_API_KEY || process.env.OPENAI_API_KEY || process.env.XAI_API_KEY) {
    check('API provider configured', true, 'key-based provider detected', 'warn');
  } else {
    const localAgent = await apiGet('/api/agents/local/status');
    if (localAgent.ok && localAgent.data?.connected) {
      check('Local agent connected', true, `${localAgent.data.name || 'agent'} connected`, 'warn');
    } else {
      check('Local agent or API key configured', false,
        'no API key set and local agent not connected — configure in War Room Settings',
        strictMode ? 'block' : 'warn');
    }
  }

  // 5. Arsenal tool availability
  const arsenal = await apiGet('/api/arsenal/status');
  if (arsenal.ok && arsenal.data) {
    const installed = arsenal.data.summary?.installedCommandReady ?? 0;
    const total = arsenal.data.summary?.commandReady ?? 0;
    check('Arsenal tools available', installed > 0,
      `${installed}/${total} command-ready tools installed`, 'warn');
  }

  const blockers = checks.filter(c => !c.passed && c.severity === 'block');
  const warnings = checks.filter(c => !c.passed && c.severity === 'warn');
  const overallPass = blockers.length === 0 && (!strictMode || warnings.length === 0);

  const result = {
    tool: 't3mp3st-ops-preflight',
    startedAt,
    finishedAt: new Date().toISOString(),
    baseUrl,
    passed: overallPass,
    summary: {
      checks: checks.length,
      passed: checks.filter(c => c.passed).length,
      warnings: warnings.length,
      blockers: blockers.length,
      strict: strictMode,
    },
    checks,
  };

  if (jsonMode) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`T3MP3ST ops preflight: ${overallPass ? 'PASS' : 'FAIL'}`);
    console.log(`${result.summary.passed}/${result.summary.checks} checks passed, ${result.summary.warnings} warning(s), ${result.summary.blockers} blocker(s)`);
    for (const c of checks) {
      const m = c.passed ? 'ok' : c.severity === 'warn' ? 'warn' : 'block';
      console.log(`- ${m.padEnd(5)} ${c.name}${c.detail ? ` - ${c.detail}` : ''}`);
    }
  }

  process.exitCode = overallPass ? 0 : 1;
}

main().catch(err => {
  console.error(`ops-preflight failed: ${err.stack || err.message || err}`);
  process.exitCode = 1;
});
