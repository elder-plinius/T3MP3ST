#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { commandExists, validateBaseUrl } from './ops-preflight.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const preflightPath = join(scriptDir, 'ops-preflight.mjs');
let passed = 0;
let failed = 0;

function healthyRoutes(overrides = {}) {
  return {
    '/health': {
      status: 'operational',
      llm: { configured: true, connected: true, provider: 'mock' },
    },
    '/api/mission/status': { active: false, progress: [], tasks: [] },
    '/api/approvals?status=pending': { approvals: [] },
    '/api/agents/local/status': { connected: [] },
    '/api/arsenal/status': {
      summary: { installedCommandReady: 2, commandReady: 4 },
    },
    ...overrides,
  };
}

async function withServer(routes, fn) {
  const server = createServer((req, res) => {
    const route = routes[req.url];
    if (!route) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
      return;
    }
    const status = route.httpStatus || 200;
    const headers = { 'content-type': 'application/json', ...(route.headers || {}) };
    res.writeHead(status, headers);
    res.end(route.raw ?? JSON.stringify(route.body ?? route));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  const url = `http://127.0.0.1:${address.port}`;
  try {
    return await fn(url);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

function runPreflight(baseUrl, args = []) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [preflightPath, '--json', ...args], {
      env: { ...process.env, T3MP3ST_API_URL: baseUrl },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', code => {
      let result;
      try {
        result = JSON.parse(stdout);
      } catch (error) {
        reject(new Error(`invalid JSON output (exit ${code}): ${error.message}\nstdout=${stdout}\nstderr=${stderr}`));
        return;
      }
      resolve({ code, result, stderr });
    });
  });
}

function findCheck(result, name) {
  const item = result.checks.find(check => check.name === name);
  assert(item, `missing check: ${name}`);
  return item;
}

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  OK ${name}`);
  } catch (error) {
    failed++;
    console.error(`  FAIL ${name}: ${error.stack || error.message || error}`);
  }
}

console.log('\n======== ops preflight tests ========\n');

await test('accepts loopback origins and rejects non-local or credentialed URLs', async () => {
  assert.equal(validateBaseUrl('http://127.0.0.1:3333').ok, true);
  assert.equal(validateBaseUrl('https://localhost:3333/').ok, true);
  assert.equal(validateBaseUrl('http://[::1]:3333').ok, true);
  assert.equal(validateBaseUrl('https://example.com').ok, false);
  assert.equal(validateBaseUrl('https://127.example.com').ok, false);
  assert.equal(validateBaseUrl('http://user:secret@127.0.0.1:3333').ok, false);
  assert.equal(validateBaseUrl('http://127.0.0.1:3333/api').ok, false);
});

await test('resolves command candidates portably without invoking a shell', async () => {
  const windowsAttempts = [];
  const windowsFound = await commandExists('npm', {
    platform: 'win32',
    env: { PATH: 'C:\\Tools;D:\\Node', PATHEXT: '.EXE;.CMD' },
    accessFn: async candidate => {
      windowsAttempts.push(candidate);
      if (candidate.toLowerCase() === 'd:\\node\\npm.cmd') return;
      throw new Error('missing');
    },
  });
  assert.equal(windowsFound, true);
  assert(windowsAttempts.some(candidate => candidate.toLowerCase() === 'd:\\node\\npm.cmd'));

  const posixFound = await commandExists('npm', {
    platform: 'linux',
    env: { PATH: '/usr/bin:/opt/node/bin' },
    accessFn: async candidate => {
      if (candidate === '/opt/node/bin/npm') return;
      throw new Error('missing');
    },
  });
  assert.equal(posixFound, true);
});

await test('passes a healthy idle War Room using server-authoritative backend state', async () => {
  await withServer(healthyRoutes(), async url => {
    const { code, result, stderr } = await runPreflight(url);
    assert.equal(stderr, '');
    assert.equal(code, 0);
    assert.equal(result.passed, true);
    assert.equal(findCheck(result, 'LLM backend available').passed, true);
    assert.equal(findCheck(result, 'No active mission in progress').detail, 'idle');
  });
});

await test('blocks an active mission and reports current nested mission fields', async () => {
  const routes = healthyRoutes({
    '/api/mission/status': {
      active: true,
      mission: { id: 'mission-123', currentPhase: 'recon' },
    },
  });
  await withServer(routes, async url => {
    const { code, result } = await runPreflight(url);
    assert.equal(code, 1);
    const item = findCheck(result, 'No active mission in progress');
    assert.equal(item.passed, false);
    assert.match(item.detail, /mission-123/);
    assert.match(item.detail, /recon/);
  });
});

await test('warns for pending approvals and strict mode fails the warning', async () => {
  const routes = healthyRoutes({
    '/api/approvals?status=pending': { approvals: [{ id: 'approval-1' }] },
  });
  await withServer(routes, async url => {
    const normal = await runPreflight(url);
    assert.equal(normal.code, 0);
    assert.equal(findCheck(normal.result, 'No pending action receipts').passed, false);
    const strict = await runPreflight(url, ['--strict']);
    assert.equal(strict.code, 1);
    assert.equal(strict.result.passed, false);
  });
});

await test('blocks when mission state cannot be verified', async () => {
  const routes = healthyRoutes({
    '/api/mission/status': { httpStatus: 503, body: { error: 'unavailable' } },
  });
  await withServer(routes, async url => {
    const { code, result } = await runPreflight(url);
    assert.equal(code, 1);
    assert.equal(findCheck(result, 'Mission status available').passed, false);
  });
});

await test('blocks when approval state is malformed instead of assuming zero', async () => {
  const routes = healthyRoutes({
    '/api/approvals?status=pending': { total: 0 },
  });
  await withServer(routes, async url => {
    const { code, result } = await runPreflight(url);
    assert.equal(code, 1);
    assert.equal(findCheck(result, 'Approval receipt status available').passed, false);
  });
});

await test('uses health LLM state when the local-agent endpoint is unavailable', async () => {
  const routes = healthyRoutes({
    '/api/agents/local/status': { httpStatus: 500, body: { error: 'unavailable' } },
  });
  await withServer(routes, async url => {
    const { code, result } = await runPreflight(url);
    assert.equal(code, 0);
    assert.equal(findCheck(result, 'LLM backend available').passed, true);
  });
});

await test('reports a missing backend and strict mode treats it as a failure', async () => {
  const routes = healthyRoutes({
    '/health': {
      status: 'operational',
      llm: { configured: false, connected: false, provider: 'openrouter' },
    },
  });
  await withServer(routes, async url => {
    const normal = await runPreflight(url);
    assert.equal(normal.code, 0);
    assert.equal(findCheck(normal.result, 'LLM backend available').passed, false);
    const strict = await runPreflight(url, ['--strict']);
    assert.equal(strict.code, 1);
  });
});

await test('reports arsenal endpoint failure and strict mode treats it as a failure', async () => {
  const routes = healthyRoutes({
    '/api/arsenal/status': { httpStatus: 500, body: { error: 'unavailable' } },
  });
  await withServer(routes, async url => {
    const normal = await runPreflight(url);
    assert.equal(normal.code, 0);
    assert.equal(findCheck(normal.result, 'Arsenal status available').passed, false);
    const strict = await runPreflight(url, ['--strict']);
    assert.equal(strict.code, 1);
  });
});

await test('rejects a non-loopback API URL before making a request', async () => {
  const { code, result } = await runPreflight('https://example.com');
  assert.equal(code, 1);
  assert.equal(result.checks.length, 1);
  assert.equal(findCheck(result, 'Local API URL').passed, false);
});

console.log(`\n======== ${failed ? `${failed} FAILED` : 'ALL PASS'} (${passed} passed) ========\n`);
if (failed) process.exitCode = 1;
