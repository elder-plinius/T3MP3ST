#!/usr/bin/env node
import { access, readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import process from 'node:process';

const execFileAsync = promisify(execFile);
const baseUrl = (process.env.T3MP3ST_API_URL || 'http://127.0.0.1:3333').replace(/\/$/, '');
const jsonMode = process.argv.includes('--json');
const strictMode = process.argv.includes('--strict');
const checks = [];

function check(name, passed, detail = '', severity = 'block') {
  checks.push({ name, passed: Boolean(passed), detail, severity });
}

async function fileExists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function commandPath(binary) {
  try {
    const { stdout } = await execFileAsync('which', [binary], { timeout: 1500 });
    return stdout.trim();
  } catch {
    return '';
  }
}

async function apiGet(path) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 2500);
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
  } finally {
    clearTimeout(timer);
  }
}

function scriptExists(pkg, scriptName) {
  return Boolean(pkg.scripts && pkg.scripts[scriptName]);
}

async function main() {
  const startedAt = new Date().toISOString();
  const major = Number(process.versions.node.split('.')[0]);
  check('Node runtime is supported', major >= 18, `node ${process.version}`);

  const packageJsonExists = await fileExists('package.json');
  check('package.json exists', packageJsonExists);
  const pkg = packageJsonExists ? JSON.parse(await readFile('package.json', 'utf8')) : {};
  for (const script of ['doctor', 'server', 'typecheck', 'test', 'arsenal:smoke', 'field:drill', 'exploit:smoke', 'prompt:audit']) {
    check(`npm script: ${script}`, scriptExists(pkg, script), pkg.scripts?.[script] || 'missing');
  }

  const requiredFiles = [
    'README.md',
    'SECURITY.md',
    'CONTRIBUTING.md',
    'docs/index.html',
    'docs/TEAM_PREVIEW.md',
    'docs/ARSENAL_ACTIVATION_PLAN.md',
    'docs/INSTALL_MATRIX.md',
    'docs/SCOPE_AND_AUTHORIZATION.md',
    'examples/demo-missions.json',
    'src/server.ts',
    'src/arsenal/catalog.ts',
  ];
  for (const file of requiredFiles) {
    check(`file: ${file}`, await fileExists(file), '', file.startsWith('docs/') || file.startsWith('examples/') ? 'warn' : 'block');
  }

  const commandChecks = [
    ['git', 'required for provenance'],
    ['node', 'required runtime'],
    ['npm', 'required package manager'],
    ['file', 'core evidence tool'],
    ['curl', 'core HTTP tool'],
    ['dig', 'DNS evidence tool'],
    ['whois', 'OSINT evidence tool'],
    ['nmap', 'optional high-value recon'],
    ['nuclei', 'optional high-value scanner'],
    ['semgrep', 'optional supply-chain scanner'],
    ['promptfoo', 'optional AI eval runner'],
  ];
  for (const [binary, detail] of commandChecks) {
    const path = await commandPath(binary);
    const required = ['git', 'node', 'npm', 'file', 'curl'].includes(binary);
    check(`command: ${binary}`, Boolean(path), path || `missing - ${detail}`, required ? 'block' : 'warn');
  }

  let apiReachable = false;
  try {
    const health = await apiGet('/health');
    apiReachable = health.ok;
    check('API health endpoint', health.ok && health.data.status === 'operational', `${health.status} ${health.data.status || 'unknown'}`);
    if (health.ok) {
      check('API exposes mission dispatch', health.data.missionDispatch === true, String(health.data.missionDispatch));
      check('API exposes resources', Number(health.data.resources?.packs || 0) >= 10, `${health.data.resources?.packs || 0} packs`);
      check('API exposes arsenal', Number(health.data.arsenal?.total || 0) >= 40, `${health.data.arsenal?.total || 0} adapters / ${health.data.arsenal?.commandReady || 0} command-ready`);
    }
  } catch (error) {
    check('API health endpoint', false, `offline - run npm run server for live API checks (${error.name || 'error'})`, 'warn');
  }

  if (apiReachable) {
    const preflight = await apiGet('/api/preflight');
    check('Capability preflight', preflight.ok && typeof preflight.data.score === 'number', `${preflight.data.score ?? 'n/a'}/100`);
    const arsenal = await apiGet('/api/arsenal/status');
    check('Arsenal status', arsenal.ok && arsenal.data.schema_version === 'plinyos.t3mp3st_arsenal_status/v1', `${arsenal.data.summary?.installedCommandReady ?? 0}/${arsenal.data.summary?.commandReady ?? 0} installed`);
    check('Arsenal does not fake empty coverage', arsenal.ok && arsenal.data.summary?.unmodeled === false, `unmodeled=${arsenal.data.summary?.unmodeled}`);
    const activation = await apiGet('/api/arsenal/activation');
    check('Arsenal activation plan', activation.ok && activation.data.schema_version === 'plinyos.t3mp3st_arsenal_activation/v1', `${activation.data.summary?.total || 0} wired / doc ${activation.data.localPlanDoc || 'missing'}`);
  }

  const blocks = checks.filter(item => !item.passed && item.severity === 'block');
  const warnings = checks.filter(item => !item.passed && item.severity === 'warn');
  const result = {
    tool: 't3mp3st-doctor',
    startedAt,
    finishedAt: new Date().toISOString(),
    baseUrl,
    passed: blocks.length === 0 && (!strictMode || warnings.length === 0),
    summary: {
      checks: checks.length,
      passed: checks.filter(item => item.passed).length,
      warnings: warnings.length,
      blockers: blocks.length,
      strict: strictMode,
    },
    checks,
  };

  if (jsonMode) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`T3MP3ST doctor: ${result.passed ? 'PASS' : 'CHECK REQUIRED'}`);
    console.log(`${result.summary.passed}/${result.summary.checks} checks passed, ${result.summary.warnings} warning(s), ${result.summary.blockers} blocker(s)`);
    for (const item of checks) {
      const marker = item.passed ? 'ok' : item.severity === 'warn' ? 'warn' : 'block';
      console.log(`- ${marker.padEnd(5)} ${item.name}${item.detail ? ` - ${item.detail}` : ''}`);
    }
  }

  process.exitCode = result.passed ? 0 : 1;
}

main().catch(error => {
  console.error(`doctor failed: ${error.stack || error.message || error}`);
  process.exitCode = 1;
});
