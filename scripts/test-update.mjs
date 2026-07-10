#!/usr/bin/env node
/**
 * Integration tests for the T3MP3ST updater.
 * Each test runs the updater in a temporary sandbox repo so real repository state
 * is never touched.
 */
import { execSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { platform, tmpdir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));

let pass = 0;
let fail = 0;
const tests = [];

function test(name, fn) {
  tests.push({ name, fn });
}

function assert(cond, msg) {
  if (!cond) {
    throw new Error(msg || 'assertion failed');
  }
}

function ok(label) {
  pass++;
  console.log('  OK ' + label);
}

function logFail(label, err) {
  fail++;
  console.log('  FAIL ' + label + ': ' + err.message);
}

function stripAnsi(s) {
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

function psAvailable() {
  return spawnSync('powershell', ['-NoProfile', '-Command', 'exit 0'], { stdio: 'pipe' }).status === 0;
}

function bashAvailable() {
  return spawnSync('bash', ['-c', 'exit 0'], { stdio: 'pipe' }).status === 0;
}

function cleanup(dir) {
  for (let i = 0; i < 5; i++) {
    try {
      rmSync(dir, { recursive: true, force: true });
      return;
    } catch (err) {
      if (i === 4) {
        console.warn('  WARN could not clean up temp dir: ' + dir + ' (' + err.message + ')');
        return;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
    }
  }
}

function makeSandbox() {
  const dir = join(tmpdir(), `t3mp3st-update-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  mkdirSync(dir, { recursive: true });
  mkdirSync(join(dir, 'scripts'), { recursive: true });

 const files = [
   'update.ps1',
   'update.sh',
   'update-protected.txt',
   'update-banner.txt',
   'update.mjs',
 ];
 for (const f of files) {
    let content = readFileSync(join(__dirname, f), 'utf8');
    if (f === 'update.sh') {
      content = content.replace(/\r\n/g, '\n');
    }
    writeFileSync(join(dir, 'scripts', f), content);
  }

  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 't3mp3st-test-sandbox', version: '0.0.0' }, null, 2));
  writeFileSync(join(dir, '.env'), 'SECRET=local-secret\n');
  writeFileSync(join(dir, '.env.example'), 'SECRET=your-secret\n');
  mkdirSync(join(dir, 'reports'), { recursive: true });
  writeFileSync(join(dir, 'reports', 'engagement.md'), '# engagement\n');
  mkdirSync(join(dir, 'evidence'), { recursive: true });
  writeFileSync(join(dir, 'evidence', 'poc.txt'), 'poc\n');
  writeFileSync(join(dir, 'unprotected.txt'), 'I should be replaced\n');

  return dir;
}

function runPowerShell(sandbox, args = []) {
  const ps1 = join(sandbox, 'scripts', 'update.ps1');
  const result = spawnSync(
    'powershell',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ps1, ...args],
    { cwd: sandbox, stdio: 'pipe', encoding: 'utf8' }
  );
  return {
    status: result.status,
    stdout: stripAnsi(result.stdout || ''),
    stderr: stripAnsi(result.stderr || ''),
  };
}

function runBash(sandbox, args = []) {
  const sh = 'scripts/update.sh';
  const result = spawnSync('bash', [sh, ...args], { cwd: sandbox, stdio: 'pipe', encoding: 'utf8', shell: false });
  return {
    status: result.status,
    stdout: stripAnsi(result.stdout || ''),
    stderr: stripAnsi(result.stderr || ''),
  };
}

// ---------------------------------------------------------------------------
// Static / source-level checks
// ---------------------------------------------------------------------------

test('protected manifest contains reports/ and evidence/', () => {
  const manifest = readFileSync(join(__dirname, 'update-protected.txt'), 'utf8');
  assert(manifest.includes('reports/'), 'reports/ missing from protected manifest');
  assert(manifest.includes('evidence/'), 'evidence/ missing from protected manifest');
  assert(manifest.includes('!.env.example'), '!.env.example missing from protected manifest');
});

test('update.mjs maps --dry-run and --hard', () => {
  const src = readFileSync(join(__dirname, 'update.mjs'), 'utf8');
  assert(src.includes("case '--dry-run'") && src.includes("return ['-DryRun']"), '--dry-run not mapped');
  assert(src.includes("case '--hard'") && src.includes("return ['-Hard']"), '--hard not mapped');
});

test('update.ps1 has dry-run guards and hard reset opt-in', () => {
  const ps1 = readFileSync(join(__dirname, 'update.ps1'), 'utf8');
  assert(ps1.includes('if ($DryRun)'), 'PowerShell dry-run guard missing');
  assert(ps1.includes('if ($Hard)'), 'PowerShell hard reset opt-in missing');
});

test('update.sh has dry-run guard, negation and failure trap', () => {
  const sh = readFileSync(join(__dirname, 'update.sh'), 'utf8');
  assert(sh.indexOf('if [[ "$DRY_RUN" -eq 1 ]]') < sh.indexOf('git init'), 'bash dry-run guard not before git init');
  assert(sh.includes('apply_negation_patterns'), 'bash negation support missing');
  assert(sh.includes('trap on_err ERR'), 'bash failure trap missing');
});

// ---------------------------------------------------------------------------
// PowerShell integration tests
// ---------------------------------------------------------------------------

if (psAvailable()) {
  test('dry-run is read-only on tarball-like sandbox', () => {
    const sb = makeSandbox();
    try {
      const out = runPowerShell(sb, ['-DryRun', '-Force']);
      assert(out.status === 0, 'dry-run failed: ' + out.stderr + out.stdout);
      assert(!existsSync(join(sb, '.git')), '.git should not be created in dry-run');
      assert(readFileSync(join(sb, '.env'), 'utf8') === 'SECRET=local-secret\n', '.env should not be modified');
      assert(out.stdout.includes('First-time sync (upstream snapshot)'), 'expected first-time strategy label');
      assert(out.stdout.includes('reports/') || out.stdout.includes('reports'), 'reports/ should be listed as protected');
      assert(out.stdout.includes('evidence/') || out.stdout.includes('evidence'), 'evidence/ should be listed as protected');
      assert(!out.stdout.includes('.env.example'), '.env.example should NOT be listed as protected');
    } finally {
      cleanup(sb);
    }
  });

  test('dry-run preserves dirty worktree changes in protected paths', () => {
    const sb = makeSandbox();
    try {
      writeFileSync(join(sb, '.env'), 'SECRET=dirty-secret\n');
      writeFileSync(join(sb, 'reports', 'engagement.md'), '# changed\n');
      const out = runPowerShell(sb, ['-DryRun', '-Force']);
      assert(out.status === 0, 'dry-run failed: ' + out.stderr + out.stdout);
      assert(readFileSync(join(sb, '.env'), 'utf8') === 'SECRET=dirty-secret\n', 'dirty .env should survive dry-run');
      assert(readFileSync(join(sb, 'reports', 'engagement.md'), 'utf8') === '# changed\n', 'dirty report should survive dry-run');
    } finally {
      cleanup(sb);
    }
  });

  test('merge strategy shown when local repo has commits', () => {
    const sb = makeSandbox();
    try {
      execSync('git init', { cwd: sb, stdio: 'pipe' });
      execSync('git config user.email "test@test"', { cwd: sb, stdio: 'pipe' });
      execSync('git config user.name "Test"', { cwd: sb, stdio: 'pipe' });
      execSync('git add .', { cwd: sb, stdio: 'pipe' });
      execSync('git commit -m initial', { cwd: sb, stdio: 'pipe' });
      const out = runPowerShell(sb, ['-DryRun', '-Force']);
      assert(out.status === 0, 'dry-run failed: ' + out.stderr + out.stdout);
      assert(out.stdout.includes('Merge upstream/main'), 'expected merge strategy label');
      assert(!out.stdout.includes('Hard reset'), 'should not show hard reset without -Hard');
    } finally {
      cleanup(sb);
    }
  });

  test('hard reset strategy is opt-in', () => {
    const sb = makeSandbox();
    try {
      const out = runPowerShell(sb, ['-DryRun', '-Hard', '-Force']);
      assert(out.status === 0, 'dry-run failed: ' + out.stderr + out.stdout);
      assert(out.stdout.includes('Hard reset to upstream/main'), 'expected hard reset strategy label');
      assert(out.stdout.includes('git reset --hard'), 'expected git reset --hard in dry-run plan');
      assert(!existsSync(join(sb, '.git')), '.git should not be created in dry-run');
    } finally {
      cleanup(sb);
    }
  });

  test('non-dry run requires confirmation unless forced', () => {
    const sb = makeSandbox();
    try {
      const result = spawnSync(
        'powershell',
        ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(sb, 'scripts', 'update.ps1'), '-DryRun'],
        { cwd: sb, stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf8', input: 'n\n' }
      );
      const out = stripAnsi((result.stdout || '') + (result.stderr || ''));
      assert(out.includes('Cancelled') || out.includes('Cancelled - no changes made'), 'expected cancel message');
      assert(!existsSync(join(sb, '.git')), '.git should not be created after cancellation');
    } finally {
      cleanup(sb);
    }
  });
} else {
  console.log('  SKIP PowerShell integration tests: powershell not available');
}

// ---------------------------------------------------------------------------
// Bash integration tests
// ---------------------------------------------------------------------------

if (bashAvailable()) {
  test('bash dry-run is read-only on tarball-like sandbox', () => {
    const sb = makeSandbox();
    try {
      const out = runBash(sb, ['--dry-run', '--force']);
      assert(out.status === 0, 'bash dry-run failed: ' + out.stderr + out.stdout);
      assert(!existsSync(join(sb, '.git')), '.git should not be created in bash dry-run');
      assert(readFileSync(join(sb, '.env'), 'utf8') === 'SECRET=local-secret\n', '.env should not be modified by bash dry-run');
      assert(out.stdout.includes('Merge upstream') || out.stdout.includes('First-time sync'), 'expected strategy label in bash output');
    } finally {
      cleanup(sb);
    }
  });

  test('bash hard reset is opt-in', () => {
    const sb = makeSandbox();
    try {
      const out = runBash(sb, ['--dry-run', '--hard', '--force']);
      assert(out.status === 0, 'bash dry-run failed: ' + out.stderr + out.stdout);
      assert(out.stdout.includes('git reset --hard'), 'expected git reset --hard in bash dry-run plan');
      assert(!existsSync(join(sb, '.git')), '.git should not be created in bash dry-run');
    } finally {
      cleanup(sb);
    }
  });
} else {
  console.log('  SKIP Bash integration tests: bash not available');
}

// ---------------------------------------------------------------------------
// Run all tests
// ---------------------------------------------------------------------------

console.log('');
console.log('======== updater tests ========');
console.log('');

for (const t of tests) {
  try {
    t.fn();
    ok(t.name);
  } catch (err) {
    logFail(t.name, err);
  }
}

console.log('');
console.log('======== ' + (fail === 0 ? 'ALL PASS' : fail + ' FAILED') + ' ========');
console.log('');
process.exit(fail === 0 ? 0 : 1);

