#!/usr/bin/env node
// Exercise the built server without importing operator settings or credentials.
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
const children = new Set();
const abort = new AbortController();
const interrupt = signal => abort.abort(new Error(`Release smoke interrupted by ${signal}`));
const onInt = () => interrupt('SIGINT');
const onTerm = () => interrupt('SIGTERM');

function launch(args, cwd, env, stdio) {
  const child = spawn(process.execPath, args, {
    cwd, env, stdio, detached: process.platform !== 'win32',
  });
  const done = new Promise(resolve => {
    child.once('error', error => resolve({ error }));
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
  const entry = { child, done, result: null };
  done.then(result => { entry.result = result; });
  children.add(entry);
  return entry;
}

function kill(entry, signal) {
  if (!entry.child.pid) return;
  try {
    if (process.platform === 'win32') entry.child.kill(signal);
    else process.kill(-entry.child.pid, signal);
  } catch (error) {
    if (error.code !== 'ESRCH') throw error;
  }
}

async function stop(entry) {
  kill(entry, 'SIGTERM');
  await Promise.race([entry.done, delay(2000)]);
  // Also reap descendant commands, even when the direct child already exited.
  kill(entry, 'SIGKILL');
  await entry.done;
  children.delete(entry);
}

async function availablePort() {
  const reservation = createServer();
  reservation.listen(0, '127.0.0.1');
  await once(reservation, 'listening');
  const port = reservation.address().port;
  await new Promise((resolve, reject) => reservation.close(error => error ? reject(error) : resolve()));
  return port;
}

function serverAlive(server) {
  if (server.result) throw new Error(`Dedicated server exited: ${JSON.stringify(server.result)}`);
  abort.signal.throwIfAborted();
}

async function waitForHealth(server, base) {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    serverAlive(server);
    try {
      const response = await fetch(`${base}/health`, { signal: AbortSignal.timeout(1000) });
      const health = await response.json();
      if (response.ok && health.status === 'operational') {
        // A different listener winning the ephemeral-port race must not hide a failed spawn.
        await delay(100, undefined, { signal: abort.signal });
        serverAlive(server);
        return;
      }
    } catch { /* Retry only while our server remains alive and the deadline allows it. */ }
    await delay(100, undefined, { signal: abort.signal });
  }
  throw new Error(`Dedicated server did not become healthy within 30 seconds: ${base}`);
}

async function runProbe(server, args, cwd, env) {
  serverAlive(server);
  console.log(`\nRelease smoke: ${args.join(' ')}`);
  const probe = launch([join(repo, 'scripts', args[0]), ...args.slice(1)], cwd, env, 'inherit');
  const timeout = AbortSignal.timeout(120000);
  const interrupted = AbortSignal.any([abort.signal, timeout]);
  try {
    const result = await Promise.race([
      probe.done,
      server.done.then(() => { throw new Error('Dedicated server exited during smoke checks'); }),
      new Promise((resolve, reject) => {
        interrupted.addEventListener('abort', () => reject(interrupted.reason), { once: true });
      }),
    ]);
    if (result.error || result.code !== 0) {
      throw new Error(`${args[0]} failed: ${result.error?.message || result.signal || result.code}`);
    }
    serverAlive(server);
  } finally {
    await stop(probe);
  }
}

async function main() {
  const workspace = await mkdtemp(join(tmpdir(), 't3mp3st-release-smoke-'));
  let serverLog = '';
  process.on('SIGINT', onInt);
  process.on('SIGTERM', onTerm);
  try {
    await copyFile(join(repo, 'package.json'), join(workspace, 'package.json'));
    const config = join(workspace, 'config');
    await mkdir(config);
    const port = await availablePort();
    const base = `http://127.0.0.1:${port}`;
    const env = {};
    // Inherit runtime lookup and OS essentials only, never provider keys, proxies, or NODE_OPTIONS.
    for (const key of ['PATH', 'SystemRoot', 'WINDIR', 'PATHEXT', 'COMSPEC', 'LANG', 'LC_ALL']) {
      if (process.env[key] !== undefined) env[key] = process.env[key];
    }
    Object.assign(env, {
      T3MP3ST_CONFIG_DIR: config,
      XDG_CONFIG_HOME: config,
      T3MP3ST_STATE_DIR: join(workspace, 'state'),
      T3MP3ST_AGENT_HOME: join(workspace, 'agents'),
      T3MP3ST_PORT: String(port),
      T3MP3ST_HOST: '127.0.0.1',
      T3MP3ST_API_URL: base,
      T3MP3ST_DISABLE_LOCAL_AGENTS: '1',
      T3MP3ST_FORCE_UNCONFIGURED: '1',
      TEMPEST_DEFAULT_PROVIDER: 'openrouter',
      NO_COLOR: '1',
    });
    const server = launch([join(repo, 'dist', 'server.js')], workspace, env, ['ignore', 'pipe', 'pipe']);
    for (const stream of [server.child.stdout, server.child.stderr]) {
      stream.on('data', chunk => { serverLog = (serverLog + chunk.toString()).slice(-16000); });
    }
    await waitForHealth(server, base);
    for (const args of [
      ['smoke.mjs', '--require-server'],
      ['exploit-chain-smoke.mjs'],
      ['field-drill.mjs'],
      ['arsenal-smoke.mjs'],
    ]) await runProbe(server, args, workspace, env);
    console.log('\nRelease smoke passed: all four server suites completed.');
  } catch (error) {
    if (serverLog) console.error(`Dedicated server log (tail):\n${serverLog}`);
    throw error;
  } finally {
    await Promise.all([...children].map(stop));
    process.off('SIGINT', onInt);
    process.off('SIGTERM', onTerm);
    await rm(workspace, { recursive: true, force: true });
  }
}

main().catch(error => {
  console.error(`Release smoke failed: ${error.message}`);
  process.exitCode = 1;
});
