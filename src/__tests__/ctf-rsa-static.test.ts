import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '../..');
const challengeDir = resolve(root, 'ctf/docker/crypto/rsa-weak');

/** Find a real Python 3.10+ interpreter.
 *
 *  `python3` alone is not enough: on Windows it is usually the Microsoft Store
 *  app-execution alias in %LOCALAPPDATA%\Microsoft\WindowsApps, a non-functional
 *  stub. Calling it either fails with "Permission denied" or — when the alias
 *  does resolve to a real interpreter — surfaces as a TypeError on the
 *  `int | str` union annotation, which reads exactly like the solver being
 *  broken. Neither failure is about the solver, so neither may be reported as
 *  if it were.
 *
 *  Returns the command to use, or null when this machine has no usable
 *  interpreter. */
function findPython(): string | null {
  for (const cmd of ['python3.13', 'python3.12', 'python3.11', 'python3.10', 'python3', 'python']) {
    try {
      const probe = execFileSync(cmd, ['-c', 'import sys;print("%d.%d" % sys.version_info[:2])'], {
        encoding: 'utf8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      const [major, minor] = probe.split('.').map(Number);
      if (major === 3 && minor >= 10) return cmd;   // PEP 604 unions need 3.10
    } catch { /* absent, or the WindowsApps stub — try the next candidate */ }
  }
  return null;
}

const python = findPython();

describe('weak-RSA CTF contract', () => {
  it('keeps manifest, compose, and immutable base-image contracts aligned', () => {
    const manifest = JSON.parse(readFileSync(resolve(root, 'ctf/challenges/manifest.json'), 'utf8')) as { challenges: Array<{ id: string; docker: { image: string; dockerfile: string; ports: string[]; healthcheck: string; teardown: string } }> };
    const challenge = manifest.challenges.find((entry) => entry.id === 'crypto_rsa_weak');
    const compose = readFileSync(resolve(root, 'ctf/docker-compose.yml'), 'utf8');
    const dockerfile = readFileSync(resolve(challengeDir, 'Dockerfile'), 'utf8');
    expect(challenge?.docker).toEqual({
      image: 't3mp3st/ctf-rsa-weak:local',
      dockerfile: '../docker/crypto/rsa-weak/Dockerfile',
      ports: ['127.0.0.1:9101:8080'],
      healthcheck: 'http://localhost:8080/health',
      teardown: 'docker compose down --remove-orphans',
    });
    expect(dockerfile).toMatch(/^FROM [^\n]+@sha256:[a-f0-9]{64}$/m);
    for (const required of ['rsa-weak-gateway:', '127.0.0.1:9101:8080', 'read_only: true', 'cap_drop:', 'pids_limit: 64', 'mem_limit: 128m', 'internal: true', 'restart: "no"']) {
      expect(compose, required).toContain(required);
    }
  });

  it('has complete provenance', () => {
    const provenance = readFileSync(resolve(challengeDir, 'PROVENANCE.md'), 'utf8');
    for (const required of ['License:', 'Reproduction:', 'Sensitive-data review:', 'Container trust:']) {
      expect(provenance, required).toContain(required);
    }
  });

  // Skipped — visibly, never silently passed — where no Python 3.10+ exists.
  // The provenance contract above still runs, because it needs no interpreter.
  it.skipIf(!python)('solver produces the deterministic answer', () => {
    expect(
      execFileSync(python as string, [resolve(challengeDir, 'solve.py')], {
        encoding: 'utf8', cwd: challengeDir, timeout: 60_000,
      }).trim(),
    ).toBe('424242');
  });
});
