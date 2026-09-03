import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '../..');
const challengeDir = resolve(root, 'ctf/docker/crypto/rsa-weak');

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

  it('has deterministic solution evidence and complete provenance', () => {
    const provenance = readFileSync(resolve(challengeDir, 'PROVENANCE.md'), 'utf8');
    for (const required of ['License:', 'Reproduction:', 'Sensitive-data review:', 'Container trust:']) {
      expect(provenance, required).toContain(required);
    }
    expect(execFileSync('python3', [resolve(challengeDir, 'solve.py')], { encoding: 'utf8' }).trim()).toBe('424242');
  });
});
