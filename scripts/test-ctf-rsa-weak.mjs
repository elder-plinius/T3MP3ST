#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const challengeDir = resolve(root, 'ctf/docker/crypto/rsa-weak');
const manifest = JSON.parse(readFileSync(resolve(root, 'ctf/challenges/manifest.json'), 'utf8'));
const compose = readFileSync(resolve(root, 'ctf/docker-compose.yml'), 'utf8');
const dockerfile = readFileSync(resolve(challengeDir, 'Dockerfile'), 'utf8');
const provenance = readFileSync(resolve(challengeDir, 'PROVENANCE.md'), 'utf8');
const challenge = manifest.challenges.find((entry) => entry.id === 'crypto_rsa_weak');

if (!challenge) throw new Error('crypto_rsa_weak is missing from the manifest');
if (challenge.docker.dockerfile !== '../docker/crypto/rsa-weak/Dockerfile') throw new Error('manifest Dockerfile does not match the challenge');
if (challenge.docker.ports?.[0] !== '127.0.0.1:9101:8080') throw new Error('manifest must publish loopback-only');
if (challenge.docker.healthcheck !== 'http://localhost:8080/health') throw new Error('manifest health check is stale');
if (!dockerfile.match(/^FROM [^\n]+@sha256:[a-f0-9]{64}$/m)) throw new Error('base image is not pinned by digest');
for (const required of ['rsa-weak-gateway:', '127.0.0.1:9101:8080', 'read_only: true', 'cap_drop:', 'pids_limit: 64', 'mem_limit: 128m', 'internal: true', 'restart: "no"']) {
  if (!compose.includes(required)) throw new Error(`compose safety contract missing: ${required}`);
}
for (const required of ['License:', 'Reproduction:', 'Sensitive-data review:', 'Container trust:']) {
  if (!provenance.includes(required)) throw new Error(`provenance contract missing: ${required}`);
}

const answer = execFileSync('python3', [resolve(challengeDir, 'solve.py')], { encoding: 'utf8' }).trim();
if (answer !== '424242') throw new Error(`deterministic solution failed: ${answer}`);
console.log('weak-RSA CTF contract and deterministic solution: PASS');
