#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const challengeDir = resolve(root, 'ctf/docker/pwn/format-string');
const manifest = JSON.parse(readFileSync(resolve(root, 'ctf/challenges/manifest.json'), 'utf8'));
const compose = readFileSync(resolve(root, 'ctf/docker-compose.yml'), 'utf8');
const dockerfile = readFileSync(resolve(challengeDir, 'Dockerfile'), 'utf8');
const provenance = readFileSync(resolve(challengeDir, 'PROVENANCE.md'), 'utf8');
const source = readFileSync(resolve(challengeDir, 'vuln.c'), 'utf8');
const challenge = manifest.challenges.find((entry) => entry.id === 'pwn_format_string');

if (!challenge) throw new Error('pwn_format_string is missing from the manifest');
if (challenge.docker.dockerfile !== '../docker/pwn/format-string/Dockerfile') throw new Error('manifest Dockerfile does not match the challenge');
if (challenge.docker.ports?.[0] !== '127.0.0.1:9002:9002') throw new Error('manifest must publish loopback-only');
if (challenge.docker.networks?.[0] !== 'format-string-internal') throw new Error('manifest network is stale');
if (challenge.docker.healthcheck !== 'tcp://localhost:9002') throw new Error('manifest health check is stale');
if (challenge.docker.teardown !== 'docker compose down --remove-orphans') throw new Error('manifest teardown is stale');
if (!dockerfile.match(/^FROM gcc:14\.2\.0-bookworm@sha256:[a-f0-9]{64} AS build$/m)) throw new Error('compiler image is not pinned by digest');
if (!dockerfile.match(/^FROM debian:bookworm-slim@sha256:[a-f0-9]{64}$/m)) throw new Error('runtime image is not pinned by digest');
if (!source.includes('dprintf(client, input, &authorized)')) throw new Error('intended format-string primitive is missing');
for (const required of ['format-string:', '127.0.0.1:9002:9002', 'format-string-internal', 'read_only: true', 'cap_drop:', 'pids_limit: 32', 'mem_limit: 64m', 'internal: true', 'restart: "no"', 'user: "65532:65532"']) {
  if (!compose.includes(required)) throw new Error(`compose safety contract missing: ${required}`);
}
for (const required of ['Origin:', 'License:', 'Build command:', 'Compiler identity:', 'Binary SHA-256', 'Protections:', 'Sensitive-data review:', 'Container trust:', 'Intended vulnerability:']) {
  if (!provenance.includes(required)) throw new Error(`provenance contract missing: ${required}`);
}
if (challenge.binary.sha256_amd64 === 'TO_BE_RECORDED_AFTER_VERIFIED_BUILD' || !/^[a-f0-9]{64}$/.test(challenge.binary.sha256_amd64)) throw new Error('manifest binary hash is not recorded');
if (!provenance.includes(challenge.binary.sha256_amd64)) throw new Error('manifest and provenance binary hashes disagree');

if (process.argv.includes('--docker')) {
  const composeFile = resolve(root, 'ctf/docker-compose.yml');
  try {
    execFileSync('docker', ['compose', '-f', composeFile, 'build', '--no-cache', 'format-string'], { stdio: 'inherit' });
    const imageHash = execFileSync('docker', ['run', '--rm', '--entrypoint', 'sha256sum', 't3mp3st/ctf-format-string:local', '/challenge/vuln'], { encoding: 'utf8' }).split(/\s+/)[0];
    if (imageHash !== challenge.binary.sha256_amd64) throw new Error(`binary hash mismatch: ${imageHash}`);
    execFileSync('docker', ['compose', '-f', composeFile, 'up', '-d', '--wait', 'format-string'], { stdio: 'inherit' });
    const flag = execFileSync('python3', [resolve(challengeDir, 'solve.py')], { encoding: 'utf8' }).trim();
    if (flag !== 'T3MP3ST{f0rm4t_str1ng_wr1t3}') throw new Error(`deterministic exploit failed: ${flag}`);
  } finally {
    execFileSync('docker', ['compose', '-f', composeFile, 'down', '--remove-orphans'], { stdio: 'inherit' });
  }
}

console.log('format-string CTF contract and deterministic exploit: PASS');
