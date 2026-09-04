#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const challengeDir = resolve(root, 'ctf/challenges/artifacts/memory-forensics');
const fixturePath = resolve(challengeDir, 'memdump.raw');
const manifest = JSON.parse(readFileSync(resolve(root, 'ctf/challenges/manifest.json'), 'utf8'));
const provenance = readFileSync(resolve(challengeDir, 'PROVENANCE.md'), 'utf8');
const challenge = manifest.challenges.find((entry) => entry.id === 'forensics_memory_dump');

if (!challenge) throw new Error('forensics_memory_dump is missing from the manifest');
if (challenge.delivery?.mode !== 'offline_artifact') throw new Error('challenge must remain offline-only');
if (challenge.delivery?.network !== 'none') throw new Error('offline fixture must not require network access');
if (challenge.delivery?.teardown !== 'temporary fixture removed by smoke test') throw new Error('manifest teardown contract is stale');
if (challenge.artifacts?.memory_dump !== './artifacts/memory-forensics/memdump.raw') throw new Error('manifest fixture path is stale');
if (challenge.artifacts?.generator !== './artifacts/memory-forensics/generate.py') throw new Error('manifest generator path is stale');
if (challenge.artifacts?.solution !== './artifacts/memory-forensics/solve.py') throw new Error('manifest solution path is stale');
if (challenge.artifacts?.profile !== 'T3MP3ST-SYNTH-MEM-v1') throw new Error('manifest fixture profile is stale');
if (!/^[a-f0-9]{64}$/.test(challenge.artifacts?.sha256 ?? '')) throw new Error('manifest fixture hash is invalid');

const fixture = readFileSync(fixturePath);
const fixtureHash = createHash('sha256').update(fixture).digest('hex');
if (fixture.length !== challenge.artifacts.size_bytes) throw new Error(`fixture size mismatch: ${fixture.length}`);
if (fixtureHash !== challenge.artifacts.sha256) throw new Error(`fixture hash mismatch: ${fixtureHash}`);
if (!provenance.includes(`Fixture SHA-256: \`${fixtureHash}\``)) throw new Error('provenance hash disagrees with the fixture');
if (!provenance.includes(`Fixture size: ${fixture.length} bytes`)) throw new Error('provenance size disagrees with the fixture');
for (const required of ['Origin:', 'License:', 'Generator:', 'Tool version:', 'Reproduction:', 'Sensitive-data review:', 'Network and container review:', 'Teardown:']) {
  if (!provenance.includes(required)) throw new Error(`provenance contract missing: ${required}`);
}

const temporaryDir = mkdtempSync(join(tmpdir(), 't3mp3st-memory-fixture-'));
const regeneratedPath = join(temporaryDir, 'memdump.raw');
try {
  execFileSync('python3', [resolve(challengeDir, 'generate.py'), regeneratedPath], { stdio: 'pipe' });
  const regenerated = readFileSync(regeneratedPath);
  if (!fixture.equals(regenerated)) throw new Error('regeneration is not byte-for-byte deterministic');
  const flag = execFileSync('python3', [resolve(challengeDir, 'solve.py'), regeneratedPath], { encoding: 'utf8' }).trim();
  if (flag !== 'T3MP3ST{synthetic_memory_credentials}') throw new Error(`deterministic solution failed: ${flag}`);
} finally {
  rmSync(temporaryDir, { recursive: true, force: true });
}

console.log('synthetic memory-forensics fixture integrity and offline solution: PASS');
