#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const challengeDir = resolve(root, 'ctf/docker/web/ssrf-metadata');
const manifest = JSON.parse(readFileSync(resolve(root, 'ctf/challenges/manifest.json'), 'utf8'));
const compose = readFileSync(resolve(root, 'ctf/docker-compose.yml'), 'utf8');
const dockerfile = readFileSync(resolve(challengeDir, 'Dockerfile'), 'utf8');
const provenance = readFileSync(resolve(challengeDir, 'PROVENANCE.md'), 'utf8');
const challenge = manifest.challenges.find((entry) => entry.id === 'web_ssrf_metadata');

if (!challenge) throw new Error('web_ssrf_metadata is missing from the manifest');
if (challenge.docker.dockerfile !== '../docker/web/ssrf-metadata/Dockerfile') throw new Error('manifest Dockerfile does not match the challenge');
if (challenge.docker.ports?.[0] !== '127.0.0.1:8083:8080') throw new Error('manifest must publish loopback-only via the gateway');
if (challenge.docker.networks?.includes('ssrf-internal') !== true) throw new Error('manifest must join the ssrf-internal network');
if (challenge.docker.healthcheck !== 'http://localhost:8080/health') throw new Error('manifest health check is stale');
if (challenge.docker.teardown !== 'docker compose down --remove-orphans') throw new Error('manifest teardown is stale');
if (challenge.flag.location !== 'metadata_service' || challenge.flag.value_env !== 'CTF_FLAG') throw new Error('flag must ride the metadata service CTF_FLAG env');
if (challenge.target.endpoint !== '/fetch') throw new Error('challenge target endpoint must be /fetch');
if (!dockerfile.match(/^FROM [^\n]+@sha256:[a-f0-9]{64}$/m)) throw new Error('base image is not pinned by digest');
for (const required of ['ssrf-metadata:', '127.0.0.1:8083:8080', 'ssrf-internal', 'ssrf-internal-edge', 'ssrf-mock', '169.254.169.254', 'read_only: true', 'cap_drop:', 'pids_limit: 64', 'mem_limit: 128m', 'internal: true', 'restart: "no"', 'CTF_FLAG=T3MP3ST{ssrf_m3t4d4t4_c4ptur3}']) {
  if (!compose.includes(required)) throw new Error(`compose safety contract missing: ${required}`);
}
for (const required of ['Origin:', 'License:', 'Flag handling:', 'Reproduction:', 'Rollback:', 'Sensitive-data review:', 'Container trust:', 'Intended vulnerability:']) {
  if (!provenance.includes(required)) throw new Error(`provenance contract missing: ${required}`);
}

const expectedFlag = 'T3MP3ST{ssrf_m3t4d4t4_c4ptur3}';
const flag = execFileSync('python3', [resolve(challengeDir, 'solve.py')], { encoding: 'utf8' }).trim();
if (flag !== expectedFlag) throw new Error(`deterministic solution failed: ${flag}`);

const smoke = `
import os, subprocess, sys, time
sys.path.insert(0, ${JSON.stringify(challengeDir)})
def up(port):
    from urllib.error import URLError
    from urllib.request import urlopen
    try:
        body = urlopen('http://127.0.0.1:%d/health' % port, timeout=1).read()
        return b'"ok"' in body
    except (URLError, OSError, ValueError):
        return False
mock = subprocess.Popen(['python3', '-u', 'metadata_mock.py'], cwd=${JSON.stringify(challengeDir)}, env={**os.environ, 'PORT': '18093'}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
server = subprocess.Popen(['python3', 'server.py'], cwd=${JSON.stringify(challengeDir)}, env={**os.environ, 'PORT': '18092', 'CTF_METADATA_HOST': '127.0.0.1', 'CTF_METADATA_PORT': '18093'}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
gateway = subprocess.Popen(['python3', 'proxy.py'], cwd=${JSON.stringify(challengeDir)}, env={**os.environ, 'PORT': '18091', 'UPSTREAM': 'http://127.0.0.1:18092'}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    deadline = time.time() + 15
    while time.time() < deadline:
        if up(18092) and up(18091):
            break
        time.sleep(0.2)
    else:
        raise SystemExit('challenge, gateway, or mock not healthy in time')
    os.environ['CTF_METADATA_HOST'] = '127.0.0.1'
    os.environ['CTF_METADATA_PORT'] = '18093'
    import solve
    print(solve.run_live('http://127.0.0.1:18091'))
finally:
    for proc in (gateway, server, mock):
        proc.terminate()
`;
try {
  const extracted = execFileSync('python3', ['-c', smoke], { encoding: 'utf8' }).trim();
  if (extracted !== expectedFlag) throw new Error(`gateway smoke extraction failed: ${extracted}`);
} catch (error) {
  if (error.status !== undefined) throw new Error(`gateway smoke test failed: ${error.stderr}`);
  throw error;
}
console.log('ssrf-metadata CTF contract and deterministic solution: PASS');
