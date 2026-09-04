#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';

const root = resolve(import.meta.dirname, '..');
const challengeDir = resolve(root, 'ctf/docker/web/xss-stored');
const manifest = JSON.parse(readFileSync(resolve(root, 'ctf/challenges/manifest.json'), 'utf8'));
const compose = readFileSync(resolve(root, 'ctf/docker-compose.yml'), 'utf8');
const dockerfile = readFileSync(resolve(challengeDir, 'Dockerfile'), 'utf8');
const provenance = readFileSync(resolve(challengeDir, 'PROVENANCE.md'), 'utf8');
const challenge = manifest.challenges.find((entry) => entry.id === 'web_xss_stored');

if (!challenge) throw new Error('web_xss_stored is missing from the manifest');
if (challenge.docker.dockerfile !== '../docker/web/xss-stored/Dockerfile') throw new Error('manifest Dockerfile does not match the challenge');
if (challenge.docker.ports?.[0] !== '127.0.0.1:8082:8080') throw new Error('manifest must publish loopback-only via the gateway');
if (challenge.docker.healthcheck !== 'http://localhost:8080/health') throw new Error('manifest health check is stale');
if (challenge.docker.teardown !== 'docker compose down --remove-orphans') throw new Error('manifest teardown is stale');
if (challenge.flag.location !== 'admin_cookie' || challenge.flag.requires_exfiltration !== true || challenge.flag.value_env !== 'CTF_FLAG') throw new Error('flag must ride the admin cookie env and require exfiltration');
if (challenge.target.endpoint !== '/') throw new Error('challenge target endpoint must be the board /');
if (!dockerfile.match(/^FROM [^\n]+@sha256:[a-f0-9]{64}$/m)) throw new Error('base image is not pinned by digest');
for (const required of ['xss-gateway:', '127.0.0.1:8082:8080', 'read_only: true', 'cap_drop:', 'pids_limit: 64', 'mem_limit: 128m', 'internal: true', 'restart: "no"', 'CTF_FLAG=T3MP3ST{st0r3d_xss_c00kie_th3ft}']) {
  if (!compose.includes(required)) throw new Error(`compose safety contract missing: ${required}`);
}
for (const required of ['Origin:', 'License:', 'Flag handling:', 'Reproduction:', 'Rollback:', 'Sensitive-data review:', 'Container trust:', 'Intended vulnerability:']) {
  if (!provenance.includes(required)) throw new Error(`provenance contract missing: ${required}`);
}

const expectedFlag = 'T3MP3ST{st0r3d_xss_c00kie_th3ft}';
const flag = execFileSync('python3', [resolve(challengeDir, 'solve.py')], { encoding: 'utf8' }).trim();
if (flag !== expectedFlag) throw new Error(`deterministic solution failed: ${flag}`);

const tmp = mkdtempSync(join(tmpdir(), 'xss-solver-'));
const callbackLog = join(tmp, 'callback.log');
writeFileSync(callbackLog, '');
const smoke = `
import os, subprocess, sys, time
sys.path.insert(0, ${JSON.stringify(challengeDir)})
def up(host):
    from urllib.error import URLError
    from urllib.request import urlopen
    try:
        body = urlopen(host + '/health', timeout=1).read()
        return b'"ok"' in body
    except (URLError, OSError, ValueError):
        return False
callback = subprocess.Popen(['python3', 'callback.py'], cwd=${JSON.stringify(challengeDir)}, env={**os.environ, 'CALLBACK_PORT': '19099', 'CALLBACK_LOG': ${JSON.stringify(callbackLog)}}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
server = subprocess.Popen(['python3', 'server.py'], cwd=${JSON.stringify(challengeDir)}, env={**os.environ, 'PORT': '18091'}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
proxy = subprocess.Popen(['python3', 'proxy.py'], cwd=${JSON.stringify(challengeDir)}, env={**os.environ, 'PORT': '18090', 'UPSTREAM': 'http://127.0.0.1:18091', 'CALLBACK': 'http://127.0.0.1:19099'}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    deadline = time.time() + 15
    while time.time() < deadline:
        if up('http://127.0.0.1:18091') and up('http://127.0.0.1:18090'):
            break
        time.sleep(0.2)
    else:
        raise SystemExit('challenge, gateway, or callback not healthy in time')
    import solve
    print(solve.run_live('http://127.0.0.1:18090', ${JSON.stringify(callbackLog)}))
finally:
    for proc in (proxy, server, callback):
        proc.terminate()
`;
try {
  const extracted = execFileSync('python3', ['-c', smoke], { encoding: 'utf8' }).trim();
  if (extracted !== expectedFlag) throw new Error(`gateway smoke extraction failed: ${extracted}`);
  const durable = readFileSync(callbackLog, 'utf8');
  if (!durable.includes(expectedFlag)) throw new Error(`callback log did not capture the flag: ${durable}`);
} catch (error) {
  if (error.status !== undefined) throw new Error(`gateway smoke test failed: ${error.stderr}`);
  throw error;
}
console.log('stored-XSS CTF contract and deterministic solution: PASS');
