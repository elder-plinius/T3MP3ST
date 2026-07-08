'use strict';
// T3MP3ST binary-sidecar — HTTPS execution bridge for binary analysis tools.
// All traffic is TLS-encrypted; requests require a bearer token.
const https   = require('https');
const fs      = require('fs');
const { spawn } = require('child_process');

const PORT  = process.env.PORT || 8080;
const TOKEN = process.env.SIDECAR_TOKEN || '';

if (!TOKEN) {
  console.error('[binary-sidecar] FATAL: SIDECAR_TOKEN env var is not set');
  process.exit(1);
}

// Tools that this sidecar is authorised to run
const ALLOWED = new Set([
  'strings', 'file', 'readelf', 'nm', 'objdump', 'xxd', 'hexdump',
  'binwalk', 'radare2', 'r2', 'yara', 'exiftool', 'python3', 'python',
  'ROPgadget', 'ropgadget',
]);

const UPLOADS_DIR = process.env.UPLOADS_DIR || '/data/uploads';

const tlsOptions = {
  key:  fs.readFileSync('/certs/key.pem'),
  cert: fs.readFileSync('/certs/cert.pem'),
};

function respondJson(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type':   'application/json',
    'Content-Length': Buffer.byteLength(json),
  });
  res.end(json);
}

function authenticate(req) {
  const auth = (req.headers['authorization'] || '').trim();
  return auth === `Bearer ${TOKEN}`;
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end',  ()    => {
      try { resolve(JSON.parse(data)); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

// Resolve a local:// reference to an absolute path inside UPLOADS_DIR
function resolveLocalRef(ref) {
  const name = ref.startsWith('local://') ? ref.slice(8) : ref;
  // Prevent path traversal
  const resolved = require('path').resolve(UPLOADS_DIR, name);
  if (!resolved.startsWith(UPLOADS_DIR)) return null;
  return resolved;
}

const server = https.createServer(tlsOptions, async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    const available = [...ALLOWED].filter(cmd => {
      try { require('child_process').execSync(`which ${cmd}`, { stdio: 'ignore' }); return true; }
      catch { return false; }
    });
    return respondJson(res, 200, { status: 'ok', sidecar: 'binary', tools: available });
  }

  if (!authenticate(req)) {
    return respondJson(res, 401, { error: 'Unauthorized' });
  }

  if (req.method === 'POST' && req.url === '/run') {
    let body;
    try { body = await parseBody(req); }
    catch { return respondJson(res, 400, { error: 'Invalid JSON body' }); }

    const { cmd, args = [], env = {}, timeout = 120000 } = body;

    if (!cmd || typeof cmd !== 'string') {
      return respondJson(res, 400, { error: 'cmd is required' });
    }

    const basecmd = cmd.split('/').pop();
    if (!ALLOWED.has(basecmd)) {
      return respondJson(res, 403, { error: `Command not allowed: ${basecmd}` });
    }

    // Resolve any local:// references in args to real paths
    const resolvedArgs = args.map(a => {
      if (typeof a === 'string' && a.startsWith('local://')) {
        const p = resolveLocalRef(a);
        return p || a;
      }
      return a;
    });

    let stdout = '', stderr = '';
    let timedOut = false;

    const child = spawn(cmd, resolvedArgs, {
      env: { ...process.env, ...env },
      cwd: UPLOADS_DIR,
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
    }, timeout);

    child.stdout.on('data', d => { stdout += d.toString(); });
    child.stderr.on('data', d => { stderr += d.toString(); });

    child.on('close', exitCode => {
      clearTimeout(timer);
      respondJson(res, 200, {
        stdout,
        stderr,
        exitCode: timedOut ? -1 : exitCode,
        timedOut,
      });
    });

    child.on('error', err => {
      clearTimeout(timer);
      respondJson(res, 500, { error: err.message, stdout, stderr });
    });

    return;
  }

  respondJson(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`[binary-sidecar] listening on :${PORT} (TLS), uploads: ${UPLOADS_DIR}`);
});

process.on('SIGTERM', () => { server.close(); process.exit(0); });
process.on('SIGINT',  () => { server.close(); process.exit(0); });
