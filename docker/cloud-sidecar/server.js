'use strict';
// T3MP3ST cloud-sidecar — HTTPS execution bridge for cloud security tools.
// All traffic is TLS-encrypted; requests require a bearer token.
// Handles inline credential injection per provider before spawning commands.
const https   = require('https');
const fs      = require('fs');
const os      = require('os');
const path    = require('path');
const { spawn, execFileSync } = require('child_process');

const PORT  = process.env.PORT || 8080;
const TOKEN = process.env.SIDECAR_TOKEN || '';

if (!TOKEN) {
  console.error('[cloud-sidecar] FATAL: SIDECAR_TOKEN env var is not set');
  process.exit(1);
}

// Tools that this sidecar is authorised to run
const ALLOWED = new Set([
  'aws', 'gcloud', 'az', 'prowler', 'checkov', 'scout',
  'curl', 'wget', 'dig', 'host', 'whois', 'nmap', 'python3', 'python',
]);

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

// --------------------------------------------------------------------------
// Credential injection — converts high-level credential blocks to env vars
// and handles provider-specific auth flows.
// --------------------------------------------------------------------------

/**
 * Prepare the environment for a command, injecting cloud credentials.
 * Returns { env, azureLoginCmd, cleanup }.
 * cleanup() must be called after the child process exits.
 */
function prepareEnv(rawEnv) {
  const merged = { ...process.env };
  const cleanups = [];

  // 1. Plain env vars — copy everything in (they may be standard AWS/Azure vars)
  for (const [k, v] of Object.entries(rawEnv)) {
    if (k !== 'GOOGLE_APPLICATION_CREDENTIALS_JSON') merged[k] = String(v);
  }

  // ── AWS ──────────────────────────────────────────────────────────────────
  // Standard: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN,
  //           AWS_DEFAULT_REGION / AWS_REGION
  // STS AssumeRole: AWS_ROLE_ARN, AWS_ROLE_SESSION_NAME, AWS_EXTERNAL_ID
  // OIDC/IRSA: AWS_WEB_IDENTITY_TOKEN_FILE, AWS_ROLE_ARN
  // Named profile: AWS_PROFILE (requires ~/.aws/credentials to exist in container)
  // All passed as-is since aws-cli reads them natively.

  // ── GCP ──────────────────────────────────────────────────────────────────
  // GOOGLE_APPLICATION_CREDENTIALS_JSON: inline service-account JSON
  // → write to a temp file and set GOOGLE_APPLICATION_CREDENTIALS
  if (rawEnv['GOOGLE_APPLICATION_CREDENTIALS_JSON']) {
    try {
      const tmpFile = path.join(os.tmpdir(), `gcp-sa-${process.pid}-${Date.now()}.json`);
      fs.writeFileSync(tmpFile, rawEnv['GOOGLE_APPLICATION_CREDENTIALS_JSON'], { mode: 0o600 });
      merged['GOOGLE_APPLICATION_CREDENTIALS'] = tmpFile;
      cleanups.push(() => { try { fs.unlinkSync(tmpFile); } catch {} });
      console.log('[cloud-sidecar] GCP SA credentials written to temp file');
    } catch (e) {
      console.error('[cloud-sidecar] Failed to write GCP SA JSON:', e.message);
    }
  }
  // GCLOUD_PROJECT / GOOGLE_CLOUD_PROJECT — accept either, normalise both
  if (merged['GCLOUD_PROJECT'] && !merged['GOOGLE_CLOUD_PROJECT']) {
    merged['GOOGLE_CLOUD_PROJECT'] = merged['GCLOUD_PROJECT'];
  }
  if (merged['GOOGLE_CLOUD_PROJECT'] && !merged['GCLOUD_PROJECT']) {
    merged['GCLOUD_PROJECT'] = merged['GOOGLE_CLOUD_PROJECT'];
  }
  // CLOUDSDK_CORE_PROJECT — also honoured by gcloud CLI
  if (!merged['CLOUDSDK_CORE_PROJECT'] && (merged['GCLOUD_PROJECT'] || merged['GOOGLE_CLOUD_PROJECT'])) {
    merged['CLOUDSDK_CORE_PROJECT'] = merged['GCLOUD_PROJECT'] || merged['GOOGLE_CLOUD_PROJECT'];
  }
  // Impersonation chain
  if (merged['CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT']) {
    // already passed through, nothing extra needed
  }

  // ── Azure ────────────────────────────────────────────────────────────────
  // Service principal: AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET
  // Certificate SP:    AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_CERTIFICATE_PATH + (optional) AZURE_CLIENT_CERTIFICATE_PASSWORD
  // Workload identity: AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_FEDERATED_TOKEN_FILE
  // Managed identity:  AZURE_CLIENT_ID (user-assigned) OR nothing (system-assigned), MSI_ENDPOINT or IDENTITY_ENDPOINT
  // Sovereign clouds:  AZURE_AUTHORITY_HOST (e.g. https://login.microsoftonline.de)
  //
  // az CLI requires explicit login; we auto-login via sp credentials if provided.
  // We use a per-request AZURE_CONFIG_DIR in /tmp so sessions don't collide.

  let azureLoginArgs = null;
  const hasSP = merged['AZURE_TENANT_ID'] && merged['AZURE_CLIENT_ID'] && (merged['AZURE_CLIENT_SECRET'] || merged['AZURE_CLIENT_CERTIFICATE_PATH']);
  const hasFederated = merged['AZURE_TENANT_ID'] && merged['AZURE_CLIENT_ID'] && merged['AZURE_FEDERATED_TOKEN_FILE'];
  const hasMSI = merged['MSI_ENDPOINT'] || merged['IDENTITY_ENDPOINT'];

  if (hasSP || hasFederated) {
    const azConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'az-'));
    merged['AZURE_CONFIG_DIR'] = azConfigDir;
    cleanups.push(() => { try { fs.rmSync(azConfigDir, { recursive: true, force: true }); } catch {} });

    if (hasFederated) {
      azureLoginArgs = [
        'login', '--service-principal',
        '-u', merged['AZURE_CLIENT_ID'],
        '--tenant', merged['AZURE_TENANT_ID'],
        '--federated-token', fs.readFileSync(merged['AZURE_FEDERATED_TOKEN_FILE'], 'utf8').trim(),
        '--allow-no-subscriptions',
      ];
    } else if (merged['AZURE_CLIENT_CERTIFICATE_PATH']) {
      azureLoginArgs = [
        'login', '--service-principal',
        '-u', merged['AZURE_CLIENT_ID'],
        '-p', merged['AZURE_CLIENT_CERTIFICATE_PATH'],
        '--tenant', merged['AZURE_TENANT_ID'],
        '--allow-no-subscriptions',
      ];
    } else {
      // password (client secret)
      azureLoginArgs = [
        'login', '--service-principal',
        '-u', merged['AZURE_CLIENT_ID'],
        '-p', merged['AZURE_CLIENT_SECRET'],
        '--tenant', merged['AZURE_TENANT_ID'],
        '--allow-no-subscriptions',
      ];
    }
    if (merged['AZURE_SUBSCRIPTION_ID']) {
      // set subscription after login
    }
  } else if (hasMSI) {
    // Managed Identity — az CLI picks it up automatically when MSI_ENDPOINT is set
    console.log('[cloud-sidecar] Azure MSI detected');
  }

  const cleanup = () => cleanups.forEach(fn => fn());
  return { env: merged, azureLoginArgs, cleanup };
}

/** Run az login before the real command if SP credentials were provided */
function azureLogin(loginArgs, env) {
  return new Promise((resolve) => {
    const child = spawn('az', loginArgs, { env, cwd: '/tmp', stdio: 'pipe' });
    let out = '', err = '';
    child.stdout.on('data', d => { out += d; });
    child.stderr.on('data', d => { err += d; });
    child.on('close', code => {
      if (code !== 0) console.warn('[cloud-sidecar] az login returned', code, err.slice(0, 200));
      else console.log('[cloud-sidecar] az SP login succeeded');
      resolve(code === 0);
    });
    child.on('error', e => { console.error('[cloud-sidecar] az login spawn error:', e.message); resolve(false); });
    setTimeout(() => { child.kill(); resolve(false); }, 30000);
  });
}

// --------------------------------------------------------------------------
// HTTP server
// --------------------------------------------------------------------------
const server = https.createServer(tlsOptions, async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    const available = [...ALLOWED].filter(cmd => {
      try { execFileSync('which', [cmd], { stdio: 'ignore' }); return true; }
      catch { return false; }
    });
    return respondJson(res, 200, { status: 'ok', sidecar: 'cloud', tools: available });
  }

  if (!authenticate(req)) {
    return respondJson(res, 401, { error: 'Unauthorized' });
  }

  if (req.method === 'POST' && req.url === '/run') {
    let body;
    try { body = await parseBody(req); }
    catch { return respondJson(res, 400, { error: 'Invalid JSON body' }); }

    const { cmd, args = [], env: rawEnv = {}, timeout = 60000 } = body;

    if (!cmd || typeof cmd !== 'string') {
      return respondJson(res, 400, { error: 'cmd is required' });
    }

    const basecmd = cmd.split('/').pop();
    if (!ALLOWED.has(basecmd)) {
      return respondJson(res, 403, { error: `Command not allowed: ${basecmd}` });
    }

    const { env: preparedEnv, azureLoginArgs, cleanup } = prepareEnv(rawEnv);

    // If this is an az command and we have SP creds, login first
    if (basecmd === 'az' && azureLoginArgs) {
      const ok = await azureLogin(azureLoginArgs, preparedEnv);
      if (!ok) {
        cleanup();
        return respondJson(res, 200, {
          stdout: '',
          stderr: 'Azure service principal login failed — check AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID',
          exitCode: 1,
          timedOut: false,
        });
      }
      // Set subscription if provided
      if (preparedEnv['AZURE_SUBSCRIPTION_ID']) {
        try {
          execFileSync('az', ['account', 'set', '--subscription', preparedEnv['AZURE_SUBSCRIPTION_ID']], {
            env: preparedEnv, stdio: 'pipe',
          });
        } catch {}
      }
    }

    let stdout = '', stderr = '';
    let timedOut = false;

    const child = spawn(cmd, args, { env: preparedEnv, cwd: '/tmp' });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
    }, timeout);

    child.stdout.on('data', d => { stdout += d.toString(); });
    child.stderr.on('data', d => { stderr += d.toString(); });

    child.on('close', exitCode => {
      clearTimeout(timer);
      cleanup();
      respondJson(res, 200, { stdout, stderr, exitCode: timedOut ? -1 : exitCode, timedOut });
    });

    child.on('error', err => {
      clearTimeout(timer);
      cleanup();
      respondJson(res, 500, { error: err.message, stdout, stderr });
    });

    return;
  }

  respondJson(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`[cloud-sidecar] listening on :${PORT} (TLS)`);
});

process.on('SIGTERM', () => { server.close(); process.exit(0); });
process.on('SIGINT',  () => { server.close(); process.exit(0); });
