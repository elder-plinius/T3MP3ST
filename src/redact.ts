/**
 * Secret / credential redaction for anything the server serves back to a client — ledgers, the
 * arsenal-approval audit, SSE events, and persisted state snapshots. Extracted from server.ts so this
 * load-bearing safety boundary is a PURE, dependency-free module that can be unit-tested in isolation
 * (importing server.ts would start the HTTP listener + LLM). server.ts imports these back unchanged.
 */

/** Provider secret signatures. Each is applied globally; a match is replaced with `[redacted]`. */
export const SECRET_PATTERNS: Record<string, { pattern: RegExp; severity: string; provider: string }> = {
  aws_access_key: { pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical', provider: 'AWS' },
  aws_secret_key: { pattern: /[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g, severity: 'critical', provider: 'AWS' },
  gcp_api_key: { pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'high', provider: 'GCP' },
  github_token: { pattern: /ghp_[A-Za-z0-9]{36}/g, severity: 'critical', provider: 'GitHub' },
  github_oauth: { pattern: /gho_[A-Za-z0-9]{36}/g, severity: 'critical', provider: 'GitHub' },
  anthropic_api_key: { pattern: /sk-ant-api\d{2}-[A-Za-z0-9_\-]{16,}/g, severity: 'critical', provider: 'Anthropic' },
  openai_api_key: { pattern: /sk-[A-Za-z0-9_\-]{20,}/g, severity: 'critical', provider: 'OpenAI' },
  gitlab_token: { pattern: /glpat-[A-Za-z0-9\-_]{20}/g, severity: 'critical', provider: 'GitLab' },
  jwt: { pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*/g, severity: 'high', provider: 'JWT' },
  stripe_live: { pattern: /sk_live_[0-9a-zA-Z]{24}/g, severity: 'critical', provider: 'Stripe' },
  slack_token: { pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g, severity: 'high', provider: 'Slack' },
  postgres_uri: { pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@[^/]+\/\w+/gi, severity: 'critical', provider: 'PostgreSQL' },
  mongodb_uri: { pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^/]+/gi, severity: 'critical', provider: 'MongoDB' },
  rsa_private: { pattern: new RegExp('-----BEGIN RSA ' + 'PRIVATE KEY-----', 'g'), severity: 'critical', provider: 'RSA' },
  openssh_private: { pattern: new RegExp('-----BEGIN OPENSSH ' + 'PRIVATE KEY-----', 'g'), severity: 'critical', provider: 'OpenSSH' },
  password_field: { pattern: /password["\s]*[:=]["\s]*[^"'\s]{4,}/gi, severity: 'high', provider: 'Generic' },
  api_key_field: { pattern: /api[_-]?key["\s]*[:=]["\s]*["']?[A-Za-z0-9\-_]{16,}["']?/gi, severity: 'high', provider: 'Generic' },
};

export function redactString(value: string): string {
  let redacted = value;
  for (const [name, { pattern }] of Object.entries(SECRET_PATTERNS)) {
    pattern.lastIndex = 0;
    if (name === 'aws_secret_key') {
      // Skip a pure-hex 40/64-char run (SHA-1 / git commit SHA / TLS fingerprint / hex blob): a real
      // AWS secret is mixed-case base64 with /,+,= and is never all-hex, so this never misses one but
      // stops the pattern from corrupting legitimate hashes in served evidence.
      redacted = redacted.replace(pattern, (m) => (/^[0-9a-fA-F]+$/.test(m) ? m : '[redacted]'));
    } else {
      redacted = redacted.replace(pattern, '[redacted]');
    }
  }
  return redacted
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]{16,}/gi, 'Bearer [redacted]')
    .replace(/(api[_-]?key|token|secret|password)=([^&\s]+)/gi, '$1=[redacted]')
    // Generic URL userinfo (basic-auth): `scheme://user:pass@host` — the SECRET_PATTERNS only cover
    // postgres/mongodb URIs, so an http(s)/ssh/ftp login URL supplied to a gated tool would otherwise
    // carry its password verbatim into the arsenal-approval audit's target/action (served over both the
    // REST endpoint and the SSE feed). Scrub the whole userinfo up to the LAST `@` before the host, so a
    // password that itself contains `@` is fully covered; credential-free URLs are left untouched.
    .replace(/([a-z][a-z0-9+.-]*:\/\/)(?:[^/\s@]+@)+/gi, '$1[redacted]@');
}

export function redactLedgerText(value: string, limit = 4000): string {
  const redacted = redactString(value);
  if (redacted.length <= limit) return redacted;
  return `${redacted.slice(0, limit)}...[truncated ${redacted.length - limit} chars]`;
}

export function redactSecrets(value: unknown, seen = new WeakSet<object>()): unknown {
  if (typeof value === 'string') return redactString(value);
  if (value === null || typeof value !== 'object') return value;
  if (seen.has(value)) return '[circular]';
  seen.add(value);

  if (Array.isArray(value)) return value.map((item) => redactSecrets(item, seen));

  const result: Record<string, unknown> = {};
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    if (/(api[_-]?key|authorization|cookie|credential|password|secret|token)/i.test(key)) {
      result[key] = '[redacted]';
    } else {
      result[key] = redactSecrets(nested, seen);
    }
  }
  return result;
}
