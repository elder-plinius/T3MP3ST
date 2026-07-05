/**
 * Authorization guards for the MCP recon plane.
 *
 * The MCP server is a standalone stdio process with no access to a running mission's egress scope, so
 * it enforces parity with the HTTP recon endpoint's posture through these pure, dependency-free
 * helpers: local/lab targets are free, public targets require an operator-supplied allowlist, and an
 * option-looking ("-…") target is rejected before it can be reparsed as an nmap flag. Pure so they
 * unit-test in isolation (the server module runs its transport on import and can't be imported directly).
 */

/**
 * A valid recon target: a hostname / IPv4 / IPv6 literal with no shell metacharacters, AND not an
 * option-looking leading dash (which nmap would reparse as a flag — parity with the adapter/post-ex
 * argv guards that already reject a leading "-").
 */
export function validMcpTarget(target: unknown): target is string {
  return typeof target === 'string' && /^[A-Za-z0-9._:-]+$/.test(target) && !target.startsWith('-');
}

/** Loopback / RFC1918 / link-local "lab" target — reachable without an allowlist entry, mirroring the
 *  War Room recon endpoint's "local/lab free" posture. */
export function isLocalLabTarget(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === '::1' || h.endsWith('.local')
    || /^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h)
    || /^172\.(1[6-9]|2\d|3[01])\./.test(h)
    || /^169\.254\./.test(h);
}

/**
 * Decide whether MCP recon may scan a target. Local/lab targets are always allowed; a public target
 * must appear in `allowlist` exactly or as a subdomain; an invalid/option-looking target is refused.
 */
export function mcpTargetDecision(
  target: unknown,
  allowlist: string[],
): { allowed: true; host: string } | { allowed: false; reason: string } {
  if (!validMcpTarget(target)) {
    return {
      allowed: false,
      reason: 'Invalid target: only hostnames / IPv4 / IPv6 literals are allowed ([A-Za-z0-9._:-]), and a target may not begin with "-".',
    };
  }
  const host = target.toLowerCase();
  if (isLocalLabTarget(host)) return { allowed: true, host };
  const allow = allowlist.map((a) => a.trim().toLowerCase()).filter(Boolean);
  if (allow.some((a) => a === host || host.endsWith('.' + a))) return { allowed: true, host };
  return {
    allowed: false,
    reason: 'Target not authorized: a public target must be listed in T3MP3ST_MCP_ALLOWED_TARGETS (host or a parent domain). Local/lab targets are allowed by default.',
  };
}

/** Read the operator's public-target allowlist from the environment (comma-separated). */
export function mcpAllowlistFromEnv(env: NodeJS.ProcessEnv = process.env): string[] {
  return (env.T3MP3ST_MCP_ALLOWED_TARGETS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
}
