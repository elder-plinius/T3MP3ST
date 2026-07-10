// =============================================================================
// SSRF guard — DNS-resolving URL validator
// Blocks private, loopback, link-local, and CGNAT destinations even when the
// caller supplies a DNS name that resolves to a denied address (DNS rebinding).
// =============================================================================

import { lookup } from 'node:dns/promises';
import net from 'node:net';

/**
 * Returns true for any IPv4 or IPv6 address that must not be a webhook/MCP target.
 * Covers RFC1918, loopback, link-local, CGNAT, and ::1 / fe80:: / fc:: / fd::.
 */
export function isDeniedIp(address: string): boolean {
  if (net.isIPv4(address)) {
    const parts = address.split('.').map(Number);
    const [a, b] = parts;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||   // CGNAT / shared
      (a === 169 && b === 254) ||               // link-local
      (a === 172 && b >= 16 && b <= 31) ||      // RFC1918
      (a === 192 && b === 168)                  // RFC1918
    );
  }
  if (net.isIPv6(address)) {
    const lower = address.toLowerCase();
    return (
      lower === '::1' ||
      lower.startsWith('fe80:') ||
      lower.startsWith('fc') ||
      lower.startsWith('fd')
    );
  }
  return true; // unrecognized format → deny
}

/**
 * Validates that `raw` is a public http:// or https:// URL whose hostname
 * resolves exclusively to non-private addresses.
 *
 * Throws a descriptive Error on any denial. Returns the parsed URL on success.
 */
export async function assertPublicHttpUrl(raw: string, label = 'URL'): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${label} is not a valid URL`);
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`${label} must be http:// or https://`);
  }

  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  // Fast-path: literal IP — no DNS needed
  if (net.isIPv4(hostname) || net.isIPv6(hostname)) {
    if (isDeniedIp(hostname)) {
      throw new Error(`${label} must not target private, loopback, or link-local addresses`);
    }
    return url;
  }

  // DNS resolution — reject if ANY resolved address is denied
  let records: { address: string }[];
  try {
    records = await lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new Error(`${label} hostname "${hostname}" could not be resolved`);
  }

  if (!records.length) {
    throw new Error(`${label} hostname "${hostname}" resolved to no addresses`);
  }

  const denied = records.find((r) => isDeniedIp(r.address));
  if (denied) {
    throw new Error(
      `${label} must not resolve to private, loopback, or link-local addresses (resolved: ${denied.address})`,
    );
  }

  return url;
}
