/**
 * T3MP3ST — Outbound SOCKS5 proxy for test/attack traffic
 * ========================================================
 *
 * WHY: an operator often does not want probe/attack traffic to leave from their
 * own IP (rate-limits, WAF bans, attribution, geo-testing). This module routes
 * ALL of Node's global `fetch` (undici) through a SOCKS5 proxy so every scattered
 * `fetch()` in the arsenal is covered by a single chokepoint — no per-call edits.
 *
 * HOW: undici's global dispatcher does not speak SOCKS natively (its ProxyAgent is
 * HTTP-only), so we build an undici `Agent` with a custom `connect` that opens a
 * SOCKS5 tunnel via the `socks` package, then hands the raw tunneled socket back to
 * undici (`httpSocket`) so undici still performs the TLS upgrade for https targets.
 *
 * LOOPBACK BYPASS (critical): the local LLM (llama.cpp/Ollama on 127.0.0.1) and the
 * server's own same-origin calls must NOT be tunneled — routing localhost through an
 * external SOCKS proxy would break them. `isLoopbackHost()` sends those direct.
 *
 * LEAK CHECK: checkIp() fetches ifconfig.co both through the (possibly proxied)
 * global dispatcher (the "exit" IP the targets see) and through a guaranteed-direct
 * dispatcher (the real IP). If they match, the proxy is off or broken → the caller
 * surfaces a "real IP exposed" warning.
 */

import { Agent, buildConnector, setGlobalDispatcher, fetch as undiciFetch } from 'undici';
import { SocksClient, type SocksProxy } from 'socks';
import tls from 'node:tls';
import { config } from '../config/index.js';

// ── parsed proxy shape ───────────────────────────────────────────────────────
interface ParsedProxy {
  socks: SocksProxy;
  host: string;
  port: number;
  type: 4 | 5;
  hasAuth: boolean;
}

// ── module state ─────────────────────────────────────────────────────────────
// A dedicated DIRECT dispatcher is kept alive for two jobs: (1) it's what we install
// as the global dispatcher when the proxy is OFF, and (2) checkIp() uses it to learn
// the real IP even while the proxy is ON.
// autoSelectFamily mirrors Node's built-in fetch (Happy Eyeballs / dual-stack): without
// it a bare undici Agent only tries the first-resolved address family and fails on
// IPv6-first hosts like ifconfig.co.
const directDispatcher = new Agent({ connect: { timeout: 10_000, autoSelectFamily: true } });
let currentUrl: string | null = null;
let enabled = false;

/**
 * Fetch without the configured attack-traffic proxy.
 *
 * Local model servers commonly live on RFC1918 addresses or private DNS names, not
 * just localhost. Giving those calls an explicit direct dispatcher avoids both
 * proxy leakage and brittle hostname heuristics/DNS races.
 */
export function directFetch(input: Parameters<typeof undiciFetch>[0], init: Parameters<typeof undiciFetch>[1] = {}) {
  return undiciFetch(input, { ...init, dispatcher: directDispatcher });
}

/** Keep ordinary global fetch semantics unless a proxy is active (important for callers/tests that instrument fetch). */
export function fetchBypassingProxy(
  input: Parameters<typeof undiciFetch>[0],
  init: Parameters<typeof undiciFetch>[1] = {},
) {
  return enabled ? directFetch(input, init) : globalThis.fetch(input as any, init as any);
}

// ── url parsing ──────────────────────────────────────────────────────────────
/**
 * Parse socks5://[user:pass@]host:port (also socks5h:// and socks4://).
 * socks5h = remote DNS resolution, which is what the SOCKS tunnel does anyway.
 * Returns null on anything malformed so the caller can fail gracefully.
 */
export function parseProxyUrl(raw: string): ParsedProxy | null {
  const s = (raw || '').trim();
  if (!s) return null;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  const scheme = u.protocol.replace(/:$/, '').toLowerCase();
  const type: 4 | 5 = scheme === 'socks4' || scheme === 'socks4a' ? 4 : 5;
  if (!['socks', 'socks5', 'socks5h', 'socks4', 'socks4a'].includes(scheme)) return null;
  const host = u.hostname;
  const port = Number(u.port);
  if (!host || !port || !Number.isInteger(port) || port < 1 || port > 65535) return null;

  const userId = u.username ? decodeURIComponent(u.username) : undefined;
  const password = u.password ? decodeURIComponent(u.password) : undefined;
  const socks: SocksProxy = {
    host,
    port,
    type,
    ...(userId ? { userId } : {}),
    ...(password ? { password } : {}),
  };
  return { socks, host, port, type, hasAuth: Boolean(userId || password) };
}

// ── loopback + API-provider bypass (bypass list) ─────────────────────────────
// LLM/API hosts whose operators block Tor exit IPs (Google 403s Tor egress;
// Anthropic/OpenAI are similarly hostile to datacenter exits). Routing the LLM
// backbone through the proxy would silently kill every mission call, so these
// are always fetched direct. Configurable via T3MP3ST_PROXY_BYPASS (comma list).
function isLoopbackHost(host: string | undefined): boolean {
  if (!host) return false;
  const h = host.toLowerCase().replace(/^\[|\]$/g, ''); // strip IPv6 brackets
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h === '::1' || h === '0.0.0.0' || h === '::') return true;
  if (h.startsWith('127.')) return true;
  const extra = (process.env.T3MP3ST_PROXY_BYPASS ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const builtin = [
    'generativelanguage.googleapis.com',
    'api.openai.com',
    'api.anthropic.com',
    'api.deepseek.com',
    'api.groq.com',
    'openrouter.ai',
    'api.ipify.org',
    'ip-api.com',
    'ipwho.is',
  ];
  for (const hostname of [...builtin, ...extra]) {
    if (h === hostname || h.endsWith('.' + hostname)) return true;
  }
  return false;
}

// ── SOCKS-aware undici connector ─────────────────────────────────────────────
/**
 * Build the `connect` function undici calls for every new upstream socket. Loopback
 * goes straight out; everything else is opened through the SOCKS tunnel and then the
 * raw socket is handed to undici's own connector (via `httpSocket`) so TLS still gets
 * negotiated for https:// destinations exactly as it would without a proxy.
 */
function makeConnect(proxy: SocksProxy) {
  // Loopback still uses undici's stock connector (net + optional TLS) unchanged.
  const direct = buildConnector({ timeout: 10_000 });
  return function connect(opts: any, callback: (err: Error | null, socket: any) => void): void {
    const hostname: string = opts.hostname;
    if (isLoopbackHost(hostname)) {
      direct(opts, callback);
      return;
    }
    const isTls = opts.protocol === 'https:';
    const destPort = Number(opts.port) || (isTls ? 443 : 80);
    SocksClient.createConnection({
      proxy,
      command: 'connect',
      destination: { host: hostname, port: destPort },
      timeout: 15_000,
    })
      .then(({ socket }) => {
        socket.setNoDelay(true);
        if (!isTls) {
          // Plain http: undici drives HTTP/1.1 directly over the raw tunnel.
          callback(null, socket);
          return;
        }
        // https: terminate TLS ourselves on top of the tunnel and hand undici a ready
        // secure socket. (undici's httpSocket upgrade path does NOT reliably fire for a
        // SOCKS-provided socket — it left the stream un-decrypted — so we do it explicitly.)
        const servername = opts.servername || hostname;
        const tlsSocket = tls.connect({
          socket,
          servername,
          ALPNProtocols: ['http/1.1'],
        });
        const onError = (err: Error) => { tlsSocket.destroy(); callback(err, null); };
        tlsSocket.once('error', onError);
        tlsSocket.once('secureConnect', () => {
          tlsSocket.removeListener('error', onError);
          callback(null, tlsSocket);
        });
      })
      .catch((err: Error) => callback(err, null));
  };
}

// ── public API ───────────────────────────────────────────────────────────────
export interface ProxyStatus {
  enabled: boolean;
  /** Credential-redacted URL, safe to show in UI/logs. */
  url: string | null;
  host: string | null;
  port: number | null;
  type: 4 | 5 | null;
}

/** Redact user:pass out of a proxy URL for display. */
function redactUrl(raw: string): string {
  try {
    const u = new URL(raw);
    if (u.username || u.password) {
      u.username = u.username ? '***' : '';
      u.password = u.password ? '***' : '';
    }
    return u.toString();
  } catch {
    return raw.replace(/\/\/[^@/]*@/, '//***@');
  }
}

/**
 * Enable/disable the outbound proxy. Pass a socks URL to enable, or null/'' to
 * disable (restores the direct dispatcher). Returns the resulting status or an error.
 */
export function configureProxy(url: string | null): ProxyStatus & { error?: string } {
  const wanted = (url || '').trim();
  if (!wanted) {
    setGlobalDispatcher(directDispatcher);
    currentUrl = null;
    enabled = false;
    return getProxyStatus();
  }
  const parsed = parseProxyUrl(wanted);
  if (!parsed) {
    return { ...getProxyStatus(), error: `Invalid SOCKS proxy URL: ${redactUrl(wanted)} (expected socks5://[user:pass@]host:port)` };
  }
  const agent = new Agent({ connect: makeConnect(parsed.socks) });
  // setGlobalDispatcher writes Symbol.for('undici.globalDispatcher.2') (undici >= 8).
  // Node's built-in fetch reads that SAME symbol, so this transparently proxies every
  // scattered global fetch() — VERIFIED e2e on Node 24.18 + undici 8.7. If a much older
  // Node (whose internal undici used the '.1' symbol) is ever targeted, this alignment
  // would break; pin/upgrade undici to match, or route arsenal fetch through undici's fetch.
  setGlobalDispatcher(agent);
  currentUrl = wanted;
  enabled = true;
  installBypassFetchWrapper();
  return getProxyStatus();
}

// ── fetch-level bypass ───────────────────────────────────────────────────────
// HTTPS through a custom-connect Agent mis-parses responses (lost headers, raw
// gzip bodies) even on the connect-level direct path. So bypassed hosts are
// fetched with the STOCK direct dispatcher instead of the proxied agent —
// loopback AND API providers whose operators block Tor (Google 403s Tor egress)
// keep working while everything else tunnels.
let bypassWrapperInstalled = false;

function installBypassFetchWrapper(): void {
  if (bypassWrapperInstalled) return;
  bypassWrapperInstalled = true;
  const typedFetch = globalThis.fetch as unknown as (
    input: Parameters<typeof undiciFetch>[0],
    init?: Parameters<typeof undiciFetch>[1],
  ) => ReturnType<typeof undiciFetch>;
  globalThis.fetch = ((input: Parameters<typeof undiciFetch>[0], init?: Parameters<typeof undiciFetch>[1]) => {
    try {
      const url = typeof input === 'string' ? new URL(input) : input instanceof URL ? input : new URL((input as Request).url);
      if (isLoopbackHost(url.hostname)) {
        return undiciFetch(input, { ...init, dispatcher: directDispatcher });
      }
    } catch { /* non-URL input — fall through */ }
    return typedFetch(input, init);
  }) as typeof globalThis.fetch;
}

export function getProxyStatus(): ProxyStatus {
  if (!enabled || !currentUrl) {
    return { enabled: false, url: null, host: null, port: null, type: null };
  }
  const parsed = parseProxyUrl(currentUrl);
  return {
    enabled: true,
    url: redactUrl(currentUrl),
    host: parsed?.host ?? null,
    port: parsed?.port ?? null,
    type: parsed?.type ?? null,
  };
}

/**
 * Read the persisted/env proxy config (TEMPEST_PROXY_URL or saved settings) and
 * install it. Safe to call at startup; a bad/missing URL just leaves us direct.
 * Returns the effective status so the boot log can report it.
 */
export function initProxyFromConfig(): ProxyStatus & { error?: string } {
  const url = config.getProxyUrl();
  if (!url) return getProxyStatus();
  return configureProxy(url);
}

// ── IP / leak checker ────────────────────────────────────────────────────────
export interface IpInfo {
  ip: string | null;
  country?: string | null;
  city?: string | null;
  asnOrg?: string | null;
  source: string;
}

export interface IpCheckResult {
  proxyEnabled: boolean;
  proxy: ProxyStatus;
  /** IP the world sees for outbound test traffic (through the proxy when on). */
  exit: IpInfo;
  /** The operator's real IP (always fetched direct, bypassing the proxy). */
  direct: IpInfo;
  /**
   * True when the exit IP equals the real IP — i.e. either no proxy is configured,
   * or the proxy is not actually changing our egress. Surface this as a leak warning.
   */
  leak: boolean;
  checkedAt: string;
}

const IP_TIMEOUT_MS = 12_000;
// ifconfig.co is the primary (as requested); ipify is a bare-IP fallback if it's down.
const IFCONFIG_JSON = 'https://ifconfig.co/json';
const IPIFY_FALLBACK = 'https://api.ipify.org?format=json';

/**
 * Fetch outbound IP info. `direct=true` forces the guaranteed-direct dispatcher so we
 * can read the real IP even while the global dispatcher is proxied.
 */
async function fetchIp(direct: boolean): Promise<IpInfo> {
  // Use undici's fetch (not Node's global) so we can pass an explicit `dispatcher`:
  // Node's built-in fetch throws UND_ERR_INVALID_ARG on a dispatcher from the separately
  // installed undici package. `direct` forces the always-direct dispatcher (real IP);
  // otherwise undici's global dispatcher is used (proxied when the proxy is on).
  const opts: any = {
    signal: AbortSignal.timeout(IP_TIMEOUT_MS),
    // ifconfig.co returns HTML to browser UAs; a curl-style UA guarantees JSON.
    headers: { 'User-Agent': 'curl/8.4.0', accept: 'application/json' },
  };
  if (direct) opts.dispatcher = directDispatcher;
  try {
    const res = await undiciFetch(IFCONFIG_JSON, opts);
    if (res.ok) {
      const j: any = await res.json();
      return {
        ip: j.ip ?? null,
        country: j.country ?? null,
        city: j.city ?? null,
        asnOrg: j.asn_org ?? null,
        source: 'ifconfig.co',
      };
    }
  } catch {
    /* fall through to fallback */
  }
  // Fallback: bare IP only.
  const fbOpts: any = { signal: AbortSignal.timeout(IP_TIMEOUT_MS) };
  if (direct) fbOpts.dispatcher = directDispatcher;
  const res = await undiciFetch(IPIFY_FALLBACK, fbOpts);
  const j: any = await res.json();
  return { ip: j.ip ?? null, source: 'api.ipify.org' };
}

// Short cache so the UI badge can poll cheaply without hammering ifconfig.co.
let cache: { at: number; result: IpCheckResult } | null = null;
const CACHE_MS = 15_000;

/**
 * Resolve exit + real IP and compute the leak flag. Cached for CACHE_MS; pass
 * force=true (e.g. right after changing the proxy) to bypass the cache.
 * Uses a monotonic-ish timestamp derived from the caller so we stay deterministic
 * where possible; falls back to performance.now for cache aging.
 */
export async function checkIp(force = false): Promise<IpCheckResult> {
  const now = performance.now();
  if (!force && cache && now - cache.at < CACHE_MS) return cache.result;

  const proxyOn = enabled;
  // Exit uses the global dispatcher (proxied when on). Direct always bypasses.
  const [exit, direct] = await Promise.all([
    fetchIp(false).catch((e) => ({ ip: null, source: `error: ${String(e?.message || e)}` } as IpInfo)),
    fetchIp(true).catch((e) => ({ ip: null, source: `error: ${String(e?.message || e)}` } as IpInfo)),
  ]);

  const leak = Boolean(exit.ip && direct.ip && exit.ip === direct.ip);
  const result: IpCheckResult = {
    proxyEnabled: proxyOn,
    proxy: getProxyStatus(),
    exit,
    direct,
    leak,
    checkedAt: new Date().toISOString(),
  };
  cache = { at: now, result };
  return result;
}

/** Drop the IP cache (call after (re)configuring the proxy). */
export function invalidateIpCache(): void {
  cache = null;
}
