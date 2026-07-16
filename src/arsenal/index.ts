/**
 * T3MP3ST Arsenal
 *
 * Tool registry and execution management.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import { execFile } from 'child_process';
import { mkdtemp, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { promisify } from 'util';
import * as net from 'net';
import * as dns from 'dns';
import * as tls from 'tls';
import { ApprovalController, isGatedRisk, type ApprovalRequest } from './approval.js';

const execFileAsync = promisify(execFile);
import type {
  CustomTool,
  ToolContext,
  ToolResult,
  Target,
  LLMToolDefinition,
  RiskTier,
} from '../types/index.js';

const dnsResolve = promisify(dns.resolve);
const dnsResolve4 = promisify(dns.resolve4);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveNs = promisify(dns.resolveNs);
const dnsReverse = promisify(dns.reverse);

import { CVE_DATABASE } from '../stubs/index.js';
import type { CVEEntry } from '../stubs/index.js';

// =============================================================================
// PORT SCANNING UTILITY
// =============================================================================

async function checkPort(host: string, port: number, timeout: number = 2000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);

    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });

    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });

    socket.connect(port, host);
  });
}

// =============================================================================
// TARGET HEADER INJECTION
// =============================================================================

interface TargetHeaderConfig {
  origin: string;
  headers: Headers;
}

const FORBIDDEN_TARGET_HEADERS = new Set([
  'connection', 'content-length', 'host', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

/** Parse an exact-origin binding and its default headers. Invalid configuration fails closed. */
function parseTargetHeaderConfig(): TargetHeaderConfig | null {
  const rawOrigin = process.env.TEMPEST_TARGET_ORIGIN?.trim();
  const rawHeaders = process.env.TEMPEST_TARGET_HEADERS?.trim();
  if (!rawOrigin || !rawHeaders) return null;

  try {
    const target = new URL(rawOrigin);
    if (!['http:', 'https:'].includes(target.protocol)
      || target.username || target.password
      || target.pathname !== '/' || target.search || target.hash) {
      return null;
    }

    const parsed: unknown = JSON.parse(rawHeaders);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;

    const headers = new Headers();
    for (const [name, value] of Object.entries(parsed)) {
      if (typeof value !== 'string' || FORBIDDEN_TARGET_HEADERS.has(name.toLowerCase())) return null;
      headers.set(name, value);
    }
    return headers.keys().next().done ? null : { origin: target.origin, headers };
  } catch {
    return null;
  }
}

function targetHeadersForUrl(url: string | URL, explicit?: RequestInit['headers']): Headers | undefined {
  const merged = new Headers();
  const config = parseTargetHeaderConfig();
  try {
    if (config && new URL(url).origin === config.origin) {
      config.headers.forEach((value, name) => merged.set(name, value));
    }
  } catch {
    // Let fetch or curl report malformed URLs; they simply receive no configured secrets.
  }
  new Headers(explicit).forEach((value, name) => merged.set(name, value));
  return merged.keys().next().done ? undefined : merged;
}

function redactConfiguredSecrets(result: ToolResult): ToolResult {
  const config = parseTargetHeaderConfig();
  const secrets = config ? [...config.headers.values()].filter(Boolean) : [];
  if (secrets.length === 0) return result;

  const redact = (value: unknown): unknown => {
    if (typeof value === 'string') {
      return secrets.reduce((text, secret) => text.split(secret).join('[REDACTED]'), value);
    }
    if (Array.isArray(value)) return value.map(redact);
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([key, nested]) => [key, redact(nested)]));
    }
    return value;
  };
  return redact(result) as ToolResult;
}

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);
const CROSS_ORIGIN_CREDENTIAL_HEADERS = ['authorization', 'cookie', 'cookie2', 'proxy-authorization'];

/** Apply exact-origin headers to every built-in fetch without leaking them across redirects. */
async function targetFetch(url: string | URL, init: RequestInit = {}): Promise<Response> {
  const config = parseTargetHeaderConfig();
  let currentUrl = new URL(url);
  if (!config || currentUrl.origin !== config.origin) return globalThis.fetch(url, init);

  const explicitHeaders = new Headers(init.headers);
  let method = (init.method || 'GET').toUpperCase();
  let body = init.body;

  for (let redirects = 0; redirects <= 20; redirects++) {
    const headers = targetHeadersForUrl(currentUrl, explicitHeaders);
    const response = await globalThis.fetch(currentUrl, { ...init, method, body, headers, redirect: 'manual' });
    const location = response.headers.get('location');
    if (!REDIRECT_STATUS.has(response.status) || !location) return response;
    if (redirects === 20) throw new Error('Target request exceeded 20 redirects');

    const nextUrl = new URL(location, currentUrl);
    if (nextUrl.origin !== currentUrl.origin) {
      config.headers.forEach((_value, name) => explicitHeaders.delete(name));
      CROSS_ORIGIN_CREDENTIAL_HEADERS.forEach(name => explicitHeaders.delete(name));
    }
    if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === 'POST')) {
      method = 'GET';
      body = undefined;
      ['content-encoding', 'content-language', 'content-location', 'content-type'].forEach(name => explicitHeaders.delete(name));
    }
    currentUrl = nextUrl;
  }
  throw new Error('Target request redirect handling failed');
}

// =============================================================================
// EVENTS
// =============================================================================

export interface ArsenalEvents {
  'tool:registered': CustomTool;
  'tool:executed': { tool: CustomTool; result: ToolResult; durationMs: number };
  'tool:error': { tool: CustomTool; error: Error };
}

export interface ToolExecution {
  id: string;
  toolName: string;
  startedAt: number;
  completedAt?: number;
  result?: ToolResult;
  error?: string;
}

// =============================================================================
// ARSENAL
// =============================================================================

// ── Egress scope gate (Phase-0 pack-hunt safety primitive) ──────────────────────────────────
// A HARD allowlist enforced inside Arsenal.execute() BEFORE any handler runs, so an LLM-supplied
// tool target can never reach an out-of-scope host. When no scope is set (library/test mode)
// enforcement is off; the server/mission sets it from the authorized targets so live runs are gated.
// This closes the "a keyless pack operator fires nuclei/nmap/sqlmap at an off-target host" hole:
// the only prior scope check was at the HTTP boundary, keyed to the mission target — the per-tool
// target the model actually supplies was never checked.
export interface ArsenalScope {
  /** exact hosts / registrable domains explicitly authorized (subdomains allowed) */
  allowedHosts: string[];
  /** allow 127.0.0.0/8, localhost, ::1 */
  allowLoopback: boolean;
  /** allow RFC-1918 / link-local / ULA lab ranges */
  allowPrivate: boolean;
}

/** The parameter keys a networked tool reads its target from (dns/web/vuln handlers). */
const SCOPE_TARGET_KEYS = ['url', 'target', 'host', 'hostname', 'domain', 'address', 'ip', 'endpoint', 'base_url', 'rhosts', 'rhost'];

/** Normalize a target-ish value to a bare lowercase host (strip scheme/user/port/path). null if not host-like. */
export function hostFromTargetValue(v: unknown): string | null {
  if (typeof v !== 'string' || !v.trim()) return null;
  let s = v.trim();
  try { if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = new URL(s).hostname; } catch { /* treat as bare host */ }
  s = s.replace(/^[^@/]*@/, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  return s.toLowerCase() || null;
}

function isLoopbackTargetHost(h: string): boolean {
  return h === 'localhost' || h === '::1' || /^127(?:\.\d{1,3}){3}$/.test(h);
}
function isPrivateTargetHost(h: string): boolean {
  return /^10(?:\.\d{1,3}){3}$/.test(h)
    || /^192\.168(?:\.\d{1,3}){2}$/.test(h)
    || /^172\.(1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}$/.test(h)
    || /^169\.254(?:\.\d{1,3}){2}$/.test(h)          // link-local
    || /^(fc|fd)[0-9a-f]{2}:/i.test(h);              // IPv6 ULA
}

/** The narrowest CIDR prefix that keeps a private/loopback host's whole block in scope — a wider
 *  (smaller-number) mask would spill outside it. Used to scope-validate a CIDR TARGET's range. */
function privateBlockMinMask(h: string): number {
  if (/^192\.168\./.test(h) || /^169\.254\./.test(h)) return 16;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return 12;
  return 8; // 10/8, 127/8, and (conservatively) IPv6 ULA
}

/** null = in scope (or no host to check); otherwise the out-of-scope host/range that must be blocked. */
export function scopeViolation(scope: ArsenalScope | null, context: ToolContext): string | null {
  if (!scope) return null; // enforcement off until configured
  // FAIL CLOSED on a value that LOOKS like a network target (scheme-relative "//host" or a
  // "scheme://…") but yields no parseable host — that's the bypass ("//evil.com" /
  // "file:///etc/passwd" host-normalize to an empty string and would otherwise slip past the gate).
  // A plain local path ("/code/src") is NOT a network target and has no host, so it's skipped — local
  // file-analysis tools (semgrep/trivy/slither) keep working. (adversarial-review C1)
  const bypassLooking = (v: string): boolean => v.startsWith('//') || v.includes('://');
  const candidates: Array<{ h: string; v: string }> = [];
  const raws: unknown[] = [context.target?.address, ...SCOPE_TARGET_KEYS.map((k) => (context.parameters || {})[k])];
  for (const raw of raws) {
    if (typeof raw !== 'string' || !raw.trim()) continue;
    const v = raw.trim();
    const h = hostFromTargetValue(v);
    if (!h) {
      if (bypassLooking(v)) return v; // network-target-shaped but unparseable → block
      continue; // plain path / non-network value → not a scope target
    }
    candidates.push({ h, v });
  }
  const allow = scope.allowedHosts.map(a => a.toLowerCase());
  for (const { h, v } of candidates) {
    // How is the BASE host admitted — and what CIDR prefix keeps the WHOLE range inside that block?
    // hostFromTargetValue strips the mask, so "10.0.0.0/0" (base 10.0.0.0 private) would otherwise
    // sweep the entire internet past a scope authorizing only that base. Validate the range, not the
    // base. (adversarial-review CIDR mask-strip escape)
    let minMask: number;
    if (scope.allowLoopback && isLoopbackTargetHost(h)) minMask = 8;              // 127/8, ::1
    else if (scope.allowPrivate && isPrivateTargetHost(h)) minMask = privateBlockMinMask(h);
    else if (allow.some(a => a === h || h.endsWith('.' + a))) minMask = 32;        // exact-allowed host → only /32
    else return h; // base host out of scope
    // treat a trailing "/N" as a CIDR mask ONLY on a bare host/ip (no scheme) — not a URL path segment.
    const cidr = !v.includes('://') && v.match(/^[^/]+\/(\d{1,3})$/);
    if (cidr && parseInt(cidr[1], 10) < minMask) return v; // CIDR range extends beyond the authorized block
  }
  return null;
}

/** Best-effort target for an approval request/warning — the first target-like param, else the
 *  context target address. Informational only (the scope gate does the real host math). */
function approvalTargetOf(context: ToolContext): string | undefined {
  const params = context.parameters || {};
  for (const k of SCOPE_TARGET_KEYS) {
    const v = params[k];
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return context.target?.address;
}

/** A one-line human-readable summary of a tool call — tool + a few scalar params + target — for the
 *  approval warning and the audit trail. Object/array params are omitted to keep it short + safe. */
function describeToolAction(toolName: string, context: ToolContext): string {
  const summary = Object.entries(context.parameters || {})
    .filter(([, v]) => v !== undefined && v !== null && typeof v !== 'object')
    .slice(0, 4)
    .map(([k, v]) => `${k}=${String(v).slice(0, 48)}`)
    .join(' ');
  const target = approvalTargetOf(context);
  return `${toolName}${summary ? ` (${summary})` : ''}${target ? ` → ${target}` : ''}`;
}

export class Arsenal extends EventEmitter<ArsenalEvents> {
  private tools: Map<string, CustomTool> = new Map();
  /** Authorized egress scope; null = enforcement off (set by the server/mission for live runs). */
  private scope: ArsenalScope | null = null;
  /** Capability approval gate; null = gating off (backward-compat). The engine wires one for live runs. */
  private approval: ApprovalController | null = null;
  private executions: ToolExecution[] = [];

  /**
   * Register a tool
   */
  register(tool: CustomTool): void {
    this.tools.set(tool.name, tool);
    this.emit('tool:registered', tool);
  }

  /**
   * Register multiple tools
   */
  registerMany(tools: CustomTool[]): void {
    for (const tool of tools) {
      this.register(tool);
    }
  }

  /**
   * Get a tool by name
   */
  getTool(name: string): CustomTool | undefined {
    return this.tools.get(name);
  }

  /**
   * Get all tools
   */
  getAllTools(): CustomTool[] {
    return Array.from(this.tools.values());
  }

  /**
   * Get tools by category
   */
  getToolsByCategory(category: string): CustomTool[] {
    return this.getAllTools().filter(t => t.category === category);
  }

  /** Set (or clear with null) the authorized egress scope enforced in execute(). */
  setScope(scope: ArsenalScope | null): void { this.scope = scope; }
  getScope(): ArsenalScope | null { return this.scope; }

  /** Set (or clear) the capability-approval gate enforced in execute() for intrusive/dangerous tools. */
  setApprovalController(approval: ApprovalController | null): void { this.approval = approval; }
  getApprovalController(): ApprovalController | null { return this.approval; }

  /**
   * Execute a tool
   */
  async execute(
    toolName: string,
    context: ToolContext
  ): Promise<ToolResult> {
    const tool = this.tools.get(toolName);
    if (!tool) {
      throw new Error(`Tool "${toolName}" not found`);
    }

    // Egress scope gate: deny out-of-scope network targets BEFORE the handler runs. A tool call
    // never reaches a host outside the authorized scope, regardless of what the model supplied.
    const blockedHost = scopeViolation(this.scope, context);
    if (blockedHost) {
      const denied: ToolResult = {
        success: false,
        error: `SCOPE DENIED: target '${blockedHost}' is not in the authorized scope — ${toolName} refused before execution. Only authorized / loopback / lab targets are permitted.`,
      };
      this.emit('tool:error', { tool, error: new Error(denied.error) });
      return denied;
    }

    // Capability approval + spicy-action warning gate: an intrusive/credential/dangerous tool is inert
    // until it has been approved (interactively "approve once, then free", or via the headless
    // pre-authorization allowlist); the hottest actions also fire a loud, audited, non-blocking
    // warning. Safe/active tools pass straight through. No controller wired = gating off (backward-compat).
    if (this.approval && isGatedRisk(tool.riskTier)) {
      const request: ApprovalRequest = {
        tool: toolName,
        risk: tool.riskTier,
        operator: context.operator,
        target: approvalTargetOf(context),
        action: describeToolAction(toolName, context),
      };
      const decision = await this.approval.gate(request);
      if (!decision.allowed) {
        const denied: ToolResult = { success: false, error: `APPROVAL REQUIRED: ${decision.reason}` };
        this.emit('tool:error', { tool, error: new Error(denied.error) });
        return denied;
      }
    }

    const execution: ToolExecution = {
      id: randomUUID(),
      toolName,
      startedAt: Date.now(),
    };
    this.executions.push(execution);

    const startTime = Date.now();

    try {
      const result = redactConfiguredSecrets(await tool.handler(context));
      const durationMs = Date.now() - startTime;

      execution.completedAt = Date.now();
      execution.result = result;

      this.emit('tool:executed', { tool, result, durationMs });

      return result;
    } catch (error) {
      execution.completedAt = Date.now();
      execution.error = redactConfiguredSecrets({
        success: false,
        error: error instanceof Error ? error.message : String(error),
      }).error;

      this.emit('tool:error', { tool, error: error as Error });

      return {
        success: false,
        error: execution.error,
      };
    }
  }

  /**
   * Get execution history
   */
  getExecutions(): ToolExecution[] {
    return [...this.executions];
  }

  /**
   * Get tool categories
   */
  getCategories(): string[] {
    const categories = new Set<string>();
    for (const tool of this.tools.values()) {
      categories.add(tool.category);
    }
    return Array.from(categories);
  }

  /**
   * Convert registered tools to LLM tool definitions for function calling
   */
  getToolDefinitions(categories?: string[], names?: string[]): LLMToolDefinition[] {
    let tools = this.getAllTools();
    // A per-operator NAME allowlist (the archetype's role toolkit) is the precise gate and
    // takes precedence over the coarse category filter; fall back to categories, then to all.
    if (names?.length) {
      tools = tools.filter(t => names.includes(t.name));
    } else if (categories?.length) {
      tools = tools.filter(t => categories.includes(t.category));
    }
    return tools.map(tool => {
      const properties: Record<string, { type: string; description?: string; enum?: string[]; default?: unknown }> = {};
      const required: string[] = [];

      for (const param of tool.parameters || []) {
        properties[param.name] = {
          type: param.type,
          description: param.description,
        };
        if (param.default !== undefined) {
          properties[param.name].default = param.default;
        }
        if (param.required) {
          required.push(param.name);
        }
      }

      return {
        name: tool.name,
        description: tool.description,
        parameters: {
          type: 'object' as const,
          properties,
          required: required.length > 0 ? required : undefined,
        },
      };
    });
  }

  /**
   * Unregister a tool
   */
  unregister(name: string): boolean {
    return this.tools.delete(name);
  }

  /**
   * Clear all tools
   */
  clear(): void {
    this.tools.clear();
    this.executions = [];
  }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

export function successResult(output: string, findings?: ToolResult['findings']): ToolResult {
  return {
    success: true,
    output,
    findings,
  };
}

export function failResult(error: string): ToolResult {
  return {
    success: false,
    error,
  };
}

export function createToolContext(
  target?: Target,
  parameters?: Record<string, unknown>
): ToolContext {
  return {
    target,
    parameters: parameters || {},
  };
}

// =============================================================================
// BUILT-IN TOOLS
// =============================================================================

/**
 * The built-in probes that are genuinely "spicy" — live credential attacks and active injection
 * testing. They ship UNGATED (no riskTier below) so every prior run and the headline benchmark keep
 * firing them freely — their safety boundary is the always-on egress scope gate. An operator who wants
 * the approval fail-safe to blanket these too opts in with T3MP3ST_GATE_BUILTINS=1, which applies these
 * tiers via stampSpicyBuiltin() at registration. Kept here, next to BUILTIN_TOOLS, as the single source
 * of truth for which built-ins are spicy.
 */
export const SPICY_BUILTIN_TIERS: Readonly<Record<string, RiskTier>> = {
  password_spray: 'credential',
  hash_crack: 'credential',
  sqli_scan: 'intrusive',
  xss_scan: 'intrusive',
};

/** Copy of `tool` stamped with a gated riskTier iff it is a spicy built-in that isn't already tiered;
 *  otherwise the tool unchanged. Never mutates the shared BUILTIN_TOOLS array — only clones when it
 *  stamps — so the default (ungated) registration and this opt-in path can coexist. */
export function stampSpicyBuiltin(tool: CustomTool): CustomTool {
  const tier = SPICY_BUILTIN_TIERS[tool.name];
  return tier && tool.riskTier === undefined ? { ...tool, riskTier: tier } : tool;
}

export const BUILTIN_TOOLS: CustomTool[] = [
  // =============================================================================
  // RECONNAISSANCE TOOLS
  // =============================================================================
  {
    name: 'dns_lookup',
    description: 'Perform DNS lookup for a target',
    category: 'recon',
    parameters: [
      { name: 'domain', type: 'string', description: 'Domain to lookup', required: true },
      { name: 'type', type: 'string', description: 'Record type (A, AAAA, MX, TXT, NS)', required: false, default: 'A' },
    ],
    handler: async (context) => {
      const domain = context.parameters.domain as string;
      const recordType = (context.parameters.type as string || 'A').toUpperCase();

      try {
        let records: string[] = [];

        switch (recordType) {
          case 'A':
            records = await dnsResolve4(domain);
            break;
          case 'MX': {
            const mxRecords = await dnsResolveMx(domain);
            records = mxRecords.map(r => `${r.priority} ${r.exchange}`);
            break;
          }
          case 'TXT': {
            const txtRecords = await dnsResolveTxt(domain);
            records = txtRecords.map(r => r.join(''));
            break;
          }
          case 'NS':
            records = await dnsResolveNs(domain);
            break;
          default:
            records = await dnsResolve(domain, recordType) as string[];
        }

        return {
          success: true,
          output: `DNS ${recordType} lookup for ${domain}:\n${records.join('\n')}`,
        };
      } catch (error) {
        return {
          success: false,
          error: `DNS lookup failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },
  {
    name: 'port_scan',
    description: 'Scan ports on a target (real TCP connect scan)',
    category: 'recon',
    parameters: [
      { name: 'target', type: 'string', description: 'Target IP or hostname', required: true },
      { name: 'ports', type: 'string', description: 'Ports to scan (e.g., "22,80,443")', required: false, default: '22,80,443,8080' },
      { name: 'timeout', type: 'number', description: 'Timeout per port in ms', required: false, default: 2000 },
    ],
    handler: async (context) => {
      const target = context.parameters.target as string || context.target?.address;
      if (!target) {
        return { success: false, error: 'No target specified' };
      }

      const portsStr = context.parameters.ports as string || '22,80,443,8080';
      const ports = portsStr.split(',').map(p => parseInt(p.trim(), 10)).filter(p => !isNaN(p));
      const timeout = (context.parameters.timeout as number) || 2000;

      const portServices: Record<number, string> = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
        3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
        6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt', 27017: 'mongodb',
      };

      const results: string[] = [];
      const openPorts: number[] = [];

      // Scan ports in parallel with concurrency limit
      const concurrency = 10;
      for (let i = 0; i < ports.length; i += concurrency) {
        const batch = ports.slice(i, i + concurrency);
        const checks = await Promise.all(
          batch.map(async (port) => {
            const isOpen = await checkPort(target, port, timeout);
            return { port, isOpen };
          })
        );

        for (const { port, isOpen } of checks) {
          if (isOpen) {
            openPorts.push(port);
            results.push(`${port}/tcp open ${portServices[port] || 'unknown'}`);
          } else {
            results.push(`${port}/tcp closed`);
          }
        }
      }

      return {
        success: true,
        output: `Port scan of ${target} (${ports.length} ports scanned):\n${results.join('\n')}\n\nOpen ports: ${openPorts.length}`,
        findings: openPorts.length > 0 ? [{
          title: 'Open Ports Detected',
          severity: 'info',
          details: `Found ${openPorts.length} open ports: ${openPorts.join(', ')}`,
        }] : undefined,
      };
    },
  },
  {
    name: 'subdomain_enum',
    description: 'Enumerate subdomains for a domain (real DNS resolution)',
    category: 'recon',
    parameters: [
      { name: 'domain', type: 'string', description: 'Domain to enumerate', required: true },
      { name: 'wordlist', type: 'string', description: 'Wordlist: common, extended', required: false, default: 'common' },
    ],
    handler: async (context) => {
      const domain = context.parameters.domain as string;
      const wordlistType = context.parameters.wordlist as string || 'common';

      const wordlists: Record<string, string[]> = {
        common: ['www', 'mail', 'ftp', 'admin', 'dev', 'staging', 'api', 'app', 'cdn', 'static', 'test', 'blog', 'shop', 'store', 'portal', 'secure', 'vpn', 'remote', 'webmail', 'ns1', 'ns2'],
        extended: ['www', 'mail', 'ftp', 'admin', 'dev', 'staging', 'api', 'app', 'cdn', 'static', 'test', 'blog', 'shop', 'store', 'portal', 'secure', 'vpn', 'remote', 'webmail', 'ns1', 'ns2', 'mx', 'smtp', 'pop', 'imap', 'cpanel', 'whm', 'webdisk', 'autodiscover', 'autoconfig', 'git', 'gitlab', 'jenkins', 'ci', 'jira', 'confluence', 'wiki', 'docs', 'status', 'monitor', 'grafana', 'prometheus', 'elastic', 'kibana', 'redis', 'mysql', 'postgres', 'mongo', 'db', 'database', 'backup', 'files', 'media', 'assets', 'images', 'img', 'video', 'download', 'upload'],
      };

      const prefixes = wordlists[wordlistType] || wordlists.common;
      const found: { subdomain: string; ip: string }[] = [];

      // Check subdomains in parallel with concurrency limit
      const concurrency = 10;
      for (let i = 0; i < prefixes.length; i += concurrency) {
        const batch = prefixes.slice(i, i + concurrency);
        const checks = await Promise.all(
          batch.map(async (prefix) => {
            const subdomain = `${prefix}.${domain}`;
            try {
              const addresses = await dnsResolve4(subdomain);
              return { subdomain, ip: addresses[0], found: true };
            } catch {
              return { subdomain, ip: '', found: false };
            }
          })
        );

        for (const result of checks) {
          if (result.found) {
            found.push({ subdomain: result.subdomain, ip: result.ip });
          }
        }
      }

      if (found.length === 0) {
        return {
          success: true,
          output: `Subdomain enumeration for ${domain}:\nNo subdomains found from ${prefixes.length} candidates tested.`,
        };
      }

      const output = found.map(f => `${f.subdomain} -> ${f.ip}`).join('\n');
      return {
        success: true,
        output: `Subdomain enumeration for ${domain}:\nFound ${found.length} subdomains (tested ${prefixes.length}):\n${output}`,
        findings: [{
          title: 'Subdomains Discovered',
          severity: 'info',
          details: `Found ${found.length} active subdomains`,
        }],
      };
    },
  },
  {
    name: 'whois_lookup',
    description: 'Perform WHOIS lookup for a domain (real WHOIS query)',
    category: 'recon',
    parameters: [
      { name: 'domain', type: 'string', description: 'Domain to lookup', required: true },
    ],
    handler: async (context) => {
      const domain = context.parameters.domain as string;

      // Determine WHOIS server based on TLD
      const tld = domain.split('.').pop()?.toLowerCase() || '';
      const whoisServers: Record<string, string> = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'info': 'whois.afilias.net',
        'biz': 'whois.biz',
        'me': 'whois.nic.me',
        'dev': 'whois.nic.google',
        'app': 'whois.nic.google',
        'uk': 'whois.nic.uk',
        'de': 'whois.denic.de',
        'fr': 'whois.nic.fr',
        'eu': 'whois.eu',
        'nl': 'whois.domain-registry.nl',
        'au': 'whois.auda.org.au',
      };

      const whoisServer = whoisServers[tld] || `whois.nic.${tld}`;

      return new Promise((resolve) => {
        const socket = new net.Socket();
        let data = '';

        socket.setTimeout(10000);

        socket.on('connect', () => {
          socket.write(`${domain}\r\n`);
        });

        socket.on('data', (chunk) => {
          data += chunk.toString();
        });

        socket.on('close', () => {
          if (data.length === 0) {
            resolve({
              success: false,
              error: `No WHOIS data received for ${domain}`,
            });
            return;
          }

          // Extract key fields from WHOIS response
          const lines = data.split('\n');
          const extracted: string[] = [];
          const importantFields = [
            'domain name', 'registrar', 'creation date', 'updated date',
            'expiration date', 'registry expiry', 'registrant',
            'name server', 'status', 'dnssec', 'registrar abuse',
          ];

          for (const line of lines) {
            const lineLower = line.toLowerCase();
            if (importantFields.some(field => lineLower.includes(field))) {
              extracted.push(line.trim());
            }
          }

          // Truncate if too long
          const output = extracted.length > 0
            ? extracted.slice(0, 20).join('\n')
            : data.slice(0, 2000);

          resolve({
            success: true,
            output: `WHOIS for ${domain} (via ${whoisServer}):\n\n${output}${extracted.length > 20 ? '\n... (truncated)' : ''}`,
          });
        });

        socket.on('error', (err) => {
          resolve({
            success: false,
            error: `WHOIS lookup failed: ${err.message}`,
          });
        });

        socket.on('timeout', () => {
          socket.destroy();
          resolve({
            success: false,
            error: `WHOIS lookup timed out for ${domain}`,
          });
        });

        socket.connect(43, whoisServer);
      });
    },
  },

  // =============================================================================
  // WEB TESTING TOOLS
  // =============================================================================
  {
    name: 'http_request',
    description: 'Make an HTTP request to a target',
    category: 'web',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to request', required: true },
      { name: 'method', type: 'string', description: 'HTTP method', required: false, default: 'GET' },
      { name: 'headers', type: 'object', description: 'Request headers', required: false },
      { name: 'body', type: 'string', description: 'Request body', required: false },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;
      const method = (context.parameters.method as string) || 'GET';
      const headers = context.parameters.headers as Record<string, string> | undefined;
      const body = context.parameters.body as string | undefined;

      try {
        const response = await targetFetch(url, {
          method,
          headers,
          body: body && method !== 'GET' ? body : undefined,
          signal: AbortSignal.timeout(10000),
        });

        const responseHeaders = Object.fromEntries(response.headers.entries());
        return {
          success: true,
          output: `HTTP ${method} ${url}\nStatus: ${response.status} ${response.statusText}\nHeaders: ${JSON.stringify(responseHeaders, null, 2)}`,
        };
      } catch (error) {
        return {
          success: false,
          error: `Failed to fetch: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },
  {
    name: 'header_analysis',
    description: 'Analyze security headers of a URL',
    category: 'web',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to analyze', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;
      const securityHeaders = [
        'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options',
        'X-Content-Type-Options', 'X-XSS-Protection', 'Referrer-Policy',
        'Permissions-Policy', 'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy',
      ];
      try {
        const response = await targetFetch(url, {
          method: 'HEAD',
          signal: AbortSignal.timeout(10000),
        });
        const analysis = securityHeaders.map(h => {
          const value = response.headers.get(h);
          return `${h}: ${value ? `✓ ${value}` : '✗ Missing'}`;
        });
        return {
          success: true,
          output: `Security Header Analysis for ${url}:\n${analysis.join('\n')}`,
        };
      } catch (error) {
        return { success: false, error: `Failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'dir_bruteforce',
    description: 'Bruteforce directories on a web server (real HTTP requests)',
    category: 'web',
    parameters: [
      { name: 'url', type: 'string', description: 'Base URL to scan', required: true },
      { name: 'wordlist', type: 'string', description: 'Wordlist type: common, admin, api, files', required: false, default: 'common' },
      { name: 'timeout', type: 'number', description: 'Timeout per request in ms', required: false, default: 5000 },
    ],
    handler: async (context) => {
      const baseUrl = (context.parameters.url as string).replace(/\/$/, '');
      const wordlistType = context.parameters.wordlist as string || 'common';
      const timeout = (context.parameters.timeout as number) || 5000;

      const wordlists: Record<string, string[]> = {
        common: ['admin', 'login', 'dashboard', 'api', 'backup', 'config', 'test', 'dev', 'staging', '.git', '.git/config', '.env', 'robots.txt', 'sitemap.xml', '.htaccess', 'wp-config.php', 'web.config'],
        admin: ['admin', 'administrator', 'wp-admin', 'phpmyadmin', 'cpanel', 'manager', 'console', 'panel', 'admin.php', 'login.php', 'controlpanel', 'adminpanel'],
        api: ['api', 'api/v1', 'api/v2', 'api/v3', 'graphql', 'rest', 'swagger', 'swagger-ui', 'docs', 'openapi', 'api-docs', 'health', 'status', 'metrics'],
        files: ['backup.zip', 'backup.tar.gz', 'db.sql', 'database.sql', 'dump.sql', '.git/HEAD', '.svn/entries', 'composer.json', 'package.json', '.DS_Store', 'Thumbs.db', 'debug.log', 'error.log'],
      };

      const words = wordlists[wordlistType] || wordlists.common;
      const found: { path: string; status: number; size?: number }[] = [];
      const interesting = [200, 201, 301, 302, 307, 308, 401, 403];

      // Scan paths in parallel with concurrency limit
      const concurrency = 5;
      for (let i = 0; i < words.length; i += concurrency) {
        const batch = words.slice(i, i + concurrency);
        const checks = await Promise.all(
          batch.map(async (path) => {
            const fullUrl = `${baseUrl}/${path}`;
            try {
              const response = await targetFetch(fullUrl, {
                method: 'GET',
                signal: AbortSignal.timeout(timeout),
                redirect: 'manual',
              });
              const contentLength = response.headers.get('content-length');
              return {
                path: `/${path}`,
                status: response.status,
                size: contentLength ? parseInt(contentLength, 10) : undefined,
                interesting: interesting.includes(response.status),
              };
            } catch {
              return { path: `/${path}`, status: 0, interesting: false };
            }
          })
        );

        for (const result of checks) {
          if (result.interesting) {
            found.push({ path: result.path, status: result.status, size: result.size });
          }
        }
      }

      if (found.length === 0) {
        return {
          success: true,
          output: `Directory bruteforce on ${baseUrl}:\nNo interesting paths found from ${words.length} tested.`,
        };
      }

      const output = found.map(f => `${f.path} -> ${f.status}${f.size ? ` (${f.size} bytes)` : ''}`).join('\n');
      const critical = found.filter(f => f.path.includes('.git') || f.path.includes('.env') || f.path.includes('backup'));

      return {
        success: true,
        output: `Directory bruteforce on ${baseUrl}:\nFound ${found.length} interesting paths (tested ${words.length}):\n${output}`,
        findings: critical.length > 0 ? [{
          title: 'Sensitive Paths Exposed',
          severity: 'high',
          details: `Found potentially sensitive paths: ${critical.map(c => c.path).join(', ')}`,
        }] : found.length > 0 ? [{
          title: 'Directories Discovered',
          severity: 'info',
          details: `Found ${found.length} accessible paths`,
        }] : undefined,
      };
    },
  },
  {
    name: 'technology_detect',
    description: 'Detect technologies used by a website (real analysis)',
    category: 'web',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to analyze', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;

      try {
        const response = await targetFetch(url, {
          signal: AbortSignal.timeout(10000),
        });

        const headers = Object.fromEntries(response.headers.entries());
        const body = await response.text();
        const detected: { tech: string; evidence: string }[] = [];

        // Server detection from headers
        if (headers['server']) {
          detected.push({ tech: headers['server'], evidence: 'Server header' });
        }
        if (headers['x-powered-by']) {
          detected.push({ tech: headers['x-powered-by'], evidence: 'X-Powered-By header' });
        }

        // CDN/Proxy detection
        if (headers['cf-ray']) detected.push({ tech: 'Cloudflare', evidence: 'CF-Ray header' });
        if (headers['x-amz-cf-id']) detected.push({ tech: 'AWS CloudFront', evidence: 'x-amz-cf-id header' });
        if (headers['x-vercel-id']) detected.push({ tech: 'Vercel', evidence: 'x-vercel-id header' });
        if (headers['x-netlify-id']) detected.push({ tech: 'Netlify', evidence: 'x-netlify-id header' });

        // Framework detection from HTML
        if (body.includes('wp-content') || body.includes('wp-includes')) {
          detected.push({ tech: 'WordPress', evidence: 'wp-content/wp-includes paths' });
        }
        if (body.includes('_next/static') || body.includes('__NEXT_DATA__')) {
          detected.push({ tech: 'Next.js', evidence: '_next paths or __NEXT_DATA__' });
        }
        if (body.includes('/_nuxt/')) {
          detected.push({ tech: 'Nuxt.js', evidence: '_nuxt paths' });
        }
        if (body.includes('ng-version') || body.includes('ng-app')) {
          detected.push({ tech: 'Angular', evidence: 'ng-version/ng-app attributes' });
        }
        if (body.includes('data-reactroot') || body.includes('__REACT_DEVTOOLS')) {
          detected.push({ tech: 'React', evidence: 'React markers in HTML' });
        }
        if (body.includes('data-v-') || body.includes('Vue.js')) {
          detected.push({ tech: 'Vue.js', evidence: 'Vue.js markers' });
        }
        if (body.includes('jquery') || body.includes('jQuery')) {
          detected.push({ tech: 'jQuery', evidence: 'jQuery references' });
        }
        if (body.includes('bootstrap')) {
          detected.push({ tech: 'Bootstrap', evidence: 'Bootstrap CSS/JS' });
        }
        if (body.includes('tailwind')) {
          detected.push({ tech: 'Tailwind CSS', evidence: 'Tailwind references' });
        }

        // CMS detection
        if (body.includes('Drupal') || body.includes('drupal.js')) {
          detected.push({ tech: 'Drupal', evidence: 'Drupal markers' });
        }
        if (body.includes('Joomla') || body.includes('/media/jui/')) {
          detected.push({ tech: 'Joomla', evidence: 'Joomla markers' });
        }
        if (body.includes('Shopify') || body.includes('cdn.shopify.com')) {
          detected.push({ tech: 'Shopify', evidence: 'Shopify CDN' });
        }

        // Meta generator tag
        const generatorMatch = body.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
        if (generatorMatch) {
          detected.push({ tech: generatorMatch[1], evidence: 'Meta generator tag' });
        }

        if (detected.length === 0) {
          return {
            success: true,
            output: `Technology detection for ${url}:\nNo technologies detected from headers or content.`,
          };
        }

        const output = detected.map(d => `• ${d.tech} (${d.evidence})`).join('\n');
        return {
          success: true,
          output: `Technology detection for ${url}:\n${output}`,
          findings: [{
            title: 'Technologies Detected',
            severity: 'info',
            details: `Detected ${detected.length} technologies: ${detected.map(d => d.tech).join(', ')}`,
          }],
        };
      } catch (error) {
        return {
          success: false,
          error: `Technology detection failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },

  // =============================================================================
  // VULNERABILITY SCANNING TOOLS
  // =============================================================================
  {
    name: 'xss_scan',
    description: 'Test for XSS vulnerabilities (real requests with payload reflection check)',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'URL with parameter to test', required: true },
      { name: 'param', type: 'string', description: 'Parameter name to test', required: true },
    ],
    handler: async (context) => {
      const baseUrl = context.parameters.url as string;
      const param = context.parameters.param as string;

      const payloads = [
        { payload: '<script>alert(1)</script>', name: 'Basic script tag' },
        { payload: '<img src=x onerror=alert(1)>', name: 'IMG onerror' },
        { payload: '"><svg onload=alert(1)>', name: 'SVG onload breakout' },
        { payload: "'-alert(1)-'", name: 'JS string breakout' },
        { payload: '<body onload=alert(1)>', name: 'Body onload' },
        { payload: '{{constructor.constructor("alert(1)")()}}', name: 'Template injection' },
      ];

      const results: { payload: string; name: string; reflected: boolean; encoded: boolean }[] = [];
      const vulnerable: string[] = [];

      for (const { payload, name } of payloads) {
        try {
          // Build URL with payload
          const testUrl = new URL(baseUrl);
          testUrl.searchParams.set(param, payload);

          const response = await targetFetch(testUrl.toString(), {
            signal: AbortSignal.timeout(5000),
          });
          const body = await response.text();

          // Check if payload is reflected
          const reflected = body.includes(payload);
          const encoded = body.includes(encodeURIComponent(payload)) ||
                         body.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'));

          results.push({ payload, name, reflected, encoded });

          if (reflected) {
            vulnerable.push(name);
          }
        } catch {
          results.push({ payload, name, reflected: false, encoded: false });
        }
      }

      const output = results.map(r => {
        const status = r.reflected ? '⚠️ REFLECTED (potentially vulnerable)' :
                       r.encoded ? '✓ Encoded/Filtered' : '✓ Not reflected';
        return `[${r.name}] ${status}`;
      }).join('\n');

      return {
        success: true,
        output: `XSS scan on ${baseUrl} (param: ${param}):\n${output}`,
        findings: vulnerable.length > 0 ? [{
          title: 'Potential XSS Vulnerability',
          severity: 'high',
          details: `Parameter "${param}" reflects unencoded payloads: ${vulnerable.join(', ')}. Manual verification required.`,
        }] : undefined,
      };
    },
  },
  {
    name: 'sqli_scan',
    description: 'Test for SQL injection vulnerabilities (real error-based detection)',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'URL with parameter to test', required: true },
      { name: 'param', type: 'string', description: 'Parameter name to test', required: true },
    ],
    handler: async (context) => {
      const baseUrl = context.parameters.url as string;
      const param = context.parameters.param as string;

      const payloads = [
        { payload: "'", name: 'Single quote', type: 'error' },
        { payload: "''", name: 'Double single quote', type: 'error' },
        { payload: "' OR '1'='1", name: 'Boolean OR true', type: 'boolean' },
        { payload: "' AND '1'='2", name: 'Boolean AND false', type: 'boolean' },
        { payload: "1 UNION SELECT NULL--", name: 'UNION attempt', type: 'union' },
        { payload: "'; WAITFOR DELAY '0:0:0'--", name: 'MSSQL time delay', type: 'time' },
        { payload: "' AND SLEEP(0)--", name: 'MySQL time delay', type: 'time' },
      ];

      // SQL error patterns to detect
      const errorPatterns = [
        /sql syntax/i, /mysql/i, /mariadb/i, /postgresql/i, /sqlite/i,
        /ora-\d{5}/i, /microsoft sql/i, /odbc/i, /jdbc/i,
        /syntax error/i, /unclosed quotation/i, /unterminated string/i,
        /quoted string not properly terminated/i, /sql command not properly ended/i,
        /invalid query/i, /database error/i, /db error/i,
        /you have an error in your sql/i, /supplied argument is not a valid/i,
      ];

      const results: { payload: string; name: string; type: string; vulnerable: boolean; indicator: string }[] = [];
      const vulnerabilities: string[] = [];

      // First, get a baseline response
      let baselineLength = 0;
      try {
        const baselineUrl = new URL(baseUrl);
        baselineUrl.searchParams.set(param, 'normalvalue');
        const baselineResp = await targetFetch(baselineUrl.toString(), { signal: AbortSignal.timeout(5000) });
        const baselineBody = await baselineResp.text();
        baselineLength = baselineBody.length;
      } catch {
        // Continue anyway
      }

      for (const { payload, name, type } of payloads) {
        try {
          const testUrl = new URL(baseUrl);
          testUrl.searchParams.set(param, payload);

          const response = await targetFetch(testUrl.toString(), { signal: AbortSignal.timeout(5000) });
          const body = await response.text();
          const bodyLower = body.toLowerCase();

          let vulnerable = false;
          let indicator = 'No indicators';

          // Check for error-based SQLi
          for (const pattern of errorPatterns) {
            if (pattern.test(body)) {
              vulnerable = true;
              indicator = `SQL error detected: ${pattern.source}`;
              break;
            }
          }

          // Check for boolean-based (significant response length difference)
          if (!vulnerable && type === 'boolean') {
            const lengthDiff = Math.abs(body.length - baselineLength);
            const percentDiff = baselineLength > 0 ? (lengthDiff / baselineLength) * 100 : 0;
            if (percentDiff > 20) {
              vulnerable = true;
              indicator = `Response length difference: ${lengthDiff} bytes (${percentDiff.toFixed(1)}%)`;
            }
          }

          // Check for content differences indicating injection
          if (!vulnerable && (bodyLower.includes('welcome') || bodyLower.includes('admin') || bodyLower.includes('logged in'))
              && type === 'boolean' && payload.includes('OR')) {
            vulnerable = true;
            indicator = 'Authentication bypass indicators detected';
          }

          results.push({ payload, name, type, vulnerable, indicator });
          if (vulnerable) {
            vulnerabilities.push(name);
          }
        } catch {
          results.push({ payload, name, type, vulnerable: false, indicator: 'Request failed' });
        }
      }

      const output = results.map(r => {
        const status = r.vulnerable ? `⚠️ VULNERABLE - ${r.indicator}` : `✓ ${r.indicator}`;
        return `[${r.name}] ${status}`;
      }).join('\n');

      return {
        success: true,
        output: `SQL Injection scan on ${baseUrl} (param: ${param}):\n${output}`,
        findings: vulnerabilities.length > 0 ? [{
          title: 'Potential SQL Injection Vulnerability',
          severity: 'critical',
          details: `Parameter "${param}" shows SQL injection indicators for: ${vulnerabilities.join(', ')}. Manual verification required.`,
        }] : undefined,
      };
    },
  },
  {
    name: 'ssl_scan',
    description: 'Analyze SSL/TLS configuration (real connection analysis)',
    category: 'vuln',
    parameters: [
      { name: 'host', type: 'string', description: 'Host to scan', required: true },
      { name: 'port', type: 'number', description: 'Port number', required: false, default: 443 },
    ],
    handler: async (context) => {
      const host = context.parameters.host as string;
      const port = (context.parameters.port as number) || 443;

      return new Promise((resolve) => {
        const issues: string[] = [];
        const info: string[] = [];

        const socket = tls.connect({
          host,
          port,
          rejectUnauthorized: false, // Allow self-signed for scanning
          timeout: 10000,
        }, () => {
          try {
            // Get certificate info
            const cert = socket.getPeerCertificate();
            const protocol = socket.getProtocol();
            const cipher = socket.getCipher();

            info.push(`Protocol: ${protocol || 'Unknown'}`);
            info.push(`Cipher: ${cipher?.name || 'Unknown'} (${cipher?.version || 'Unknown'})`);

            if (cert && Object.keys(cert).length > 0) {
              info.push(`Subject: ${cert.subject?.CN || 'Unknown'}`);
              info.push(`Issuer: ${cert.issuer?.CN || 'Unknown'}`);
              info.push(`Valid From: ${cert.valid_from || 'Unknown'}`);
              info.push(`Valid To: ${cert.valid_to || 'Unknown'}`);

              // Check for issues
              if (cert.valid_to) {
                const expiryDate = new Date(cert.valid_to);
                const now = new Date();
                const daysUntilExpiry = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

                if (daysUntilExpiry < 0) {
                  issues.push('⚠ CRITICAL: Certificate has expired!');
                } else if (daysUntilExpiry < 30) {
                  issues.push(`⚠ Certificate expires in ${daysUntilExpiry} days`);
                }
              }

              // Check for weak key
              if (cert.bits && cert.bits < 2048) {
                issues.push(`⚠ Weak key size: ${cert.bits} bits (recommend 2048+)`);
              }

              // Check for self-signed
              if (cert.subject?.CN === cert.issuer?.CN) {
                issues.push('⚠ Self-signed certificate detected');
              }
            }

            // Check protocol version
            if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
              issues.push(`⚠ Outdated protocol: ${protocol} (should use TLSv1.2+)`);
            }

            // Check cipher strength
            if (cipher?.name) {
              const weakCiphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'];
              for (const weak of weakCiphers) {
                if (cipher.name.toUpperCase().includes(weak)) {
                  issues.push(`⚠ Weak cipher detected: ${cipher.name}`);
                  break;
                }
              }
            }

            socket.end();

            const output = `SSL/TLS scan of ${host}:${port}:\n\n` +
              `Connection Info:\n${info.map(i => `  ${i}`).join('\n')}\n\n` +
              (issues.length > 0
                ? `Issues Found:\n${issues.map(i => `  ${i}`).join('\n')}`
                : '✓ No critical issues found');

            resolve({
              success: true,
              output,
              findings: issues.length > 0 ? [{
                title: 'SSL/TLS Configuration Issues',
                severity: issues.some(i => i.includes('CRITICAL') || i.includes('expired')) ? 'critical' : 'medium',
                details: issues.join('; '),
              }] : undefined,
            });
          } catch (err) {
            socket.end();
            resolve({
              success: false,
              error: `SSL analysis failed: ${err instanceof Error ? err.message : String(err)}`,
            });
          }
        });

        socket.on('error', (err) => {
          resolve({
            success: false,
            error: `SSL connection failed: ${err.message}`,
          });
        });

        socket.on('timeout', () => {
          socket.destroy();
          resolve({
            success: false,
            error: `SSL connection timed out to ${host}:${port}`,
          });
        });
      });
    },
  },

  // =============================================================================
  // CREDENTIAL TOOLS
  // =============================================================================
  {
    name: 'password_spray',
    description: 'Test common passwords against a login endpoint (real HTTP requests)',
    category: 'auth',
    parameters: [
      { name: 'url', type: 'string', description: 'Login URL', required: true },
      { name: 'username', type: 'string', description: 'Username to test', required: true },
      { name: 'username_field', type: 'string', description: 'Username field name', required: false, default: 'username' },
      { name: 'password_field', type: 'string', description: 'Password field name', required: false, default: 'password' },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;
      const username = context.parameters.username as string;
      const usernameField = context.parameters.username_field as string || 'username';
      const passwordField = context.parameters.password_field as string || 'password';

      const passwords = ['password', '123456', 'admin', 'letmein', 'welcome', 'Password1', 'password123', 'qwerty', 'abc123', '111111'];
      const results: { password: string; status: number; success: boolean; indicator: string }[] = [];
      const validCredentials: string[] = [];

      // Get a baseline failed login response
      let baselineLength = 0;
      let baselineStatus = 0;
      try {
        const baselineBody = new URLSearchParams();
        baselineBody.set(usernameField, username);
        baselineBody.set(passwordField, 'definitely_invalid_password_xyz123!@#');

        const baselineResp = await targetFetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: baselineBody.toString(),
          redirect: 'manual',
          signal: AbortSignal.timeout(5000),
        });
        baselineStatus = baselineResp.status;
        const baselineText = await baselineResp.text();
        baselineLength = baselineText.length;
      } catch {
        return {
          success: false,
          error: `Failed to connect to login endpoint: ${url}`,
        };
      }

      // Test each password
      for (const password of passwords) {
        try {
          const body = new URLSearchParams();
          body.set(usernameField, username);
          body.set(passwordField, password);

          const response = await targetFetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body.toString(),
            redirect: 'manual',
            signal: AbortSignal.timeout(5000),
          });

          const status = response.status;
          const responseText = await response.text();
          const responseLower = responseText.toLowerCase();

          let success = false;
          let indicator = 'No change';

          // Check for redirect (common success indicator)
          if (status === 302 || status === 301 || status === 303) {
            const location = response.headers.get('location') || '';
            if (!location.includes('login') && !location.includes('error')) {
              success = true;
              indicator = `Redirect to ${location}`;
            }
          }

          // Check for success indicators in response
          const successIndicators = ['welcome', 'dashboard', 'logged in', 'logout', 'my account', 'profile'];
          const failureIndicators = ['invalid', 'incorrect', 'failed', 'error', 'wrong', 'denied'];

          if (!success) {
            for (const ind of successIndicators) {
              if (responseLower.includes(ind)) {
                success = true;
                indicator = `Contains "${ind}"`;
                break;
              }
            }
          }

          // Check for significant response length change
          if (!success) {
            const lengthDiff = Math.abs(responseText.length - baselineLength);
            const percentDiff = baselineLength > 0 ? (lengthDiff / baselineLength) * 100 : 0;
            if (percentDiff > 30 && !failureIndicators.some(f => responseLower.includes(f))) {
              success = true;
              indicator = `Response length change: ${percentDiff.toFixed(1)}%`;
            }
          }

          // Check for status code change
          if (!success && status !== baselineStatus && (status === 200 || status === 302)) {
            success = true;
            indicator = `Status changed: ${baselineStatus} -> ${status}`;
          }

          results.push({ password, status, success, indicator });
          if (success) {
            validCredentials.push(password);
          }

          // Add small delay to avoid rate limiting
          await new Promise(r => setTimeout(r, 200));
        } catch {
          results.push({ password, status: 0, success: false, indicator: 'Request failed' });
        }
      }

      const output = results.map(r => {
        const status = r.success ? `✓ POSSIBLE VALID - ${r.indicator}` : `✗ ${r.indicator}`;
        return `${r.password} - ${status}`;
      }).join('\n');

      return {
        success: true,
        output: `Password spray on ${url} for user ${username}:\n${output}`,
        findings: validCredentials.length > 0 ? [{
          title: 'Potential Valid Credentials Found',
          severity: 'critical',
          details: `User "${username}" may have weak password: ${validCredentials.join(', ')}. Manual verification required.`,
        }] : undefined,
      };
    },
  },
  {
    name: 'hash_crack',
    description: 'Attempt to crack a password hash using dictionary attack',
    category: 'auth',
    parameters: [
      { name: 'hash', type: 'string', description: 'Hash to crack', required: true },
      { name: 'type', type: 'string', description: 'Hash type: md5, sha1, sha256, ntlm (auto-detect if not specified)', required: false, default: 'auto' },
    ],
    handler: async (context) => {
      const { createHash } = await import('crypto');
      const hash = (context.parameters.hash as string).toLowerCase();
      const hashType = context.parameters.type as string || 'auto';

      // Detect hash type based on length and format
      let detectedType = 'Unknown';
      const possibleTypes: string[] = [];

      if (hash.length === 32 && /^[a-f0-9]+$/.test(hash)) {
        detectedType = 'MD5 or NTLM';
        possibleTypes.push('md5', 'ntlm');
      } else if (hash.length === 40 && /^[a-f0-9]+$/.test(hash)) {
        detectedType = 'SHA1';
        possibleTypes.push('sha1');
      } else if (hash.length === 64 && /^[a-f0-9]+$/.test(hash)) {
        detectedType = 'SHA256';
        possibleTypes.push('sha256');
      } else if (hash.length === 128 && /^[a-f0-9]+$/.test(hash)) {
        detectedType = 'SHA512';
        possibleTypes.push('sha512');
      }

      if (hashType !== 'auto') {
        possibleTypes.length = 0;
        possibleTypes.push(hashType.toLowerCase());
        detectedType = hashType.toUpperCase();
      }

      // Common passwords dictionary for cracking
      const wordlist = [
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'letmein',
        'dragon', 'master', 'admin', 'root', 'toor', 'login', 'welcome', 'shadow',
        'sunshine', 'princess', 'football', 'baseball', 'iloveyou', 'trustno1',
        'password1', 'password123', 'pass123', 'Password1', 'Password123',
        '123456789', '12345', '1234567', '1234567890', 'qwerty123', 'qwertyuiop',
        'passw0rd', 'p@ssword', 'p@ssw0rd', 'secret', 'test', 'testing', 'user',
        'guest', 'administrator', 'default', 'changeme', 'summer', 'winter',
        '111111', '000000', '123123', '654321', 'superman', 'batman', 'michael',
        'jennifer', 'jordan', 'hunter', 'ranger', 'buster', 'charlie', 'thomas',
      ];

      // Function to compute hash
      const computeHash = (plaintext: string, type: string): string => {
        if (type === 'ntlm') {
          // NTLM hash: MD4 of UTF-16LE encoded password
          const utf16 = Buffer.from(plaintext, 'utf16le');
          return createHash('md4').update(utf16).digest('hex');
        }
        return createHash(type).update(plaintext).digest('hex');
      };

      let crackedPassword: string | null = null;
      let crackedType: string | null = null;
      let attempts = 0;

      // Try cracking with each hash type
      for (const type of possibleTypes) {
        for (const word of wordlist) {
          attempts++;
          try {
            const computed = computeHash(word, type);
            if (computed === hash) {
              crackedPassword = word;
              crackedType = type.toUpperCase();
              break;
            }
          } catch {
            // Skip unsupported hash types
          }
        }
        if (crackedPassword) break;
      }

      const output = crackedPassword
        ? `Hash crack attempt:
Hash: ${hash}
Detected type: ${detectedType}
Status: ✓ CRACKED
Plaintext: ${crackedPassword}
Hash type: ${crackedType}
Attempts: ${attempts}`
        : `Hash crack attempt:
Hash: ${hash}
Detected type: ${detectedType}
Status: ✗ Not cracked
Attempts: ${attempts} (tried ${wordlist.length} common passwords)
Note: Consider using larger wordlists (rockyou.txt) or hashcat for better results`;

      return {
        success: true,
        output,
        findings: crackedPassword ? [{
          title: 'Weak Password Hash Cracked',
          severity: 'critical',
          details: `Hash cracked to plaintext: "${crackedPassword}" using ${crackedType}`,
        }] : undefined,
      };
    },
  },

  // =============================================================================
  // UTILITY TOOLS
  // =============================================================================
  {
    name: 'base64_decode',
    description: 'Decode base64 encoded data',
    category: 'util',
    parameters: [
      { name: 'data', type: 'string', description: 'Base64 data to decode', required: true },
    ],
    handler: async (context) => {
      const data = context.parameters.data as string;
      try {
        const decoded = Buffer.from(data, 'base64').toString('utf-8');
        return { success: true, output: `Decoded: ${decoded}` };
      } catch {
        return { success: false, error: 'Invalid base64 data' };
      }
    },
  },
  {
    name: 'jwt_decode',
    description: 'Decode and analyze a JWT token',
    category: 'util',
    parameters: [
      { name: 'token', type: 'string', description: 'JWT token to analyze', required: true },
    ],
    handler: async (context) => {
      const token = context.parameters.token as string;
      const parts = token.split('.');
      if (parts.length !== 3) {
        return { success: false, error: 'Invalid JWT format' };
      }
      try {
        const b64urlDecode = (s: string) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();
        const header = JSON.parse(b64urlDecode(parts[0]));
        const payload = JSON.parse(b64urlDecode(parts[1]));
        const issues: string[] = [];
        if (header.alg === 'none') issues.push('⚠ Algorithm is "none" - VULNERABLE');
        if (header.alg === 'HS256') issues.push('⚠ HS256 may be vulnerable to key confusion');
        if (payload.exp && payload.exp < Date.now() / 1000) issues.push('⚠ Token is expired');
        return {
          success: true,
          output: `JWT Analysis:
Header: ${JSON.stringify(header, null, 2)}
Payload: ${JSON.stringify(payload, null, 2)}
${issues.length ? `Issues:\n${issues.join('\n')}` : '✓ No obvious issues'}`,
        };
      } catch {
        return { success: false, error: 'Failed to decode JWT' };
      }
    },
  },

  // =============================================================================
  // ADDITIONAL RECONNAISSANCE TOOLS
  // =============================================================================
  {
    name: 'robots_txt_fetch',
    description: 'Fetch and parse robots.txt, extract disallowed paths and sitemaps',
    category: 'recon',
    parameters: [
      { name: 'url', type: 'string', description: 'Base URL of the target (e.g., https://example.com)', required: true },
    ],
    handler: async (context) => {
      const baseUrl = (context.parameters.url as string).replace(/\/+$/, '');

      try {
        const robotsUrl = `${baseUrl}/robots.txt`;
        const response = await targetFetch(robotsUrl, {
          signal: AbortSignal.timeout(10000),
        });

        if (response.status === 404) {
          return {
            success: true,
            output: `robots.txt not found at ${robotsUrl} (404)`,
          };
        }

        if (!response.ok) {
          return {
            success: false,
            error: `Failed to fetch robots.txt: HTTP ${response.status}`,
          };
        }

        const body = await response.text();
        const lines = body.split('\n');

        const disallowed: string[] = [];
        const allowed: string[] = [];
        const sitemaps: string[] = [];
        let currentUserAgent = '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith('#') || trimmed === '') continue;

          const colonIndex = trimmed.indexOf(':');
          if (colonIndex === -1) continue;

          const directive = trimmed.slice(0, colonIndex).trim().toLowerCase();
          const value = trimmed.slice(colonIndex + 1).trim();

          switch (directive) {
            case 'user-agent':
              currentUserAgent = value;
              break;
            case 'disallow':
              if (value) disallowed.push(`[${currentUserAgent}] ${value}`);
              break;
            case 'allow':
              if (value) allowed.push(`[${currentUserAgent}] ${value}`);
              break;
            case 'sitemap':
              if (value) sitemaps.push(value);
              break;
          }
        }

        const sections: string[] = [];
        sections.push(`robots.txt for ${baseUrl}:`);
        if (disallowed.length > 0) {
          sections.push(`\nDisallowed Paths (${disallowed.length}):\n${disallowed.map(d => `  ${d}`).join('\n')}`);
        }
        if (allowed.length > 0) {
          sections.push(`\nExplicitly Allowed Paths (${allowed.length}):\n${allowed.map(a => `  ${a}`).join('\n')}`);
        }
        if (sitemaps.length > 0) {
          sections.push(`\nSitemaps (${sitemaps.length}):\n${sitemaps.map(s => `  ${s}`).join('\n')}`);
        }
        if (disallowed.length === 0 && allowed.length === 0 && sitemaps.length === 0) {
          sections.push('\nNo useful directives found in robots.txt');
        }

        const sensitivePatterns = ['/admin', '/backup', '/config', '/private', '/secret', '/internal', '/api', '/debug', '/test', '/.git', '/.env', '/wp-admin', '/phpmyadmin'];
        const sensitiveFinds = disallowed.filter(d => sensitivePatterns.some(p => d.toLowerCase().includes(p)));

        return {
          success: true,
          output: sections.join('\n'),
          findings: sensitiveFinds.length > 0 ? [{
            title: 'Sensitive Paths in robots.txt',
            severity: 'medium' as const,
            details: `robots.txt reveals potentially sensitive paths: ${sensitiveFinds.map(f => f.split('] ')[1]).join(', ')}`,
          }] : undefined,
        };
      } catch (error) {
        return {
          success: false,
          error: `Failed to fetch robots.txt: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },
  {
    name: 'reverse_dns',
    description: 'Perform reverse DNS lookup to find hostnames for an IP address',
    category: 'recon',
    parameters: [
      { name: 'ip', type: 'string', description: 'IP address to reverse lookup', required: true },
    ],
    handler: async (context) => {
      const ip = context.parameters.ip as string;

      // Validate IP format
      const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
      const ipv6Regex = /^[0-9a-fA-F:]+$/;
      if (ipv4Regex.test(ip)) {
        const octets = ip.split('.').map(o => parseInt(o, 10));
        if (octets.some(o => o < 0 || o > 255)) {
          return { success: false, error: `Invalid IPv4 address (octet out of range): ${ip}` };
        }
      } else if (!ipv6Regex.test(ip)) {
        return {
          success: false,
          error: `Invalid IP address format: ${ip}`,
        };
      }

      try {
        const hostnames = await dnsReverse(ip);

        if (hostnames.length === 0) {
          return {
            success: true,
            output: `Reverse DNS for ${ip}: No PTR records found`,
          };
        }

        return {
          success: true,
          output: `Reverse DNS for ${ip}:\n${hostnames.map(h => `  ${h}`).join('\n')}`,
          findings: [{
            title: 'Reverse DNS Hostnames Found',
            severity: 'info' as const,
            details: `IP ${ip} resolves to: ${hostnames.join(', ')}`,
          }],
        };
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : String(error);
        // ENOTFOUND is normal for IPs without PTR records
        if (errMsg.includes('ENOTFOUND') || errMsg.includes('ENODATA')) {
          return {
            success: true,
            output: `Reverse DNS for ${ip}: No PTR records found`,
          };
        }
        return {
          success: false,
          error: `Reverse DNS lookup failed: ${errMsg}`,
        };
      }
    },
  },
  {
    name: 'version_detect',
    description: 'Detect software versions from response headers, meta tags, and known paths',
    category: 'recon',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to analyze', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;
      const baseUrl = url.replace(/\/+$/, '');
      const detected: { software: string; version: string; source: string }[] = [];

      try {
        // Fetch main page
        const response = await targetFetch(url, {
          signal: AbortSignal.timeout(10000),
        });
        const headers = Object.fromEntries(response.headers.entries());
        const body = await response.text();

        // Check Server header for version
        if (headers['server']) {
          const serverMatch = headers['server'].match(/^([^\s/]+)(?:\/(\S+))?/);
          if (serverMatch) {
            detected.push({
              software: serverMatch[1],
              version: serverMatch[2] || 'unknown',
              source: 'Server header',
            });
          }
        }

        // Check X-Powered-By
        if (headers['x-powered-by']) {
          const pwrMatch = headers['x-powered-by'].match(/^([^\s/]+)(?:\/(\S+))?/);
          if (pwrMatch) {
            detected.push({
              software: pwrMatch[1],
              version: pwrMatch[2] || 'unknown',
              source: 'X-Powered-By header',
            });
          }
        }

        // Check X-AspNet-Version
        if (headers['x-aspnet-version']) {
          detected.push({ software: 'ASP.NET', version: headers['x-aspnet-version'], source: 'X-AspNet-Version header' });
        }

        // Check X-Generator header
        if (headers['x-generator']) {
          detected.push({ software: 'Generator', version: headers['x-generator'], source: 'X-Generator header' });
        }

        // Meta generator tag
        const generatorMatch = body.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
        if (generatorMatch) {
          const parts = generatorMatch[1].split(/\s+/);
          detected.push({
            software: parts[0],
            version: parts.slice(1).join(' ') || 'unknown',
            source: 'Meta generator tag',
          });
        }

        // WordPress version from readme or meta
        const wpVersionMatch = body.match(/WordPress\s+([\d.]+)/i);
        if (wpVersionMatch) {
          detected.push({ software: 'WordPress', version: wpVersionMatch[1], source: 'HTML content' });
        }

        // jQuery version
        const jqueryMatch = body.match(/jquery[.-]?([\d.]+(?:\.min)?\.js)/i);
        if (jqueryMatch) {
          detected.push({ software: 'jQuery', version: jqueryMatch[1].replace('.min.js', '').replace('.js', ''), source: 'Script tag' });
        }

        // Probe known version-exposing paths
        const versionPaths = [
          { path: '/wp-includes/version.php', name: 'WordPress' },
          { path: '/CHANGELOG.txt', name: 'CMS Changelog' },
          { path: '/readme.html', name: 'CMS Readme' },
          { path: '/package.json', name: 'Node.js App' },
          { path: '/composer.json', name: 'PHP App' },
        ];

        const probePromises = versionPaths.map(async (vp) => {
          try {
            const probeResp = await targetFetch(`${baseUrl}${vp.path}`, {
              signal: AbortSignal.timeout(5000),
              redirect: 'manual',
            });
            if (probeResp.status === 200) {
              const probeBody = await probeResp.text();
              // Try to extract version from content
              const vMatch = probeBody.match(/["']?version["']?\s*[:=]\s*["']?([\d.]+)/i);
              if (vMatch) {
                detected.push({ software: vp.name, version: vMatch[1], source: vp.path });
              } else {
                detected.push({ software: vp.name, version: 'file accessible', source: vp.path });
              }
            }
          } catch {
            // Ignore probe failures
          }
        });

        await Promise.all(probePromises);

        if (detected.length === 0) {
          return {
            success: true,
            output: `Version detection for ${url}:\nNo software versions detected.`,
          };
        }

        const output = detected.map(d => `  ${d.software}: ${d.version} (via ${d.source})`).join('\n');
        const versionExposed = detected.filter(d => d.version !== 'unknown' && d.version !== 'file accessible');

        return {
          success: true,
          output: `Version detection for ${url}:\n${output}`,
          findings: versionExposed.length > 0 ? [{
            title: 'Software Versions Exposed',
            severity: 'low' as const,
            details: `Detected versions: ${versionExposed.map(d => `${d.software} ${d.version}`).join(', ')}. Version disclosure helps attackers find known vulnerabilities.`,
          }] : undefined,
        };
      } catch (error) {
        return {
          success: false,
          error: `Version detection failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },
  {
    name: 'network_trace',
    description: 'Simple traceroute-like probe using incremental TTL TCP connects',
    category: 'recon',
    parameters: [
      { name: 'host', type: 'string', description: 'Target hostname or IP', required: true },
      { name: 'port', type: 'number', description: 'Target port', required: false, default: 80 },
      { name: 'max_hops', type: 'number', description: 'Maximum hops', required: false, default: 15 },
    ],
    handler: async (context) => {
      const host = context.parameters.host as string;
      const port = (context.parameters.port as number) || 80;
      const maxHops = Math.max(1, Math.min((context.parameters.max_hops as number) || 15, 30));

      // Resolve host to IP first
      let targetIp: string;
      try {
        const addresses = await dnsResolve4(host);
        targetIp = addresses[0];
      } catch {
        targetIp = host; // Assume it's already an IP
      }

      const hops: { hop: number; ip: string; rtt: number }[] = [];
      const timeouts: number[] = [];

      for (let ttl = 1; ttl <= maxHops; ttl++) {
        const startTime = Date.now();
        try {
          const result = await new Promise<{ ip: string; reached: boolean }>((resolve) => {
            const socket = new net.Socket();
            // Note: Node.js net.Socket doesn't directly support TTL on all platforms,
            // but we can attempt a TCP connect and measure timing
            socket.setTimeout(2000);

            socket.on('connect', () => {
              socket.destroy();
              resolve({ ip: targetIp, reached: true });
            });

            socket.on('timeout', () => {
              socket.destroy();
              resolve({ ip: '*', reached: false });
            });

            socket.on('error', () => {
              socket.destroy();
              resolve({ ip: '*', reached: false });
            });

            socket.connect(port, host);
          });

          const rtt = Date.now() - startTime;

          if (result.reached) {
            hops.push({ hop: ttl, ip: result.ip, rtt });
            break; // Reached destination
          } else {
            timeouts.push(ttl);
            hops.push({ hop: ttl, ip: '*', rtt });
          }
        } catch {
          hops.push({ hop: ttl, ip: '*', rtt: -1 });
        }

        // For TCP-based trace, stop after first successful connection
        if (hops.length > 0 && hops[hops.length - 1].ip !== '*') break;

        // If we get 3 timeouts in a row after hop 1, try direct connection
        if (timeouts.length >= 3) {
          const directStart = Date.now();
          const isReachable = await checkPort(host, port, 3000);
          const directRtt = Date.now() - directStart;
          if (isReachable) {
            hops.push({ hop: ttl + 1, ip: targetIp, rtt: directRtt });
          }
          break;
        }
      }

      const output = hops.map(h =>
        h.ip === '*' ? `  ${h.hop}  *  (timeout)` : `  ${h.hop}  ${h.ip}  ${h.rtt}ms`
      ).join('\n');

      return {
        success: true,
        output: `Network trace to ${host}:${port} (resolved: ${targetIp}):\n${output}\n\n${hops.some(h => h.ip !== '*') ? 'Target is reachable' : 'Target may be unreachable or filtered'}`,
      };
    },
  },

  // =============================================================================
  // ADDITIONAL WEB TESTING TOOLS
  // =============================================================================
  {
    name: 'csp_analysis',
    description: 'Analyze Content-Security-Policy header for weaknesses and misconfigurations',
    category: 'web',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to analyze', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;

      try {
        const response = await targetFetch(url, {
          method: 'GET',
          signal: AbortSignal.timeout(10000),
        });

        const csp = response.headers.get('content-security-policy');
        const cspReportOnly = response.headers.get('content-security-policy-report-only');

        if (!csp && !cspReportOnly) {
          return {
            success: true,
            output: `CSP Analysis for ${url}:\nNo Content-Security-Policy header found!`,
            findings: [{
              title: 'Missing Content-Security-Policy Header',
              severity: 'medium' as const,
              details: 'No CSP header is set. This makes the site more vulnerable to XSS and data injection attacks.',
            }],
          };
        }

        const policyToAnalyze = csp || cspReportOnly || '';
        const isReportOnly = !csp && !!cspReportOnly;
        const directives = policyToAnalyze.split(';').map(d => d.trim()).filter(d => d);
        const issues: string[] = [];
        const info: string[] = [];

        if (isReportOnly) {
          issues.push('Policy is report-only (not enforced)');
        }

        const directiveMap: Record<string, string> = {};
        for (const directive of directives) {
          const parts = directive.split(/\s+/);
          const name = parts[0];
          const values = parts.slice(1).join(' ');
          directiveMap[name] = values;
          info.push(`  ${name}: ${values}`);
        }

        // Check for unsafe directives
        if (policyToAnalyze.includes("'unsafe-inline'")) {
          issues.push("'unsafe-inline' allows inline scripts/styles, weakening XSS protection");
        }
        if (policyToAnalyze.includes("'unsafe-eval'")) {
          issues.push("'unsafe-eval' allows eval(), Function(), etc. - high XSS risk");
        }
        if (policyToAnalyze.includes('*')) {
          issues.push('Wildcard (*) source allows loading from any origin');
        }
        if (policyToAnalyze.includes('data:')) {
          issues.push("'data:' URI scheme can be used for XSS bypasses");
        }
        if (policyToAnalyze.includes('blob:')) {
          issues.push("'blob:' URI scheme can be abused for script execution");
        }

        // Check for missing critical directives
        const criticalDirectives = ['default-src', 'script-src', 'style-src', 'img-src', 'object-src', 'frame-ancestors'];
        const missing = criticalDirectives.filter(d => !directiveMap[d] && (d !== 'script-src' || !directiveMap['default-src']));
        if (missing.length > 0) {
          issues.push(`Missing directives: ${missing.join(', ')}`);
        }

        // Check if object-src is not 'none'
        if (directiveMap['object-src'] && directiveMap['object-src'] !== "'none'") {
          issues.push("object-src should be 'none' to prevent Flash/Java plugin exploitation");
        }

        // Check for base-uri
        if (!directiveMap['base-uri']) {
          issues.push("Missing base-uri directive (allows base tag injection)");
        }

        // Check for form-action
        if (!directiveMap['form-action']) {
          issues.push("Missing form-action directive (forms can submit to any origin)");
        }

        const severity = issues.length === 0 ? 'info' : (issues.some(i => i.includes('unsafe-inline') || i.includes('unsafe-eval') || i.includes('Wildcard')) ? 'high' : 'medium');

        const output = `CSP Analysis for ${url}:\n${isReportOnly ? '(Report-Only Mode)\n' : ''}\nDirectives:\n${info.join('\n')}\n\n${issues.length > 0 ? `Issues Found (${issues.length}):\n${issues.map(i => `  - ${i}`).join('\n')}` : 'No major issues found'}`;

        return {
          success: true,
          output,
          findings: issues.length > 0 ? [{
            title: 'CSP Configuration Issues',
            severity: severity as 'info' | 'low' | 'medium' | 'high' | 'critical',
            details: issues.join('; '),
          }] : undefined,
        };
      } catch (error) {
        return {
          success: false,
          error: `CSP analysis failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },
  {
    name: 'api_endpoint_discovery',
    description: 'Discover API endpoints by probing common patterns',
    category: 'web',
    parameters: [
      { name: 'url', type: 'string', description: 'Base URL of the target', required: true },
      { name: 'wordlist', type: 'string', description: 'Probe set: common, graphql, rest', required: false, default: 'common' },
    ],
    handler: async (context) => {
      const baseUrl = (context.parameters.url as string).replace(/\/+$/, '');
      const wordlistType = context.parameters.wordlist as string || 'common';

      const wordlists: Record<string, string[]> = {
        common: [
          '/api', '/api/v1', '/api/v2', '/api/v3',
          '/graphql', '/graphiql', '/playground',
          '/swagger', '/swagger-ui', '/swagger.json', '/swagger.yaml',
          '/openapi', '/openapi.json', '/openapi.yaml', '/api-docs',
          '/docs', '/redoc',
          '/health', '/healthz', '/health/check', '/healthcheck',
          '/status', '/info', '/version',
          '/metrics', '/prometheus',
          '/.well-known/openid-configuration',
          '/api/users', '/api/user', '/api/auth', '/api/login',
          '/api/config', '/api/settings', '/api/admin',
          '/rest', '/rest/api', '/jsonapi',
          '/v1', '/v2', '/v3',
          '/wp-json', '/wp-json/wp/v2',
        ],
        graphql: [
          '/graphql', '/graphiql', '/playground', '/graphql/console',
          '/gql', '/query', '/graphql/schema',
          '/api/graphql', '/v1/graphql', '/v2/graphql',
          '/graphql?query={__schema{types{name}}}',
        ],
        rest: [
          '/api', '/api/v1', '/api/v2',
          '/api/users', '/api/user', '/api/accounts',
          '/api/products', '/api/items', '/api/orders',
          '/api/auth', '/api/login', '/api/register',
          '/api/search', '/api/config', '/api/settings',
          '/api/admin', '/api/dashboard', '/api/stats',
          '/api/upload', '/api/files', '/api/export',
          '/api/health', '/api/status', '/api/info',
        ],
      };

      const endpoints = wordlists[wordlistType] || wordlists.common;
      const found: { path: string; status: number; contentType: string; size: number }[] = [];
      const interesting = [200, 201, 204, 301, 302, 307, 308, 401, 403, 405];

      const concurrency = 5;
      for (let i = 0; i < endpoints.length; i += concurrency) {
        const batch = endpoints.slice(i, i + concurrency);
        const checks = await Promise.all(
          batch.map(async (path) => {
            try {
              const fullUrl = `${baseUrl}${path}`;
              const resp = await targetFetch(fullUrl, {
                method: 'GET',
                signal: AbortSignal.timeout(5000),
                redirect: 'manual',
              });
              const contentType = resp.headers.get('content-type') || '';
              const bodyText = await resp.text();
              return {
                path,
                status: resp.status,
                contentType,
                size: bodyText.length,
                interesting: interesting.includes(resp.status),
              };
            } catch {
              return { path, status: 0, contentType: '', size: 0, interesting: false };
            }
          })
        );

        for (const result of checks) {
          if (result.interesting) {
            found.push({
              path: result.path,
              status: result.status,
              contentType: result.contentType,
              size: result.size,
            });
          }
        }
      }

      if (found.length === 0) {
        return {
          success: true,
          output: `API endpoint discovery on ${baseUrl}:\nNo API endpoints found from ${endpoints.length} probes.`,
        };
      }

      const output = found.map(f =>
        `  ${f.path} -> ${f.status} (${f.contentType.split(';')[0] || 'unknown'}, ${f.size} bytes)`
      ).join('\n');

      const apiEndpoints = found.filter(f => f.contentType.includes('json') || f.contentType.includes('xml') || f.path.includes('api') || f.path.includes('graphql'));
      const docEndpoints = found.filter(f => f.path.includes('swagger') || f.path.includes('openapi') || f.path.includes('docs') || f.path.includes('graphiql') || f.path.includes('playground'));

      return {
        success: true,
        output: `API endpoint discovery on ${baseUrl}:\nFound ${found.length} endpoints (tested ${endpoints.length}):\n${output}`,
        findings: (apiEndpoints.length > 0 || docEndpoints.length > 0) ? [
          ...(apiEndpoints.length > 0 ? [{
            title: 'API Endpoints Discovered',
            severity: 'info' as const,
            details: `Found ${apiEndpoints.length} API endpoints: ${apiEndpoints.map(e => e.path).join(', ')}`,
          }] : []),
          ...(docEndpoints.length > 0 ? [{
            title: 'API Documentation Exposed',
            severity: 'low' as const,
            details: `API documentation accessible at: ${docEndpoints.map(e => e.path).join(', ')}`,
          }] : []),
        ] : undefined,
      };
    },
  },
  {
    name: 'http_methods_test',
    description: 'Test which HTTP methods are allowed on a URL',
    category: 'web',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to test', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;
      const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT'];
      const results: { method: string; status: number; allowed: boolean }[] = [];
      const dangerousMethods: string[] = [];

      // First try OPTIONS to see if Allow header is returned
      let optionsAllow: string | null = null;
      try {
        const optResp = await targetFetch(url, {
          method: 'OPTIONS',
          signal: AbortSignal.timeout(5000),
        });
        optionsAllow = optResp.headers.get('allow');
        const accessControlMethods = optResp.headers.get('access-control-allow-methods');
        if (accessControlMethods) {
          optionsAllow = optionsAllow ? `${optionsAllow}, ${accessControlMethods}` : accessControlMethods;
        }
      } catch {
        // OPTIONS request failed, continue with individual tests
      }

      // Test each method individually
      for (const method of methods) {
        if (method === 'CONNECT') {
          // CONNECT is for proxying, skip actual test
          results.push({ method, status: 0, allowed: false });
          continue;
        }

        try {
          const response = await targetFetch(url, {
            method,
            signal: AbortSignal.timeout(5000),
            redirect: 'manual',
          });

          const status = response.status;
          // Consider a method "allowed" if it doesn't return 405 Method Not Allowed
          const allowed = status !== 405 && status !== 501;
          results.push({ method, status, allowed });

          if (allowed && ['PUT', 'DELETE', 'TRACE', 'PATCH'].includes(method)) {
            dangerousMethods.push(method);
          }

          // Consume response body to prevent connection leaks
          await response.text().catch(() => {});
        } catch {
          results.push({ method, status: 0, allowed: false });
        }
      }

      const output = results.map(r => {
        if (r.status === 0) return `  ${r.method}: unreachable`;
        return `  ${r.method}: ${r.status} ${r.allowed ? '(allowed)' : '(not allowed)'}`;
      }).join('\n');

      const sections = [`HTTP Methods Test for ${url}:\n${output}`];
      if (optionsAllow) {
        sections.push(`\nAllow header: ${optionsAllow}`);
      }

      return {
        success: true,
        output: sections.join('\n'),
        findings: dangerousMethods.length > 0 ? [{
          title: 'Dangerous HTTP Methods Enabled',
          severity: 'medium' as const,
          details: `The following potentially dangerous HTTP methods are enabled: ${dangerousMethods.join(', ')}. TRACE can enable XST attacks, PUT/DELETE may allow unauthorized modifications.`,
        }] : undefined,
      };
    },
  },

  // =============================================================================
  // ADDITIONAL VULNERABILITY SCANNING TOOLS
  // =============================================================================
  {
    name: 'cors_check',
    description: 'Test CORS configuration with various Origin headers',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to test', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;

      // Parse the target origin for comparison
      let targetOrigin: URL;
      try {
        targetOrigin = new URL(url);
      } catch {
        return { success: false, error: `Invalid URL: ${url}` };
      }

      const testOrigins = [
        { origin: 'https://evil.com', name: 'Arbitrary origin' },
        { origin: `https://sub.${targetOrigin.hostname}`, name: 'Subdomain' },
        { origin: `https://${targetOrigin.hostname}.evil.com`, name: 'Domain suffix attack' },
        { origin: 'null', name: 'Null origin' },
        { origin: `https://evil${targetOrigin.hostname}`, name: 'Prefix attack' },
        { origin: targetOrigin.origin, name: 'Same origin (baseline)' },
      ];

      const results: { origin: string; name: string; acao: string | null; acac: string | null; vulnerable: boolean; issue: string }[] = [];
      const vulnerabilities: string[] = [];

      for (const test of testOrigins) {
        try {
          const response = await targetFetch(url, {
            method: 'GET',
            headers: { 'Origin': test.origin },
            signal: AbortSignal.timeout(5000),
          });

          const acao = response.headers.get('access-control-allow-origin');
          const acac = response.headers.get('access-control-allow-credentials');

          let vulnerable = false;
          let issue = 'No CORS headers returned';

          if (acao) {
            if (acao === '*') {
              issue = 'Wildcard ACAO (*)';
              if (acac === 'true') {
                vulnerable = true;
                issue = 'Wildcard ACAO with credentials - CRITICAL';
              }
            } else if (acao === test.origin && test.name !== 'Same origin (baseline)') {
              issue = `Origin reflected: ${acao}`;
              vulnerable = true;
              if (acac === 'true') {
                issue += ' WITH credentials - CRITICAL';
              }
            } else if (acao === 'null' && test.origin === 'null') {
              vulnerable = true;
              issue = 'Null origin accepted';
            } else {
              issue = `ACAO: ${acao}`;
            }
          }

          results.push({ origin: test.origin, name: test.name, acao, acac, vulnerable, issue });
          if (vulnerable) {
            vulnerabilities.push(`${test.name}: ${issue}`);
          }

          // Consume response body
          await response.text().catch(() => {});
        } catch {
          results.push({ origin: test.origin, name: test.name, acao: null, acac: null, vulnerable: false, issue: 'Request failed' });
        }
      }

      const output = results.map(r =>
        `  [${r.name}] Origin: ${r.origin}\n    -> ${r.issue}${r.acac ? ` | Credentials: ${r.acac}` : ''}`
      ).join('\n');

      return {
        success: true,
        output: `CORS Configuration Check for ${url}:\n${output}`,
        findings: vulnerabilities.length > 0 ? [{
          title: 'CORS Misconfiguration',
          severity: vulnerabilities.some(v => v.includes('CRITICAL')) ? 'critical' as const : 'high' as const,
          details: vulnerabilities.join('; '),
        }] : undefined,
      };
    },
  },
  {
    name: 'cookie_analysis',
    description: 'Fetch a URL and analyze Set-Cookie headers for security flags',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to analyze', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;

      try {
        const response = await targetFetch(url, {
          signal: AbortSignal.timeout(10000),
          redirect: 'manual', // Don't follow redirects to capture Set-Cookie
        });

        // Get all Set-Cookie headers
        const setCookieHeaders = response.headers.getSetCookie ? response.headers.getSetCookie() : [];
        // Fallback: try raw header
        const rawSetCookie = response.headers.get('set-cookie');

        const cookies: string[] = [...setCookieHeaders];
        if (cookies.length === 0 && rawSetCookie) {
          // Some environments return all cookies in a single header
          cookies.push(...rawSetCookie.split(/,(?=[^;]*=)/));
        }

        if (cookies.length === 0) {
          return {
            success: true,
            output: `Cookie Analysis for ${url}:\nNo Set-Cookie headers found in the response.`,
          };
        }

        const issues: string[] = [];
        const cookieAnalysis: string[] = [];

        for (const cookie of cookies) {
          const parts = cookie.split(';').map(p => p.trim());
          const nameValue = parts[0];
          const cookieName = nameValue.split('=')[0].trim();
          const flags = parts.slice(1).map(f => f.toLowerCase());

          const hasHttpOnly = flags.some(f => f === 'httponly');
          const hasSecure = flags.some(f => f === 'secure');
          const hasSameSite = flags.some(f => f.startsWith('samesite'));
          const sameSiteValue = flags.find(f => f.startsWith('samesite'))?.split('=')[1]?.trim() || 'not set';
          const pathValue = flags.find(f => f.startsWith('path'))?.split('=')[1]?.trim() || '/';
          const hasDomain = flags.some(f => f.startsWith('domain'));
          const domainValue = flags.find(f => f.startsWith('domain'))?.split('=')[1]?.trim() || '';
          const hasExpires = flags.some(f => f.startsWith('expires') || f.startsWith('max-age'));

          const cookieIssues: string[] = [];
          if (!hasHttpOnly) cookieIssues.push('Missing HttpOnly');
          if (!hasSecure) cookieIssues.push('Missing Secure');
          if (!hasSameSite) cookieIssues.push('Missing SameSite');
          if (sameSiteValue === 'none' && !hasSecure) cookieIssues.push('SameSite=None without Secure');
          if (sameSiteValue === 'none') cookieIssues.push('SameSite=None (allows cross-site)');

          // Check for session-like cookie names without security flags
          const sessionLike = /sess|token|auth|jwt|sid|id/i.test(cookieName);
          if (sessionLike && !hasHttpOnly) {
            cookieIssues.push('Session cookie without HttpOnly - vulnerable to XSS theft');
          }

          cookieAnalysis.push(
            `  Cookie: ${cookieName}\n` +
            `    HttpOnly: ${hasHttpOnly ? 'Yes' : 'NO'}\n` +
            `    Secure: ${hasSecure ? 'Yes' : 'NO'}\n` +
            `    SameSite: ${sameSiteValue}\n` +
            `    Path: ${pathValue}\n` +
            `    Domain: ${hasDomain ? domainValue : '(not set)'}\n` +
            `    Persistent: ${hasExpires ? 'Yes' : 'No (session)'}\n` +
            `    Issues: ${cookieIssues.length > 0 ? cookieIssues.join(', ') : 'None'}`
          );

          issues.push(...cookieIssues.map(i => `[${cookieName}] ${i}`));
        }

        return {
          success: true,
          output: `Cookie Analysis for ${url}:\nFound ${cookies.length} cookie(s):\n\n${cookieAnalysis.join('\n\n')}`,
          findings: issues.length > 0 ? [{
            title: 'Cookie Security Issues',
            severity: issues.some(i => i.includes('Session cookie') || i.includes('Missing HttpOnly')) ? 'high' as const : 'medium' as const,
            details: issues.join('; '),
          }] : undefined,
        };
      } catch (error) {
        return {
          success: false,
          error: `Cookie analysis failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },
  {
    name: 'open_redirect_test',
    description: 'Test URL parameters for open redirect vulnerabilities',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'URL with redirect parameter to test', required: true },
      { name: 'param', type: 'string', description: 'Parameter name to test (e.g., "redirect", "url", "next")', required: true },
    ],
    handler: async (context) => {
      const baseUrl = context.parameters.url as string;
      const param = context.parameters.param as string;

      const payloads = [
        { payload: 'https://evil.com', name: 'Direct external URL' },
        { payload: '//evil.com', name: 'Protocol-relative URL' },
        { payload: '/\\evil.com', name: 'Backslash bypass' },
        { payload: 'https://evil.com%00.legitimate.com', name: 'Null byte injection' },
        { payload: 'https://evil.com?.legitimate.com', name: 'Question mark bypass' },
        { payload: 'https://evil.com#.legitimate.com', name: 'Fragment bypass' },
        { payload: 'https://evil.com@legitimate.com', name: 'At-sign bypass' },
        { payload: '/%2f/evil.com', name: 'URL-encoded slash bypass' },
        { payload: 'javascript:alert(1)', name: 'JavaScript URI' },
        { payload: 'data:text/html,<script>alert(1)</script>', name: 'Data URI' },
      ];

      const results: { payload: string; name: string; redirected: boolean; location: string }[] = [];
      const vulnerabilities: string[] = [];

      for (const { payload, name } of payloads) {
        try {
          const testUrl = new URL(baseUrl);
          testUrl.searchParams.set(param, payload);

          const response = await targetFetch(testUrl.toString(), {
            redirect: 'manual', // Don't follow redirects
            signal: AbortSignal.timeout(5000),
          });

          const location = response.headers.get('location') || '';
          const status = response.status;
          const isRedirect = [301, 302, 303, 307, 308].includes(status);

          let redirected = false;
          if (isRedirect && location) {
            // Check if it redirects to our payload or an external domain
            try {
              const locUrl = new URL(location, baseUrl);
              const origUrl = new URL(baseUrl);
              if (locUrl.hostname !== origUrl.hostname) {
                redirected = true;
              }
            } catch {
              // If location contains evil.com or similar
              if (location.includes('evil.com')) {
                redirected = true;
              }
            }
          }

          results.push({ payload, name, redirected, location: isRedirect ? location : `(${status})` });
          if (redirected) {
            vulnerabilities.push(`${name}: redirects to ${location}`);
          }

          // Consume response body
          await response.text().catch(() => {});
        } catch {
          results.push({ payload, name, redirected: false, location: '(error)' });
        }
      }

      const output = results.map(r => {
        const status = r.redirected ? `VULNERABLE -> ${r.location}` : `OK ${r.location}`;
        return `  [${r.name}] ${status}`;
      }).join('\n');

      return {
        success: true,
        output: `Open Redirect Test on ${baseUrl} (param: ${param}):\n${output}`,
        findings: vulnerabilities.length > 0 ? [{
          title: 'Open Redirect Vulnerability',
          severity: 'medium' as const,
          details: `Parameter "${param}" is vulnerable to open redirect: ${vulnerabilities.join('; ')}`,
        }] : undefined,
      };
    },
  },
  {
    name: 'lfi_test',
    description: 'Test for Local File Inclusion with common traversal payloads',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'URL with file parameter to test', required: true },
      { name: 'param', type: 'string', description: 'Parameter name to test (e.g., "file", "page", "path")', required: true },
    ],
    handler: async (context) => {
      const baseUrl = context.parameters.url as string;
      const param = context.parameters.param as string;

      const payloads = [
        { payload: '../../../../etc/passwd', name: 'Basic traversal (etc/passwd)' },
        { payload: '....//....//....//....//etc/passwd', name: 'Double dot filter bypass' },
        { payload: '..%2f..%2f..%2f..%2fetc%2fpasswd', name: 'URL-encoded traversal' },
        { payload: '..%252f..%252f..%252f..%252fetc%252fpasswd', name: 'Double-encoded traversal' },
        { payload: '/etc/passwd', name: 'Absolute path (etc/passwd)' },
        { payload: '../../../../etc/shadow', name: 'Shadow file attempt' },
        { payload: '../../../../windows/system32/drivers/etc/hosts', name: 'Windows hosts file' },
        { payload: '../../../../windows/win.ini', name: 'Windows win.ini' },
        { payload: 'php://filter/convert.base64-encode/resource=/etc/passwd', name: 'PHP filter wrapper' },
        { payload: '/proc/self/environ', name: 'Proc environ' },
      ];

      // Signatures that indicate successful file read
      const linuxFileSignatures = ['root:', 'bin:', 'daemon:', 'nobody:', '/bin/bash', '/bin/sh', 'nologin'];
      const windowsFileSignatures = ['[boot loader]', '[fonts]', '[extensions]', '[mci extensions]', 'for 16-bit app support'];
      const phpFilterSignature = /^[A-Za-z0-9+/=]{20,}/; // Base64 encoded content

      const results: { payload: string; name: string; vulnerable: boolean; indicator: string }[] = [];
      const vulnerabilities: string[] = [];

      // Get baseline response for comparison
      let baselineLength = 0;
      try {
        const baselineUrl = new URL(baseUrl);
        baselineUrl.searchParams.set(param, 'nonexistent_file_xyz');
        const baseResp = await targetFetch(baselineUrl.toString(), { signal: AbortSignal.timeout(5000) });
        const baseBody = await baseResp.text();
        baselineLength = baseBody.length;
      } catch {
        // Continue anyway
      }

      for (const { payload, name } of payloads) {
        try {
          const testUrl = new URL(baseUrl);
          testUrl.searchParams.set(param, payload);

          const response = await targetFetch(testUrl.toString(), {
            signal: AbortSignal.timeout(5000),
          });
          const body = await response.text();
          const bodyLower = body.toLowerCase();

          let vulnerable = false;
          let indicator = 'No LFI indicators';

          // Check for Linux file content
          const linuxMatches = linuxFileSignatures.filter(s => bodyLower.includes(s.toLowerCase()));
          if (linuxMatches.length >= 2) {
            vulnerable = true;
            indicator = `Linux file content detected (${linuxMatches.join(', ')})`;
          }

          // Check for Windows file content
          const windowsMatches = windowsFileSignatures.filter(s => bodyLower.includes(s.toLowerCase()));
          if (windowsMatches.length >= 1) {
            vulnerable = true;
            indicator = `Windows file content detected (${windowsMatches.join(', ')})`;
          }

          // Check for PHP filter (base64) response
          if (name.includes('PHP filter') && phpFilterSignature.test(body.trim())) {
            vulnerable = true;
            indicator = 'PHP filter wrapper returned base64 content';
          }

          // Check for significant response length difference suggesting file read
          if (!vulnerable && baselineLength > 0) {
            const lengthDiff = body.length - baselineLength;
            if (lengthDiff > 200 && response.status === 200) {
              indicator = `Larger response (+${lengthDiff} bytes) - possible file content`;
            }
          }

          // Check for error messages that confirm LFI attempt but filtered
          if (bodyLower.includes('no such file') || bodyLower.includes('failed to open') ||
              bodyLower.includes('include(') || bodyLower.includes('require(') ||
              bodyLower.includes('file_get_contents')) {
            indicator = 'File operation error message disclosed (path traversal partially works)';
          }

          results.push({ payload, name, vulnerable, indicator });
          if (vulnerable) {
            vulnerabilities.push(`${name}: ${indicator}`);
          }
        } catch {
          results.push({ payload, name, vulnerable: false, indicator: 'Request failed' });
        }
      }

      const output = results.map(r => {
        const status = r.vulnerable ? `VULNERABLE - ${r.indicator}` : r.indicator;
        return `  [${r.name}] ${status}`;
      }).join('\n');

      return {
        success: true,
        output: `LFI Test on ${baseUrl} (param: ${param}):\n${output}`,
        findings: vulnerabilities.length > 0 ? [{
          title: 'Local File Inclusion Vulnerability',
          severity: 'critical' as const,
          details: `Parameter "${param}" is vulnerable to LFI: ${vulnerabilities.join('; ')}`,
        }] : undefined,
      };
    },
  },
  {
    name: 'ssti_test',
    description: 'Test for Server-Side Template Injection with common payloads',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'URL with parameter to test', required: true },
      { name: 'param', type: 'string', description: 'Parameter name to test', required: true },
    ],
    handler: async (context) => {
      const baseUrl = context.parameters.url as string;
      const param = context.parameters.param as string;

      const payloads = [
        { payload: '{{7*7}}', expected: '49', name: 'Jinja2/Twig double-brace' },
        { payload: '${7*7}', expected: '49', name: 'FreeMarker/Spring EL dollar-brace' },
        { payload: '#{7*7}', expected: '49', name: 'Thymeleaf hash-brace' },
        { payload: '<%= 7*7 %>', expected: '49', name: 'ERB/JSP expression tag' },
        { payload: '{{7*\'7\'}}', expected: '7777777', name: 'Jinja2 string multiplication' },
        { payload: '${7*7}', expected: '49', name: 'Java EL expression' },
        { payload: '{{config}}', expected: '', name: 'Jinja2 config access probe' },
        { payload: '{{self.__class__}}', expected: '', name: 'Jinja2 class introspection' },
        { payload: '${T(java.lang.Runtime)}', expected: '', name: 'Spring RCE probe' },
        { payload: '{php}echo 7*7;{/php}', expected: '49', name: 'Smarty PHP tag' },
      ];

      const results: { payload: string; name: string; vulnerable: boolean; indicator: string }[] = [];
      const vulnerabilities: string[] = [];

      for (const { payload, expected, name } of payloads) {
        try {
          const testUrl = new URL(baseUrl);
          testUrl.searchParams.set(param, payload);

          const response = await targetFetch(testUrl.toString(), {
            signal: AbortSignal.timeout(5000),
          });
          const body = await response.text();

          let vulnerable = false;
          let indicator = 'Payload not evaluated';

          // Check if the template expression was evaluated (result present, payload absent)
          if (expected && body.includes(expected) && !body.includes(payload)) {
            vulnerable = true;
            indicator = `Expression evaluated: ${payload} = ${expected}`;
          }

          // For probes without a specific expected result, check for template engine info leakage
          if (!expected && name.includes('config') && (body.includes('SECRET_KEY') || body.includes('DEBUG') || body.includes('<Config'))) {
            vulnerable = true;
            indicator = 'Template config object accessible';
          }

          if (!expected && name.includes('class') && (body.includes('__class__') || body.includes('TemplateReference') || body.includes('Undefined'))) {
            vulnerable = true;
            indicator = 'Template class introspection possible';
          }

          // Check for template engine error messages (partial vulnerability)
          if (!vulnerable) {
            const templateErrors = [
              'TemplateSyntaxError', 'UndefinedError', 'jinja2', 'twig',
              'freemarker', 'thymeleaf', 'velocity', 'smarty',
              'template error', 'expression error', 'ELException',
            ];
            for (const errStr of templateErrors) {
              if (body.toLowerCase().includes(errStr.toLowerCase())) {
                indicator = `Template engine error: "${errStr}" - engine identified but expression blocked`;
                break;
              }
            }
          }

          results.push({ payload, name, vulnerable, indicator });
          if (vulnerable) {
            vulnerabilities.push(`${name}: ${indicator}`);
          }
        } catch {
          results.push({ payload, name, vulnerable: false, indicator: 'Request failed' });
        }
      }

      const output = results.map(r => {
        const status = r.vulnerable ? `VULNERABLE - ${r.indicator}` : r.indicator;
        return `  [${r.name}] ${status}`;
      }).join('\n');

      return {
        success: true,
        output: `SSTI Test on ${baseUrl} (param: ${param}):\n${output}`,
        findings: vulnerabilities.length > 0 ? [{
          title: 'Server-Side Template Injection',
          severity: 'critical' as const,
          details: `Parameter "${param}" is vulnerable to SSTI: ${vulnerabilities.join('; ')}`,
        }] : undefined,
      };
    },
  },
  {
    name: 'clickjacking_test',
    description: 'Check if a URL is protected against clickjacking (X-Frame-Options and CSP frame-ancestors)',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to test', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;

      try {
        const response = await targetFetch(url, {
          method: 'GET',
          signal: AbortSignal.timeout(10000),
        });

        const xfo = response.headers.get('x-frame-options');
        const csp = response.headers.get('content-security-policy');

        const issues: string[] = [];
        const info: string[] = [];

        // Analyze X-Frame-Options
        if (xfo) {
          const xfoUpper = xfo.toUpperCase().trim();
          info.push(`X-Frame-Options: ${xfo}`);
          if (xfoUpper === 'DENY') {
            info.push('  -> Framing completely denied (strong)');
          } else if (xfoUpper === 'SAMEORIGIN') {
            info.push('  -> Framing allowed from same origin only (good)');
          } else if (xfoUpper.startsWith('ALLOW-FROM')) {
            info.push(`  -> Framing allowed from specific origin (note: ALLOW-FROM is deprecated and not supported by modern browsers)`);
            issues.push('X-Frame-Options ALLOW-FROM is deprecated; use CSP frame-ancestors instead');
          } else {
            issues.push(`Invalid X-Frame-Options value: ${xfo}`);
          }
        } else {
          issues.push('X-Frame-Options header is missing');
        }

        // Analyze CSP frame-ancestors
        let hasFrameAncestors = false;
        if (csp) {
          const frameAncestorsMatch = csp.match(/frame-ancestors\s+([^;]+)/i);
          if (frameAncestorsMatch) {
            hasFrameAncestors = true;
            const value = frameAncestorsMatch[1].trim();
            info.push(`CSP frame-ancestors: ${value}`);
            if (value === "'none'") {
              info.push('  -> Framing completely denied via CSP (strong)');
            } else if (value === "'self'") {
              info.push('  -> Framing allowed from same origin via CSP (good)');
            } else {
              info.push(`  -> Custom frame-ancestors policy: ${value}`);
              if (value.includes('*')) {
                issues.push('CSP frame-ancestors contains wildcard - weakens clickjacking protection');
              }
            }
          }
        }

        if (!hasFrameAncestors && !xfo) {
          issues.push('No clickjacking protection found (neither X-Frame-Options nor CSP frame-ancestors)');
        } else if (!hasFrameAncestors) {
          info.push('CSP frame-ancestors: Not set (relying on X-Frame-Options only)');
        }

        const output = `Clickjacking Protection Test for ${url}:\n\n${info.join('\n')}\n\n${issues.length > 0 ? `Issues (${issues.length}):\n${issues.map(i => `  - ${i}`).join('\n')}` : 'Site appears protected against clickjacking'}`;

        return {
          success: true,
          output,
          findings: issues.length > 0 ? [{
            title: 'Clickjacking Protection Issues',
            severity: issues.some(i => i.includes('No clickjacking protection')) ? 'medium' as const : 'low' as const,
            details: issues.join('; '),
          }] : undefined,
        };
      } catch (error) {
        return {
          success: false,
          error: `Clickjacking test failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },

  // =============================================================================
  // ADDITIONAL UTILITY TOOLS
  // =============================================================================
  {
    name: 'cve_lookup',
    description: 'Look up CVEs from the built-in CVE database by keyword or CVE ID',
    category: 'util',
    parameters: [
      { name: 'query', type: 'string', description: 'Search keyword or CVE ID (e.g., "log4j" or "CVE-2021-44228")', required: true },
    ],
    handler: async (context) => {
      const query = (context.parameters.query as string).toLowerCase();

      const matches: CVEEntry[] = CVE_DATABASE.filter(cve =>
        cve.id.toLowerCase().includes(query) ||
        cve.description.toLowerCase().includes(query)
      );

      if (matches.length === 0) {
        return {
          success: true,
          output: `CVE Lookup for "${query}":\nNo matching CVEs found in the local database (${CVE_DATABASE.length} entries).`,
        };
      }

      const output = matches.map(cve =>
        `  ${cve.id} (CVSS: ${cve.cvss})\n    ${cve.description}`
      ).join('\n\n');

      return {
        success: true,
        output: `CVE Lookup for "${query}":\nFound ${matches.length} matching CVE(s):\n\n${output}`,
        findings: matches.filter(m => m.cvss >= 9.0).length > 0 ? [{
          title: 'Critical CVEs Found',
          severity: 'critical' as const,
          details: `Found ${matches.filter(m => m.cvss >= 9.0).length} critical CVEs (CVSS >= 9.0): ${matches.filter(m => m.cvss >= 9.0).map(m => m.id).join(', ')}`,
        }] : undefined,
      };
    },
  },
  {
    name: 'url_encode',
    description: 'URL encode or decode data',
    category: 'util',
    parameters: [
      { name: 'data', type: 'string', description: 'Data to encode or decode', required: true },
      { name: 'mode', type: 'string', description: 'Mode: "encode" or "decode"', required: false, default: 'encode' },
      { name: 'component', type: 'boolean', description: 'Use encodeURIComponent (true) or encodeURI (false)', required: false, default: true },
    ],
    handler: async (context) => {
      const data = context.parameters.data as string;
      const mode = (context.parameters.mode as string || 'encode').toLowerCase();
      const component = context.parameters.component !== false;

      try {
        let result: string;

        if (mode === 'decode') {
          result = component ? decodeURIComponent(data) : decodeURI(data);
        } else {
          result = component ? encodeURIComponent(data) : encodeURI(data);
        }

        return {
          success: true,
          output: `URL ${mode === 'decode' ? 'Decode' : 'Encode'} (${component ? 'component' : 'full URI'}):\nInput:  ${data}\nOutput: ${result}`,
        };
      } catch (error) {
        return {
          success: false,
          error: `URL ${mode} failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },
  {
    name: 'cidr_expand',
    description: 'Expand a CIDR notation into individual IP addresses (limited to /24 max)',
    category: 'util',
    parameters: [
      { name: 'cidr', type: 'string', description: 'CIDR notation (e.g., "192.168.1.0/24")', required: true },
    ],
    handler: async (context) => {
      const cidr = context.parameters.cidr as string;

      const cidrMatch = cidr.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
      if (!cidrMatch) {
        return {
          success: false,
          error: `Invalid CIDR notation: ${cidr}. Expected format: x.x.x.x/prefix (e.g., 192.168.1.0/24)`,
        };
      }

      const ipStr = cidrMatch[1];
      const prefix = parseInt(cidrMatch[2], 10);

      if (prefix < 0 || prefix > 32) {
        return {
          success: false,
          error: `Invalid prefix length: /${prefix}. Must be between 0 and 32.`,
        };
      }

      if (prefix < 24) {
        return {
          success: false,
          error: `Prefix /${prefix} would generate ${Math.pow(2, 32 - prefix)} IPs. Maximum supported is /24 (256 IPs) to prevent excessive output.`,
        };
      }

      // Parse the base IP to a 32-bit integer
      const octets = ipStr.split('.').map(o => parseInt(o, 10));
      if (octets.some(o => o < 0 || o > 255)) {
        return {
          success: false,
          error: `Invalid IP address: ${ipStr}. Each octet must be 0-255.`,
        };
      }

      const ipInt = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
      const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
      const network = (ipInt & mask) >>> 0;
      const broadcast = (network | (~mask >>> 0)) >>> 0;
      const totalHosts = broadcast - network + 1;

      const ips: string[] = [];
      for (let ip = network; ip <= broadcast; ip++) {
        ips.push(
          `${(ip >>> 24) & 255}.${(ip >>> 16) & 255}.${(ip >>> 8) & 255}.${ip & 255}`
        );
      }

      const networkIp = ips[0];
      const broadcastIp = ips[ips.length - 1];
      const usableRange = totalHosts > 2
        ? `${ips[1]} - ${ips[ips.length - 2]}`
        : 'N/A (point-to-point or host)';

      return {
        success: true,
        output: `CIDR Expansion for ${cidr}:\n` +
          `Network:    ${networkIp}\n` +
          `Broadcast:  ${broadcastIp}\n` +
          `Subnet Mask: ${((mask >>> 24) & 255)}.${((mask >>> 16) & 255)}.${((mask >>> 8) & 255)}.${mask & 255}\n` +
          `Total IPs:  ${totalHosts}\n` +
          `Usable Range: ${usableRange}\n` +
          `Usable Hosts: ${Math.max(0, totalHosts - 2)}\n\n` +
          `All IPs:\n${ips.map(ip => `  ${ip}`).join('\n')}`,
      };
    },
  },
];

// =============================================================================
// SUBPROCESS TOOL EXECUTION
// =============================================================================

/**
 * Check if a command-line tool is available on the system
 */
export async function isToolAvailable(command: string): Promise<boolean> {
  try {
    await execFileAsync('which', [command], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Run a subprocess tool with timeout and output capture
 */
export async function runSubprocess(
  command: string,
  args: string[],
  options?: { timeout?: number; maxOutput?: number }
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const timeout = options?.timeout ?? 60000;
  const maxOutput = options?.maxOutput ?? 1024 * 1024; // 1MB

  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout,
      maxBuffer: maxOutput,
    });
    return { stdout, stderr, exitCode: 0 };
  } catch (error: unknown) {
    const err = error as { stdout?: string; stderr?: string; code?: number; killed?: boolean };
    if (err.killed) {
      return { stdout: err.stdout || '', stderr: 'Process killed (timeout)', exitCode: -1 };
    }
    return { stdout: err.stdout || '', stderr: err.stderr || String(error), exitCode: err.code || 1 };
  }
}

/**
 * External CLI tools that wrap real security tools when available.
 * These gracefully degrade — if the tool isn't installed, they return a helpful message.
 */
// LLM-supplied `flags` for shell-out tools are ATTACKER-INFLUENCED: word-splitting them into argv is
// flag injection that reads/writes the OPERATOR's own machine (curl -o/-K/-T/-x/--config, nmap
// -oN/--script/-iL). This sanitizer drops the file-write/read/config/script flags (and their values);
// curl bodies are separately forced through --data-raw with an explicit @/< reject. Mirrors the
// hardened templates in adapter-tools.ts; fail-closed on the known-dangerous vectors.
const DANGEROUS_EXTERNAL_FLAGS: Record<string, RegExp> = {
  curl: /^(-o|-O|--output|--remote-name|-K|--config|-T|--upload-file|-x|--proxy|--preproxy|-D|--dump-header|--trace|--trace-ascii|-w|--write-out|--cert|--key|--cacert|--capath|--cert-type|--key-type|--output-dir|--create-dirs|-c|--cookie-jar)$/i,
  nmap: /^(-o[NXGAS]|--script|--script-args|--script-args-file|--script-help|--script-updatedb|-iL|--excludefile|--datadir|--servicedb|--versiondb|--resume|--stylesheet|--webxml)$/i,
};
function sanitizeExternalFlags(tool: 'curl' | 'nmap', raw?: string): string[] {
  const bad = DANGEROUS_EXTERNAL_FLAGS[tool];
  const toks = (raw || '').split(/\s+/).filter(Boolean);
  const out: string[] = [];
  for (let i = 0; i < toks.length; i++) {
    const name = toks[i].split('=')[0];
    if (bad.test(name)) {
      if (!toks[i].includes('=') && toks[i + 1] && !toks[i + 1].startsWith('-')) i++; // also drop the flag's value token
      continue;
    }
    out.push(toks[i]);
  }
  return out;
}

function withoutCurlRedirectFlags(flags: string[]): string[] {
  return flags.filter(flag => !/^--location(?:-trusted)?(?:=|$)/i.test(flag) && !/^-[^-]*L/.test(flag));
}

export const EXTERNAL_TOOLS: CustomTool[] = [
  {
    name: 'nmap_scan',
    description: 'Run nmap port/service scan (requires nmap installed)',
    category: 'recon',
    parameters: [
      { name: 'target', type: 'string', description: 'Target IP or hostname', required: true },
      { name: 'flags', type: 'string', description: 'nmap flags (e.g., "-sV -sC -T4")', required: false, default: '-sV -T4' },
      { name: 'ports', type: 'string', description: 'Port specification (e.g., "1-1000" or "22,80,443")', required: false },
    ],
    handler: async (context) => {
      if (!(await isToolAvailable('nmap'))) {
        return { success: false, error: 'nmap is not installed. Install it with: apt install nmap' };
      }
      const target = context.parameters.target as string;
      const flags = sanitizeExternalFlags('nmap', context.parameters.flags as string || '-sV -T4'); // drop -oN/--script/-iL injection
      const ports = context.parameters.ports as string | undefined;

      const args = [...flags];
      if (ports) args.push('-p', ports);
      args.push(target);

      const result = await runSubprocess('nmap', args, { timeout: 120000 });
      if (result.exitCode !== 0) {
        return { success: false, error: `nmap failed: ${result.stderr}` };
      }

      // Parse open ports from output
      const openPorts = (result.stdout.match(/(\d+)\/tcp\s+open/g) || []).length;
      return {
        success: true,
        output: result.stdout,
        findings: openPorts > 0 ? [{
          title: 'Open Ports/Services Detected (nmap)',
          severity: 'info',
          details: `nmap found ${openPorts} open ports on ${target}`,
        }] : undefined,
      };
    },
  },
  {
    name: 'nuclei_scan',
    description: 'Run nuclei vulnerability scanner (requires nuclei installed)',
    category: 'vuln',
    parameters: [
      { name: 'target', type: 'string', description: 'Target URL', required: true },
      { name: 'severity', type: 'string', description: 'Severity filter: info,low,medium,high,critical', required: false, default: 'medium,high,critical' },
      { name: 'tags', type: 'string', description: 'Template tags (e.g., "cve,sqli,xss")', required: false },
    ],
    handler: async (context) => {
      if (!(await isToolAvailable('nuclei'))) {
        return { success: false, error: 'nuclei is not installed. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' };
      }
      const target = context.parameters.target as string;
      const severity = context.parameters.severity as string || 'medium,high,critical';
      const tags = context.parameters.tags as string | undefined;

      const args = ['-target', target, '-severity', severity, '-silent', '-jsonl'];
      if (tags) args.push('-tags', tags);

      const result = await runSubprocess('nuclei', args, { timeout: 300000 });

      // Parse JSON lines output
      const findings: Array<{ title: string; severity: 'info' | 'low' | 'medium' | 'high' | 'critical'; details: string }> = [];
      for (const line of result.stdout.split('\n').filter(l => l.trim())) {
        try {
          const entry = JSON.parse(line);
          findings.push({
            title: entry.info?.name || entry['template-id'] || 'Unknown',
            severity: entry.info?.severity || 'info',
            details: `${entry.info?.name || 'Finding'} at ${entry.host || target}: ${entry.info?.description || entry.matched || ''}`,
          });
        } catch {
          // Skip non-JSON lines
        }
      }

      return {
        success: true,
        output: findings.length > 0
          ? `Nuclei scan of ${target}:\nFound ${findings.length} vulnerabilities:\n${findings.map(f => `  [${f.severity.toUpperCase()}] ${f.title}`).join('\n')}`
          : `Nuclei scan of ${target}: No vulnerabilities found at severity level: ${severity}`,
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 'ffuf_fuzz',
    description: 'Run ffuf web fuzzer for directory/parameter discovery (requires ffuf installed)',
    category: 'web',
    parameters: [
      { name: 'url', type: 'string', description: 'URL with FUZZ keyword (e.g., http://target/FUZZ)', required: true },
      { name: 'wordlist', type: 'string', description: 'Path to wordlist', required: false, default: '/usr/share/wordlists/dirb/common.txt' },
      { name: 'mc', type: 'string', description: 'Match HTTP status codes', required: false, default: '200,301,302,403' },
    ],
    handler: async (context) => {
      if (!(await isToolAvailable('ffuf'))) {
        return { success: false, error: 'ffuf is not installed. Install: go install github.com/ffuf/ffuf/v2@latest' };
      }
      const url = context.parameters.url as string;
      const wordlist = context.parameters.wordlist as string || '/usr/share/wordlists/dirb/common.txt';
      const mc = context.parameters.mc as string || '200,301,302,403';

      const args = ['-u', url, '-w', wordlist, '-mc', mc, '-o', '/dev/stdout', '-of', 'json', '-s'];
      const result = await runSubprocess('ffuf', args, { timeout: 120000 });

      try {
        const data = JSON.parse(result.stdout);
        const results = data.results || [];
        return {
          success: true,
          output: `ffuf scan of ${url}:\nFound ${results.length} results:\n${results.slice(0, 50).map((r: { input?: { FUZZ?: string }; status?: number; length?: number }) =>
            `  ${r.input?.FUZZ || '?'} -> ${r.status} (${r.length} bytes)`
          ).join('\n')}`,
          findings: results.length > 0 ? [{
            title: 'Directories/Files Discovered (ffuf)',
            severity: 'info',
            details: `Found ${results.length} accessible paths`,
          }] : undefined,
        };
      } catch {
        return { success: true, output: result.stdout || 'No results found' };
      }
    },
  },
  {
    name: 'curl_request',
    description: 'Make an HTTP request using curl (supports advanced options)',
    category: 'web',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to request', required: true },
      { name: 'method', type: 'string', description: 'HTTP method', required: false, default: 'GET' },
      { name: 'data', type: 'string', description: 'Request body data', required: false },
      { name: 'headers', type: 'string', description: 'Headers as "Key: Value" (comma separated)', required: false },
      { name: 'flags', type: 'string', description: 'Additional curl flags', required: false },
    ],
    handler: async (context) => {
      if (!(await isToolAvailable('curl'))) {
        return { success: false, error: 'curl is not installed' };
      }
      const url = context.parameters.url as string;
      const method = context.parameters.method as string || 'GET';
      const data = context.parameters.data as string | undefined;
      const headers = context.parameters.headers as string | undefined;
      const flags = context.parameters.flags as string | undefined;

      const args = ['-s', '-i', '-X', method];
      let configuredHeaders = targetHeadersForUrl(url);
      let configDir: string | undefined;
      if (data) {
        // A body starting with @ (read local file) or < (read stdin) turns curl into a local-file
        // disclosure primitive. --data-raw sends it verbatim and disables @/< interpretation.
        if (/^[@<]/.test(data)) return { success: false, error: `curl_request: refusing a data value starting with '${data[0]}' (would read a local file/stdin)` };
        args.push('--data-raw', data);
      }
      if (headers) {
        const headerLines = headers.split(',').map(header => header.trim()).filter(Boolean);
        if (configuredHeaders) {
          const explicitHeaders = new Headers();
          for (const header of headerLines) {
            const separator = header.indexOf(':');
            if (separator <= 0) return { success: false, error: `curl_request: invalid header '${header}'` };
            explicitHeaders.set(header.slice(0, separator).trim(), header.slice(separator + 1).trim());
          }
          configuredHeaders = targetHeadersForUrl(url, explicitHeaders);
        } else {
          for (const header of headerLines) args.push('-H', header);
        }
      }
      if (flags) {
        const sanitized = sanitizeExternalFlags('curl', flags); // drop -o/-K/-T/-x file-read/write injection
        args.push(...(configuredHeaders ? withoutCurlRedirectFlags(sanitized) : sanitized));
      }
      try {
        if (configuredHeaders) {
          configDir = await mkdtemp(join(tmpdir(), 't3mp3st-curl-'));
          const configPath = join(configDir, 'headers.conf');
          const escapeConfig = (value: string): string => value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
          const config = [...configuredHeaders.entries()]
            .map(([name, value]) => `header = "${escapeConfig(`${name}: ${value}`)}"`)
            .join('\n');
          await writeFile(configPath, `${config}\n`, { mode: 0o600 });
          args.push('--config', configPath);
        }
        args.push(url);
        const result = await runSubprocess('curl', args, { timeout: 30000 });
        return redactConfiguredSecrets({
          success: result.exitCode === 0,
          output: result.stdout,
          error: result.exitCode !== 0 ? result.stderr : undefined,
        });
      } finally {
        if (configDir) await rm(configDir, { recursive: true, force: true });
      }
    },
  },
];
