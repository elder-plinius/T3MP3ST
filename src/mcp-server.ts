#!/usr/bin/env node
/**
 * T3MP3ST MCP Server v3.0
 *
 * Production-grade Model Context Protocol server exposing t3mp3st security
 * tooling (security_recon — nmap/DNS reconnaissance).
 *
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

// Strict target allowlist: hostnames, IPv4/IPv6, no shell metacharacters.
// Anything outside this set is rejected before it can reach a subprocess.
const TARGET_RE = /^[A-Za-z0-9._:-]+$/;

// =============================================================================
// COMPREHENSIVE PAYLOAD DATABASES
// =============================================================================


// =============================================================================
// SECRET PATTERNS DATABASE (GRIFFIN)
// =============================================================================


// =============================================================================
// PRIVILEGE ESCALATION DATABASE (CERBERUS)
// =============================================================================


// =============================================================================
// WAF BYPASS TECHNIQUES (TYPHON)
// =============================================================================


// =============================================================================
// TOOL DEFINITIONS
// =============================================================================

const MCP_TOOLS: Tool[] = [
  {
    name: 'security_recon',
    description: `Quick reconnaissance using nmap and DNS tools.

Performs network reconnaissance with configurable depth.

Use when: Starting an engagement.
Requires: Target hostname or IP.`,
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Target hostname or IP' },
        scan_type: { type: 'string', enum: ['quick', 'standard', 'full', 'stealth'], description: 'Scan depth' }
      },
      required: ['target']
    }
  },
  {
    name: 'cve_lookup',
    description: `Look up a single CVE record from the T3MP3ST threat-intel feed (CISA KEV + curated vendor catalogs + EPSS).

Use when: You have a CVE id and need severity, EPSS, ransomware association, and whether an active probe/payload exists.
Requires: CVE id (e.g. CVE-2021-44228).`,
    inputSchema: {
      type: 'object',
      properties: {
        cveId: { type: 'string', description: 'CVE identifier, e.g. CVE-2021-44228' }
      },
      required: ['cveId']
    }
  },
  {
    name: 'cve_feed_query',
    description: `Query the T3MP3ST CVE feed (1,700+ KEV entries + curated vendor catalogs) by vendor or keyword.

Use when: Fingerprinting a product and wanting its known-exploited vulnerabilities.
Requires: Nothing (vendor optional).`,
    inputSchema: {
      type: 'object',
      properties: {
        vendor: { type: 'string', description: 'Vendor/product filter, e.g. WoltLab, Tomcat, Ivanti' },
        limit: { type: 'number', description: 'Max results (default 15)' }
      },
      required: []
    }
  },
  {
    name: 'payloads_for_cve',
    description: `Fetch operator exploit payloads for a KEV CVE from the T3MP3ST payload catalog (inert/canary variants included where out-of-band proof suffices).

Use when: A correlated CVE node needs its actual exploit input instead of "run a scan".
Requires: CVE id present in the catalog.`,
    inputSchema: {
      type: 'object',
      properties: {
        cveId: { type: 'string', description: 'CVE identifier, e.g. CVE-2024-4577' }
      },
      required: ['cveId']
    }
  },
  {
    name: 'rapid_response_check',
    description: `Run one T3MP3ST rapid-response KEV probe (inert/canary by design — version gates and passive verifiers, never a live gadget) against a target through the platform's receipt guard.

Use when: A target matches a KEV entry and you need a fast non-destructive verdict.
Requires: checkId from the probe catalog and a target URL. External targets require the platform's operator approval.`,
    inputSchema: {
      type: 'object',
      properties: {
        checkId: { type: 'string', description: 'Probe id, e.g. log4shell-jndi-probe, mirth-connect-xstream, tomcat-clear-session' },
        target: { type: 'string', description: 'Target base URL, e.g. http://host:port' },
        timeoutMs: { type: 'number', description: 'Probe timeout in ms (default 8000)' }
      },
      required: ['checkId', 'target']
    }
  }
];

// =============================================================================
// TOOL IMPLEMENTATIONS
// =============================================================================

const SAFE_COMMANDS = ['nmap', 'curl', 'dig', 'host', 'whois', 'nikto', 'gobuster', 'whatweb'];

/**
 * Run a whitelisted binary with an explicit argument array — NO shell.
 *
 * Because execFile does not spawn a shell and each arg is passed verbatim as a
 * single argv entry, shell metacharacters in the (already regex-validated)
 * target cannot be interpreted as command separators. The binary is checked
 * against the allowlist, and every arg is validated for the absence of NUL.
 */
async function runTool(
  binary: string,
  args: string[],
  timeout = 30000
): Promise<{ success: boolean; output: string; error?: string }> {
  if (!SAFE_COMMANDS.includes(binary)) {
    return { success: false, output: '', error: `Command not allowed: ${binary}` };
  }
  // Defence-in-depth: reject NUL bytes which can truncate args at the syscall boundary.
  if (args.some((a) => a.includes('\0'))) {
    return { success: false, output: '', error: 'Invalid argument: NUL byte' };
  }
  try {
    const { stdout, stderr } = await execFileAsync(binary, args, {
      timeout,
      maxBuffer: 1024 * 1024 * 5,
    });
    return { success: true, output: stdout || stderr };
  } catch (error: any) {
    return { success: false, output: error.stdout || '', error: error.message };
  }
}



// The CVE/probe tools proxy the RUNNING T3MP3ST platform (its caches, EPSS state, and
// receipt guard live there). Configurable for non-default installs via T3MP3ST_API_URL.
const PLATFORM_URL = (process.env.T3MP3ST_API_URL || 'http://127.0.0.1:3333').replace(/\/$/, '');

async function platformApi(method: string, path: string, body?: unknown): Promise<string> {
  let res: Response;
  try {
    res = await fetch(`${PLATFORM_URL}${path}`, {
      method,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(20000),
    });
  } catch {
    return JSON.stringify({
      error: `T3MP3ST platform is not reachable at ${PLATFORM_URL}.`,
      hint: 'Start it with: T3MP3ST_FULL_ARSENAL=1 node dist/server.js  (or set T3MP3ST_API_URL to a running instance)',
    }, null, 2);
  }
  const text = await res.text();
  return text;
}

async function handleToolCall(name: string, args: Record<string, unknown>): Promise<string> {
  switch (name) {
    // =========================================================================
    // SECURITY RECON
    // =========================================================================
    case 'security_recon': {
      const { target, scan_type = 'quick' } = args as any;

      // Validate the target BEFORE it reaches any subprocess. Only hostnames /
      // IPv4 / IPv6 literals are permitted; shell metacharacters (';', '|',
      // '&', '$', spaces, backticks, ...) are rejected here. Combined with the
      // no-shell execFile call below, "evil.com; id" is refused and, even if it
      // slipped through, would be passed as a single inert argv entry.
      if (typeof target !== 'string' || !TARGET_RE.test(target)) {
        return JSON.stringify({
          error: 'Invalid target: only hostnames, IPv4/IPv6 addresses are allowed ([A-Za-z0-9._:-]).',
          target: typeof target === 'string' ? target : String(target)
        }, null, 2);
      }

      const scanConfigs: Record<string, { portArgs: string[]; timing: string; scripts: boolean }> = {
        quick: { portArgs: ['-F'], timing: '-T4', scripts: false },
        standard: { portArgs: ['--top-ports', '1000'], timing: '-T3', scripts: true },
        full: { portArgs: ['-p-'], timing: '-T2', scripts: true },
        stealth: { portArgs: ['--top-ports', '100'], timing: '-T1', scripts: false }
      };

      const config = scanConfigs[scan_type] || scanConfigs.quick;

      const nmapArgs = [
        ...config.portArgs,
        config.timing,
        '-sV',
        ...(config.scripts ? ['-sC'] : []),
        '--open',
        target
      ];

      const [dns, ports] = await Promise.all([
        runTool('dig', ['+short', target, 'ANY']),
        runTool('nmap', nmapArgs, 300000)
      ]);

      return JSON.stringify({
        tool: 'RECON',
        version: '3.0.0',
        target,
        scan_type,
        results: {
          dns: {
            success: dns.success,
            records: dns.output.trim().split('\n').filter(Boolean)
          },
          ports: {
            success: ports.success,
            output: ports.output,
            error: ports.error
          }
        },
        commands_executed: [
          `dig +short ${target} ANY`,
          `nmap ${nmapArgs.join(' ')}`
        ],
        next_steps: [
          'Run vulnerability scan with nuclei',
          'Enumerate web directories with gobuster',
          'Check for common vulnerabilities'
        ]
      }, null, 2);
    }

    // =========================================================================
    // PLATFORM-BACKED THREAT INTEL + PROBES (read-only intel; probes go through
    // the platform's receipt guard — external targets need operator approval there)
    // =========================================================================
    case 'cve_lookup': {
      const cveId = String(args.cveId || '').trim();
      if (!/^CVE-\d{4}-\d{4,}$/i.test(cveId)) {
        return JSON.stringify({ error: 'cveId must look like CVE-YYYY-NNNN' }, null, 2);
      }
      return platformApi('GET', `/api/cves/${encodeURIComponent(cveId.toUpperCase())}`);
    }
    case 'cve_feed_query': {
      const vendor = String(args.vendor || '').trim();
      const limit = Math.min(Math.max(Number(args.limit) || 15, 1), 100);
      const q = vendor ? `?vendor=${encodeURIComponent(vendor)}&limit=${limit}` : `?limit=${limit}`;
      return platformApi('GET', `/api/cves/feed${q}`);
    }
    case 'payloads_for_cve': {
      const cveId = String(args.cveId || '').trim();
      if (!/^CVE-\d{4}-\d{4,}$/i.test(cveId)) {
        return JSON.stringify({ error: 'cveId must look like CVE-YYYY-NNNN' }, null, 2);
      }
      return platformApi('GET', `/api/cves/payloads?cveId=${encodeURIComponent(cveId.toUpperCase())}`);
    }
    case 'rapid_response_check': {
      const checkId = String(args.checkId || '').trim();
      const target = String(args.target || '').trim();
      if (!checkId || !target) {
        return JSON.stringify({ error: 'checkId and target are required' }, null, 2);
      }
      if (typeof target !== 'string' || !TARGET_RE.test(target.replace(/^https?:\/\//, '').replace(/\/.*$/, ''))) {
        return JSON.stringify({ error: 'Invalid target: only hostnames / IPv4 / IPv6 are allowed' }, null, 2);
      }
      const timeoutMs = Math.min(Math.max(Number(args.timeoutMs) || 8000, 1000), 20000);
      return platformApi('POST', '/api/tools/rapid-response/check', { checkId, target, timeoutMs });
    }

    default:
      return JSON.stringify({ error: `Unknown tool: ${name}` });
  }
}

// =============================================================================
// MCP SERVER
// =============================================================================

const server = new Server(
  { name: 't3mp3st-chef-specials', version: '3.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: MCP_TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
  const { name, arguments: args } = request.params;
  try {
    const result = await handleToolCall(name, args || {});
    return { content: [{ type: 'text', text: result }] };
  } catch (error: any) {
    return { content: [{ type: 'text', text: JSON.stringify({ error: error.message }) }], isError: true };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[T3MP3ST MCP] server running — security_recon (nmap/DNS recon) + cve_lookup / cve_feed_query / payloads_for_cve / rapid_response_check (via ' + PLATFORM_URL + ')');
}

main().catch(console.error);
