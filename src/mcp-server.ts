#!/usr/bin/env node
/**
 * T3MP3ST MCP Server v3.0
 *
 * Model Context Protocol server exposing t3mp3st security tooling.
 * Exposes: security_recon — nmap/DNS reconnaissance.
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
        target: { type: 'string', description: 'Target hostname or IP (hostname/IP only — no shell metacharacters)' },
        scan_type: { type: 'string', enum: ['quick', 'standard', 'full', 'stealth'], description: 'Scan depth' }
      },
      required: ['target']
    }
  }
];

// =============================================================================
// TOOL IMPLEMENTATIONS
// =============================================================================

// Strict allowlist: only these binaries may be invoked
const ALLOWED_BINARIES: Record<string, string> = {
  nmap: 'nmap',
  dig: 'dig',
};

// Target must be a plain hostname or IP — no shell metacharacters
const TARGET_RE = /^[a-zA-Z0-9][a-zA-Z0-9._:-]*$/;

function validateTarget(target: string): void {
  if (!target || !TARGET_RE.test(target)) {
    throw new Error(`Invalid target: "${target}" — must be a hostname or IP with no shell metacharacters`);
  }
}

async function runCommand(
  binary: keyof typeof ALLOWED_BINARIES,
  args: string[],
  timeoutMs = 30000,
): Promise<{ success: boolean; output: string; error?: string }> {
  const bin = ALLOWED_BINARIES[binary];
  if (!bin) return { success: false, output: '', error: `Binary not allowed: ${binary}` };
  try {
    const { stdout, stderr } = await execFileAsync(bin, args, {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024 * 5,
    });
    return { success: true, output: stdout || stderr };
  } catch (error: unknown) {
    const e = error as { stdout?: string; message?: string };
    return { success: false, output: e.stdout || '', error: e.message };
  }
}

async function handleToolCall(name: string, args: Record<string, unknown>): Promise<string> {
  switch (name) {
    // =========================================================================
    // SECURITY RECON
    // =========================================================================
    case 'security_recon': {
      const target = args.target as string;
      const scan_type = (args.scan_type as string | undefined) ?? 'quick';

      validateTarget(target);

      const scanConfigs: Record<string, { ports: string[]; timing: string; scripts: boolean }> = {
        quick:    { ports: ['-F'],                timing: '-T4', scripts: false },
        standard: { ports: ['--top-ports', '1000'], timing: '-T3', scripts: true  },
        full:     { ports: ['-p-'],               timing: '-T2', scripts: true  },
        stealth:  { ports: ['--top-ports', '100'], timing: '-T1', scripts: false },
      };

      const cfg = scanConfigs[scan_type] ?? scanConfigs.quick;
      const nmapArgs = [
        ...cfg.ports,
        cfg.timing,
        '-sV',
        ...(cfg.scripts ? ['-sC'] : []),
        '--open',
        target,
      ];

      const [dns, ports] = await Promise.all([
        runCommand('dig', ['+short', target, 'ANY']),
        runCommand('nmap', nmapArgs, 300000),
      ]);

      return JSON.stringify({
        tool: 'RECON',
        version: '3.0.0',
        target,
        scan_type,
        results: {
          dns:   { success: dns.success,   records: dns.output.trim().split('\n').filter(Boolean) },
          ports: { success: ports.success, output: ports.output, error: ports.error },
        },
        next_steps: [
          'Run vulnerability scan with nuclei',
          'Enumerate web directories with gobuster',
          'Check for common vulnerabilities',
        ],
      }, null, 2);
    }

    default:
      return JSON.stringify({ error: `Unknown tool: ${name}` });
  }
}

// =============================================================================
// MCP SERVER
// =============================================================================

const server = new Server(
  { name: 't3mp3st-mcp', version: '3.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: MCP_TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request: unknown) => {
  const req = request as { params: { name: string; arguments?: Record<string, unknown> } };
  const { name, arguments: args } = req.params;
  try {
    const result = await handleToolCall(name, args || {});
    return { content: [{ type: 'text', text: result }] };
  } catch (error: unknown) {
    const e = error as { message?: string };
    return { content: [{ type: 'text', text: JSON.stringify({ error: e.message }) }], isError: true };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[T3MP3ST MCP] server running — security_recon (nmap/DNS recon)');
}

main().catch(console.error);
