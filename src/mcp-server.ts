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
import { mcpTargetDecision, mcpAllowlistFromEnv } from './mcp-guards.js';
import { redactString } from './redact.js';

const execFileAsync = promisify(execFile);

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



async function handleToolCall(name: string, args: Record<string, unknown>): Promise<string> {
  switch (name) {
    // =========================================================================
    // SECURITY RECON
    // =========================================================================
    case 'security_recon': {
      const { target, scan_type = 'quick' } = args as any;

      // Authorize the target BEFORE it reaches any subprocess. Only hostnames / IPv4 / IPv6 literals
      // are permitted (shell metacharacters and option-looking "-…" targets are rejected), AND a
      // public target must be listed in T3MP3ST_MCP_ALLOWED_TARGETS — parity with the HTTP recon
      // endpoint's approval gate — while local/lab targets stay frictionless. Combined with the
      // no-shell execFile call below, a metacharacter target is refused and would be inert anyway.
      const decision = mcpTargetDecision(target, mcpAllowlistFromEnv());
      if (!decision.allowed) {
        return JSON.stringify({
          error: decision.reason,
          target: typeof target === 'string' ? target : String(target),
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
            records: redactString(dns.output).trim().split('\n').filter(Boolean)
          },
          ports: {
            success: ports.success,
            output: redactString(ports.output),
            error: ports.error ? redactString(ports.error) : ports.error
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
  console.error('[T3MP3ST MCP] server running — security_recon (nmap/DNS recon)');
}

main().catch(console.error);
