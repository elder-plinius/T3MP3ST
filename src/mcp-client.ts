// =============================================================================
// T3MP3ST MCP CLIENT — connect to external MCP servers and call their tools
// =============================================================================
// Allows T3MP3ST to consume tools from any MCP server (stdio or HTTP/SSE),
// exposing them through the /api/mcp/* endpoints so operators can invoke
// external capabilities directly from the web UI.
// =============================================================================

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

export type McpTransportType = 'stdio' | 'sse';

export interface McpServerConfig {
  id: string;
  label: string;
  transport: McpTransportType;
  // stdio transport
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  // sse / http transport
  url?: string;
}

export interface McpRemoteTool {
  serverId: string;
  serverLabel: string;
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

interface McpClientEntry {
  config: McpServerConfig;
  client: Client;
  tools: McpRemoteTool[];
}

const _clients = new Map<string, McpClientEntry>();

// =============================================================================
// CONNECTION MANAGEMENT
// =============================================================================

export async function connectMcpServer(
  config: McpServerConfig,
): Promise<McpRemoteTool[]> {
  // Replace any existing connection for this id
  if (_clients.has(config.id)) {
    await disconnectMcpServer(config.id);
  }

  const client = new Client(
    { name: 't3mp3st-client', version: '1.0.0' },
    { capabilities: {} },
  );

  if (config.transport === 'stdio') {
    if (!config.command) throw new Error('command is required for stdio transport');
    const t = new StdioClientTransport({
      command: config.command,
      args: config.args ?? [],
      env: config.env,
    });
    await client.connect(t);
  } else {
    if (!config.url) throw new Error('url is required for sse transport');
    const t = new SSEClientTransport(new URL(config.url));
    await client.connect(t);
  }

  const { tools: rawTools } = await client.listTools();
  const tools: McpRemoteTool[] = (rawTools ?? []).map((t) => ({
    serverId: config.id,
    serverLabel: config.label,
    name: t.name,
    description: t.description ?? '',
    inputSchema: (t.inputSchema as Record<string, unknown>) ?? {},
  }));

  _clients.set(config.id, { config, client, tools });
  console.log(
    `[mcp-client] connected to "${config.label}" (${config.id}): ${tools.length} tool(s)`,
  );
  return tools;
}

export async function disconnectMcpServer(id: string): Promise<void> {
  const entry = _clients.get(id);
  if (!entry) return;
  try {
    await entry.client.close();
  } catch {
    // best-effort close
  }
  _clients.delete(id);
}

// =============================================================================
// TOOL DISCOVERY & INVOCATION
// =============================================================================

export function listConnectedServers(): McpServerConfig[] {
  return Array.from(_clients.values()).map((e) => e.config);
}

export function listRemoteTools(): McpRemoteTool[] {
  return Array.from(_clients.values()).flatMap((e) => e.tools);
}

export async function callRemoteTool(
  serverId: string,
  toolName: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  const entry = _clients.get(serverId);
  if (!entry) throw new Error(`MCP server not connected: ${serverId}`);
  const result = await entry.client.callTool({ name: toolName, arguments: args });
  // Refresh tool list after a tool call in case the server signalled list-changed
  try {
    const { tools: rawTools } = await entry.client.listTools();
    entry.tools = (rawTools ?? []).map((t) => ({
      serverId,
      serverLabel: entry.config.label,
      name: t.name,
      description: t.description ?? '',
      inputSchema: (t.inputSchema as Record<string, unknown>) ?? {},
    }));
  } catch {
    // non-fatal — stale tool list is better than a broken call
  }
  return result;
}
