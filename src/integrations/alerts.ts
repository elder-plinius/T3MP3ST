import { directFetch } from '../net/proxy.js';
import { redactSecrets } from '../redact.js';
import type { HoneytokenAlertSink, HoneytokenTrigger } from '../deception/honeytokens.js';

export type AlertProvider = 'slack' | 'discord' | 'siem';
export type AlertProxyPolicy = 'configured' | 'direct';
export interface AlertDestinationSpec {
  id: string;
  provider: AlertProvider;
  envKey: 'SLACK_WEBHOOK_URL' | 'DISCORD_WEBHOOK_URL' | 'SIEM_WEBHOOK_URL';
  allowedHosts: readonly string[];
  proxyPolicy: AlertProxyPolicy;
  timeoutMs?: number;
  maxAttempts?: number;
  rateLimitMs?: number;
  maxPayloadBytes?: number;
}
export interface SecurityAlert {
  event: string;
  title: string;
  details: string;
  occurredAt: number;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  target?: string;
  metadata?: Record<string, unknown>;
}
export interface AlertReceipt {
  destinationId: string;
  provider: AlertProvider;
  delivered: boolean;
  attempts: number;
  status?: number;
  error?: 'not-configured' | 'rate-limited' | 'payload-too-large' | 'timeout' | 'network' | 'http-error';
}

type Fetcher = (input: string, init: RequestInit) => Promise<Response>;
interface Destination { spec: Required<Omit<AlertDestinationSpec, 'allowedHosts'>> & { allowedHosts: readonly string[] }; url?: URL }
export interface AlertDispatcherOptions {
  environment?: Readonly<Record<string, string | undefined>>;
  configuredFetch?: Fetcher;
  directFetch?: Fetcher;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

function resolvedSpec(spec: AlertDestinationSpec): Destination['spec'] {
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(spec.id)) throw new Error('Alert destination id is invalid');
  if (!spec.allowedHosts.length) throw new Error(`Alert destination ${spec.id} requires an allowlist`);
  return {
    ...spec,
    timeoutMs: Math.min(60_000, Math.max(100, spec.timeoutMs ?? 10_000)),
    maxAttempts: Math.min(5, Math.max(1, spec.maxAttempts ?? 3)),
    rateLimitMs: Math.min(60_000, Math.max(0, spec.rateLimitMs ?? 1_000)),
    maxPayloadBytes: Math.min(256 * 1024, Math.max(1_024, spec.maxPayloadBytes ?? 32 * 1024)),
  };
}

function resolveDestination(spec: Destination['spec'], environment: Readonly<Record<string, string | undefined>>): URL | undefined {
  const value = environment[spec.envKey];
  if (!value) return undefined;
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(`Alert destination ${spec.id} has an invalid environment URL`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error(`Alert destination ${spec.id} must use credential-free HTTPS URL syntax`);
  const host = url.hostname.toLowerCase();
  if (!spec.allowedHosts.some((allowed) => host === allowed.toLowerCase())) throw new Error(`Alert destination ${spec.id} host is not allowlisted`);
  return url;
}

function safeAlert(alert: SecurityAlert): SecurityAlert {
  if (typeof alert.event !== 'string' || typeof alert.title !== 'string' || typeof alert.details !== 'string' || !alert.event.trim() || !alert.title.trim() || !alert.details.trim() || !Number.isFinite(alert.occurredAt) || Number.isNaN(new Date(alert.occurredAt).getTime())) throw new Error('Alert event, title, details, and occurredAt are required');
  if (alert.severity !== undefined && !['critical', 'high', 'medium', 'low', 'info'].includes(alert.severity)) throw new Error('Alert severity is invalid');
  if (alert.target !== undefined && typeof alert.target !== 'string') throw new Error('Alert target is invalid');
  if (alert.metadata !== undefined && (typeof alert.metadata !== 'object' || alert.metadata === null || Array.isArray(alert.metadata))) throw new Error('Alert metadata is invalid');
  return redactSecrets(alert) as SecurityAlert;
}

function providerPayload(provider: AlertProvider, alert: SecurityAlert): unknown {
  if (provider === 'slack') return { text: `[T3MP3ST ${alert.severity ?? 'info'}] ${alert.title}\n${alert.details}`, ...(alert.target ? { blocks: [{ type: 'section', text: { type: 'mrkdwn', text: `*Target:* ${alert.target}` } }] } : {}) };
  if (provider === 'discord') return { username: 'T3MP3ST', embeds: [{ title: alert.title, description: alert.details, fields: [...(alert.target ? [{ name: 'Target', value: alert.target }] : []), { name: 'Severity', value: alert.severity ?? 'info' }], timestamp: new Date(alert.occurredAt).toISOString() }] };
  return { source: 't3mp3st', event_type: alert.event, timestamp: new Date(alert.occurredAt).toISOString(), severity: alert.severity ?? 'info', title: alert.title, description: alert.details, ...(alert.target ? { target: alert.target } : {}), ...(alert.metadata ? { metadata: alert.metadata } : {}) };
}

function retryableStatus(status: number): boolean { return status === 408 || status === 429 || status >= 500; }

export class AlertDispatcher implements HoneytokenAlertSink {
  private readonly destinations: Destination[];
  private readonly lastDispatch = new Map<string, number>();
  private readonly configuredFetch: Fetcher;
  private readonly directFetcher: Fetcher;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;

  constructor(specs: readonly AlertDestinationSpec[], options: AlertDispatcherOptions = {}) {
    const environment = options.environment ?? process.env;
    this.destinations = specs.map((input) => {
      const spec = resolvedSpec(input);
      return { spec, url: resolveDestination(spec, environment) };
    });
    this.configuredFetch = options.configuredFetch ?? ((input, init) => globalThis.fetch(input, init));
    this.directFetcher = options.directFetch ?? (directFetch as unknown as Fetcher);
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.now = options.now ?? Date.now;
  }

  async deliver(event: HoneytokenTrigger): Promise<void> {
    const receipts = await this.dispatch({ event: 'honeytoken_triggered', title: 'Honeytoken trigger pending review', details: `Trigger ${event.id} requires classification.`, occurredAt: event.at, severity: 'high', metadata: { tokenId: event.tokenId, nonceHash: event.nonceHash, sourceHash: event.sourceHash, provenance: event.provenance } });
    if (receipts.some((receipt) => !receipt.delivered && receipt.error !== 'not-configured')) throw new Error('One or more alert destinations failed');
  }

  async dispatch(input: SecurityAlert): Promise<AlertReceipt[]> {
    const alert = safeAlert(input);
    return Promise.all(this.destinations.map((destination) => this.send(destination, alert)));
  }

  listDestinations(): Array<{ id: string; provider: AlertProvider; configured: boolean; host?: string; proxyPolicy: AlertProxyPolicy }> {
    return this.destinations.map(({ spec, url }) => ({ id: spec.id, provider: spec.provider, configured: Boolean(url), ...(url ? { host: url.hostname } : {}), proxyPolicy: spec.proxyPolicy }));
  }

  private async send(destination: Destination, alert: SecurityAlert): Promise<AlertReceipt> {
    const { spec, url } = destination;
    if (!url) return { destinationId: spec.id, provider: spec.provider, delivered: false, attempts: 0, error: 'not-configured' };
    const body = JSON.stringify(providerPayload(spec.provider, alert));
    if (Buffer.byteLength(body) > spec.maxPayloadBytes) return { destinationId: spec.id, provider: spec.provider, delivered: false, attempts: 0, error: 'payload-too-large' };
    const elapsed = this.now() - (this.lastDispatch.get(spec.id) ?? -Infinity);
    if (elapsed < spec.rateLimitMs) return { destinationId: spec.id, provider: spec.provider, delivered: false, attempts: 0, error: 'rate-limited' };
    this.lastDispatch.set(spec.id, this.now());
    const fetcher = spec.proxyPolicy === 'direct' ? this.directFetcher : this.configuredFetch;
    let lastStatus: number | undefined;
    let lastError: AlertReceipt['error'] = 'network';
    let attemptsMade = 0;
    for (let attempt = 1; attempt <= spec.maxAttempts; attempt++) {
      attemptsMade = attempt;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), spec.timeoutMs);
      try {
        const response = await fetcher(url.toString(), { method: 'POST', redirect: 'manual', signal: controller.signal, headers: { 'content-type': 'application/json', accept: 'application/json' }, body });
        lastStatus = response.status;
        if (response.ok) return { destinationId: spec.id, provider: spec.provider, delivered: true, attempts: attempt, status: response.status };
        lastError = 'http-error';
        if (!retryableStatus(response.status)) break;
      } catch (error) {
        lastError = controller.signal.aborted || (error instanceof Error && error.name === 'AbortError') ? 'timeout' : 'network';
      } finally { clearTimeout(timer); }
      if (attempt < spec.maxAttempts) await this.sleep(Math.min(10_000, 250 * (2 ** (attempt - 1))));
    }
    return { destinationId: spec.id, provider: spec.provider, delivered: false, attempts: attemptsMade, ...(lastStatus ? { status: lastStatus } : {}), error: lastError };
  }
}

export function defaultAlertDestinations(siemAllowedHosts: readonly string[] = []): AlertDestinationSpec[] {
  return [
    { id: 'slack', provider: 'slack', envKey: 'SLACK_WEBHOOK_URL', allowedHosts: ['hooks.slack.com'], proxyPolicy: 'configured' },
    { id: 'discord', provider: 'discord', envKey: 'DISCORD_WEBHOOK_URL', allowedHosts: ['discord.com', 'discordapp.com'], proxyPolicy: 'configured' },
    ...(siemAllowedHosts.length ? [{ id: 'siem', provider: 'siem' as const, envKey: 'SIEM_WEBHOOK_URL' as const, allowedHosts: siemAllowedHosts, proxyPolicy: 'configured' as const }] : []),
  ];
}
