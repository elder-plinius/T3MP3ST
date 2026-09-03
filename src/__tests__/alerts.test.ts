import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { AlertDispatcher, defaultAlertDestinations, type AlertDestinationSpec, type SecurityAlert } from '../integrations/alerts.js';

const secretUrl = (host = 'hooks.slack.com') => `https://${host}/services/${crypto.randomUUID()}`;
const alert = (overrides: Partial<SecurityAlert> = {}): SecurityAlert => ({ event: 'finding_discovered', title: 'Finding', details: 'Evidence observed', occurredAt: 1_800_000_000_000, severity: 'high', target: 'lab.example', ...overrides });
const spec = (overrides: Partial<AlertDestinationSpec> = {}): AlertDestinationSpec => ({ id: 'slack', provider: 'slack', envKey: 'SLACK_WEBHOOK_URL', allowedHosts: ['hooks.slack.com'], proxyPolicy: 'configured', rateLimitMs: 0, ...overrides });
const response = (status = 200) => new Response('', { status });

describe('secure alert destination configuration', () => {
  it('loads only fixed environment keys and never returns secret URLs', () => {
    const url = secretUrl();
    const dispatcher = new AlertDispatcher([spec()], { environment: { SLACK_WEBHOOK_URL: url } });
    const listed = dispatcher.listDestinations();
    expect(listed).toEqual([{ id: 'slack', provider: 'slack', configured: true, host: 'hooks.slack.com', proxyPolicy: 'configured' }]);
    expect(JSON.stringify(listed)).not.toContain(url);
    expect(JSON.stringify(listed)).not.toContain(url.split('/').at(-1));
  });

  it.each([
    ['http://hooks.slack.com/services/x', 'HTTPS'],
    ['https://user:pass@hooks.slack.com/services/x', 'credential-free'],
    ['https://attacker.example/services/x', 'allowlisted'],
  ])('rejects unsafe destination %s', (url, message) => {
    expect(() => new AlertDispatcher([spec()], { environment: { SLACK_WEBHOOK_URL: url } })).toThrow(message);
  });

  it('reports an absent environment key without making a request', async () => {
    const fetch = vi.fn();
    const receipts = await new AlertDispatcher([spec()], { environment: {}, configuredFetch: fetch }).dispatch(alert());
    expect(receipts).toEqual([{ destinationId: 'slack', provider: 'slack', delivered: false, attempts: 0, error: 'not-configured' }]);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('does not add SIEM until an explicit host allowlist exists', () => {
    expect(defaultAlertDestinations().map(({ provider }) => provider)).toEqual(['slack', 'discord']);
    expect(defaultAlertDestinations(['siem.internal']).at(-1)).toMatchObject({ provider: 'siem', allowedHosts: ['siem.internal'] });
  });
});

describe('provider payload and secret boundaries', () => {
  it('rejects malformed runtime alert fields before delivery', async () => {
    const fetcher = vi.fn();
    const dispatcher = new AlertDispatcher([spec()], { environment: { SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/secret' }, configuredFetch: fetcher });
    await expect(dispatcher.dispatch(alert({ occurredAt: 9e99 }))).rejects.toThrow('required');
    await expect(dispatcher.dispatch(alert({ severity: 'urgent' as SecurityAlert['severity'] }))).rejects.toThrow('severity');
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([
    ['slack', 'SLACK_WEBHOOK_URL', 'hooks.slack.com'],
    ['discord', 'DISCORD_WEBHOOK_URL', 'discord.com'],
    ['siem', 'SIEM_WEBHOOK_URL', 'siem.internal'],
  ] as const)('sends an isolated %s contract with redaction and no redirect following', async (provider, envKey, host) => {
    const url = secretUrl(host);
    const fetch = vi.fn().mockResolvedValue(response());
    const dispatcher = new AlertDispatcher([spec({ id: provider, provider, envKey, allowedHosts: [host] })], { environment: { [envKey]: url }, configuredFetch: fetch });
    const receipts = await dispatcher.dispatch(alert({ details: 'token=do-not-send', metadata: { apiKey: 'also-private', safe: 'yes' } }));
    expect(receipts).toEqual([{ destinationId: provider, provider, delivered: true, attempts: 1, status: 200 }]);
    const [calledUrl, init] = fetch.mock.calls[0];
    expect(calledUrl).toBe(url);
    expect(init).toMatchObject({ method: 'POST', redirect: 'manual' });
    expect(init.body).not.toContain('do-not-send');
    expect(init.body).not.toContain('also-private');
    expect(init.body).toContain('[redacted]');
    expect(init.body).toContain('Finding');
  });

  it('rejects oversized redacted payloads before network use', async () => {
    const fetch = vi.fn();
    const receipt = await new AlertDispatcher([spec({ maxPayloadBytes: 1024 })], { environment: { SLACK_WEBHOOK_URL: secretUrl() }, configuredFetch: fetch }).dispatch(alert({ details: 'x'.repeat(2_000) }));
    expect(receipt[0]).toMatchObject({ delivered: false, attempts: 0, error: 'payload-too-large' });
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('delivery reliability controls', () => {
  it('routes configured and direct policies through separate fetchers', async () => {
    const configuredFetch = vi.fn().mockResolvedValue(response());
    const directFetch = vi.fn().mockResolvedValue(response());
    const specs = [spec({ id: 'proxied' }), spec({ id: 'direct', envKey: 'SIEM_WEBHOOK_URL', proxyPolicy: 'direct' })];
    await new AlertDispatcher(specs, { environment: { SLACK_WEBHOOK_URL: secretUrl(), SIEM_WEBHOOK_URL: secretUrl() }, configuredFetch, directFetch }).dispatch(alert());
    expect(configuredFetch).toHaveBeenCalledOnce();
    expect(directFetch).toHaveBeenCalledOnce();
  });

  it('retries transient failures with bounded backoff but not terminal 4xx', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(response(503)).mockResolvedValueOnce(response(200));
    const sleep = vi.fn().mockResolvedValue(undefined);
    const dispatcher = new AlertDispatcher([spec({ maxAttempts: 3 })], { environment: { SLACK_WEBHOOK_URL: secretUrl() }, configuredFetch: fetch, sleep });
    await expect(dispatcher.dispatch(alert())).resolves.toEqual([{ destinationId: 'slack', provider: 'slack', delivered: true, attempts: 2, status: 200 }]);
    expect(sleep).toHaveBeenCalledWith(250);

    const terminal = vi.fn().mockResolvedValue(response(400));
    const result = await new AlertDispatcher([spec()], { environment: { SLACK_WEBHOOK_URL: secretUrl() }, configuredFetch: terminal }).dispatch(alert());
    expect(result[0]).toMatchObject({ delivered: false, attempts: 1, status: 400, error: 'http-error' });
  });

  it('enforces per-destination rate limits without sleeping or mutating callers', async () => {
    const fetch = vi.fn().mockResolvedValue(response());
    const input = alert();
    const dispatcher = new AlertDispatcher([spec({ rateLimitMs: 1000 })], { environment: { SLACK_WEBHOOK_URL: secretUrl() }, configuredFetch: fetch, now: () => 5000 });
    await dispatcher.dispatch(input);
    const second = await dispatcher.dispatch(input);
    expect(second[0]).toMatchObject({ delivered: false, attempts: 0, error: 'rate-limited' });
    expect(fetch).toHaveBeenCalledOnce();
    expect(input.details).toBe('Evidence observed');
  });

  it('classifies timeout/network errors without leaking provider messages or URLs', async () => {
    vi.useFakeTimers();
    const fetch = vi.fn((_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => init.signal?.addEventListener('abort', () => reject(Object.assign(new Error('secret URL leaked'), { name: 'AbortError' })), { once: true })));
    const promise = new AlertDispatcher([spec({ timeoutMs: 100, maxAttempts: 1 })], { environment: { SLACK_WEBHOOK_URL: secretUrl() }, configuredFetch: fetch }).dispatch(alert());
    await vi.advanceTimersByTimeAsync(100);
    expect(await promise).toEqual([{ destinationId: 'slack', provider: 'slack', delivered: false, attempts: 1, error: 'timeout' }]);
    vi.useRealTimers();
  });

  it('maps honeytoken events without exposing destination credentials', async () => {
    const fetch = vi.fn().mockResolvedValue(response());
    const dispatcher = new AlertDispatcher([spec()], { environment: { SLACK_WEBHOOK_URL: secretUrl() }, configuredFetch: fetch });
    await expect(dispatcher.deliver({ id: 'event-1', tokenId: 'token-id', at: 1_800_000_000_000, nonceHash: 'nonce-hash', sourceHash: 'source-hash', classification: 'pending', provenance: 'authenticated-honeytoken-use' })).resolves.toBeUndefined();
    expect(fetch.mock.calls[0][1].body).toContain('event-1');
  });

  it('contains no CORS override or dotenv loading surface', () => {
    const source = readFileSync(new URL('../integrations/alerts.ts', import.meta.url), 'utf8');
    expect(source).not.toMatch(/cors|dotenv|process\.cwd|api\/config\/env/);
    expect(source).toContain("envKey: 'SLACK_WEBHOOK_URL' | 'DISCORD_WEBHOOK_URL' | 'SIEM_WEBHOOK_URL'");
  });
});
