import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { Arsenal, BUILTIN_TOOLS, createToolContext } from '../arsenal/index.js';

const httpTool = BUILTIN_TOOLS.find(tool => tool.name === 'http_request');
const technologyTool = BUILTIN_TOOLS.find(tool => tool.name === 'technology_detect');
if (!httpTool || !technologyTool) throw new Error('Required HTTP tools are not registered');
const originalOrigin = process.env.TEMPEST_TARGET_ORIGIN;
const originalHeaders = process.env.TEMPEST_TARGET_HEADERS;

function response(status = 200, headers: Record<string, string> = {}): Response {
  const normalized = new Map(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]));
  return {
    status,
    statusText: status === 200 ? 'OK' : 'Found',
    headers: {
      entries: () => normalized.entries(),
      get: (name: string) => normalized.get(name.toLowerCase()) ?? null,
    },
    text: async () => '<html></html>',
  } as unknown as Response;
}

function configure(origin = 'https://target.example') {
  process.env.TEMPEST_TARGET_ORIGIN = origin;
  process.env.TEMPEST_TARGET_HEADERS = JSON.stringify({
    Authorization: 'Bearer configured-secret',
    'X-Tenant': 'acme',
  });
}

beforeEach(() => configure());

afterEach(() => {
  if (originalOrigin === undefined) delete process.env.TEMPEST_TARGET_ORIGIN;
  else process.env.TEMPEST_TARGET_ORIGIN = originalOrigin;
  if (originalHeaders === undefined) delete process.env.TEMPEST_TARGET_HEADERS;
  else process.env.TEMPEST_TARGET_HEADERS = originalHeaders;
  vi.unstubAllGlobals();
});

describe('target header binding', () => {
  it('injects configured headers only into the exact origin', async () => {
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);

    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example/api' }));
    await httpTool.handler(createToolContext(undefined, { url: 'https://other.example/api' }));
    await httpTool.handler(createToolContext(undefined, { url: 'http://target.example/api' }));

    expect(new Headers(mockFetch.mock.calls[0][1].headers).get('authorization')).toBe('Bearer configured-secret');
    expect(new Headers(mockFetch.mock.calls[1][1]?.headers).has('authorization')).toBe(false);
    expect(new Headers(mockFetch.mock.calls[2][1]?.headers).has('authorization')).toBe(false);
  });

  it('requires both the origin binding and a valid non-empty string header map', async () => {
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);

    delete process.env.TEMPEST_TARGET_ORIGIN;
    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example' }));
    process.env.TEMPEST_TARGET_ORIGIN = 'https://target.example';
    process.env.TEMPEST_TARGET_HEADERS = JSON.stringify({ Authorization: 123 });
    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example' }));

    expect(new Headers(mockFetch.mock.calls[0][1].headers).has('authorization')).toBe(false);
    expect(new Headers(mockFetch.mock.calls[1][1].headers).has('authorization')).toBe(false);
  });

  it('rejects origins with paths and transport-level headers', async () => {
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);

    configure('https://target.example/api');
    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example/api' }));
    configure();
    process.env.TEMPEST_TARGET_HEADERS = JSON.stringify({ Host: 'other.example' });
    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example/api' }));

    expect(new Headers(mockFetch.mock.calls[0][1].headers).has('authorization')).toBe(false);
    expect(new Headers(mockFetch.mock.calls[1][1].headers).has('host')).toBe(false);
  });

  it('lets explicit tool headers override configured headers case-insensitively', async () => {
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);

    await httpTool.handler(createToolContext(undefined, {
      url: 'https://target.example',
      headers: { authorization: 'Bearer request-secret' },
    }));

    const sent = new Headers(mockFetch.mock.calls[0][1].headers);
    expect(sent.get('authorization')).toBe('Bearer request-secret');
    expect([...sent.keys()].filter(name => name === 'authorization')).toHaveLength(1);
    expect(sent.get('x-tenant')).toBe('acme');
  });

  it('applies configured headers to built-in probes beyond http_request', async () => {
    const mockFetch = vi.fn().mockResolvedValue(response());
    vi.stubGlobal('fetch', mockFetch);

    await technologyTool.handler(createToolContext(undefined, { url: 'https://target.example' }));

    expect(new Headers(mockFetch.mock.calls[0][1].headers).get('authorization')).toBe('Bearer configured-secret');
  });
});

describe('target header redirect safety', () => {
  it('removes every configured header before a cross-origin redirect', async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(response(302, { location: 'https://external.example/landing' }))
      .mockResolvedValueOnce(response());
    vi.stubGlobal('fetch', mockFetch);

    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example/start' }));

    expect(new Headers(mockFetch.mock.calls[0][1].headers).get('x-tenant')).toBe('acme');
    expect(new Headers(mockFetch.mock.calls[1][1].headers).has('authorization')).toBe(false);
    expect(new Headers(mockFetch.mock.calls[1][1].headers).has('x-tenant')).toBe(false);
    expect(String(mockFetch.mock.calls[1][0])).toBe('https://external.example/landing');
  });

  it('keeps configured headers on same-origin redirects', async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(response(302, { location: '/next' }))
      .mockResolvedValueOnce(response());
    vi.stubGlobal('fetch', mockFetch);

    await httpTool.handler(createToolContext(undefined, { url: 'https://target.example/start' }));

    expect(new Headers(mockFetch.mock.calls[1][1].headers).get('authorization')).toBe('Bearer configured-secret');
  });
});

describe('target header secret handling', () => {
  it('redacts configured values from persisted tool output and findings', async () => {
    const mockFetch = vi.fn().mockResolvedValue(response(200, {
      'x-reflected-value': 'Bearer configured-secret',
    }));
    vi.stubGlobal('fetch', mockFetch);
    const arsenal = new Arsenal();
    arsenal.register(httpTool);

    const result = await arsenal.execute('http_request', createToolContext(undefined, {
      url: 'https://target.example',
    }));

    expect(result.output).toContain('[REDACTED]');
    expect(result.output).not.toContain('configured-secret');
    expect(arsenal.getExecutions()[0].result?.output).not.toContain('configured-secret');
  });

  it('keeps configured curl headers out of argv and disables redirect-following flags', () => {
    const source = readFileSync(join(process.cwd(), 'src/arsenal/index.ts'), 'utf8');
    const curl = source.slice(source.indexOf("name: 'curl_request'"));
    expect(curl).toContain("writeFile(configPath");
    expect(curl).toContain("mode: 0o600");
    expect(curl).toContain('withoutCurlRedirectFlags');
    expect(curl).not.toContain("args.push('-H', `${name}: ${value}`)");
  });

  it('routes every built-in fetch call through the target-aware helper', () => {
    const source = readFileSync(join(process.cwd(), 'src/arsenal/index.ts'), 'utf8');
    const builtins = source.slice(source.indexOf('export const BUILTIN_TOOLS'), source.indexOf('export const EXTERNAL_TOOLS'));
    expect(builtins).not.toMatch(/\bfetch\s*\(/);
    expect(builtins).toContain('targetFetch(');
  });
});
