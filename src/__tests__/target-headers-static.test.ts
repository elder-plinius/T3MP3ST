/**
 * TEMPEST_TARGET_HEADERS — static invariants + runtime behaviour
 *
 * Pins the contract for the env-driven header injection feature:
 *   - parseTargetHeaders() is defined and handles all edge cases (invalid JSON, arrays, empty)
 *   - all three HTTP tools (http_request, header_analysis, curl_request) inject env headers
 *   - per-request headers always override env headers for the same key
 *   - the .env.example documents the variable with worked examples
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { BUILTIN_TOOLS, createToolContext } from '../arsenal/index.js';

const arsenalSource = readFileSync(join(process.cwd(), 'src/arsenal/index.ts'), 'utf8');

function sourceBlock(startMarker: string, endMarker: string): string {
  const start = arsenalSource.indexOf(startMarker);
  expect(start, `missing start marker "${startMarker}"`).toBeGreaterThanOrEqual(0);
  const end = arsenalSource.indexOf(endMarker, start);
  expect(end, `missing end marker "${endMarker}"`).toBeGreaterThan(start);
  return arsenalSource.slice(start, end);
}

// =============================================================================
// STATIC INVARIANTS
// =============================================================================

describe('TEMPEST_TARGET_HEADERS static invariants', () => {
  it('parseTargetHeaders function is defined in the arsenal source', () => {
    expect(arsenalSource).toContain('function parseTargetHeaders()');
  });

  it('parseTargetHeaders silently swallows invalid JSON — no rethrow', () => {
    const fn = sourceBlock('function parseTargetHeaders()', '\n}');
    // The catch must swallow, not re-throw.
    expect(fn).toContain('} catch {');
    expect(fn).not.toContain('throw');
  });

  it('parseTargetHeaders rejects arrays — only plain objects are valid header maps', () => {
    const fn = sourceBlock('function parseTargetHeaders()', '\n}');
    expect(fn).toContain('!Array.isArray(parsed)');
  });

  it('http_request spreads env headers first so per-request headers override them', () => {
    // Spread order must be: { ...parseTargetHeaders(), ...per-request }
    const block = sourceBlock("name: 'http_request'", "name: 'header_analysis'");
    const envIdx = block.indexOf('...parseTargetHeaders()');
    const perIdx = block.indexOf('context.parameters.headers');
    expect(envIdx, 'parseTargetHeaders() spread must be present').toBeGreaterThanOrEqual(0);
    expect(perIdx, 'per-request headers spread must come after env headers').toBeGreaterThan(envIdx);
  });

  it('header_analysis passes target headers to the HEAD request', () => {
    const block = sourceBlock("name: 'header_analysis'", "name: 'dir_bruteforce'");
    expect(block).toContain('parseTargetHeaders()');
    expect(block).toContain("method: 'HEAD'");
  });

  it('curl_request prepends env -H args before per-request headers (last-wins = request overrides)', () => {
    const curlStart = arsenalSource.indexOf("name: 'curl_request'");
    expect(curlStart, "curl_request tool must exist in arsenal source").toBeGreaterThanOrEqual(0);
    const block = arsenalSource.slice(curlStart);
    const envHeadersIdx = block.indexOf('parseTargetHeaders()');
    // Per-request headers are pushed in `if (headers) {` block — must come after env headers.
    const perRequestIdx = block.indexOf('if (headers) {');
    expect(envHeadersIdx, 'parseTargetHeaders() must be used in curl_request').toBeGreaterThanOrEqual(0);
    expect(perRequestIdx, 'per-request headers block must come after env headers').toBeGreaterThan(envHeadersIdx);
  });

  it('.env.example documents TEMPEST_TARGET_HEADERS with Bearer and Cookie examples', () => {
    const envExample = readFileSync(join(process.cwd(), '.env.example'), 'utf8');
    expect(envExample).toContain('TEMPEST_TARGET_HEADERS');
    expect(envExample).toContain('Authorization');
    expect(envExample).toContain('Cookie');
  });
});

// =============================================================================
// RUNTIME BEHAVIOUR
// =============================================================================

const httpTool = BUILTIN_TOOLS.find(t => t.name === 'http_request')!;
const headersTool = BUILTIN_TOOLS.find(t => t.name === 'header_analysis')!;

/**
 * Minimal Response stub for fetch mocks.
 * - entries() feeds http_request's Object.fromEntries(response.headers.entries())
 * - get() feeds header_analysis's security-header inspection loop
 */
function makeResponse(status = 200, headerMap: Record<string, string> = {}): Response {
  return {
    status,
    statusText: 'OK',
    headers: {
      entries: (): Iterable<[string, string]> => Object.entries(headerMap),
      get: (name: string): string | null => headerMap[name] ?? null,
    },
  } as unknown as Response;
}

describe('TEMPEST_TARGET_HEADERS runtime behaviour — http_request', () => {
  let prevHeaders: string | undefined;

  beforeEach(() => {
    prevHeaders = process.env.TEMPEST_TARGET_HEADERS;
  });

  afterEach(() => {
    if (prevHeaders === undefined) {
      delete process.env.TEMPEST_TARGET_HEADERS;
    } else {
      process.env.TEMPEST_TARGET_HEADERS = prevHeaders;
    }
    vi.unstubAllGlobals();
  });

  it('sends a bearer token from env on every request', async () => {
    process.env.TEMPEST_TARGET_HEADERS = JSON.stringify({ Authorization: 'Bearer test-token' });
    const mockFetch = vi.fn().mockResolvedValue(makeResponse());
    vi.stubGlobal('fetch', mockFetch);

    await httpTool.handler(createToolContext(undefined, { url: 'https://example.com' }));

    expect(mockFetch).toHaveBeenCalledOnce();
    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer test-token');
  });

  it('per-request header overrides env header for the same key', async () => {
    process.env.TEMPEST_TARGET_HEADERS = JSON.stringify({ Authorization: 'Bearer env-token' });
    const mockFetch = vi.fn().mockResolvedValue(makeResponse());
    vi.stubGlobal('fetch', mockFetch);

    await httpTool.handler(createToolContext(undefined, {
      url: 'https://example.com',
      headers: { Authorization: 'Bearer request-override' },
    }));

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer request-override');
  });

  it('env and per-request headers are both forwarded when they target different keys', async () => {
    process.env.TEMPEST_TARGET_HEADERS = JSON.stringify({ 'X-Tenant': 'acme' });
    const mockFetch = vi.fn().mockResolvedValue(makeResponse());
    vi.stubGlobal('fetch', mockFetch);

    await httpTool.handler(createToolContext(undefined, {
      url: 'https://example.com',
      headers: { Authorization: 'Bearer scoped' },
    }));

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const sent = init.headers as Record<string, string>;
    expect(sent['X-Tenant']).toBe('acme');
    expect(sent['Authorization']).toBe('Bearer scoped');
  });

  it('sends no env headers when TEMPEST_TARGET_HEADERS is unset', async () => {
    delete process.env.TEMPEST_TARGET_HEADERS;
    const mockFetch = vi.fn().mockResolvedValue(makeResponse());
    vi.stubGlobal('fetch', mockFetch);

    await httpTool.handler(createToolContext(undefined, { url: 'https://example.com' }));

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(Object.keys(init.headers as Record<string, string>)).toHaveLength(0);
  });

  it('sends no env headers when TEMPEST_TARGET_HEADERS is invalid JSON', async () => {
    process.env.TEMPEST_TARGET_HEADERS = 'not-valid-json{{{';
    const mockFetch = vi.fn().mockResolvedValue(makeResponse());
    vi.stubGlobal('fetch', mockFetch);

    await httpTool.handler(createToolContext(undefined, { url: 'https://example.com' }));

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(Object.keys(init.headers as Record<string, string>)).toHaveLength(0);
  });

  it('sends no env headers when TEMPEST_TARGET_HEADERS is a JSON array (not an object)', async () => {
    process.env.TEMPEST_TARGET_HEADERS = '["Authorization","Bearer token"]';
    const mockFetch = vi.fn().mockResolvedValue(makeResponse());
    vi.stubGlobal('fetch', mockFetch);

    await httpTool.handler(createToolContext(undefined, { url: 'https://example.com' }));

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(Object.keys(init.headers as Record<string, string>)).toHaveLength(0);
  });
});

describe('TEMPEST_TARGET_HEADERS runtime behaviour — header_analysis', () => {
  let prevHeaders: string | undefined;

  beforeEach(() => {
    prevHeaders = process.env.TEMPEST_TARGET_HEADERS;
  });

  afterEach(() => {
    if (prevHeaders === undefined) {
      delete process.env.TEMPEST_TARGET_HEADERS;
    } else {
      process.env.TEMPEST_TARGET_HEADERS = prevHeaders;
    }
    vi.unstubAllGlobals();
  });

  it('forwards env headers to the HEAD request when set', async () => {
    process.env.TEMPEST_TARGET_HEADERS = JSON.stringify({ Cookie: 'session=abc123' });
    const mockFetch = vi.fn().mockResolvedValue(makeResponse(200, {}));
    vi.stubGlobal('fetch', mockFetch);

    await headersTool.handler(createToolContext(undefined, { url: 'https://example.com' }));

    expect(mockFetch).toHaveBeenCalledOnce();
    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['Cookie']).toBe('session=abc123');
  });

  it('passes headers: undefined to fetch when no env headers are set', async () => {
    delete process.env.TEMPEST_TARGET_HEADERS;
    const mockFetch = vi.fn().mockResolvedValue(makeResponse(200, {}));
    vi.stubGlobal('fetch', mockFetch);

    await headersTool.handler(createToolContext(undefined, { url: 'https://example.com' }));

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    // When parseTargetHeaders() returns {}, the handler passes `undefined` (not an empty object)
    expect(init.headers).toBeUndefined();
  });

  it('returns a successful security header analysis', async () => {
    process.env.TEMPEST_TARGET_HEADERS = JSON.stringify({ Authorization: 'Bearer token' });
    const mockFetch = vi.fn().mockResolvedValue(makeResponse(200, {
      'Strict-Transport-Security': 'max-age=31536000',
    }));
    vi.stubGlobal('fetch', mockFetch);

    const result = await headersTool.handler(createToolContext(undefined, { url: 'https://example.com' }));

    expect(result.success).toBe(true);
    expect(result.output).toContain('Strict-Transport-Security');
  });
});
