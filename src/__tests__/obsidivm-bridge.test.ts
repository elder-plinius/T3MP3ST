/**
 * Diagnostics guard for issue #156 — "Benchmark showing error" / `FATAL: fetch failed`.
 *
 * The obsidivm:* benchmarks are a thin HTTP client over the separate OBSIDIVM
 * range service (default http://127.0.0.1:4200, see docs/OBSIDIVM.md). Every
 * request routes through the bridge's `call()`. When the service is down, the
 * raw `fetch` throws a bare `TypeError: fetch failed`, which surfaced to the user
 * as an opaque `FATAL: fetch failed` naming neither the service, the URL, nor how
 * to start it — even in `--hunter stub` mode, whose grading step still needs it.
 *
 * This pins that a connection failure becomes an ACTIONABLE error: it says the
 * OBSIDIVM service is unreachable, names the base URL, and points at the escape
 * hatches (docs/OBSIDIVM.md / OBSIDIVM_URL).
 */
import { describe, it, expect } from 'vitest';
import net from 'node:net';
import { obsidivm } from '../../scripts/obsidivm-bridge.mjs';

/**
 * A guaranteed-closed localhost port: bind an ephemeral listener, capture its
 * port, then close it — a connection there now yields ECONNREFUSED,
 * deterministically and with no external network (hermetic, no mocking).
 */
function closedPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as net.AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

describe('obsidivm bridge — unreachable-service diagnostics (#156)', () => {
  it('turns a connection failure into an actionable error, not a bare "fetch failed"', async () => {
    const port = await closedPort();
    const o = obsidivm({ baseUrl: `http://127.0.0.1:${port}`, timeoutMs: 2000 });

    const err = (await o.getSpec().then(() => null, (e: unknown) => e)) as (Error & { unreachable?: boolean }) | null;

    expect(err, 'getSpec should reject when the service is down').toBeTruthy();
    // names the failure, the URL, and the self-service escape hatches
    expect(err!.message).toMatch(/OBSIDIVM service unreachable/i);
    expect(err!.message).toContain(`127.0.0.1:${port}`);
    expect(err!.message).toMatch(/OBSIDIVM_URL|docs\/OBSIDIVM\.md/);
    // and is flagged so callers can distinguish "down" from an HTTP-status error
    expect(err!.unreachable).toBe(true);
  });

  it('reports a timeout distinctly (not as "unreachable")', async () => {
    // A server that accepts the connection but never responds forces the
    // AbortController timeout path — distinct from a refused connection.
    const srv = net.createServer(() => {
      /* accept, then hang: never write a response */
    });
    try {
      const port: number = await new Promise((resolve) =>
        srv.listen(0, '127.0.0.1', () => resolve((srv.address() as net.AddressInfo).port)),
      );
      const o = obsidivm({ baseUrl: `http://127.0.0.1:${port}`, timeoutMs: 200 });
      const err = (await o.getSpec().then(() => null, (e: unknown) => e)) as (Error & { unreachable?: boolean }) | null;

      expect(err, 'getSpec should reject on timeout').toBeTruthy();
      expect(err!.message).toMatch(/timed out after \d+ms/i);
      expect(err!.unreachable).toBeUndefined(); // a timeout is not "service down"
    } finally {
      // Fire-and-forget: the aborted request leaves a half-open socket, so
      // awaiting close() would hang. Destroy connections and close without
      // waiting — the assertions are already done. (closeAllConnections lands in
      // newer @types/node than this repo pins, hence the cast.)
      (srv as net.Server & { closeAllConnections?: () => void }).closeAllConnections?.();
      srv.close();
    }
  });

  it('reports a malformed base URL as a config error, not "unreachable"', async () => {
    // ERR_INVALID_URL is the operator's mistake, not a down service — the message
    // must point at OBSIDIVM_URL, not at starting the range service.
    const o = obsidivm({ baseUrl: 'not-a-valid-url' });
    const err = (await o.getSpec().then(() => null, (e: unknown) => e)) as (Error & { unreachable?: boolean }) | null;

    expect(err, 'getSpec should reject on a bad URL').toBeTruthy();
    expect(err!.message).toMatch(/invalid OBSIDIVM base URL/i);
    expect(err!.message).toMatch(/OBSIDIVM_URL/);
    expect(err!.message).not.toMatch(/unreachable|is it running/i);
    expect(err!.unreachable).toBeUndefined();
  });
});
