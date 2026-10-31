/**
 * Egress honesty + inline operator authorization — regression tests for the
 * 2026-10-22 "fix egress proxy / make scans live" pass.
 *
 * Three properties:
 *   1. CAIRN BUDGET IS A WALL-CLOCK CONTRACT. The old engine only checked the
 *      deadline between rounds, so an in-flight task kept its whole per-task
 *      timeout past the budget (measured live: a 60s budget ran 222s). Every
 *      task is now cut at min(taskTimeoutMs, remaining).
 *   2. THE EXIT-IP PROBE CANNOT MEASURE A BYPASSED HOST. api.ipify.org (the old
 *      exit fallback) is on the connector's bypass list, so a dead proxy made
 *      the "exit" leg answer with the REAL IP through the direct path — the
 *      check reporting the exact leak it exists to catch as a working proxy.
 *      The exit fallbacks must never name a bypassed host.
 *   3. INLINE OPERATOR AUTHORIZATION. authorize:true on an operator's own click
 *      mints the receipt APPROVED in the same stroke (30-min TTL, visible in
 *      Scope Receipts) and the scan RUNS; without it a public target still
 *      stalls on a pending receipt. Deep autonomous_execution is never
 *      inline-authorizable.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import type { AddressInfo } from 'node:net';

import { runCairnSearch, type ChatFn } from '../search/cairn-engine.js';

const PROXY_SRC = readFileSync(join(process.cwd(), 'src', 'net', 'proxy.ts'), 'utf8');
const SERVER_SRC = readFileSync(join(process.cwd(), 'src', 'server.ts'), 'utf8');

describe('cairn budget — wall-clock contract', () => {
  it('no in-flight task outlives the budget: a task admitted at t=0 is cut at the deadline, not at its full timeout', async () => {
    // A "hung model": every call answers valid JSON but only after 8s. With the
    // old code the bootstrap task ran to its full 8s and the conclude phase
    // another 8s (~16s total) because the deadline was only checked BETWEEN
    // rounds. Now the bootstrap is cut at the 2s budget and the conclude at its
    // 5s floor — the whole search must end well under the old wall-clock.
    const hungChat: ChatFn = () =>
      new Promise((resolve) => setTimeout(() => resolve('{"accepted":true,"data":{"fact":{"description":"late fact"}}}'), 8_000));
    const r = await runCairnSearch({ origin: 'h', goal: 'g', chat: hungChat, config: { budgetMs: 2_000 } });
    // Old code: ~16s (8s bootstrap + 8s conclude, both run to completion). New code:
    // measured 10.0s on a loaded box (2s cut + 5s floor + timer drift) — the bound
    // must keep clear daylight from the old behaviour while tolerating drift.
    expect(r.ms).toBeLessThan(14_000);
    expect(r.state).toBe('budget_exhausted');
    expect(r.completion).toBeNull();
  }, 30_000);
});

describe('egress exit probe — bypass honesty', () => {
  it('the exit-IP fallbacks never name a host on the connector bypass list', () => {
    // The direct leg may use api.ipify.org (bypassed is CORRECT there — that leg
    // is SUPPOSED to measure the real IP). The exit fallbacks must not.
    expect(PROXY_SRC).toContain('const EXIT_FALLBACKS');
    expect(PROXY_SRC).toMatch(/EXIT_FALLBACKS\s*=\s*\['https:\/\/ifconfig\.me\/all\.json',\s*'https:\/\/ipinfo\.io\/json'\]/);
    const bypassList = PROXY_SRC.slice(PROXY_SRC.indexOf('const builtin = ['), PROXY_SRC.indexOf('];', PROXY_SRC.indexOf('const builtin = [')));
    for (const fallback of ['ifconfig.me', 'ipinfo.io']) {
      expect(bypassList).not.toContain(fallback);
    }
  });

  it('checkIp reports proxyReachable so a dead proxy is its own state, not a leak riddle', () => {
    expect(PROXY_SRC).toMatch(/proxyReachable: boolean \| null/);
    expect(PROXY_SRC).toMatch(/probeProxyReachable\(\)/);
    expect(PROXY_SRC).toMatch(/socket\.connect\(parsed\.port, parsed\.host\)/);
  });
});

describe('inline operator authorization — wiring + live behaviour', () => {
  let proc: ChildProcess | undefined;
  afterAll(() => { if (proc && !proc.killed) proc.kill(); });

  it('guardAction mints an APPROVED receipt on authorize:true and never for autonomous_execution', () => {
    expect(SERVER_SRC).toMatch(/if \(body\.authorize === true && action !== 'autonomous_execution'\) \{/);
    // Same semantics as POST /api/approvals/:id/approve: approved, attributed, 30-min TTL, audited.
    expect(SERVER_SRC).toMatch(/approval\.approvedBy = typeof body\.approvedBy === 'string' && body\.approvedBy\.trim\(\)[\s\S]*?approval\.expiresAt = new Date\(Date\.now\(\) \+ 30 \* 60_000\)\.toISOString\(\)/);
    expect(SERVER_SRC).toMatch(/emitContractEvent\('approval\.approved', \{ approvalId: approval\.id, action, target, inline: true \}\)/);
  });

  it('the recon route returns the receipt object and an honest egress note so the UI can show how the scan ran', () => {
    expect(SERVER_SRC).toMatch(/approval: guard\.approval \|\| null/);
    // WSL2 cannot reach the Windows-host SOCKS client, so a WSL-resolved scan must
    // SAY it egressed from the real IP instead of silently riding the proxy badge.
    expect(SERVER_SRC).toMatch(/egressNote = 'nmap ran in WSL/);
  });

  it('live: authorize:true runs a real scan against a public target and records an APPROVED receipt; without it the scan stalls pending', async () => {
    let PORT = 0;

    const net = await import('node:net');
    PORT = await new Promise((resolve, reject) => {
      const srv = net.createServer();
      srv.once('error', reject);
      srv.listen(0, '127.0.0.1', () => {
        const p = (srv.address() as AddressInfo).port;
        srv.close(() => resolve(p));
      });
    });

    // TEMPEST_PROXY_URL is blanked so the run does not depend on Tor being up;
    // the target is a guaranteed-unresolvable name, so dig+nmap fail fast and
    // the assertion is about the GATE, not about any real host answering.
    const env = { ...process.env, T3MP3ST_PORT: String(PORT), T3MP3ST_HOST: '127.0.0.1', TEMPEST_PROXY_URL: '' };
    proc = spawn(process.execPath, [join(process.cwd(), 'dist', 'server.js')], { env, stdio: 'ignore' });

    let up = false;
    for (let i = 0; i < 40 && !up; i++) {
      await new Promise((r) => setTimeout(r, 500));
      try { up = (await fetch(`http://127.0.0.1:${PORT}/api/health`)).ok; } catch { /* not up yet */ }
    }
    expect(up, 'server did not come up on the test port').toBe(true);

    const base = `http://127.0.0.1:${PORT}`;
    const target = 'no-such-host-t3mp3st-test.invalid';

    // 1. WITHOUT authorize: a public target stalls on a PENDING receipt.
    const blocked = await fetch(`${base}/api/tools/recon`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, scan_type: 'quick' }),
    });
    expect(blocked.status).toBe(403);
    const blockedBody: any = await blocked.json();
    expect(blockedBody.approval?.status).toBe('pending');

    // 2. WITH authorize: the SAME kind of request runs, and the receipt it minted
    //    is APPROVED inline with the panel attribution and a 30-minute TTL.
    const run = await fetch(`${base}/api/tools/recon`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, scan_type: 'quick', authorize: true, source: 'human' }),
    });
    expect(run.status).toBe(200);
    const runBody: any = await run.json();
    expect(runBody.success).toBe(true);
    expect(runBody.approval?.status).toBe('approved');
    expect(runBody.approval?.approvedBy).toBe('operator-panel');
    expect(Date.parse(runBody.approval?.expiresAt ?? '')).toBeGreaterThan(Date.now() + 29 * 60_000);

    // 3. The receipt is a first-class citizen: visible (approved) in the ledger.
    const ledger: any = await (await fetch(`${base}/api/approvals`)).json();
    const recorded = (ledger.approvals ?? []).find((a: any) => a.id === runBody.approval.id);
    expect(recorded?.status).toBe('approved');
  }, 120_000);
});
