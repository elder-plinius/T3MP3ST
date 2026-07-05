/**
 * Arsenal.execute() enforces the capability-approval gate for gated tools, alongside the scope gate.
 * A dangerous/credential/intrusive tool must not run until approved; ungated tools are untouched; the
 * gate runs BEFORE the handler (a denied call never executes).
 */
import { describe, it, expect, vi } from 'vitest';
import { Arsenal, BUILTIN_TOOLS, EXTERNAL_TOOLS, SPICY_BUILTIN_TIERS, stampSpicyBuiltin } from '../arsenal/index.js';
import { ApprovalController } from '../arsenal/approval.js';
import type { CustomTool, ToolContext } from '../types/index.js';

const ctx = (parameters: Record<string, unknown> = {}): ToolContext => ({ parameters });

function probe(name: string, riskTier?: CustomTool['riskTier']): CustomTool & { ran: () => boolean } {
  let ran = false;
  const tool: CustomTool = {
    name, description: 'x', category: 'exploitation', riskTier, parameters: [],
    handler: async () => { ran = true; return { success: true, output: 'DID_RUN' }; },
  };
  return Object.assign(tool, { ran: () => ran });
}

describe('Arsenal.execute() — approval gate', () => {
  it('no controller wired = gating off (backward-compat): a dangerous tool still runs', async () => {
    const ars = new Arsenal();
    const t = probe('metasploit_module', 'dangerous');
    ars.register(t);
    expect((await ars.execute('metasploit_module', ctx())).success).toBe(true);
    expect(t.ran()).toBe(true);
  });

  it('fail-safe: a gated tool is DENIED (handler never runs) when nothing approves it', async () => {
    const ars = new Arsenal();
    const t = probe('metasploit_module', 'dangerous');
    ars.register(t);
    ars.setApprovalController(new ApprovalController()); // no approver, no allowlist
    const res = await ars.execute('metasploit_module', ctx());
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/APPROVAL REQUIRED/);
    expect(t.ran()).toBe(false); // gate ran before the handler
  });

  it('a pre-authorized gated tool runs, and a spicy call fires the warning', async () => {
    const ars = new Arsenal();
    const onWarning = vi.fn();
    const t = probe('metasploit_module', 'dangerous');
    ars.register(t);
    ars.setApprovalController(new ApprovalController({ preApprovedTools: ['metasploit_module'], onWarning }));
    const res = await ars.execute('metasploit_module', ctx({ module: 'exploit/x', target: '10.0.0.5' }));
    expect(res.success).toBe(true);
    expect(t.ran()).toBe(true);
    expect(onWarning).toHaveBeenCalledTimes(1);
    expect(onWarning.mock.calls[0][0].action).toContain('metasploit_module');
  });

  it('ZERO-REGRESSION: pre-existing built-in tools stay UNGATED — only the new opt-in arsenal is gated', () => {
    // The approval gate covers the newly-armed dangerous arsenal (metasploit/hydra + Kali+ adapters,
    // stamped by post-ex.ts / the adapter factory). Built-in tools that ran freely before the gate
    // existed must keep that behavior — they carry NO riskTier, so isGatedRisk() never fires on them.
    const all = [...BUILTIN_TOOLS, ...EXTERNAL_TOOLS];
    const tier = (name: string): string | undefined => all.find((t) => t.name === name)?.riskTier;
    for (const n of ['sqli_scan', 'xss_scan', 'password_spray', 'hash_crack', 'dir_bruteforce']) {
      expect(tier(n), `${n} must stay ungated (zero regression)`).toBeUndefined();
    }
  });

  it('an ungated tool is never gated even with a locked-down controller', async () => {
    const ars = new Arsenal();
    const t = probe('httpx_tool', 'active'); // active = ungated
    ars.register(t);
    ars.setApprovalController(new ApprovalController()); // fail-safe deny for gated tools only
    expect((await ars.execute('httpx_tool', ctx())).success).toBe(true);
    expect(t.ran()).toBe(true);
  });

  it('an UNGATED spicy (credential) built-in still runs but always warns + audits (never silent)', async () => {
    const ars = new Arsenal();
    const onWarning = vi.fn();
    const onDecision = vi.fn();
    const t = probe('password_spray'); // spicy NAME but no riskTier = the default ungated posture
    ars.register(t);
    ars.setApprovalController(new ApprovalController({ onWarning, onDecision }));
    const res = await ars.execute('password_spray', ctx({ url: 'https://target.example.com/login', username: 'admin' }));
    expect(res.success).toBe(true); // NOT blocked — default posture preserved
    expect(t.ran()).toBe(true);
    expect(onWarning).toHaveBeenCalledTimes(1); // credential is spicy → warned
    expect(onDecision).toHaveBeenCalledTimes(1);
    expect(ars.getApprovalController()?.getAudit().some(r => r.tool === 'password_spray' && r.outcome === 'allowed-ungated')).toBe(true);
  });

  it('an ungated intrusive built-in is audited without a (spicy-only) warning', async () => {
    const ars = new Arsenal();
    const onWarning = vi.fn();
    const t = probe('sqli_scan'); // intrusive tier — audited but not "spicy"
    ars.register(t);
    ars.setApprovalController(new ApprovalController({ onWarning }));
    await ars.execute('sqli_scan', ctx({ url: 'https://target.example.com/?id=1', param: 'id' }));
    expect(onWarning).not.toHaveBeenCalled();
    expect(ars.getApprovalController()?.getAudit().some(r => r.tool === 'sqli_scan' && r.outcome === 'allowed-ungated')).toBe(true);
  });
});

describe('opt-in built-in gating (T3MP3ST_GATE_BUILTINS) — stampSpicyBuiltin', () => {
  it('stamps ONLY the spicy built-ins with their tier, and never mutates the shared array', () => {
    // the shared BUILTIN_TOOLS stay ungated (default posture / zero regression) …
    for (const n of Object.keys(SPICY_BUILTIN_TIERS)) {
      expect(BUILTIN_TOOLS.find((t) => t.name === n)?.riskTier, `${n} shared def stays ungated`).toBeUndefined();
    }
    // … and stampSpicyBuiltin returns a tiered COPY for a spicy tool, the tool unchanged otherwise.
    for (const t of BUILTIN_TOOLS) {
      const stamped = stampSpicyBuiltin(t);
      const wantTier = SPICY_BUILTIN_TIERS[t.name];
      if (wantTier) {
        expect(stamped.riskTier).toBe(wantTier);
        expect(stamped).not.toBe(t); // fresh object — original untouched
        expect(t.riskTier).toBeUndefined();
      } else {
        expect(stamped).toBe(t); // ungated tools pass through by reference
      }
    }
  });

  it('a stamped spicy built-in IS fenced by the same fail-safe gate (password_spray → denied unattended)', async () => {
    const spray = BUILTIN_TOOLS.find((t) => t.name === 'password_spray');
    expect(spray, 'password_spray must exist in the arsenal').toBeTruthy();
    const gated = stampSpicyBuiltin(spray as CustomTool);
    expect(gated.riskTier).toBe('credential');
    const ars = new Arsenal();
    ars.register(gated);
    ars.setApprovalController(new ApprovalController()); // headless, no approver, no allowlist
    const res = await ars.execute('password_spray', ctx({ url: 'https://target.example.com/login' }));
    expect(res.success).toBe(false); // fail-safe deny — the opt-in gate now covers it
    expect(res.error).toMatch(/APPROVAL REQUIRED/);
  });

  it('a stamped spicy built-in RUNS once pre-approved (approve-once / allowlist)', async () => {
    const t = probe('password_spray', 'credential'); // as stampSpicyBuiltin would produce
    const ars = new Arsenal();
    ars.register(t);
    ars.setApprovalController(new ApprovalController({ preApprovedTools: ['password_spray'] }));
    expect((await ars.execute('password_spray', ctx({ url: 'https://target.example.com/login' }))).success).toBe(true);
    expect(t.ran()).toBe(true);
  });
});
