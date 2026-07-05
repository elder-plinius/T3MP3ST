/**
 * T3MP3ST Arsenal — capability approval + spicy-action warning gate.
 *
 * The human-veto layer that lets an operator be trusted with live post-ex tools (metasploit, hydra,
 * sqlmap, …) safely: an intrusive/credential/dangerous tool is INERT until the tool has been approved
 * — approved once, then free for the session ("approve once, then free") — and the hottest actions
 * still fire a loud, audited WARNING every time so you always SEE what the agent is about to do.
 *
 * Two ways a gated tool becomes approved:
 *   1. INTERACTIVE — the first time an operator reaches for it, `requestApproval` asks the human;
 *      a yes approves the TOOL for the rest of the session.
 *   2. PRE-AUTHORIZED — a headless / unattended run (benchmarks, pack hunts) is handed an allowlist
 *      up front (`preApprovedTools`); those run free, everything is audited, anything off-list denies.
 *
 * FAIL-SAFE: a gated tool that is neither pre-approved nor interactively approvable (no approver
 * wired) is DENIED — an unattended run never silently fires an exploit because nobody was there to
 * say no.
 *
 * SCOPE (what "gated" covers): a tool is gated iff it carries a gated `riskTier`. By default that is
 * the OPT-IN specialist arsenal — the purpose-built post-ex drivers (metasploit=dangerous,
 * hydra=credential) and the Kali+ adapter tools (stamped from their catalog risk). The pre-existing
 * BUILT-IN probes (sqli_scan, password_spray, …) ship UNGATED for backward-compatibility — their
 * safety boundary is the always-on egress SCOPE gate (an out-of-scope target is refused regardless of
 * approval). An operator can extend this gate to cover the spicy built-ins too by launching with
 * T3MP3ST_GATE_BUILTINS=1, which stamps them with a riskTier. So the fail-safe above applies to every
 * tool that is gated; it does not, by itself, make the ungated built-ins inert.
 *
 * This module is PURE — no engine/server imports, no I/O. The host injects the approver + warning
 * sink via the policy, so it is fully unit-testable with fakes. Sits behind Arsenal.execute(),
 * alongside the egress scope gate.
 */

import type { RiskTier } from '../types/index.js';

// Re-exported so callers can `import { ..., RiskTier } from './approval.js'` in one place.
export type { RiskTier };

/** Tiers that require the tool to be APPROVED (interactively or via the allowlist) before it can run. */
const GATED_TIERS: ReadonlySet<RiskTier> = new Set<RiskTier>(['intrusive', 'credential', 'dangerous']);

/** The hottest tiers — an approved call still fires a loud, audited, NON-BLOCKING warning each time. */
const SPICY_TIERS: ReadonlySet<RiskTier> = new Set<RiskTier>(['credential', 'dangerous']);

/** True for a tool whose risk requires approval before it can execute. Undefined/safe/active → false.
 *  A type guard so callers narrow `riskTier?` to a defined RiskTier after the check. */
export function isGatedRisk(risk?: RiskTier): risk is RiskTier {
  return risk !== undefined && GATED_TIERS.has(risk);
}

/** True for a tool whose action warrants a loud warning even when approved (exploits, cred attacks). */
export function isSpicyRisk(risk?: RiskTier): boolean {
  return risk !== undefined && SPICY_TIERS.has(risk);
}

/** What the agent is about to do — enough for a human to make a call, or for the audit trail. */
export interface ApprovalRequest {
  /** The tool being invoked (the approval unit — "approve once" approves this name). */
  tool: string;
  /** The tool's risk tier (drives gating + spiciness). */
  risk: RiskTier;
  /** The operator/agent that wants to run it, when known. */
  operator?: string;
  /** The resolved target the action would hit, when known (informational for the warning/audit). */
  target?: string;
  /** A one-line human-readable summary of the specific action (tool + key params + target). */
  action: string;
}

/** How a gated call was resolved — recorded on every audit entry. */
export type ApprovalOutcome =
  | 'allowed-preapproved' // already on the allowlist or approved earlier this session
  | 'allowed-interactive' // the operator said yes just now (and the tool is now free)
  | 'allowed-ungated' // an ungated spicy built-in that ran without a gate but is warned + audited
  | 'denied-declined' // the operator said no
  | 'denied-no-approver'; // fail-safe: gated, not approved, and no approver was wired

/** One immutable audit record. The controller keeps the full trail for the engagement report. */
export interface ApprovalRecord extends ApprovalRequest {
  outcome: ApprovalOutcome;
  /** Whether a spicy warning was surfaced for this call. */
  spicy: boolean;
  /** Epoch-ms when the decision was made. */
  at: number;
}

export interface ApprovalPolicy {
  /**
   * Tools pre-authorized up front — the headless/unattended allowlist. A gated tool named here runs
   * free (still audited, still warns on spicy actions). This is also the store the "approve once"
   * interactive path writes into.
   */
  preApprovedTools?: string[];
  /**
   * Interactive approver, asked ONCE per gated tool the first time it is used. Return true to approve
   * the tool for the rest of the session. If omitted, a gated tool that isn't pre-approved is DENIED
   * (fail-safe) — the unattended/headless posture.
   */
  requestApproval?: (req: ApprovalRequest) => Promise<boolean>;
  /**
   * Sink for the non-blocking spicy-action warning — surface it live (CLI banner / UI toast / event).
   * Called on every spicy call that is allowed; the same request is also written to the audit trail.
   */
  onWarning?: (req: ApprovalRequest) => void;
  /**
   * Sink for EVERY gated decision (allowed or denied), fired as it is recorded to the audit trail.
   * The engine wires this to an SSE event so the dashboard sees a live approval/audit feed.
   */
  onDecision?: (record: ApprovalRecord) => void;
  /** Injected clock for deterministic tests. Defaults to Date.now. */
  now?: () => number;
}

/**
 * Holds the session's approved-tool set + the full audit trail, and adjudicates each gated call.
 * One instance per engine/mission; wired onto the Arsenal via setApprovalController().
 */
export class ApprovalController {
  private readonly approved: Set<string>;
  private readonly audit: ApprovalRecord[] = [];
  private readonly now: () => number;

  constructor(private readonly policy: ApprovalPolicy = {}) {
    this.approved = new Set(policy.preApprovedTools ?? []);
    this.now = policy.now ?? Date.now;
  }

  /** Approve a tool for the rest of the session ("approve once, then free"). */
  approveTool(name: string): void {
    this.approved.add(name);
  }

  /**
   * Record + surface an UNGATED spicy built-in call. Such tools (the default-posture credential /
   * intrusive probes) are NOT blocked — they still run — but a live credential or injection probe must
   * never fire silently: this always lands the call in the audit trail and, for a spicy tier, fires the
   * non-blocking warning. Distinct from gate(): no allow/deny decision, only visibility.
   */
  noteUngated(req: ApprovalRequest): void {
    const spicy = isSpicyRisk(req.risk);
    if (spicy && this.policy.onWarning) this.policy.onWarning(req);
    const rec: ApprovalRecord = { ...req, outcome: 'allowed-ungated', spicy, at: this.now() };
    this.audit.push(rec);
    this.policy.onDecision?.(rec);
  }

  /** Is this tool currently approved (via the allowlist or an earlier interactive yes)? */
  isApproved(name: string): boolean {
    return this.approved.has(name);
  }

  /** The names currently approved (defensive copy). */
  approvedTools(): string[] {
    return [...this.approved];
  }

  /** The full audit trail (defensive copy) — every gated decision + whether it warned. */
  getAudit(): ApprovalRecord[] {
    return this.audit.map((r) => ({ ...r }));
  }

  /**
   * The gate. Called from Arsenal.execute() BEFORE a tool's handler runs.
   *
   *  - ungated risk (safe/active/undefined) → allowed, nothing recorded.
   *  - gated + already approved → allowed; a spicy call fires the (non-blocking) warning. Audited.
   *  - gated + not approved + an approver is wired → ask once; yes approves the tool + allows (spicy
   *    still warns), no denies. Audited.
   *  - gated + not approved + NO approver → DENIED (fail-safe). Audited.
   */
  async gate(req: ApprovalRequest): Promise<{ allowed: boolean; reason: string }> {
    if (!isGatedRisk(req.risk)) return { allowed: true, reason: 'ungated' };

    const spicy = isSpicyRisk(req.risk);
    const warnIfSpicy = (): void => {
      if (spicy && this.policy.onWarning) this.policy.onWarning(req);
    };
    const record = (outcome: ApprovalOutcome): void => {
      const rec: ApprovalRecord = { ...req, outcome, spicy, at: this.now() };
      this.audit.push(rec);
      this.policy.onDecision?.(rec);
    };

    // Already approved — the allowlist, or an earlier "approve once".
    if (this.approved.has(req.tool)) {
      warnIfSpicy();
      record('allowed-preapproved');
      return { allowed: true, reason: `approved (${req.risk})` };
    }

    // Not yet approved — ask the human once, if an approver is wired.
    if (this.policy.requestApproval) {
      const ok = await this.policy.requestApproval(req);
      if (ok) {
        this.approveTool(req.tool); // approve once, then free
        warnIfSpicy();
        record('allowed-interactive');
        return { allowed: true, reason: `operator approved ${req.tool}` };
      }
      record('denied-declined');
      return { allowed: false, reason: `${req.tool} (${req.risk}) was declined by the operator` };
    }

    // Fail-safe: gated, not approved, no way to ask.
    record('denied-no-approver');
    return {
      allowed: false,
      reason:
        `${req.tool} is a ${req.risk} tool and is not authorized. Approve it up front ` +
        `(pre-authorization allowlist) or via an interactive approver before use.`,
    };
  }
}
