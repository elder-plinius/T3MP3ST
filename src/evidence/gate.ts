/**
 * The live verification gate — the honesty spine, IN the engine path.
 *
 * Rules:
 *  1. Any finding must have real tool-output evidence (not prose).
 *  2. Web probe phases (delivery/exploitation/weaponization) must have BOTH
 *     a request AND a response — "got a response" is not a finding; the
 *     response must be examined for a confirmation signal.
 *  3. If a second-pass validationResult exists and rejected the finding,
 *     the gate blocks it regardless of tool provenance.
 *  4. critical/high severity with zero evidence is always blocked.
 */

import type { Finding } from '../types/index.js';

/** Evidence types that represent real machine/tool output (vs a human note). */
const TOOL_EVIDENCE = new Set(['output', 'command', 'response', 'request', 'log', 'file']);

/**
 * Phases where we require BOTH a request AND a response — the probe must
 * show what was sent and what came back, not just that a tool ran.
 */
const WEB_PROBE_PHASES = new Set(['delivery', 'exploitation', 'weaponization']);

export type LiveProvenance = 'none' | 'context' | 'tool';

export interface LiveGateResult {
  passed: boolean;
  provenance: LiveProvenance;
  reasons: string[];
  checkedAt: number;
}

/**
 * Gate a live finding. PASS only when:
 *  - Real tool output is present
 *  - For web probe phases: both request AND response evidence exist
 *  - Second-pass validation (if present) confirmed the finding
 */
export function gateLiveFinding(f: Finding): LiveGateResult {
  const reasons: string[] = [];
  const evidence = Array.isArray(f.evidence) ? f.evidence : [];
  const toolEv = evidence.filter((e) => e && TOOL_EVIDENCE.has(e.type) && String(e.content || '').trim().length > 0);

  if (toolEv.length === 0) {
    reasons.push('no tool-output evidence (output/command/response/log/file) — provenance-strict requires real tool output, not prose');
  }

  // Web probe phases: require both sides of the HTTP exchange.
  // Exception: code-scan tools (semgrep, trivy, gitleaks) run in the weaponization phase
  // but produce command evidence instead of HTTP evidence — allow command+output to satisfy
  // the gate without requiring a request/response pair.
  if (WEB_PROBE_PHASES.has(f.phase)) {
    const hasCommandEv = evidence.some(e => e.type === 'command' && String(e.content || '').trim().length > 0);
    if (!hasCommandEv) {
      const hasRequest = evidence.some(e => e.type === 'request' && String(e.content || '').trim().length > 0);
      const hasResponse = evidence.some(e => e.type === 'response' && String(e.content || '').trim().length > 0);
      if (!hasRequest) {
        reasons.push(`${f.phase} finding missing request evidence — what probe was sent? A response alone does not confirm a vulnerability`);
      }
      if (!hasResponse) {
        reasons.push(`${f.phase} finding missing response evidence — what did the target return?`);
      }
    }
  }

  // Second-pass validator rejection overrides tool provenance
  if (f.validationResult && !f.validationResult.confirmed) {
    reasons.push(`second-pass validation rejected: ${f.validationResult.reasoning} (confidence: ${Math.round((f.validationResult.confidence ?? 0) * 100)}%)`);
  }

  if ((f.severity === 'critical' || f.severity === 'high') && evidence.length === 0) {
    reasons.push(`${f.severity} severity asserted with zero evidence — severity must be backed by evidence`);
  }

  const provenance: LiveProvenance = toolEv.length > 0 ? 'tool' : (evidence.length > 0 ? 'context' : 'none');
  return { passed: reasons.length === 0, provenance, reasons, checkedAt: Date.now() };
}
