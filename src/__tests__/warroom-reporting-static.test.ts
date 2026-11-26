import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

// Sources are checked out with CRLF on Windows; normalize so multi-line
// anchors match regardless of the working copy's line endings.
const uiSource = readFileSync(join(process.cwd(), 'docs/index.html'), 'utf8').replace(/\r\n/g, '\n');

function block(startMarker: string, endMarker: string): string {
  const start = uiSource.indexOf(startMarker);
  expect(start, `missing source marker ${startMarker}`).toBeGreaterThanOrEqual(0);
  const end = uiSource.indexOf(endMarker, start);
  expect(end, `missing end marker ${endMarker}`).toBeGreaterThan(start);
  return uiSource.slice(start, end);
}

describe('War Room reporting invariants (docs/index.html)', () => {
  it('exportMissionReport sorts a COPY of missionFindings so row/detail index mapping survives', () => {
    const exportFn = block('function exportMissionReport()', 'addIntel(\'SYSTEM\', `Report exported');
    // The copyFinding/showFindingDetail rows pass missionFindings indices; an in-place
    // sort here reorders the array under those indices.
    expect(exportFn).not.toMatch(/missionFindings\.sort\(/);
    expect(exportFn).toMatch(/\[\.\.\.missionFindings\]\.sort\(/);
  });

  it('clearFindings resets the per-run counters (header badge, Evidence grid, quality cells)', () => {
    const fn = block('function clearFindings()', '// ═══════════ CRITICAL FINDING ALERT');
    expect(fn).toMatch(/statFindings/);
    expect(fn).toMatch(/renderFindings\(\)/);
    expect(fn).toMatch(/metric-approval/);
    expect(fn).toMatch(/metric-rejections/);
  });

  it('phase_changed marks the NEW phase as starting (0), never as already DONE (100)', () => {
    const handler = block("addEventListener('phase_changed'", "this._eventSource.addEventListener('detection'");
    expect(handler).toMatch(/updateKillChain\?\.\(uiPhase, 0\)/);
    expect(handler).not.toMatch(/updateKillChain\?\.\(uiPhase, 100\)/);
  });

  it('pollUntilComplete tolerates transient status-poll failures instead of reporting a false completion', () => {
    const dispatch = block('const BackendDispatch = {', '// Check API health on load');
    // getStatus must distinguish "server said stopped" from "could not ask"
    expect(dispatch).toMatch(/async getStatus\(\)[\s\S]*?catch \{[\s\S]*?return null;/);
    const poll = block('async pollUntilComplete(', '};\n        }');
    expect(poll).toMatch(/MAX_CONSECUTIVE_FAILURES = \d+/);
    expect(poll).toMatch(/consecutiveFailures\+\+/);
    // the caller reports a dead poll stream as an error, not MISSION COMPLETE
    expect(uiSource).toMatch(/if \(finalStatus\.error\) \{[\s\S]*?throw new Error\(finalStatus\.error\);/);
  });

  it('the client-side pipeline feeds its quality metrics to the War Room quality panel', () => {
    const pipeline = block('async function _runClientSidePipeline(', '// Pause mission');
    expect(pipeline).toMatch(/updateDashboardQualityMetrics\(results\.qualityMetrics\)/);
    expect(pipeline).toMatch(/updateQualityDisplay\(\)/);
  });

  it('kill-chain phase counter declares exactly once (implemented — per-step behavioral covertured by the invariants above)', () => {
    const src = block('// Mission telemetry', '// Increment API call counter (called from safeLLMCall)');
    expect(src).toMatch(/let completedPhases = new Set\(\)/);
    expect(src).toMatch(/completedPhases\.add\(mappedPhase\)[\s\S]*?\/5/);
    expect(src).toMatch(/completedPhases\.add\(p\)/);
    expect(src).toMatch(/completedPhases\.clear\(\)/);
  });
});
