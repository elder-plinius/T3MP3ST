import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ReportWorkspace } from './adapter-tools.js';

/**
 * Create a private per-run directory for report-file tools. `mkdtemp` creates the directory with
 * mode 0700, and cleanup removes the whole tree so partial files from failed tools are covered too.
 */
export async function createPrivateReportWorkspace(adapterId: string): Promise<ReportWorkspace> {
  const safeId = adapterId.replace(/[^a-z0-9_-]+/gi, '_');
  const dir = await mkdtemp(join(tmpdir(), `t3mp3st-${safeId}-`));
  return {
    reportBase: join(dir, 'report'),
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
}

/** Read report bytes without deleting them; the workspace owner handles unconditional cleanup. */
export function readPrivateToolReport(path: string): Promise<string> {
  return readFile(path, 'utf8');
}
