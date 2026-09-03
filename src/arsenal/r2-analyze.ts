/**
 * T3MP3ST r2_analyze — radare2-backed binary analysis: confirm dangerous sinks
 * found by binary_sink_scan with real disassembly, list functions/imports/strings.
 *
 * Runs radare2 in headless mode (-qc) with a bounded, read-only command set:
 *   functions   -> afl (function list)
 *   imports     -> iil (imported symbols)
 *   strings     -> izz with count
 *   xrefs       -> axt @ str.<string> (who references a string — sink confirmation)
 * Safe: analysis only, never writes to the file, bounded timeout.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import type { CustomTool, ToolFinding } from '../types/index.js';
import { approvedLocalPath } from './local-file-scope.js';

const execFileAsync = promisify(execFile);

async function r2(path: string, cmd: string, timeoutMs: number): Promise<string> {
  const { stdout, stderr } = await execFileAsync('r2', ['-q', '-e', 'scr.color=false', '-c', cmd, path], { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 });
  return (stdout || stderr || '').slice(0, 6000);
}

export const r2AnalyzeTool: CustomTool = {
  name: 'r2_analyze',
  description: 'radare2 binary analysis: list functions, imports, strings, or confirm xrefs to a sink string (disassembly-backed verification of binary_sink_scan hits)',
  category: 're',
  parameters: [
    { name: 'path', type: 'string', description: 'Absolute path to the binary/DLL', required: true },
    { name: 'query', type: 'string', description: 'functions | imports | strings | xrefs', required: false, default: 'functions' },
    { name: 'string', type: 'string', description: 'String to cross-reference (for query=xrefs)', required: false },
  ],
  handler: async (context) => {
    const requestedPath = String(context.parameters.path || '').trim();
    if (!requestedPath) return { success: false, error: 'r2_analyze: path required' };
    const approved = approvedLocalPath('r2_analyze', requestedPath);
    if (!approved.ok) return { success: false, error: approved.error };
    const filePath = approved.path;
    const query = String(context.parameters.query || 'functions').toLowerCase();
    const sink = String(context.parameters.string || '').trim();
    try {
      let out: string;
      if (query === 'imports') {
        out = await r2(filePath, 'iil', 60000);
        return { success: true, output: `Imports for ${filePath}:\n${out || '(none)'}` };
      }
      if (query === 'strings') {
        out = await r2(filePath, 'izz~[0:1]', 60000);
        const count = (out.match(/\d+/g) || [])[0] || '?';
        return { success: true, output: `String count for ${filePath}: ${count}\n${out.slice(0, 1000)}` };
      }
      if (query === 'xrefs') {
        if (!sink) return { success: false, error: 'r2_analyze: string required for xrefs query' };
        out = await r2(filePath, `aaa; axt @ str.${sink.replace(/[^a-zA-Z0-9_.-]/g, '_')}`, 120000);
        const finding: ToolFinding[] | undefined = out.trim()
          ? [{ title: `Sink xref confirmed: ${sink}`, severity: 'medium', details: `radare2 cross-references for str.${sink}:\n${out.slice(0, 1500)}` }]
          : undefined;
        return { success: true, output: out.trim() ? `Xrefs to "${sink}":\n${out}` : `No xrefs found for "${sink}" (string may not be referenced or was not analyzed).`, findings: finding };
      }
      out = await r2(filePath, 'aaa; afl', 120000);
      const lines = out.split('\n').filter(Boolean);
      const summary = lines.slice(0, 40);
      const more = lines.length > 40 ? `\n… +${lines.length - 40} more functions` : '';
      return { success: true, output: `Functions in ${filePath} (${lines.length}):\n${summary.join('\n')}${more}` };
    } catch (e) {
      return { success: false, error: `r2_analyze failed: ${e instanceof Error ? e.message.slice(0, 160) : 'unknown'}` };
    }
  },
};
