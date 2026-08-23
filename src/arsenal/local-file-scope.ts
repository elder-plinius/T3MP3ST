import { realpathSync, statSync } from 'fs';
import { isAbsolute, relative, resolve, sep } from 'path';

export function approvedLocalPath(tool: string, requested: string, allowDirectory = false): { ok: true; path: string } | { ok: false; error: string } {
  const configuredRoot = process.env.T3MP3ST_SOURCE_ROOT?.trim();
  if (!configuredRoot) return { ok: false, error: `${tool}: T3MP3ST_SOURCE_ROOT must name the approved analysis root` };
  try {
    const root = realpathSync(resolve(configuredRoot));
    const candidate = realpathSync(isAbsolute(requested) ? requested : resolve(root, requested));
    const rel = relative(root, candidate);
    if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
      return { ok: false, error: `${tool}: path is outside T3MP3ST_SOURCE_ROOT` };
    }
    const stat = statSync(candidate);
    if (!stat.isFile() && !(allowDirectory && stat.isDirectory())) {
      return { ok: false, error: `${tool}: path must be ${allowDirectory ? 'a regular file or directory' : 'a regular file'}` };
    }
    return { ok: true, path: candidate };
  } catch {
    return { ok: false, error: `${tool}: path cannot be resolved inside T3MP3ST_SOURCE_ROOT` };
  }
}
