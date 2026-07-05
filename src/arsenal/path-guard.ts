/**
 * File-path guard shared by the fuzz / credential tools (built-in ffuf, adapter ffuf/gobuster, hydra).
 *
 * These tools take a wordlist / userlist / passlist path from LLM-controlled parameters and send each
 * line to the (in-scope, possibly attacker-controlled) target, so pointing one at a key/credential file
 * would exfiltrate it line-by-line. This denies the high-value secrets — SSH/PGP/cloud-cred dotdirs,
 * the shadow file, and private-key files — with near-zero collision against ordinary wordlists
 * (SecLists, /usr/share/wordlists/…). It lives in its own module so arsenal/index.ts, adapter-tools.ts,
 * and post-ex.ts can all import it without a circular dependency. Pure (home injectable for tests).
 */
import { homedir } from 'os';
import { resolve as resolvePath, basename, sep, join as joinPath } from 'path';

/** Secret directories under the operator's home whose contents must never be fed to a target. */
const SECRET_HOME_DIRS = ['.ssh', '.aws', '.gnupg', '.config'];

export function isSensitiveFilePath(p: string | undefined, home: string = homedir()): boolean {
  if (!p || typeof p !== 'string') return false;
  const expanded = p.startsWith('~') ? home + p.slice(1) : p;
  const lower = resolvePath(expanded).toLowerCase();
  const homeLower = home.toLowerCase();
  const base = basename(lower);

  for (const d of SECRET_HOME_DIRS) {
    const dir = joinPath(homeLower, d);
    if (lower === dir || lower.startsWith(dir + sep)) return true;
  }
  if (lower === '/etc/shadow' || lower === '/etc/gshadow') return true;
  if (/^id_(rsa|dsa|ecdsa|ed25519)$/.test(base) || base.endsWith('.pem')) return true;
  return false;
}
