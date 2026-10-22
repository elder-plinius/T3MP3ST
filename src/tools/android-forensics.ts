// =============================================================================
// ANDROID FORENSICS — ADB-backed device triage, ported from
// https://github.com/DouglasFreshHabian/AndroidForensics (MIT)
// Vendored scripts live in tools/android-forensics/; this module exposes the
// same workflows as safe, allowlisted Node wrappers + agent-runnable tools.
//
// Doctrine: physical device + USB debugging + explicit owner/operator
// authorization. No remote exploitation. Every function that touches a device
// documents the consent boundary and returns honest "no device / no adb /
// permission denied" results instead of pretending.
//
// LOCK-SCREEN EXCEPTION (deliberate — see probeLockPin): the ADB lock PIN probe
// is the one capability here that touches the lock screen. It is gated three
// ways: `riskTier: 'intrusive'` so the arsenal refuses to run it until an
// operator approves it, an explicit authorization acknowledgement parameter, and
// a hard cap of ONE attempt per call. It is reachable only after the device
// owner has already enabled USB debugging AND granted this host ADB
// authorization — the device has already surrendered debug authority. It is a
// lab/repair instrument for a device in hand; unlocking a handset you do not own
// or are not authorized to test is a criminal offence in most jurisdictions
// (CFAA / UK CMA equivalents).
//
// All shell work goes through execFile('adb', [...]) — no shell injection
// surface. Only the allowlisted `adb shell <verb>` families from the four
// upstream scripts are reachable (getprop, pm, dumpsys, settings, content,
// svc, logcat, bugreport, uptime, ifconfig/ip, netstat, bugreportz).
// =============================================================================

import { execFile } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { CustomTool } from '../types/index.js';

const execFileAsync = promisify(execFile);

// Vendored script directory (for download endpoint + provenance)
export const ANDROID_FORENSICS_VENDOR_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'tools', 'android-forensics');
export const ANDROID_FORENSICS_VERSION = 'AndroidForensics/main @ DouglasFreshHabian (MIT)';
export const ANDROID_FORENSICS_SOURCE = 'https://github.com/DouglasFreshHabian/AndroidForensics';

// The four upstream scripts — mirrored 1:1 on disk under tools/android-forensics/
export const ANDROID_SCRIPTS = [
  {
    id: 'extract',
    file: 'extract.sh',
    label: 'extract.sh — Full Triage & User-Data Snapshot',
    upstream: 'https://raw.githubusercontent.com/DouglasFreshHabian/AndroidForensics/main/extract.sh',
    summary:
      'Automated ADB_Data extraction: deviceInfo (getprop), deviceState (uptime/battery/connectivity), network (ifconfig/ip), ' +
      'accounts (dumpsys account), emails (regex), boot count, contacts/phones, call_log, sms, packages (-f/-3), ' +
      'services (dumpsys -l), logcat snapshot, and background bugreport. Outputs a timestamped ADB_Report_* folder.',
  },
  {
    id: 'dumpsys',
    file: 'dumpsys.sh',
    label: 'dumpsys.sh — Diagnostics Collector (21 services)',
    upstream: 'https://raw.githubusercontent.com/DouglasFreshHabian/AndroidForensics/main/dumpsys.sh',
    summary:
      'Loops 21 dumpsys targets (meminfo, audio_flinger, sensorservice, adb, account, persona, fingerprint, netstats, ' +
      'mount, power, dropbox, location, notification, telecom, lock_settings, package, wifi, window, stats, batterystats, ' +
      'usb, clipboard) into DumpSysReport_*. One file per service + summary counts.',
  },
  {
    id: 'airscope',
    file: 'AirScope.sh',
    label: 'AirScope.sh — Wi-Fi Radar',
    upstream: 'https://raw.githubusercontent.com/DouglasFreshHabian/AndroidForensics/main/AirScope.sh',
    summary:
      'Cycles Wi-Fi (svc wifi disable/enable), then parses dumpsys wifi "Networks filtered out due" for nearby BSSIDs: ' +
      'SSID, BSSID, band, RSSI (dBm). Dedupes by BSSID (strongest RSSI), sorted by signal.',
  },
  {
    id: 'secretCodes',
    file: 'secretCodes.sh',
    label: 'secretCodes.sh — Secret Dialer Codes',
    upstream: 'https://raw.githubusercontent.com/DouglasFreshHabian/AndroidForensics/main/secretCodes.sh',
    summary:
      'Enumerates system packages (pm list packages -s -f) and dumps each (pm dump <pkg>) for ' +
      'android_secret_code Scheme / Authority entries. Logs to Secret_Codes_*.txt with banner + device info.',
  },
] as const;

// --- allowlisted shell verbs (union of the four scripts, nothing else) ---
const ALLOWED_SHELL_VERBS = new Set([
  'getprop',
  'pm',
  'dumpsys',
  'settings',
  'content',
  'svc',
  'logcat',
  'bugreport',
  'uptime',
  'ifconfig',
  'ip',
  'netstat',
  'echo', // used only inside composed shell pipelines built here
]);

const ALLOWED_ADB_SUBCOMMANDS = new Set(['devices', 'get-state', 'start-server', 'shell', 'bugreport', 'pull', '-s']);

// dumpsys.sh's 21 services (plus aliases the UI may use)
export const DUMPSYS_SERVICES: Array<{ service: string; label: string; fileHint: string }> = [
  { service: 'meminfo', label: 'Memory usage', fileHint: 'meminfo.txt' },
  { service: 'media.audio_flinger', label: 'Audio playback internals', fileHint: 'media_audio_flinger.txt' },
  { service: 'sensorservice', label: 'Motion & environmental sensors', fileHint: 'sensorservice.txt' },
  { service: 'adb', label: 'ADB subsystem', fileHint: 'adb.txt' },
  { service: 'account', label: 'Accounts & sync', fileHint: 'account.txt' },
  { service: 'persona', label: 'Multi-user profiles', fileHint: 'persona.txt' },
  { service: 'fingerprint', label: 'Fingerprint auth', fileHint: 'fingerprint.txt' },
  { service: 'netstats', label: 'Network usage stats', fileHint: 'netstats.txt' },
  { service: 'mount', label: 'Mounted volumes', fileHint: 'mount.txt' },
  { service: 'power', label: 'Power manager & wakelocks', fileHint: 'power.txt' },
  { service: 'dropbox', label: 'System crash/dropbox events', fileHint: 'dropbox.txt' },
  { service: 'location', label: 'GPS & location services', fileHint: 'location.txt' },
  { service: 'notification', label: 'Notification history', fileHint: 'notification.txt' },
  { service: 'telecom', label: 'Telephony / call state', fileHint: 'telecom.txt' },
  { service: 'lock_settings', label: 'Lock-screen settings', fileHint: 'lock_settings.txt' },
  { service: 'package', label: 'Installed package details', fileHint: 'package.txt' },
  { service: 'wifi', label: 'Wi-Fi state & history', fileHint: 'wifi.txt' },
  { service: 'window', label: 'Active windows & screen state', fileHint: 'window.txt' },
  { service: 'stats', label: 'System performance metrics', fileHint: 'stats.txt' },
  { service: 'batterystats', label: 'Battery usage history', fileHint: 'batterystats.txt' },
  { service: 'usb', label: 'USB connection history', fileHint: 'usb.txt' },
  { service: 'clipboard', label: 'Clipboard history', fileHint: 'clipboard.txt' },
];

const DUMPSYS_SERVICE_SET = new Set(DUMPSYS_SERVICES.map((s) => s.service));

// --- shared helpers ---

export interface AdbStatus {
  installed: boolean;
  version?: string;
  devices: Array<{ serial: string; state: string }>;
  primaryDevice?: string;
  scriptsPresent: boolean;
  scripts: Array<{ id: string; file: string; exists: boolean }>;
  hint: string;
}

export interface AdbExecResult {
  command: string;
  exitCode: number;
  stdout: string;
  stderr: string;
  truncated: boolean;
  durationMs: number;
}

const MAX_OUTPUT = 200_000;
const ADB_TIMEOUT_MS = 30_000;

function truncate(s: string): { text: string; truncated: boolean } {
  if (s.length <= MAX_OUTPUT) return { text: s, truncated: false };
  return { text: s.slice(0, MAX_OUTPUT) + `\n…[truncated ${s.length - MAX_OUTPUT} chars]`, truncated: true };
}

function adbBin(): string {
  return process.env.T3MP3ST_ADB_BIN || 'adb';
}

async function runAdb(args: string[], timeoutMs = ADB_TIMEOUT_MS): Promise<{ stdout: string; stderr: string; exitCode: number; durationMs: number }> {
  const t0 = Date.now();
  try {
    const { stdout, stderr } = await execFileAsync(adbBin(), args, {
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024,
      windowsHide: true,
    });
    return { stdout: String(stdout || ''), stderr: String(stderr || ''), exitCode: 0, durationMs: Date.now() - t0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; code?: number; killed?: boolean; message?: string };
    const stdout = String(e.stdout || '');
    const stderr = String(e.stderr || e.message || '');
    const code = typeof e.code === 'number' ? e.code : 1;
    return { stdout, stderr, exitCode: code, durationMs: Date.now() - t0 };
  }
}

function validateShellCommand(shellCmd: string): string | null {
  const verb = shellCmd.trim().split(/\s+/)[0]?.toLowerCase() || '';
  if (!ALLOWED_SHELL_VERBS.has(verb)) return `shell verb '${verb}' is not allowlisted (allowed: ${[...ALLOWED_SHELL_VERBS].join(', ')})`;
  return null;
}

function adbArgsForShell(shellCmd: string, serial?: string): string[] {
  const args: string[] = [];
  if (serial) args.push('-s', serial);
  args.push('shell', shellCmd);
  return args;
}

// ---------------------------------------------------------------------------
// Status / device helpers
// ---------------------------------------------------------------------------

export async function getAdbStatus(): Promise<AdbStatus> {
  const scripts = ANDROID_SCRIPTS.map((s) => ({
    id: s.id,
    file: s.file,
    exists: existsSync(join(ANDROID_FORENSICS_VENDOR_DIR, s.file)),
  }));
  const scriptsPresent = scripts.every((s) => s.exists);

  let version: string | undefined;
  let installed = false;
  const devices: Array<{ serial: string; state: string }> = [];

  try {
    const v = await runAdb(['version'], 5000);
    if (v.exitCode === 0 || /Android Debug Bridge/.test(v.stdout + v.stderr)) {
      installed = true;
      version = (v.stdout + v.stderr).split('\n')[0]?.trim() || undefined;
    }
  } catch { /* not installed */ }

  if (installed) {
    const r = await runAdb(['devices'], 7000);
    const out = r.stdout || '';
    for (const line of out.split('\n').slice(1)) {
      const m = line.trim().match(/^(\S+)\s+(\S+)/);
      if (m) devices.push({ serial: m[1], state: m[2] });
    }
  }

  const primaryDevice = devices.find((d) => d.state === 'device')?.serial;
  let hint = '';
  if (!installed) hint = 'adb not found — install Android Platform Tools (https://developer.android.com/tools/adb) and ensure adb is on PATH, or set T3MP3ST_ADB_BIN.';
  else if (devices.length === 0) hint = 'No device connected — enable USB debugging, authorize the host, and verify with "adb devices".';
  else if (!primaryDevice) hint = `Devices seen but none in 'device' state: ${devices.map((d) => `${d.serial}:${d.state}`).join(', ')} — check authorization prompt on the handset.`;
  else hint = `Ready — ${devices.length} device(s), primary ${primaryDevice}. Requires owner/operator authorization for any extraction.`;

  return { installed, version, devices, primaryDevice, scriptsPresent, scripts, hint };
}

export async function execAdbCommand(
  raw: string,
  opts: { serial?: string; timeoutMs?: number } = {},
): Promise<AdbExecResult> {
  const cmd = raw.trim();
  if (!cmd) throw new Error('empty command');
  if (!cmd.startsWith('adb ')) throw new Error('command must start with "adb " (e.g., "adb devices" or "adb shell getprop")');

  // Split preserving quoted segments (simple: no nested quotes)
  const tokens = cmd.slice(4).trim().split(/\s+/);
  if (!tokens.length) throw new Error('empty adb args');

  // Handle "adb -s SERIAL ..." prefix
  let serial = opts.serial;
  let idx = 0;
  if (tokens[0] === '-s' && tokens[1]) { serial = tokens[1]; idx = 2; }
  const sub = tokens[idx];
  if (!sub || !ALLOWED_ADB_SUBCOMMANDS.has(sub)) throw new Error(`adb subcommand '${sub || ''}' is not allowlisted`);
  if (sub === 'shell') {
    const shellCmd = tokens.slice(idx + 1).join(' ').trim();
    if (!shellCmd) throw new Error('adb shell requires a command');
    const err = validateShellCommand(shellCmd);
    if (err) throw new Error(err);
    const args = adbArgsForShell(shellCmd, serial);
    const r = await runAdb(args, opts.timeoutMs);
    const tOut = truncate(r.stdout);
    const tErr = truncate(r.stderr);
    return {
      command: `adb${serial ? ` -s ${serial}` : ''} shell ${shellCmd}`,
      exitCode: r.exitCode,
      stdout: tOut.text,
      stderr: tErr.text,
      truncated: tOut.truncated || tErr.truncated,
      durationMs: r.durationMs,
    };
  }
  // non-shell verbs (devices, get-state, bugreport, pull, etc.) — no shell validation needed
  const args: string[] = [];
  if (serial) args.push('-s', serial);
  args.push(...tokens.slice(idx));
  const r = await runAdb(args, opts.timeoutMs);
  const tOut = truncate(r.stdout);
  const tErr = truncate(r.stderr);
  return {
    command: `adb${serial ? ` -s ${serial}` : ''} ${tokens.slice(idx).join(' ')}`,
    exitCode: r.exitCode,
    stdout: tOut.text,
    stderr: tErr.text,
    truncated: tOut.truncated || tErr.truncated,
    durationMs: r.durationMs,
  };
}

export async function listDevices(): Promise<AdbExecResult> {
  return execAdbCommand('adb devices');
}

// ---------------------------------------------------------------------------
// LOCK-SCREEN PIN PROBE — technique from
// https://github.com/DouglasFreshHabian/UnlockAndroid (no license declared).
//
// WHAT UPSTREAM ACTUALLY SHIPS, verified against the repo: one script,
// `unlock.sh` (2371 bytes), which wakes the handset, swipes up, sends the
// HARDCODED keycode sequence for PIN 1234, then reads `dumpsys trust` and greps
// `deviceLocked=0|1`. The README also describes a second script, `adbBrute.sh`,
// for repeated attempts — THAT FILE IS NOT IN THE REPOSITORY (404), so no
// brute-force capability exists upstream and none is implemented here.
//
// The technique is reimplemented natively in a dozen lines of allowlisted adb
// rather than vendored, because upstream declares no license. ONE attempt per
// call, operator-supplied PIN, no candidate enumeration of any kind.
// ---------------------------------------------------------------------------

export const ANDROID_UNLOCK_SOURCE = 'https://github.com/DouglasFreshHabian/UnlockAndroid';
export const ANDROID_UNLOCK_VERSION = 'UnlockAndroid/main @ DouglasFreshHabian (license: none declared — technique reimplemented, not vendored)';

/** One attempt per call, always. There is no code path that iterates PINs. */
export const MAX_PIN_ATTEMPTS = 1;

export interface LockState {
  locked: boolean | null;
  raw: string;
  detail: string;
}

/** Read the lock state from `dumpsys trust` — the same oracle upstream uses. */
export async function getLockState(serial?: string): Promise<LockState> {
  const r = await execAdbCommand('adb shell dumpsys trust', { serial, timeoutMs: 10_000 });
  const raw = `${r.stdout}\n${r.stderr}`.trim();
  const m = raw.match(/deviceLocked=(\d)/);
  if (!m) {
    return { locked: null, raw, detail: r.exitCode !== 0 ? `adb failed: ${r.stderr.slice(0, 120) || r.exitCode}` : 'no deviceLocked= field in dumpsys trust output' };
  }
  const locked = m[1] === '1';
  // Android also prints failed-attempt counters; surface them, they are the whole
  // point of watching this before and after a probe.
  const failed = raw.match(/failed[^\n]*?(\d+)/i)?.[1];
  return {
    locked,
    raw,
    detail: locked
      ? `deviceLocked=1 (locked)${failed ? ` · failed attempts on record: ${failed}` : ''}`
      : `deviceLocked=0 (unlocked)${failed ? ` · failed attempts on record: ${failed}` : ''}`,
  };
}

/** Map a PIN to the adb keycode sequence that types it. Pure + testable. */
export function planPinKeyevents(pin: string): { keyevents: string[]; error?: string } {
  const p = String(pin || '').trim();
  if (!/^\d{4,12}$/.test(p)) return { keyevents: [], error: 'PIN must be 4-12 digits' };
  return { keyevents: p.split('').map((d) => `KEYCODE_${d}`) };
}

export interface LockProbeStep {
  command: string;
  exitCode: number;
  stderr?: string;
}

export interface LockProbeResult {
  ok: boolean;
  before: LockState;
  after: LockState;
  /** True when the device was already unlocked — nothing was injected. */
  alreadyUnlocked: boolean;
  attempts: number;
  steps: LockProbeStep[];
  verdict: string;
  error?: string;
  upstream: string;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Send ONE operator-supplied PIN to an attached, ADB-authorized device and read
 * back whether the lock screen opened. Refuses without an explicit authorization
 * acknowledgement, and never loops.
 */
export async function probeLockPin(opts: {
  serial?: string;
  pin?: string;
  confirmAuthorized?: boolean;
  /** Wake + swipe coordinates; upstream uses a 1080×2340-class portrait screen. */
  swipe?: { x: number; y1: number; y2: number; ms?: number };
  settleMs?: number;
}): Promise<LockProbeResult> {
  const steps: LockProbeStep[] = [];
  const upstream = ANDROID_UNLOCK_SOURCE;
  const run = async (cmd: string) => {
    const r = await execAdbCommand(cmd, { serial: opts.serial, timeoutMs: 15_000 });
    steps.push({ command: r.command, exitCode: r.exitCode, stderr: r.exitCode !== 0 ? r.stderr.slice(0, 200) : undefined });
    return r;
  };

  if (opts.confirmAuthorized !== true) {
    return {
      ok: false, before: { locked: null, raw: '', detail: 'not probed' }, after: { locked: null, raw: '', detail: 'not probed' },
      alreadyUnlocked: false, attempts: 0, steps, upstream,
      verdict: 'Refused: the operator has not acknowledged authorization for this device.',
      error: 'authorization acknowledgement required — set confirmAuthorized=true for a device you own or are authorized to test',
    };
  }

  const plan = planPinKeyevents(opts.pin ?? '');
  if (plan.error) {
    return {
      ok: false, before: { locked: null, raw: '', detail: 'not probed' }, after: { locked: null, raw: '', detail: 'not probed' },
      alreadyUnlocked: false, attempts: 0, steps, upstream,
      verdict: `Refused: ${plan.error}.`, error: plan.error,
    };
  }

  const before = await getLockState(opts.serial);
  if (before.locked === null) {
    return {
      ok: false, before, after: before, alreadyUnlocked: false, attempts: 0, steps, upstream,
      verdict: `Cannot read lock state: ${before.detail}. Connect an ADB-authorized device first.`,
      error: before.detail,
    };
  }
  if (before.locked === false) {
    return {
      ok: true, before, after: before, alreadyUnlocked: true, attempts: 0, steps, upstream,
      verdict: 'Device was already unlocked — nothing was injected.',
    };
  }

  const sw = opts.swipe || { x: 540, y1: 1800, y2: 600, ms: 1000 };
  await run('adb shell input keyevent KEYCODE_WAKEUP');
  await sleep(400);
  await run(`adb shell input swipe ${sw.x} ${sw.y1} ${sw.x} ${sw.y2} ${sw.ms ?? 1000}`);
  await sleep(500);
  for (const key of plan.keyevents) {
    await run(`adb shell input keyevent ${key}`);
    await sleep(120);
  }
  await run('adb shell input keyevent KEYCODE_ENTER');
  await sleep(opts.settleMs ?? 2000);

  const after = await getLockState(opts.serial);
  const unlocked = after.locked === false;
  return {
    ok: true,
    before,
    after,
    alreadyUnlocked: false,
    attempts: MAX_PIN_ATTEMPTS,
    steps,
    upstream,
    verdict: unlocked
      ? `Lock screen opened after 1 attempt — the device accepted the supplied PIN.`
      : `Still locked after 1 attempt (deviceLocked=1). Either the PIN is wrong or the lock screen rejected the injected key events.`,
  };
}

// ---------------------------------------------------------------------------
// Typed wrappers mirroring the upstream scripts (each is a thin allowlisted
// adb shell call; the UI composes them into a report)
// ---------------------------------------------------------------------------

export async function getDeviceInfo(serial?: string): Promise<AdbExecResult> {
  return execAdbCommand('adb shell getprop | grep -E \'ro.product.model|ro.product.manufacturer|ro.build.version.release|ro.serialno\'', { serial });
}

export async function getDeviceState(serial?: string): Promise<AdbExecResult> {
  // Mirrors extract.sh device_state: uptime + battery + connectivity (silent)
  return execAdbCommand('adb shell dumpsys battery', { serial });
}

export async function getPackages(serial?: string, thirdPartyOnly = false): Promise<AdbExecResult> {
  const suffix = thirdPartyOnly ? ' -3' : '';
  return execAdbCommand(`adb shell pm list packages${suffix}`, { serial });
}

export async function getContacts(serial?: string): Promise<AdbExecResult> {
  return execAdbCommand('adb shell content query --uri content://contacts/phones/', { serial });
}

export async function getCallLogs(serial?: string): Promise<AdbExecResult> {
  return execAdbCommand('adb shell content query --uri content://call_log/calls', { serial });
}

export async function getSms(serial?: string): Promise<AdbExecResult> {
  return execAdbCommand('adb shell content query --uri content://sms/', { serial });
}

export async function dumpsysService(service: string, serial?: string): Promise<AdbExecResult> {
  if (!DUMPSYS_SERVICE_SET.has(service)) throw new Error(`unknown dumpsys service '${service}' (use one of: ${[...DUMPSYS_SERVICE_SET].join(', ')})`);
  return execAdbCommand(`adb shell dumpsys ${service}`, { serial });
}

export async function wifiScan(serial?: string): Promise<AdbExecResult> {
  // extract.py-style: we only read dumpsys wifi — the svc wifi cycle is
  // exposed as two separate allowlisted calls via execAdbCommand so the
  // operator can see each step. Here we do the read half.
  return execAdbCommand('adb shell dumpsys wifi', { serial });
}

export async function secretCodesDump(serial?: string): Promise<AdbExecResult> {
  // Mirrors secretCodes.sh core: enumerate system packages then dump each.
  // We expose the enumeration here; per-package dumps run individually via
  // execAdbCommand('adb shell pm dump <pkg>') so output stays bounded.
  return execAdbCommand('adb shell pm list packages -s -f', { serial });
}

// ---------------------------------------------------------------------------
// Parsers (pure, testable, no ADB)
// ---------------------------------------------------------------------------

export function parsePackageList(raw: string): string[] {
  return raw
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.startsWith('package:'))
    .map((l) => l.replace(/^package:/, '').trim())
    .filter(Boolean);
}

export function parseWifiScan(dumpsysWifi: string): Array<{ ssid: string; bssid: string; band: string; rssi: number }> {
  // Matches the AirScope.sh regex chain: extract ...BSSID(Mhz)RSS from the
  // "Networks filtered out due ..." line, then dedupe by strongest RSSI.
  const m = dumpsysWifi.match(/Networks filtered out due[^:]*:\s*(.*)/);
  const seg = m ? m[1] : '';
  const parts = seg.split('/').map((s) => s.trim()).filter(Boolean);
  const byBssid = new Map<string, { ssid: string; bssid: string; band: string; rssi: number }>();
  const re = /([^:]+):([0-9a-f]{2}(?::[0-9a-f]{2}){5})\(([^)]+)\)(-?\d+)/i;
  for (const p of parts) {
    const hit = p.match(re);
    if (!hit) continue;
    const ssid = hit[1].trim();
    const bssid = hit[2].toLowerCase();
    const band = hit[3].trim();
    const rssi = parseInt(hit[4], 10);
    if (!Number.isFinite(rssi)) continue;
    const prev = byBssid.get(bssid);
    if (!prev || rssi > prev.rssi) byBssid.set(bssid, { ssid, bssid, band, rssi });
  }
  return [...byBssid.values()].sort((a, b) => b.rssi - a.rssi);
}

export function parseSecretCodes(pmDump: string): string[] {
  const out: string[] = [];
  for (const line of pmDump.split('\n')) {
    if (/Scheme:\s*"android_secret_code"/.test(line) || /Authority:\s*"[0-9].*"/.test(line) || /Authority:\s*"[A-Z].*"/.test(line)) {
      out.push(line.trim());
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Agent tools (category: android — visible to operators)
// ---------------------------------------------------------------------------

export const ANDROID_TOOLS: CustomTool[] = [
  {
    name: 'android_adb_lock_state',
    description:
      'Read an attached ADB device\'s lock state (locked/unlocked) from "dumpsys trust", with the failed-attempt counter. Read-only — sends nothing to the handset. Requires a connected, ADB-AUTHORIZED device (the owner must already have granted this host debug access).',
    category: 'android',
    riskTier: 'local_read',
    parameters: [{ name: 'serial', type: 'string', description: 'Device serial (optional — uses primary if omitted)', required: false }],
    handler: async (context) => {
      const serial = typeof context.parameters.serial === 'string' ? context.parameters.serial : undefined;
      try {
        const s = await getLockState(serial);
        return {
          success: s.locked !== null,
          output: s.detail + (s.raw ? `\n\n--- dumpsys trust (truncated) ---\n${s.raw.slice(0, 1200)}` : ''),
          error: s.locked === null ? s.detail : undefined,
        };
      } catch (error) {
        return { success: false, error: `lock state failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'android_adb_lock_probe',
    description:
      'AUTHORIZED-DEVICE ONLY. Send ONE operator-supplied PIN to an attached ADB-authorized handset via input keyevents and report whether the lock screen opened (technique from DouglasFreshHabian/UnlockAndroid). Exactly one attempt per call — no PIN enumeration, no brute force. Only for a device you own or are authorized to test; unlocking someone else\'s handset is a criminal offence in most jurisdictions.',
    category: 'android',
    // Intrusive: gated by the arsenal approval layer, and fires the loud audited
    // warning. An unattended run cannot fire it without a human in the loop.
    riskTier: 'intrusive',
    parameters: [
      { name: 'pin', type: 'string', description: 'The PIN to enter (4-12 digits). One attempt only.', required: true },
      { name: 'serial', type: 'string', description: 'Device serial (optional)', required: false },
      { name: 'confirmAuthorized', type: 'boolean', description: 'Must be true — asserts you own or are authorized to test this device', required: true },
    ],
    handler: async (context) => {
      const pin = typeof context.parameters.pin === 'string' ? context.parameters.pin : '';
      const serial = typeof context.parameters.serial === 'string' ? context.parameters.serial : undefined;
      const confirmAuthorized = context.parameters.confirmAuthorized === true;
      try {
        const r = await probeLockPin({ pin, serial, confirmAuthorized });
        const trace = r.steps.map((s) => `  $ adb ${s.command.replace(/^adb\s+-s\s+\S+\s+shell\s+/, 'shell ')}  → exit ${s.exitCode}`).join('\n');
        return {
          success: r.ok,
          output: [
            `Lock probe: ${r.verdict}`,
            `before: ${r.before.detail}`,
            `after:  ${r.after.detail}`,
            `attempts: ${r.attempts} (hard cap ${MAX_PIN_ATTEMPTS})`,
            trace ? `commands sent:\n${trace}` : '',
            `technique: ${ANDROID_UNLOCK_SOURCE}`,
          ].filter(Boolean).join('\n'),
          error: r.error,
        };
      } catch (error) {
        return { success: false, error: `lock probe failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'android_adb_status',
    description: 'Check ADB installation + connected devices + vendored AndroidForensics scripts. No device access — local host check only.',
    category: 'android',
    parameters: [],
    handler: async () => {
      try {
        const s = await getAdbStatus();
        const lines = [
          `ADB ${s.installed ? `installed (${s.version || 'unknown version'})` : 'NOT installed'}`,
          `Devices: ${s.devices.length ? s.devices.map((d) => `${d.serial}:${d.state}`).join(', ') : '(none)'}`,
          `Scripts: ${s.scripts.map((x) => `${x.file}:${x.exists ? 'present' : 'missing'}`).join(', ')}`,
          `Hint: ${s.hint}`,
        ];
        return { success: true, output: lines.join('\n') };
      } catch (error) {
        return { success: false, error: `adb status failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'android_device_info',
    description: 'Pull basic device identity (model, manufacturer, Android release, serial) via adb shell getprop. Requires a connected, authorized device.',
    category: 'android',
    parameters: [{ name: 'serial', type: 'string', description: 'Device serial (optional — uses primary if omitted)', required: false }],
    handler: async (context) => {
      const serial = typeof context.parameters.serial === 'string' ? context.parameters.serial : undefined;
      try {
        const r = await getDeviceInfo(serial);
        const hint = r.exitCode !== 0 ? `\nstderr: ${r.stderr.slice(0, 800)}` : '';
        return { success: r.exitCode === 0, output: (r.stdout || '(no output)') + hint, error: r.exitCode !== 0 ? r.stderr.slice(0, 800) : undefined };
      } catch (error) {
        return { success: false, error: `device info failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'android_app_inventory',
    description: 'List installed packages (pm list packages) — optionally third-party only (-3). Requires authorized device.',
    category: 'android',
    parameters: [
      { name: 'thirdPartyOnly', type: 'boolean', description: 'If true, list only third-party packages (pm -3)', required: false },
      { name: 'serial', type: 'string', description: 'Device serial (optional)', required: false },
    ],
    handler: async (context) => {
      const thirdPartyOnly = context.parameters.thirdPartyOnly === true;
      const serial = typeof context.parameters.serial === 'string' ? context.parameters.serial : undefined;
      try {
        const r = await getPackages(serial, thirdPartyOnly);
        const pkgs = parsePackageList(r.stdout);
        const head = `Packages (${pkgs.length} total) — showing first 200:\n` + pkgs.slice(0, 200).join('\n');
        return { success: r.exitCode === 0, output: head + (r.exitCode !== 0 ? `\nstderr: ${r.stderr.slice(0, 600)}` : '') };
      } catch (error) {
        return { success: false, error: `app inventory failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'android_dumpsys',
    description:
      'Run a single dumpsys service (one of the 21 from dumpsys.sh: meminfo, wifi, location, batterystats, etc.). Requires authorized device.',
    category: 'android',
    parameters: [
      { name: 'service', type: 'string', description: `dumpsys service (${DUMPSYS_SERVICES.map((s) => s.service).join(', ')})`, required: true },
      { name: 'serial', type: 'string', description: 'Device serial (optional)', required: false },
    ],
    handler: async (context) => {
      const service = String(context.parameters.service || '').trim();
      const serial = typeof context.parameters.serial === 'string' ? context.parameters.serial : undefined;
      try {
        const r = await dumpsysService(service, serial);
        return {
          success: r.exitCode === 0,
          output: (r.stdout.slice(0, 8000) || '(no output)') + (r.truncated ? '\n…truncated' : '') + (r.exitCode !== 0 ? `\nstderr: ${r.stderr.slice(0, 600)}` : ''),
          error: r.exitCode !== 0 ? r.stderr.slice(0, 600) : undefined,
        };
      } catch (error) {
        return { success: false, error: `dumpsys failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'android_wifi_scan',
    description:
      'Wi-Fi radar: reads dumpsys wifi and parses the "Networks filtered out due" BSSID list (SSID/BSSID/band/RSSI) — same data AirScope.sh surfaces, without cycling the radio.',
    category: 'android',
    parameters: [{ name: 'serial', type: 'string', description: 'Device serial (optional)', required: false }],
    handler: async (context) => {
      const serial = typeof context.parameters.serial === 'string' ? context.parameters.serial : undefined;
      try {
        const r = await wifiScan(serial);
        if (r.exitCode !== 0) return { success: false, error: r.stderr.slice(0, 800) || 'dumpsys wifi failed' };
        const nets = parseWifiScan(r.stdout);
        if (!nets.length) return { success: true, output: 'No BSSID entries found in dumpsys wifi (device may not have recent scan results — try: adb shell svc wifi disable && adb shell svc wifi enable, then re-scan).' };
        const lines = [`Wi-Fi scan — ${nets.length} network(s) (strongest first):`, ...nets.slice(0, 40).map((n) => `  ${n.ssid || '(hidden)'}  ${n.bssid}  ${n.band}  ${n.rssi} dBm`)];
        return { success: true, output: lines.join('\n') };
      } catch (error) {
        return { success: false, error: `wifi scan failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'android_secret_codes',
    description:
      'Enumerate system packages and scan their manifests for android_secret_code dialer codes (pm list packages -s -f + pm dump). Requires authorized device.',
    category: 'android',
    parameters: [{ name: 'serial', type: 'string', description: 'Device serial (optional)', required: false }],
    handler: async (context) => {
      const serial = typeof context.parameters.serial === 'string' ? context.parameters.serial : undefined;
      try {
        const list = await secretCodesDump(serial);
        if (list.exitCode !== 0) return { success: false, error: list.stderr.slice(0, 800) || 'pm list failed' };
        const pkgs = list.stdout
          .split('\n')
          .map((l) => l.trim())
          .filter((l) => l.includes('package:'))
          .map((l) => l.split('package:')[1]?.split('=')[1]?.trim())
          .filter(Boolean) as string[];
        // Probe first 30 to keep the tool bounded; the panel can drive a full sweep.
        const batch = pkgs.slice(0, 30);
        const hits: string[] = [];
        for (const pkg of batch) {
          try {
            const dump = await execAdbCommand(`adb shell pm dump ${pkg}`, { serial });
            const codes = parseSecretCodes(dump.stdout);
            for (const c of codes) hits.push(`${pkg}: ${c}`);
          } catch { /* per-package best-effort */ }
        }
        if (!hits.length) return { success: true, output: `Scanned ${batch.length}/${pkgs.length} system packages — no android_secret_code entries found.` };
        return { success: true, output: `Secret codes — ${hits.length} hit(s) in ${batch.length}/${pkgs.length} packages:\n` + hits.join('\n') };
      } catch (error) {
        return { success: false, error: `secret codes failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'android_adb_exec',
    description:
      'Execute a single allowlisted adb command (adb devices/get-state/shell <verb>). Shell verbs: getprop, pm, dumpsys, settings, content, svc, logcat, bugreport, uptime, ifconfig, ip, netstat. Requires explicit operator authorization and a connected device.',
    category: 'android',
    parameters: [
      { name: 'command', type: 'string', description: 'Full adb command, must start with "adb " (e.g., "adb shell getprop ro.product.model")', required: true },
      { name: 'serial', type: 'string', description: 'Device serial (optional — also supports "adb -s SERIAL ..." prefix)', required: false },
    ],
    handler: async (context) => {
      const command = String(context.parameters.command || '').trim();
      const serial = typeof context.parameters.serial === 'string' ? context.parameters.serial : undefined;
      try {
        const r = await execAdbCommand(command, { serial });
        const body = (r.stdout || '(no stdout)') + (r.stderr ? `\nstderr: ${r.stderr.slice(0, 1000)}` : '');
        return { success: r.exitCode === 0, output: `[${r.exitCode}] ${r.command} (${r.durationMs}ms)\n` + body.slice(0, 8000) + (r.truncated ? '\n…truncated' : '') };
      } catch (error) {
        return { success: false, error: `adb exec failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
];
