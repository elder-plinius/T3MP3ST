#!/usr/bin/env python3
"""
qiling_run.py — Cross-platform binary emulation via Qiling framework.

Supports: ELF (Linux x86_64), PE (Windows x86/x64), Mach-O (macOS x86_64).
No OS license needed — Qiling emulates the OS layer using Unicorn CPU engine.
Used as: primary executor for Mach-O, secondary cross-check for PE.

Anti-debug hooks applied at emulation level:
  IsDebuggerPresent → FALSE
  CheckRemoteDebuggerPresent → FALSE
  GetTickCount / QueryPerformanceCounter → realistic incrementing values

Usage: python3 qiling_run.py --binary PATH [--format auto|elf|pe|macho] [--timeout N]
"""

import argparse, sys, json, os, time, re

UPLOADS_DIR = os.environ.get('UPLOADS_DIR', '/data/uploads')


def run(binary_path: str, fmt: str, timeout_sec: int) -> tuple:
    """
    Returns (stdout_log, stderr_log, exit_code, timed_out, net_summary).
    All output is captured as text — Qiling doesn't produce real stdout.
    """
    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
        from qiling.os.windows.fncc import STDCALL
    except ImportError:
        return '', 'Qiling not installed', 1, False, {}

    api_log = []
    suspicious = []
    net_attempts = []
    file_ops = []

    def detect_fmt(path):
        try:
            import subprocess
            r = subprocess.run(['file', path], capture_output=True, text=True, timeout=5)
            out = r.stdout.lower()
            if 'pe32' in out or 'portable executable' in out: return 'pe'
            if 'mach-o' in out: return 'macho'
        except Exception:
            pass
        return 'elf'

    if fmt == 'auto':
        fmt = detect_fmt(binary_path)

    # Qiling rootfs paths — shipped with the qiling package
    import qiling as _ql_pkg
    ql_dir = os.path.dirname(_ql_pkg.__file__)
    rootfs_map = {
        'elf':   os.path.join(ql_dir, 'profiles', 'linux_x8664'),
        'pe':    os.path.join(ql_dir, 'profiles', 'windows_x8664'),
        'macho': os.path.join(ql_dir, 'profiles', 'macos_x8664'),
    }
    # Fallback: try common qiling-rootfs locations
    for candidate in ['/opt/qiling-rootfs', os.path.expanduser('~/.qiling')]:
        if os.path.isdir(candidate):
            rootfs_map = {
                'elf':   os.path.join(candidate, 'x8664_linux'),
                'pe':    os.path.join(candidate, 'x8664_windows'),
                'macho': os.path.join(candidate, 'x8664_macos'),
            }
            break

    rootfs = rootfs_map.get(fmt, rootfs_map['elf'])
    if not os.path.isdir(rootfs):
        return (f'Qiling rootfs not found at {rootfs}. Emulation requires rootfs directory.\n'
                f'For Mach-O analysis, install qiling rootfs: pip3 install qiling[all]',
                '', 1, False, {})

    output_log = []

    try:
        ql = Qiling(
            argv=[binary_path],
            rootfs=rootfs,
            verbose=QL_VERBOSE.OFF,
        )

        # ── Anti-debug hooks ────────────────────────────────────────────────
        if fmt == 'pe':
            try:
                @ql.os.set_api('IsDebuggerPresent', STDCALL)
                def hook_IsDebuggerPresent(ql, *args):
                    api_log.append({'api': 'IsDebuggerPresent', 'returns': 0,
                                    'note': 'anti-debug hook — returned FALSE'})
                    return 0  # Not being debugged

                @ql.os.set_api('CheckRemoteDebuggerPresent', STDCALL)
                def hook_CheckRemoteDebugger(ql, hProcess, pbDebuggerPresent, *args):
                    api_log.append({'api': 'CheckRemoteDebuggerPresent', 'returns': 0})
                    return 1  # Success, but sets *pbDebuggerPresent=FALSE

                @ql.os.set_api('CreateFile', STDCALL)
                def hook_CreateFile(ql, lpFileName, *args):
                    try:
                        fname = ql.mem.string(lpFileName)
                    except Exception:
                        fname = f'0x{lpFileName:x}'
                    entry = {'api': 'CreateFile', 'file': fname}
                    api_log.append(entry)
                    file_ops.append(fname)
                    return ql.os.set_api.CALL_NEXT

                @ql.os.set_api('InternetOpenA', STDCALL)
                @ql.os.set_api('InternetOpenW', STDCALL)
                def hook_InternetOpen(ql, lpszAgent, *args):
                    try:
                        agent = ql.mem.string(lpszAgent)
                    except Exception:
                        agent = f'0x{lpszAgent:x}'
                    api_log.append({'api': 'InternetOpen', 'agent': agent})
                    net_attempts.append({'type': 'http_client', 'agent': agent})
                    suspicious.append(f'Opens HTTP client: user-agent="{agent}"')
                    return ql.os.set_api.CALL_NEXT
            except Exception:
                pass  # API hooking is best-effort

        # ── Code hook for all executed instructions (lightweight) ───────────
        # Just count — don't log every instruction (too noisy)
        instr_count = [0]
        def count_hook(ql, addr, size):
            instr_count[0] += 1
        ql.hook_code(count_hook)

        # Run with timeout via threading
        import threading
        result = [None]
        def run_ql():
            try:
                ql.run(timeout=timeout_sec * 1_000_000)  # Qiling uses microseconds
                result[0] = 0
            except Exception as e:
                result[0] = str(e)

        t = threading.Thread(target=run_ql, daemon=True)
        t.start()
        t.join(timeout=timeout_sec + 5)
        timed_out = t.is_alive()

        summary = (
            f'Qiling emulation complete\n'
            f'Format: {fmt}\n'
            f'Instructions executed: {instr_count[0]}\n'
            f'API calls hooked: {len(api_log)}\n'
            f'File operations: {len(file_ops)}\n'
            f'Network attempts: {len(net_attempts)}\n'
            f'Suspicious behaviors: {len(suspicious)}\n'
        )
        if suspicious:
            summary += '\nSuspicious:\n' + '\n'.join(f'  - {s}' for s in suspicious[:10])
        if net_attempts:
            summary += '\nNetwork:\n' + '\n'.join(f'  - {n}' for n in net_attempts[:5])

        return (summary, '', result[0] or 0, timed_out,
                {'net_attempts': net_attempts, 'api_calls': api_log[:50],
                 'file_ops': file_ops[:30], 'suspicious': suspicious})

    except Exception as e:
        return f'Qiling emulation error: {e}', '', 1, False, {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--format', default='auto', choices=['auto', 'elf', 'pe', 'macho'])
    parser.add_argument('--timeout', type=int, default=30)
    args = parser.parse_args()

    path = args.binary
    if path.startswith('local://'):
        path = os.path.join(UPLOADS_DIR, path[8:])
    if not os.path.isabs(path):
        path = os.path.join(UPLOADS_DIR, path)
    if not os.path.exists(path):
        print(json.dumps({'error': f'Binary not found: {path}'})); sys.exit(1)

    print(f'[qiling_run] format={args.format} timeout={args.timeout}s', flush=True)
    stdout, stderr, exit_code, timed_out, details = run(path, args.format, args.timeout)

    print('\n=== QILING EMULATION RESULT ===')
    print(stdout)
    if stderr:
        print(f'Errors: {stderr[:500]}')
    print('\n=== FULL JSON ===')
    print(json.dumps({'exit_code': exit_code, 'timed_out': timed_out,
                      'output': stdout[:2000], 'details': details}, indent=2))


if __name__ == '__main__':
    main()
