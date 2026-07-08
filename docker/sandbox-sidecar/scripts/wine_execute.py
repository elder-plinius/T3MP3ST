#!/usr/bin/env python3
"""
wine_execute.py — Windows PE execution via Wine64 with Win10 Pro disguise.

Configures Wine to look like a corporate Windows 10 machine, renames the
binary to alias, captures Win32 API relay log, and returns behavioral summary.
Can be called standalone or imported by sandbox_execute.py.

Usage: python3 wine_execute.py --binary PATH [--alias NAME]
       [--network none|monitored|open] [--timeout N]
"""

import argparse, subprocess, os, shutil, sys, json, re, random, signal, time

WINEPREFIX   = os.environ.get('WINEPREFIX', '/opt/wine-env')
UPLOADS_DIR  = os.environ.get('UPLOADS_DIR', '/data/uploads')

PE_ALIASES = ['svchost.exe', 'SearchIndexer.exe', 'chrome_update.exe',
              'MicrosoftEdgeUpdate.exe', 'RuntimeBroker.exe', 'dllhost.exe']

# Win32 relay calls we care about for behavioral analysis
INTERESTING_APIS = {
    'CreateFile':            'file_ops',
    'RegSetValue':           'registry',
    'RegCreateKey':          'registry',
    'RegOpenKey':            'registry',
    'InternetOpen':          'network',
    'InternetConnect':       'network',
    'HttpOpenRequest':       'network',
    'WinHttpOpen':           'network',
    'socket':                'network',
    'connect':               'network',
    'send':                  'network',
    'recv':                  'network',
    'WSAConnect':            'network',
    'CreateProcess':         'process',
    'ShellExecute':          'process',
    'CreateRemoteThread':    'injection',
    'VirtualAllocEx':        'injection',
    'WriteProcessMemory':    'injection',
    'IsDebuggerPresent':     'anti_debug',
    'CheckRemoteDebugger':   'anti_debug',
    'OutputDebugString':     'anti_debug',
    'CryptEncrypt':          'crypto',
    'CryptDecrypt':          'crypto',
    'CryptGenKey':           'crypto',
    'DeleteFile':            'file_ops',
    'MoveFile':              'file_ops',
    'SetFileAttributes':     'file_ops',
}


def parse_relay_log(relay_text: str) -> dict:
    """Parse WINEDEBUG=+relay output into categorized API calls."""
    cats = {v: [] for v in set(INTERESTING_APIS.values())}
    all_calls = []

    for line in relay_text.splitlines():
        for api, cat in INTERESTING_APIS.items():
            if api in line:
                # Extract argument values from relay format:
                # "Call KERNEL32.CreateFile(ptr 004a1234 "filename.txt" ...)"
                arg_m = re.search(rf'{re.escape(api)}\s*\(([^)]*)\)', line)
                args_str = arg_m.group(1) if arg_m else ''
                # Extract quoted strings (file paths, registry keys, URLs)
                strings = re.findall(r'"([^"]{1,200})"', line)
                entry = {'api': api, 'args': args_str[:200], 'strings': strings[:5]}
                cats[cat].append(entry)
                all_calls.append(entry)
                break

    # Deduplicate (same api + same first string)
    for k in cats:
        seen = set()
        deduped = []
        for e in cats[k]:
            key = e['api'] + str(e['strings'][:1])
            if key not in seen:
                seen.add(key)
                deduped.append(e)
        cats[k] = deduped[:20]

    return cats


def run(binary_path: str, alias: str, binary_args: list,
        timeout_sec: int, network: str) -> tuple:
    """Execute PE binary via Wine. Returns (stdout, stderr, exit_code, timed_out, net_summary)."""

    wine_pub = os.path.join(WINEPREFIX, 'drive_c', 'Users', 'Public')
    os.makedirs(wine_pub, exist_ok=True)

    alias_path = os.path.join(wine_pub, alias)
    shutil.copy2(binary_path, alias_path)
    os.chmod(alias_path, 0o755)

    # Wine path format
    win_path = f'C:\\Users\\Public\\{alias}'

    relay_file = '/tmp/wine_relay.log'
    env = {
        **os.environ,
        'WINEPREFIX':    WINEPREFIX,
        'WINEARCH':      'win64',
        'WINEDEBUG':     '+relay,+imports',
        'DISPLAY':       ':99',
        'COMPUTERNAME':  'DESKTOP-ABC123F',
        'USERNAME':      'john.smith',
        'USERDOMAIN':    'CORP',
        'LOGONSERVER':   '\\\\CORP-DC01',
        'SYSTEMROOT':    'C:\\Windows',
    }

    # Redirect relay log via stderr (WINEDEBUG output goes to stderr)
    relay_fh = open(relay_file, 'w')

    cmd = ['xvfb-run', '-a', 'wine64', win_path] + binary_args
    if not shutil.which('xvfb-run'):
        cmd = ['wine64', win_path] + binary_args

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=relay_fh,
                             env=env, start_new_session=True)

    timed_out = False
    try:
        stdout_data, _ = proc.communicate(timeout=timeout_sec)
        stdout = stdout_data.decode('utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            import os as _os
            _os.killpg(_os.getpgid(proc.pid), signal.SIGTERM)
            time.sleep(1)
            _os.killpg(_os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
        proc.wait()
        stdout = ''
    finally:
        relay_fh.close()
        try: os.unlink(alias_path)
        except Exception: pass

    relay_text = ''
    try:
        with open(relay_file) as f:
            relay_text = f.read()
    except Exception:
        pass

    api_calls = parse_relay_log(relay_text)
    return stdout, relay_text[:3000], proc.returncode or 0, timed_out, {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary',  required=True)
    parser.add_argument('--alias',   default='')
    parser.add_argument('--network', default='none')
    parser.add_argument('--timeout', type=int, default=30)
    args = parser.parse_args()

    path = args.binary
    if path.startswith('local://'):
        path = os.path.join(UPLOADS_DIR, path[8:])
    if not os.path.isabs(path):
        path = os.path.join(UPLOADS_DIR, path)
    if not os.path.exists(path):
        print(json.dumps({'error': f'Binary not found: {path}'})); sys.exit(1)

    alias = args.alias or random.choice(PE_ALIASES)
    print(f'[wine_execute] alias={alias} timeout={args.timeout}s network={args.network}', flush=True)

    stdout, relay_text, exit_code, timed_out, _ = run(path, alias, [], args.timeout, args.network)
    api_calls = parse_relay_log(relay_text)

    print('\n=== WINE EXECUTION RESULT ===')
    if stdout.strip():
        print(f'stdout: {stdout[:500]}')
    print(f'exit_code: {exit_code}  timed_out: {timed_out}')

    for cat, entries in api_calls.items():
        if entries:
            print(f'\n[{cat.upper()}] ({len(entries)} calls):')
            for e in entries[:5]:
                strs = ', '.join(f'"{s}"' for s in e['strings'])
                print(f'    {e["api"]}({strs or e["args"][:80]})')

    print('\n=== FULL JSON ===')
    print(json.dumps({'alias': alias, 'exit_code': exit_code, 'timed_out': timed_out,
                      'api_calls': api_calls, 'stdout': stdout[:1000]}, indent=2))


if __name__ == '__main__':
    main()
