#!/usr/bin/env python3
"""
sandbox_unpack.py — Packer/crypter detector via runtime memory dump.

Monitors for new EXEC memory regions appearing at runtime (sign of a packer
decrypting its payload to memory). When detected, dumps the region for
follow-on static analysis via binary_investigate.

Usage: python3 sandbox_unpack.py --binary PATH [--timeout N] [--alias NAME]
"""

import argparse, subprocess, os, shutil, sys, json, re, random, signal, time, threading

ANTIDEBUG_SO = '/usr/local/lib/antidebug.so'
UPLOADS_DIR  = os.environ.get('UPLOADS_DIR', '/data/uploads')
ELF_ALIASES  = ['kworker', 'systemd-helper', 'dbus-daemon']


def get_exec_regions(pid: int) -> set:
    """Return set of (addr, size) for executable private mappings."""
    regions = set()
    try:
        with open(f'/proc/{pid}/maps') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and 'x' in parts[1] and parts[4] == '0':
                    addr_range = parts[0]
                    start, end = [int(x, 16) for x in addr_range.split('-')]
                    regions.add((start, end - start))
    except Exception:
        pass
    return regions


def dump_region(pid: int, addr: int, size: int, out_path: str) -> bool:
    """Use gdb to dump a memory region from a running process."""
    end = addr + size
    gdb_cmds = [
        f'attach {pid}',
        f'dump binary memory {out_path} 0x{addr:x} 0x{end:x}',
        'detach',
        'quit',
    ]
    gdb_input = '\n'.join(gdb_cmds)
    try:
        r = subprocess.run(
            ['gdb', '--batch', '--quiet'],
            input=gdb_input, capture_output=True, text=True, timeout=15
        )
        return os.path.exists(out_path) and os.path.getsize(out_path) > 0
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary',  required=True)
    parser.add_argument('--timeout', type=int, default=30)
    parser.add_argument('--alias',   default='')
    args = parser.parse_args()

    path = args.binary
    if path.startswith('local://'):
        path = os.path.join(UPLOADS_DIR, path[8:])
    if not os.path.isabs(path):
        path = os.path.join(UPLOADS_DIR, path)
    if not os.path.exists(path):
        print(json.dumps({'error': f'Binary not found: {path}'})); sys.exit(1)

    alias = args.alias or random.choice(ELF_ALIASES)
    staged = f'/tmp/{alias}'
    shutil.copy2(path, staged)
    os.chmod(staged, 0o755)

    print(f'[sandbox_unpack] alias={alias} timeout={args.timeout}s', flush=True)
    print('[sandbox_unpack] monitoring for new EXEC memory regions (packer detection)...', flush=True)

    env = {**os.environ, 'LD_PRELOAD': ANTIDEBUG_SO, 'DISPLAY': ':99'}
    import shutil as _sh
    qemu = _sh.which('qemu-x86_64-static')
    cmd = [qemu, staged] if qemu else [staged]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=env, start_new_session=True)

    # Watch /proc/<pid>/maps for new executable private regions
    initial_regions = get_exec_regions(proc.pid)
    dumps = []
    deadline = time.time() + args.timeout
    poll_interval = 0.2

    while time.time() < deadline and proc.poll() is None:
        time.sleep(poll_interval)
        current = get_exec_regions(proc.pid)
        new_regions = current - initial_regions
        for (addr, size) in new_regions:
            if size < 64:
                continue
            out = f'/tmp/unpacked_{addr:x}_{size}.bin'
            print(f'[sandbox_unpack] NEW EXEC REGION detected: 0x{addr:x} size={size} — dumping...', flush=True)
            if dump_region(proc.pid, addr, size, out):
                dumps.append({'address': hex(addr), 'size': size, 'dump_path': out})
                print(f'[sandbox_unpack] dumped to {out}', flush=True)
            initial_regions.add((addr, size))

    # Kill binary
    try:
        import os as _os
        _os.killpg(_os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        pass
    proc.wait()

    try: os.unlink(staged)
    except Exception: pass

    result = {
        'dumps_found': len(dumps),
        'regions': dumps,
        'note': ('Pass dump_path values to binary_investigate for static analysis of unpacked code.'
                 if dumps else 'No dynamic EXEC regions detected. Binary may not be packed, or '
                               'packer did not unpack during the observation window.'),
    }

    if dumps:
        print(f'\n[!] PACKER DETECTED — {len(dumps)} memory region(s) unpacked at runtime.')
        for d in dumps:
            print(f'    Address: {d["address"]}  Size: {d["size"]} bytes  Dump: {d["dump_path"]}')
        print('\nNext step: run binary_investigate on each dump_path to analyze the real payload.')
    else:
        print('\n[*] No runtime unpacking detected within observation window.')

    print('\n=== FULL JSON ===')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
