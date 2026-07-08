#!/usr/bin/env python3
"""
sandbox_trace.py — strace/ltrace wrapper with categorized output.

Usage: python3 sandbox_trace.py --binary PATH [--tracer strace|ltrace]
       [--timeout N] [--alias NAME]
"""

import argparse, subprocess, os, shutil, sys, json, re, random, signal, time

ANTIDEBUG_SO = '/usr/local/lib/antidebug.so'
UPLOADS_DIR  = os.environ.get('UPLOADS_DIR', '/data/uploads')

ELF_ALIASES = ['kworker', 'systemd-helper', 'dbus-daemon', 'nm-dispatcher']


SUSPICIOUS_PATTERNS = {
    'execve':        r'\bexecve\s*\(',
    'ptrace':        r'\bptrace\s*\(',
    'socket_inet':   r'\bsocket\s*\(AF_INET',
    'connect':       r'\bconnect\s*\(',
    'shadow_read':   r'open.*"/etc/shadow"',
    'passwd_read':   r'open.*"/etc/passwd"',
    'cron_write':    r'open.*/etc/cron|crond',
    'mprotect_exec': r'mprotect\(0x[0-9a-f]+,\s*\d+,\s*PROT_\w*EXEC',
    'self_delete':   r'unlink.*self|unlinkat.*self',
    'fork_bomb':     r'\bfork\s*\(\)',
    'memfd_create':  r'\bmemfd_create\s*\(',
}

FILE_SYSCALLS   = {'open', 'openat', 'read', 'write', 'close', 'unlink', 'rename', 'stat', 'lstat', 'fstat'}
NET_SYSCALLS    = {'socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv', 'sendto', 'recvfrom'}
PROC_SYSCALLS   = {'fork', 'clone', 'execve', 'wait4', 'waitpid', 'kill', 'ptrace', 'exit', 'exit_group'}
CRYPTO_FUNCS    = {'EVP_EncryptInit', 'EVP_DecryptInit', 'AES_encrypt', 'AES_decrypt',
                   'RSA_private_encrypt', 'MD5_Init', 'SHA1_Init', 'SHA256_Init'}
MEM_SYSCALLS    = {'mmap', 'mprotect', 'munmap', 'madvise', 'brk', 'sbrk', 'mremap'}


def categorize_trace(lines: list[str]) -> dict:
    cats = {'file_ops': [], 'network_attempts': [], 'process_spawns': [],
            'crypto_ops': [], 'memory_ops': [], 'suspicious': []}

    for line in lines:
        line_l = line.lower()
        # Check suspicious patterns
        for key, pattern in SUSPICIOUS_PATTERNS.items():
            if re.search(pattern, line, re.I):
                entry = {'flag': key, 'line': line.strip()[:200]}
                if entry not in cats['suspicious']:
                    cats['suspicious'].append(entry)

        # Categorize by syscall name
        call_m = re.match(r'\w+\s+(\w+)\s*\(', line)
        if call_m:
            call = call_m.group(1)
            if call in FILE_SYSCALLS:
                cats['file_ops'].append(line.strip()[:150])
            elif call in NET_SYSCALLS:
                cats['network_attempts'].append(line.strip()[:150])
            elif call in PROC_SYSCALLS:
                cats['process_spawns'].append(line.strip()[:150])
            elif call in MEM_SYSCALLS:
                cats['memory_ops'].append(line.strip()[:150])

        # ltrace: look for crypto library calls
        for fn in CRYPTO_FUNCS:
            if fn in line:
                cats['crypto_ops'].append(line.strip()[:150])

    # Deduplicate and cap
    for k in cats:
        seen = set()
        deduped = []
        for item in cats[k]:
            key = str(item)[:80]
            if key not in seen:
                seen.add(key)
                deduped.append(item)
        cats[k] = deduped[:50]

    return cats


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary',  required=True)
    parser.add_argument('--tracer',  default='strace', choices=['strace', 'ltrace'])
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

    trace_file = '/tmp/sandbox_trace.log'
    extra_env = {**os.environ, 'LD_PRELOAD': ANTIDEBUG_SO}

    if args.tracer == 'strace':
        cmd = ['strace', '-e', 'trace=all', '-f', '-o', trace_file, staged]
    else:
        cmd = ['ltrace', '-f', '-o', trace_file, staged]

    print(f'[sandbox_trace] tracer={args.tracer} alias={alias} timeout={args.timeout}s', flush=True)

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=extra_env, start_new_session=True)
    timed_out = False
    try:
        proc.communicate(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            import os as _os
            _os.killpg(_os.getpgid(proc.pid), signal.SIGTERM)
            time.sleep(0.5)
            _os.killpg(_os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
        proc.wait()
    finally:
        try: os.unlink(staged)
        except Exception: pass

    # Read trace file
    raw_lines = []
    try:
        with open(trace_file) as f:
            raw_lines = f.readlines()
    except Exception:
        pass

    cats = categorize_trace(raw_lines)
    total = sum(len(v) for v in cats.values())

    result = {
        'tracer': args.tracer,
        'alias': alias,
        'timed_out': timed_out,
        'total_entries': len(raw_lines),
        'categories': cats,
        'raw_sample': [l.strip() for l in raw_lines[:30]],
    }

    print(f'\n=== TRACE SUMMARY ({args.tracer.upper()}) ===')
    print(f'Total syscalls captured: {len(raw_lines)}')
    if cats['suspicious']:
        print(f'\n[!] SUSPICIOUS BEHAVIORS ({len(cats["suspicious"])}):')
        for s in cats['suspicious'][:10]:
            print(f'    [{s["flag"]}] {s["line"]}')
    if cats['network_attempts']:
        print(f'\n[NET] Network activity ({len(cats["network_attempts"])}):')
        for n in cats['network_attempts'][:5]:
            print(f'    {n}')
    print('\n=== FULL JSON ===')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
