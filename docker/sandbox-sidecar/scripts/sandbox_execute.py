#!/usr/bin/env python3
"""
sandbox_execute.py — T3MP3ST main dynamic execution orchestrator.

Usage: python3 sandbox_execute.py --binary PATH [--network none|monitored|open]
       [--timeout N] [--alias NAME] [-- binary_arg1 binary_arg2 ...]

Detects binary format (ELF/PE/Mach-O), renames to alias, executes under
appropriate isolation (QEMU user-mode for ELF, Wine for PE, Qiling for Mach-O),
captures behavior, and returns JSON result.
"""

import argparse, subprocess, os, shutil, sys, json, re, time, signal, random
import tempfile, threading

ANTIDEBUG_SO = '/usr/local/lib/antidebug.so'
UPLOADS_DIR  = os.environ.get('UPLOADS_DIR', '/data/uploads')
WINEPREFIX   = os.environ.get('WINEPREFIX', '/opt/wine-env')

ELF_ALIASES   = ['kworker', 'systemd-helper', 'dbus-daemon', 'nm-dispatcher', 'polkitd']
PE_ALIASES    = ['svchost.exe', 'SearchIndexer.exe', 'chrome_update.exe',
                 'MicrosoftEdgeUpdate.exe', 'RuntimeBroker.exe']
MACHO_ALIASES = ['loginwindow', 'mdworker', 'com.apple.ManagedClient', 'accountsd']


def detect_format(path: str) -> str:
    try:
        r = subprocess.run(['file', path], capture_output=True, text=True, timeout=10)
        out = r.stdout.lower()
        if 'pe32' in out or 'ms-dos' in out or 'portable executable' in out:
            return 'pe'
        if 'mach-o' in out:
            return 'macho'
        return 'elf'
    except Exception:
        return 'elf'


def random_alias(fmt: str) -> str:
    pools = {'pe': PE_ALIASES, 'macho': MACHO_ALIASES, 'elf': ELF_ALIASES}
    return random.choice(pools.get(fmt, ELF_ALIASES))


def stage_binary(src: str, alias: str) -> str:
    """Copy binary to /tmp/<alias> so process appears under that name."""
    dest = f'/tmp/{alias}'
    shutil.copy2(src, dest)
    os.chmod(dest, 0o755)
    return dest


def run_with_timeout(cmd, timeout_sec, extra_env=None):
    """Run a command, kill after timeout_sec, return (stdout, stderr, exit_code, timed_out)."""
    env = {**os.environ, **(extra_env or {})}
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=env, start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout_sec)
        return stdout.decode('utf-8', errors='replace'), \
               stderr.decode('utf-8', errors='replace'), \
               proc.returncode, False
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            time.sleep(1)
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
        proc.wait()
        stdout, stderr = b'', b''
        try:
            stdout = proc.stdout.read()
            stderr = proc.stderr.read()
        except Exception:
            pass
        return stdout.decode('utf-8', errors='replace'), \
               stderr.decode('utf-8', errors='replace'), \
               -1, True


# ── Network mode helpers ───────────────────────────────────────────────────────

def start_network_capture():
    """Start tcpdump + dnsmasq for monitored mode. Returns (tcpdump_proc, dns_proc)."""
    cap_file = '/tmp/sandbox_cap.pcap'
    dns_log  = '/tmp/sandbox_dns.log'
    # tcpdump on all interfaces
    tcpdump = subprocess.Popen(
        ['tcpdump', '-w', cap_file, '-U', '-n', 'not port 8080'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    # dnsmasq in no-daemon mode, log queries, return NXDOMAIN for everything
    dnsmasq = subprocess.Popen(
        ['dnsmasq', '--no-daemon', '--no-resolv', '--log-queries',
         f'--log-facility={dns_log}', '--address=/#/127.0.0.1'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(1)  # brief wait for both to start
    return tcpdump, dnsmasq, cap_file, dns_log


def stop_network_capture(tcpdump_proc, dnsmasq_proc):
    for p in (tcpdump_proc, dnsmasq_proc):
        try: p.terminate(); p.wait(timeout=3)
        except Exception: pass


def parse_network_summary(cap_file: str, dns_log: str) -> dict:
    summary = {'dns_queries': [], 'tcp_connections': [], 'http_hosts': [], 'tls_sni': []}
    # Parse dnsmasq log for DNS queries
    try:
        with open(dns_log) as f:
            for line in f:
                m = re.search(r'query\[.*?\]\s+(\S+)\s+from', line)
                if m and m.group(1) not in summary['dns_queries']:
                    summary['dns_queries'].append(m.group(1))
    except Exception:
        pass
    # Parse tcpdump PCAP using tcpdump -r (text output)
    try:
        r = subprocess.run(
            ['tcpdump', '-r', cap_file, '-nn', 'tcp'],
            capture_output=True, text=True, timeout=15
        )
        for line in r.stdout.splitlines():
            m = re.search(r'(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+)', line)
            if m:
                dst = f"{m.group(3)}:{m.group(4)}"
                if not dst.startswith('127.') and dst not in summary['tcp_connections']:
                    summary['tcp_connections'].append(dst)
    except Exception:
        pass
    return summary


# ── ELF execution ─────────────────────────────────────────────────────────────

def run_elf(staged_path: str, binary_args: list, timeout_sec: int,
            network: str) -> tuple:
    # ── Pass 1: strace (no LD_PRELOAD) ────────────────────────────────────────
    # Binary may detect strace and exit early, but strace still captures
    # anti-debug patterns, file accesses, and any syscalls before exit.
    strace_log = f'/tmp/strace_{os.getpid()}.log'
    strace_cmd = [
        'strace', '-e',
        'trace=execve,execveat,socket,connect,open,openat,read,write,ptrace,unlink,creat,chmod',
        '-e', 'inject=ptrace:retval=0',  # defeat ptrace(PTRACE_TRACEME)-based anti-debug
        '-f', '-o', strace_log, '--',
        staged_path,
    ] + binary_args
    run_with_timeout(strace_cmd, min(8, max(3, timeout_sec // 3)), {})
    strace_output = ''
    try:
        with open(strace_log) as f:
            strace_output = f.read(8000)
        os.unlink(strace_log)
    except Exception:
        pass

    # ── Pass 2: LD_PRELOAD (no strace) ────────────────────────────────────────
    # Defeats /proc/self/status TracerPid checks, ptrace self-checks, and
    # LD_PRELOAD getenv() checks. Actually runs the binary to its real logic.
    extra_env = {'LD_PRELOAD': ANTIDEBUG_SO, 'DISPLAY': ':99'}
    qemu = shutil.which('qemu-x86_64-static')
    if qemu:
        cmd = [qemu, staged_path] + binary_args
    else:
        cmd = [staged_path] + binary_args

    # network=none: Docker's own isolation prevents external connectivity.
    # network=monitored/open: start tcpdump for outbound capture.
    tcpdump_proc = dnsmasq_proc = cap_file = dns_log = None
    if network in ('monitored', 'open'):
        tcpdump_proc, dnsmasq_proc, cap_file, dns_log = start_network_capture()

    stdout, stderr, exit_code, timed_out = run_with_timeout(cmd, timeout_sec, extra_env)

    net_summary = {}
    if tcpdump_proc:
        stop_network_capture(tcpdump_proc, dnsmasq_proc)
        net_summary = parse_network_summary(cap_file, dns_log)

    # Extract C2 targets from strace connect() lines (captured before anti-debug exit)
    if 'tcp_connections' not in net_summary:
        net_summary['tcp_connections'] = []
    for m in re.finditer(
        r'connect\(\d+.*?inet_addr\("(\d+\.\d+\.\d+\.\d+)"\).*?htons\((\d+)\)',
        strace_output
    ):
        conn = f"{m.group(1)}:{m.group(2)}"
        if conn not in net_summary['tcp_connections'] and not m.group(1).startswith('127.'):
            net_summary['tcp_connections'].append(conn)

    # Append strace pass output to stderr so behavioral patterns can match syscall strings
    combined_stderr = stderr + '\n=== STRACE PASS ===\n' + strace_output
    return stdout, combined_stderr, exit_code, timed_out, net_summary


# ── PE execution via Wine ─────────────────────────────────────────────────────

def run_pe(binary_path: str, alias: str, binary_args: list, timeout_sec: int,
           network: str) -> tuple:
    import wine_execute
    return wine_execute.run(binary_path, alias, binary_args, timeout_sec, network)


# ── Mach-O execution via Qiling ───────────────────────────────────────────────

def run_macho(staged_path: str, timeout_sec: int) -> tuple:
    import qiling_run
    return qiling_run.run(staged_path, 'macho', timeout_sec)


# ── Behavioral highlights extractor ──────────────────────────────────────────

def extract_behavioral_highlights(stdout: str, stderr: str, fmt: str) -> list:
    highlights = []
    combined = stdout + stderr
    combined_lower = combined.lower()

    # Syscall-level patterns (matched against strace pass output in stderr)
    for pattern, desc in [
        (r'\bexecve\b', 'spawns new process (execve)'),
        (r'\bsocket\s*\(af_inet', 'creates network socket'),
        (r'\bconnect\s*\(', 'initiates TCP/UDP connection'),
        (r'\b/etc/shadow\b', 'reads /etc/shadow (credential access)'),
        (r'\b/etc/passwd\b', 'reads /etc/passwd'),
        (r'\bcrontab\b|/etc/cron', 'accesses cron (persistence)'),
        (r'\bptrace\b', 'calls ptrace (anti-debug or process injection)'),
        (r'proc.*self.*status|self.*status.*o_rdonly', 'reads /proc/self/status (TracerPid anti-debug check)'),
        (r'\bself-delet|unlink.*self\b', 'attempts self-deletion'),
        (r'\bchmod.*777\b|\bchmod.*0777\b', 'sets world-writable permissions'),
        (r'internetopen|winhttp|winhttpopen', 'opens HTTP/HTTPS connection (Windows)'),
        (r'regsetvalue|regcreatekey', 'writes registry key (persistence)'),
        (r'createremotethread|virtualalloc.*exec', 'process injection indicator'),
        (r'isdebuggerpresent|checkremotedebugger', 'anti-debug check detected'),
    ]:
        if re.search(pattern, combined_lower):
            highlights.append(desc)

    # Runtime output patterns — detect behavioral indicators in binary's own stdout/stderr
    # Routable IP addresses in output (potential C2 beaconing or exfil targets)
    ips_found = re.findall(
        r'\b((?!127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
        combined
    )
    if ips_found:
        highlights.append(f'routable IP addresses in output: {", ".join(set(ips_found[:3]))} (potential C2 or exfil target)')

    # URLs in output
    urls = re.findall(r'https?://[^\s\'"]{8,}', combined)
    if urls:
        highlights.append(f'URLs in output: {", ".join(urls[:3])}')

    # Credential-like output
    if re.search(r'(password|passwd|token|apikey|secret|credential)\s*[:=]\s*\S+', combined_lower):
        highlights.append('credential strings in output')

    # Anti-debug message
    if re.search(r'analysis.{0,20}(environment|detected|found)|debugger.{0,20}(detected|found)', combined_lower):
        highlights.append('anti-analysis detection triggered — binary may have exited early')

    return highlights


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary',  required=True)
    parser.add_argument('--network', default='none', choices=['none', 'monitored', 'open'])
    parser.add_argument('--timeout', type=int, default=30)
    parser.add_argument('--alias',   default='')
    parser.add_argument('binary_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    binary_args = [a for a in args.binary_args if a != '--']

    # Resolve path
    path = args.binary
    if path.startswith('local://'):
        path = os.path.join(UPLOADS_DIR, path[8:])
    if not os.path.isabs(path):
        path = os.path.join(UPLOADS_DIR, path)

    if not os.path.exists(path):
        print(json.dumps({'error': f'Binary not found: {path}'}))
        sys.exit(1)

    fmt = detect_format(path)
    alias = args.alias or random_alias(fmt)

    print(f'[sandbox] binary={os.path.basename(path)} format={fmt} alias={alias} '
          f'network={args.network} timeout={args.timeout}s', flush=True)

    # Stage binary under alias name
    staged = stage_binary(path, alias)

    try:
        if fmt == 'pe':
            stdout, stderr, exit_code, timed_out, net_summary = run_pe(
                path, alias, binary_args, args.timeout, args.network)
        elif fmt == 'macho':
            stdout, stderr, exit_code, timed_out, net_summary = run_macho(staged, args.timeout)
        else:
            stdout, stderr, exit_code, timed_out, net_summary = run_elf(
                staged, binary_args, args.timeout, args.network)
    finally:
        try: os.unlink(staged)
        except Exception: pass

    highlights = extract_behavioral_highlights(stdout, stderr, fmt)

    result = {
        'format': fmt,
        'alias': alias,
        'exit_code': exit_code,
        'timed_out': timed_out,
        'stdout': stdout[:4000],
        'stderr': stderr[:4000],
        'network_summary': net_summary,
        'behavioral_highlights': highlights,
    }
    print('\n=== SANDBOX EXECUTION RESULT ===')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
