#!/usr/bin/env python3
"""
sandbox_network.py — C2 network observation with monitored outbound.

Runs binary with full outbound network access for duration_sec, capturing
all DNS queries, TCP connections, HTTP requests, TLS SNI names.
Use for staged malware analysis to observe C2 beaconing and payload fetches.

Usage: python3 sandbox_network.py --binary PATH [--duration N] [--alias NAME]
"""

import argparse, subprocess, os, shutil, sys, json, re, random, signal, time

ANTIDEBUG_SO = '/usr/local/lib/antidebug.so'
UPLOADS_DIR  = os.environ.get('UPLOADS_DIR', '/data/uploads')
ELF_ALIASES  = ['kworker', 'systemd-helper', 'nm-dispatcher', 'dbus-daemon']


def detect_format(path):
    try:
        r = subprocess.run(['file', path], capture_output=True, text=True, timeout=10)
        out = r.stdout.lower()
        if 'pe32' in out or 'portable executable' in out: return 'pe'
        if 'mach-o' in out: return 'macho'
        return 'elf'
    except Exception:
        return 'elf'


def parse_pcap(cap_file: str) -> dict:
    result = {'tcp': [], 'udp': [], 'http_hosts': [], 'tls_sni': [], 'dns': []}
    try:
        r = subprocess.run(['tcpdump', '-r', cap_file, '-nn', '-A'],
                           capture_output=True, text=True, timeout=20)
        text = r.stdout

        # TCP connections (external IPs only)
        for m in re.finditer(r'(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+)', text):
            dst = f"{m.group(3)}:{m.group(4)}"
            if not m.group(3).startswith(('127.', '10.', '172.', '192.168.')):
                if dst not in result['tcp']:
                    result['tcp'].append(dst)

        # HTTP Host headers
        for m in re.finditer(r'Host:\s*([^\r\n]+)', text):
            h = m.group(1).strip()
            if h not in result['http_hosts']:
                result['http_hosts'].append(h)

        # TLS SNI (Server Name Indication in ClientHello — appears as printable string)
        for m in re.finditer(r'[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.(?:com|net|org|io|ru|cn|de|uk|fr)\b', text):
            sni = m.group(0)
            if sni not in result['tls_sni'] and sni not in result['http_hosts']:
                result['tls_sni'].append(sni)

        # HTTP request URLs
        http_urls = re.findall(r'(?:GET|POST|PUT|HEAD)\s+(https?://\S+|\S+)\s+HTTP', text)
        result['http_requests'] = http_urls[:20]

    except Exception as e:
        result['parse_error'] = str(e)
    return result


def parse_dns_log(dns_log: str) -> list:
    queries = []
    try:
        with open(dns_log) as f:
            for line in f:
                m = re.search(r'query\[.*?\]\s+(\S+)\s+from', line)
                if m:
                    q = m.group(1)
                    if q not in queries:
                        queries.append(q)
    except Exception:
        pass
    return queries


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary',   required=True)
    parser.add_argument('--duration', type=int, default=30)
    parser.add_argument('--alias',    default='')
    args = parser.parse_args()

    path = args.binary
    if path.startswith('local://'):
        path = os.path.join(UPLOADS_DIR, path[8:])
    if not os.path.isabs(path):
        path = os.path.join(UPLOADS_DIR, path)
    if not os.path.exists(path):
        print(json.dumps({'error': f'Binary not found: {path}'})); sys.exit(1)

    fmt = detect_format(path)
    alias = args.alias or (random.choice(ELF_ALIASES) if fmt == 'elf' else
                           random.choice(['svchost.exe', 'SearchIndexer.exe']))
    staged = f'/tmp/{alias}'
    shutil.copy2(path, staged)
    os.chmod(staged, 0o755)

    cap_file = '/tmp/net_cap.pcap'
    dns_log  = '/tmp/net_dns.log'

    print(f'[sandbox_network] alias={alias} duration={args.duration}s network=monitored', flush=True)

    # Start tcpdump
    tcpdump = subprocess.Popen(
        ['tcpdump', '-w', cap_file, '-U', '-n'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    # Start dnsmasq (log-only, responds with 127.0.0.1 to all queries)
    dnsmasq = subprocess.Popen(
        ['dnsmasq', '--no-daemon', '--no-resolv', '--log-queries',
         f'--log-facility={dns_log}', '--address=/#/127.0.0.1'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(0.5)

    # Run the binary
    env = {**os.environ, 'LD_PRELOAD': ANTIDEBUG_SO, 'DISPLAY': ':99'}
    import shutil as _sh
    qemu = _sh.which('qemu-x86_64-static')
    cmd = ([qemu, staged] if qemu and fmt == 'elf' else [staged])
    if fmt == 'pe':
        import wine_execute
        cmd = None  # handled below

    binary_stdout = binary_stderr = ''
    if cmd:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env=env, start_new_session=True)
        try: binary_stdout, binary_stderr = [x.decode('utf-8', errors='replace')
                                              for x in proc.communicate(timeout=args.duration)]
        except subprocess.TimeoutExpired:
            try:
                import os as _os
                _os.killpg(_os.getpgid(proc.pid), signal.SIGTERM)
            except Exception: pass
            proc.wait()
    else:
        import wine_execute
        binary_stdout, binary_stderr, _, _, _ = wine_execute.run(
            path, alias, [], args.duration, 'monitored')

    # Stop capture
    time.sleep(0.5)
    for p in (tcpdump, dnsmasq):
        try: p.terminate(); p.wait(timeout=3)
        except Exception: pass

    try: os.unlink(staged)
    except Exception: pass

    net = parse_pcap(cap_file)
    net['dns'] = parse_dns_log(dns_log)

    print('\n=== NETWORK CAPTURE SUMMARY ===')
    if net['dns']:
        print(f'DNS queries ({len(net["dns"])}): {", ".join(net["dns"][:10])}')
    if net['tcp']:
        print(f'TCP connections: {", ".join(net["tcp"][:10])}')
    if net['http_hosts']:
        print(f'HTTP hosts: {", ".join(net["http_hosts"][:5])}')
    if net['tls_sni']:
        print(f'TLS SNI: {", ".join(net["tls_sni"][:5])}')
    if not any([net['dns'], net['tcp'], net['http_hosts']]):
        print('No outbound network activity detected during execution window.')

    print('\n=== FULL JSON ===')
    print(json.dumps({'network': net, 'binary_stdout': binary_stdout[:2000],
                      'binary_stderr': binary_stderr[:1000]}, indent=2))


if __name__ == '__main__':
    main()
