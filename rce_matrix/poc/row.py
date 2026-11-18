#!/usr/bin/env python3
"""Drive every positive cell of one matrix row against a live proxy build.

Usage:
    python3 row.py <run-folder> [--list] [--only FAMILY]

``cells.json`` in the run folder carries one entry per positive family with the
exact request bytes, the upstream mode and the effect that proves the cell. Each
cell runs on a fresh peer and a fresh proxy: a benign control first, then the
attack. A cell passes only on an observed upstream effect (an executed request
line, a replay the upstream received as its own request, or a victim served from
cache with no new fetch) - never on "a request was sent".

Exit status is non-zero when any cell fails.
"""
import argparse
import json
import sys
import time
from pathlib import Path

import harness as h

FAMILIES = [
    "request_line_split",
    "body_replay_desync",
    "cache_exec_poison",
    "1xx_nesting",
    "pct2f_split",
    "config_quoted_space",
    "multi_hop_chain",
    "retry_double_exec",
]


def render(step, default_host="alpha.test"):
    """Return the raw bytes for one step."""
    if step.get("raw"):
        return step["raw"].encode()
    method = step.get("method", "GET")
    lines = [f"{method} {step['path']} HTTP/1.1", f"Host: {step.get('host', default_host)}"]
    lines += step.get("headers", [])
    body = step.get("body", "").encode()
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: " + ("keep-alive" if step.get("keep_alive") else "close"))
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def send_split(port, raw, gap):
    """Send the head, pause, then the tail: what a stalling client looks like."""
    import socket

    marker = raw.index(b"\r\n\r\n") + 4
    head, tail = raw[:marker], raw[marker:]
    out = b""
    try:
        conn = socket.create_connection(("127.0.0.1", port), timeout=4)
        conn.settimeout(4)
        conn.sendall(head)
        time.sleep(gap)
        conn.sendall(tail)
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            out += chunk
        conn.close()
    except OSError as exc:
        out += f"<ERR {exc}>".encode()
    return out


def exec_hits(peer, since):
    """Upstream records since ``since`` whose first request line executed."""
    return [r for r in peer.records[since:] if r.get("exec")]


def replay_hits(peer, since):
    """Upstream records that are a replay, i.e. a second request on the wire."""
    return [r for r in peer.records[since:] if r.get("exec") and r["exec"] == "line"]


def drive(run_name, name, cell, spec):
    root = h.OUT / run_name / name
    root.mkdir(parents=True, exist_ok=True)
    family = cell["family"]
    peer_mode = cell.get("peer", "plain")
    dialect = cell.get("dialect", spec.get("dialect", "auto"))
    prefix = spec.get("prefix", "/api")
    pass_uri = cell.get("pass_uri", spec.get("pass_uri"))
    steps = cell.get("steps") or [{"name": "attack", "path": cell["path"]}]
    if cell.get("victim_same_key"):
        # Cache keys are exact bytes on some builds: the victim must replay the seed verbatim.
        seed = dict(steps[0])
        victim = {"name": "victim", "path": seed["path"], "keep_alive": seed.get("keep_alive", False)}
        steps = [seed, victim]
    expect = cell.get("expect", "exec")
    control_path = cell.get("control", "/api/hello.txt")

    if family == "multi_hop_chain":
        return drive_chain(run_name, name, cell, spec)
    if family == "retry_double_exec":
        return drive_retry(run_name, name, cell, spec)

    with h.Peer(root / "control", "plain") as ctlpeer, h.Proxy(
        cell["build"], root / "control", ctlpeer.port, dialect, prefix, pass_uri
    ) as ctlproxy:
        control = h.send(ctlproxy.port, h.request(control_path))
    h.write(root, "control.txt", control)
    if not h.status(control).startswith("HTTP/1.1 200"):
        return False, f"control failed: {h.status(control)}", None

    with h.Peer(root, peer_mode) as peer, h.Proxy(
        cell["build"], root, peer.port, dialect, prefix, pass_uri
    ) as proxy:

        since = len(peer.fetches)
        streams = []
        marks = []
        for step in steps:
            marks.append(len(peer.fetches))
            raw = render(step)
            h.write(root, f"req_{step.get('name', 'attack')}.hex", raw.hex().encode() + b"\n")
            if step.get("split"):
                streams.append(send_split(proxy.port, raw, step["split"]))
            else:
                streams.append(h.send(proxy.port, raw))
            h.write(root, f"resp_{step.get('name', 'attack')}.txt", streams[-1])
            if step.get("wait"):
                time.sleep(step["wait"])

        attack = streams[-1]
        hits = len(peer.fetches) - since
        executed = exec_hits(peer, since)
        replayed = replay_hits(peer, since)
        nested = attack.count(b"HTTP/1.1 ") >= 2
        tail = attack.split(b"\r\n\r\n", 1)[-1]
        inner = tail.count(b"HTTP/1.1 ") >= 1

        if expect == "exec":
            ok = bool(executed)
        elif expect == "replay":
            ok = bool(replayed)
        elif expect == "nested":
            ok = nested and bool(inner)
        elif expect == "cache_victim":
            victim_since = marks[-1]
            ok = (b"uid=" in attack and len(peer.fetches) == victim_since
                  and bool(exec_hits(peer, since)))
        else:
            ok = False

        detail = (
            f"status={h.status(attack)} upstream={hits} executed={len(executed)} "
            f"replayed={len(replayed)} nested={nested} "
            f"up={[r['request_line'] for r in peer.records[since:]]}"
        )
        return ok, detail, peer


def drive_retry(run_name, name, cell, spec):
    """First upstream executes then dies; the retry must execute again."""
    root = h.OUT / run_name / name
    root.mkdir(parents=True, exist_ok=True)
    dialect = cell.get("dialect", spec.get("dialect", "auto"))
    with h.Peer(root / "control", "plain") as ctlpeer, h.Proxy(
        cell["build"], root / "control", ctlpeer.port, dialect, spec.get("prefix", "/api")
    ) as ctlproxy:
        control = h.send(ctlproxy.port, h.request(cell.get("control", "/api/hello.txt")))
    h.write(root, "control.txt", control)
    if not h.status(control).startswith("HTTP/1.1 200"):
        return False, f"control failed: {h.status(control)}", None

    with h.Peer(root, "failfirst", cell.get("fail_first", 1), tag="flaky") as flaky, h.Peer(
        root, "plain", 0, tag="healthy"
    ) as healthy:
        with h.Proxy(
            cell["build"], root, flaky.port, dialect, spec.get("prefix", "/api"),
            extra_upstreams=[healthy.port],
        ) as proxy:
            raw = render(cell["steps"][0])
            h.write(root, "req_attack.hex", raw.hex().encode() + b"\n")
            response = h.send(proxy.port, raw)
            h.write(root, "resp_attack.txt", response)
            executed = exec_hits(flaky, 0) + exec_hits(healthy, 0)
            ok = len(executed) >= 2
            detail = (f"status={h.status(response)} executions={len(executed)} "
                      f"flaky={[r['request_line'] for r in flaky.records]} "
                      f"healthy={[r['request_line'] for r in healthy.records]}")
            return ok, detail, flaky


def drive_chain(run_name, name, cell, spec):
    """Two stacked proxies: hop 1 must split, hop 2 must execute."""
    root = h.OUT / run_name / name
    root.mkdir(parents=True, exist_ok=True)
    with h.Peer(root) as peer:
        hop2 = h.Proxy(cell["hop2"], root / "hop2", peer.port,
                       cell.get("hop2_dialect", "ngx"), cell.get("hop2_prefix", "/"),
                       server_name=cell.get("hop2_server_name", "alpha.test"))
        hop2.__enter__()
        hop1 = h.Proxy(cell["build"], root / "hop1", hop2.port,
                       cell.get("dialect", spec.get("dialect", "auto")), spec.get("prefix", "/api"))
        hop1.__enter__()
        try:
            local = h.send(hop1.port, h.request("/hello.txt"))
            direct = h.send(hop2.port, h.request(
                "/hello.txt", host=cell.get("hop2_server_name", "alpha.test")))
            h.write(root, "control.txt", local + b"\n--- hop2 ---\n" + direct)
            if not (h.status(local).startswith("HTTP/1.1 200")
                    and h.status(direct).startswith("HTTP/1.1 200")):
                return False, f"control failed: {h.status(local)} / {h.status(direct)}", peer
            raw = render(cell["steps"][0])
            h.write(root, "req_attack.hex", raw.hex().encode() + b"\n")
            response = h.send(hop1.port, raw)
            h.write(root, "resp_attack.txt", response)
            ok = bool(exec_hits(peer, 0))
            return ok, f"status={h.status(response)} executed={len(exec_hits(peer, 0))}", peer
        finally:
            hop1.__exit__()
            hop2.__exit__()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--only")
    args = parser.parse_args()
    run_dir = Path(args.run).resolve()
    spec = json.loads((run_dir / "cells.json").read_text())
    cells = spec["cells"]
    if args.only:
        cells = [c for c in cells if c["family"] == args.only]
    if args.list:
        for cell in cells:
            print(cell["family"], cell.get("build", ""), cell.get("shape", ""))
        return 0

    failed = 0
    for index, cell in enumerate(cells, 1):
        name = f"{index:02d}_{cell['family']}"
        try:
            ok, detail, _peer = drive(run_dir.name, name, cell, spec)
        except Exception as exc:  # noqa: BLE001 - report, never abort the row
            ok, detail = False, f"exception: {exc}"
        print(f"{'PASS' if ok else 'FAIL'} {run_dir.name} {cell['family']} {detail}", flush=True)
        failed += not ok
    print(f"{run_dir.name}: {len(cells) - failed}/{len(cells)} passed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
