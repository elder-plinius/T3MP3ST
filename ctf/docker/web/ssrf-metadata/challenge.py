"""Deterministic constants and offline mock for the SSRF-to-metadata lab.

The lab emulates a link-local cloud metadata endpoint (AWS IMDSv2 style plus a
`computeMetadata/v1` style path). The vulnerable handler dereferences the
caller-supplied URL directly, so the in-lab mock at 169.254.169.254 is the only
metadata surface reachable from the challenge container. All values are
committed synthetic constants; never copy this construction into production.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

# Visibly synthetic, deterministic credential set served by the metadata mock.
FLAG = "T3MP3ST{ssrf_m3t4d4t4_c4ptur3}"
SYNTHETIC_SECRET = "synth-secret-9f3c-a1b2"
SYNTHETIC_TOKEN = "synth-session-token-77e1"
SYNTHETIC_EXPIRY = "20380119T031407Z"
SYNTHETIC_ROLE = "t3mp3st-synth"
TOKEN_VALUE = "t3mp3st-synth-imds-token"
# The lab's metadata endpoint address. Defaults to the classic link-local 169.254.169.254:80
# (real in the compose lab); overridable so the host-side smoke points the server at a
# local mock process instead of the host's own link-local address.
METADATA_HOST = os.environ.get("CTF_METADATA_HOST", "169.254.169.254")
METADATA_PORT = os.environ.get("CTF_METADATA_PORT", "80")
# A second, non-metadata host: fetching it must NOT return the metadata flag, proving
# the solver resolved the metadata address and not a catch-all.
EXTERNAL_HOST = os.environ.get("CTF_EXTERNAL_HOST", "169.254.169.253")
EXTERNAL_PORT = os.environ.get("CTF_EXTERNAL_PORT", "")
EXTERNAL_PATH = "/outside-metadata"
EXTERNAL_BODY = "external-synth-not-metadata"
IAM_PATH = "/latest/meta-data/iam/security-credentials/t3mp3st-synth"
TOKEN_PATH = "/latest/api/token"

MAX_URL = 300
MAX_READ = 16384


def flag_in_iam() -> str:
    """The flag as it rides inside the IAM security-credentials response."""
    return FLAG[8:-1]


def iam_credential(role: str = SYNTHETIC_ROLE) -> bytes:
    """Render the mock IAM security-credentials JSON body for `role`."""
    payload = {
        "AccessKeyId": f"AKIA{flag_in_iam().upper()}",
        "SecretAccessKey": SYNTHETIC_SECRET,
        "Token": SYNTHETIC_TOKEN,
        "Expiration": SYNTHETIC_EXPIRY,
        "RoleName": role,
    }
    return json.dumps(payload, sort_keys=True).encode()


def metadata_response(path: str) -> tuple[int, bytes]:
    """Serve the deterministic mock metadata payload for `path`."""
    if path == "/health":
        return 200, b"{'status': 'ok'}"
    if path in ("", "/"):
        return 200, b"t3mp3st-m3t4-index"
    if path == "/latest/meta-data/":
        return 200, b"iam/\npublic-keys"
    if path == "/latest/api/token":
        return 200, TOKEN_VALUE.encode()
    if path.startswith("/latest/meta-data/iam/security-credentials"):
        role = path.rsplit("/", 1)
        return 200, iam_credential(role[-1] or SYNTHETIC_ROLE)
    if path.startswith("/computeMetadata/v1") or path.startswith("/metadata/"):
        return 200, FLAG.encode()
    if path == EXTERNAL_PATH:
        return 200, EXTERNAL_BODY.encode()
    return 404, b"{'error': 'no such path'}"


def fetch_offline(url: object) -> tuple[int, bytes]:
    """Fetch without a network: metadata host served in-process, all else denied.

    This is the deterministic stand-in used by the offline solver and smoke
    tests; it is exactly the contract the live lab enforces through the mock
    container plus the internal network's default-deny egress.
    """
    target = str(url)[:MAX_URL]
    try:
        parsed = urllib.parse.urlsplit(target)
    except (ValueError, OSError):
        return 400, b"{'error': 'bad url'}"
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return 400, b"{'error': 'bad url'}"
    if parsed.hostname == METADATA_HOST:
        return metadata_response(parsed.path)
    return 403, b"{'error': 'egress denied'}"


def metadata_url(path: str) -> str:
    port = METADATA_PORT if int(METADATA_PORT) != 80 else ""
    suffix = f":{port}" if port else ""
    return f"http://{METADATA_HOST}{suffix}{path}"


def flag_url() -> str:
    return metadata_url(IAM_PATH)


def token_url() -> str:
    return metadata_url(TOKEN_PATH)


def external_url() -> str:
    suffix = f":{EXTERNAL_PORT}" if EXTERNAL_PORT else ""
    return f"http://{EXTERNAL_HOST}{suffix}{EXTERNAL_PATH}"
