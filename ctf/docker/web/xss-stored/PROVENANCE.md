# Stored-XSS challenge provenance
- Origin: implemented for T3MP3ST issue #190 after decomposition of proposal #163.
- License: AGPL-3.0-or-later, matching the repository.
- Intended vulnerability: the note board renders each stored note verbatim (no HTML escaping) and every reader's browser runs it. The board defines a single exfiltration helper, `window.ctfCollect()`, which fetches `document.cookie` to the lab callback service; storing a note whose markup calls that helper exfiltrates the flag-bearing admin session cookie.
- Flag handling: `T3MP3ST{st0r3d_xss_c00kie_th3ft}` is a committed synthetic lab constant set as the `ctf_flag` cookie on admin sign-in; the callback service logs the exfiltrated cookie body and the solver recovers and asserts the flag from it.
- Reproduction: `python3 ctf/docker/web/xss-stored/solve.py` must print the flag.
- Rollback: delete `docker/web/xss-stored/`, the two `xss-*` compose services plus the `xss-callback-internal` network, the `web_xss_stored` manifest entry, and `scripts/test-ctf-xss-stored.mjs`; the lab leaves no host state, volumes, or external network.
- Sensitive-data review: the note, credentials, session token, and flag are synthetic constants created for this lab. No acquired data, production secret, key, credential, or user identifier is present; no host credential or production-data mount exists.
- Container trust: the Dockerfile pins the same digest as the sibling labs (official Python multi-platform OCI index). There are no package-manager or third-party runtime dependencies (stdlib only). The challenge and callback services run on an isolated internal bridge with no direct host binding; a separately constrained allow-list gateway owns the loopback host port and fronts the exfiltration leg. Health checks probe the gateway.
- Verification date: 2026-09-03.
