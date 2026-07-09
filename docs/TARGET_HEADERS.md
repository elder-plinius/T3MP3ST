# Target Header Injection (`TEMPEST_TARGET_HEADERS`)

## Overview

T3MP3ST can inject a fixed set of HTTP headers into every outbound request made by its arsenal tools. This is useful when scanning authenticated endpoints — set your credentials once in `~/.t3mp3st/.env` and every HTTP probe picks them up automatically, without having to repeat them in every tool call.

## Configuration

Set `TEMPEST_TARGET_HEADERS` in `~/.t3mp3st/.env` as a JSON object of header name → value pairs:

```bash
# Bearer token
TEMPEST_TARGET_HEADERS={"Authorization":"Bearer eyJhbGciOiJSUzI1NiJ9..."}

# Session cookie
TEMPEST_TARGET_HEADERS={"Cookie":"session=abc123; csrf=xyz"}

# Multiple headers
TEMPEST_TARGET_HEADERS={"Authorization":"Bearer token","X-Tenant":"acme","X-API-Key":"secret"}
```

The value must be a valid JSON object. If the variable is absent, empty, contains malformed JSON, or contains a non-object value (e.g. a JSON array), no headers are injected and the tool continues silently — there is no error.

## Affected Tools

| Tool | How headers are injected |
| --- | --- |
| `http_request` | Merged into the `headers` init of every `fetch()` call. Per-request `headers` parameter overrides env headers for the same key. |
| `header_analysis` | Forwarded as `headers` on the `HEAD` request used to inspect security response headers. |
| `curl_request` | Prepended as `-H "Name: Value"` arguments before any per-request headers. Since curl applies last-wins for duplicate `-H` flags, per-request headers always take precedence. |

## Override Precedence

Per-request headers (the `headers` parameter of a specific tool call) always override env headers for the same key. Env headers serve as defaults that apply to every call automatically.

```
# .env
TEMPEST_TARGET_HEADERS={"Authorization":"Bearer base-token","X-Tenant":"acme"}

# Agent tool call with an explicit override:
http_request(url="https://api.target.com/users", headers={"Authorization":"Bearer scoped-token"})

# Effective headers sent:
#   Authorization: Bearer scoped-token   ← per-request wins
#   X-Tenant: acme                       ← from env (not overridden)
```

## Security Notes

- `~/.t3mp3st/.env` is created with mode `0600` by `scripts/setup-api.sh` — readable only by your user.
- Never commit `.env` to source control. The repo's `.gitignore` already excludes it.
- Header values are injected at the tool handler level and are never logged or written to evidence stores.
- The env variable name `TEMPEST_TARGET_HEADERS` is intentionally namespaced to avoid accidental collision with generic shell variables.

## Reference

- Source: `src/arsenal/index.ts` — `parseTargetHeaders()` function and its three call sites.
- Template: `.env.example` — documents `TEMPEST_TARGET_HEADERS` with inline examples.
- Related: `docs/SCOPE_AND_AUTHORIZATION.md` for the broader egress scope gate that controls which hosts these headers are sent to.
