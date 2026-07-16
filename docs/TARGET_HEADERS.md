# Target Header Injection

T3MP3ST can apply authentication headers to its HTTP arsenal tools. The headers are bound to one exact origin so credentials are not sent to other authorized targets, subdomains, ports, or redirect destinations.

## Configuration

Set both values in `~/.t3mp3st/.env`:

```bash
TEMPEST_TARGET_ORIGIN=https://api.target.example
TEMPEST_TARGET_HEADERS={"Authorization":"Bearer token","X-Tenant":"acme"}
```

`TEMPEST_TARGET_ORIGIN` must contain only an `http` or `https` origin: scheme, hostname, and optional port. Paths, query strings, fragments, and embedded credentials are rejected. Origin matching includes the scheme and effective port.

`TEMPEST_TARGET_HEADERS` must be a non-empty JSON object whose values are strings. Invalid or incomplete configuration fails closed: the request continues without configured headers.

Transport-level headers such as `Host`, `Content-Length`, `Connection`, `Transfer-Encoding`, and proxy authorization headers are rejected. Authentication headers including `Authorization`, `Cookie`, and application-specific API key headers are supported.

## Coverage And Overrides

Configured headers are applied to HTTP requests made by all built-in web probes and to `curl_request` when the request URL matches the configured origin. They are not applied to unrelated origins.

Headers supplied explicitly by a tool call override configured defaults case-insensitively. For example, `authorization` overrides a configured `Authorization` value without sending duplicates.

## Redirect Safety

Built-in requests follow redirects while retaining configured headers only for same-origin hops. Before following a cross-origin redirect, T3MP3ST removes every configured header as well as standard credential headers.

When configured headers are active, `curl_request` removes `-L`, `--location`, and `--location-trusted` from caller-supplied flags. This prevents custom authentication headers from being forwarded to a redirect destination.

## Secret Handling

Configured curl headers are written to a temporary mode `0600` config file rather than command-line arguments, then deleted after execution. This keeps values out of the local process list.

Before Arsenal records or emits a tool result, configured header values are replaced with `[REDACTED]` in output, errors, findings, and other structured result fields. This also covers targets that reflect a credential in a response.

Keep `~/.t3mp3st/.env` private and never commit real credentials. Rotate a credential if it appears in logs or evidence created outside the Arsenal execution path.
