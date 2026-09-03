# Secure outbound alert delivery

`AlertDispatcher` sends redacted security-event summaries to Slack, Discord, and generic SIEM webhooks. Destinations are optional and resolved only from the fixed server-side environment keys `SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL`, and `SIEM_WEBHOOK_URL`. URLs are private runtime state: list and receipt surfaces expose only destination ID, provider, configured status, allowlisted hostname, and proxy policy. The module does not load `.env` files or add browser/configuration APIs.

Every configured URL must use HTTPS, contain no URL userinfo or fragment, and match an exact hostname allowlist. Redirect following is disabled. Slack and Discord ship with narrow default hosts; SIEM is omitted until an operator supplies its host allowlist. Each destination explicitly selects `configured` routing (the process-wide configured proxy) or `direct` routing.

Alerts are recursively redacted before provider-specific serialization. Payloads above the configured byte limit are rejected before network use. Delivery uses explicit timeouts, bounded exponential retry for network errors, timeout, HTTP 408/429, and 5xx responses, no retry for terminal 4xx responses, and per-destination rate limiting. Receipts use fixed error categories and never include provider response bodies, exception text, or webhook URLs.

Delivery returns isolated receipts and does not mutate the alert, mission, finding, or honeytoken event. The `HoneytokenAlertSink` adapter raises a generic failure only after recording the trigger independently; destination failure cannot corrupt security state. Data leaving the system is limited to the redacted provider payload at dispatch time: event name, title, details, timestamp, optional severity/target, and redacted metadata.
