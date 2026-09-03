# Scoped honeytokens and tripwires

`HoneytokenManager` is an opt-in, in-memory lifecycle service. Creation returns token material to the authorized deployment caller exactly once; list, trigger, alert, error, and audit surfaces contain metadata or keyed hashes, never the token. Callers must not log the returned material or pass it into model context, findings, fixtures, command-line arguments, or persistent storage.

Lifecycle states are `created`, `active`, and `revoked`. Activation fails closed unless the token's environment appears in the manager's explicit allowlist. Rotation revokes and zeroes the old in-process buffer and returns a new inactive generation. Revocation removes lookup capability and zeroes the buffer; cleanup additionally removes the record. These are process-memory controls, not claims of secure deletion from caller memory, swap, crash dumps, or external deployment targets.

Triggers require an active token, a timestamp within five minutes, a nonce, and `HMAC-SHA-256(token, nonce:timestamp)`. Used nonces are retained as keyed hashes and rejected on replay. Token material, nonce text, and source identifiers are absent from events; sources and nonces are represented by audit-keyed hashes. New triggers start `pending` and require an operator to classify them `confirmed` or `dismissed`, preserving false-positive review.

Audit events record lifecycle action, public token ID, actor, timestamp, and non-secret transition detail. Alerts use the `HoneytokenAlertSink` interface only; a delivery failure cannot roll back or corrupt the trigger. Concrete Slack, Discord, and SIEM delivery belongs to #176.
