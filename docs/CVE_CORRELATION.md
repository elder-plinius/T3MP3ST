# Technology-to-CVE correlation

`POST /api/recon/correlate-cves` compares technology observations with a caller-supplied, already-ingested CISA KEV snapshot and optionally joins FIRST EPSS records by CVE ID. Correlation never performs a remote fetch.

## Request and limits

The JSON body contains `technologies` (1–100 `{ name, version?, source? }` observations), `kev` (a `FeedResult<KevRecord>`), and optional `epss` (a `FeedResult<EpssRecord>`). Each feed is limited to 10,000 records. The server validates feed metadata, record provenance, CVE identifiers, and EPSS probabilities; invalid bodies receive HTTP 400.

## Match semantics

- Exact normalized product or vendor-plus-product names have confidence `0.95`.
- Multi-token subset matches have confidence `0.8`.
- Known aliases have confidence `0.75`.
- Broad single-token matches have confidence `0.45` and should be treated as discovery leads.
- If either supplied feed is stale, every confidence value is capped at `0.5` and the response carries a warning.

Versions are preserved but are not evaluated against affected-version ranges because KEV does not supply those ranges. Results therefore report `not-evaluated` (or `not-provided`) and always carry `verificationStatus: "unverified-candidate"`. A match must never be presented as a verified vulnerability finding without independent product/version validation.

Every result embeds its original KEV record and any joined EPSS record, including their provenance. Duplicate CVEs are collapsed to the highest-confidence observation and output is deterministic. An empty KEV snapshot returns HTTP 200 with `status: "empty-feed"`, no matches, and the standard verification warning.
