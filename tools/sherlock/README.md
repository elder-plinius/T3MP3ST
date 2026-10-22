# Sherlock site database (vendored)

`sherlock_project/resources/data.json` from [sherlock-project/sherlock](https://github.com/sherlock-project/sherlock)
(MIT, © 2019 Sherlock Project — see `LICENSE`). Vendored verbatim so the OSINT sweep can
reuse Sherlock's curated platform list and, more importantly, its **absence-detection
semantics** (status code / error-message marker / redirect-target / regex pre-filter)
without requiring Python on the analyst box.

Refresh:

```bash
curl -sL https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json \
  -o tools/sherlock/data.json
```

The engine (`src/tools/sherlock-sites.ts`) maps each entry into a `OsintSite` and merges
it with the hand-curated catalog. T3MP3ST's own entries win on name collisions — they carry
API-endpoint probes and identity corroboration that Sherlock's generic page checks lack.
