# Release Checklist

A repeatable, artifact-first checklist for cutting a T3MP3ST release. The guiding rule is the
same as the project itself: **every headline number re-derives from committed artifacts** — so a
release isn't cut until the deterministic gates and the local smoke path are green.

## 1. Deterministic gates (must all pass)

```bash
npm ci
npm run typecheck            # tsc — 0 errors
npm run build                # tsc build
npm run lint                 # 0 errors (warnings OK)
npm test                     # unit + integration suite
npm run verify-claims        # re-derives every headline number from committed artifacts
npm audit                    # expect 0 vulnerabilities
npm run test:no-fitting      # anti-benchmark-fitting guard
npm run test:no-self-fitting
npm run test:no-phantom-tools
npm run test:gate
npm run prompt:audit
```

## 2. Local API smoke (loopback only)

```bash
T3MP3ST_PORT=<free-port> npm run server &                 # start on an isolated port
T3MP3ST_PORT=<free-port> npm run smoke                    # health + endpoint smoke
T3MP3ST_API_URL=http://127.0.0.1:<free-port> npm run exploit:smoke
T3MP3ST_API_URL=http://127.0.0.1:<free-port> npm run field:drill
npm run arsenal:smoke                                     # self-contained, 125 checks
```

Stop any listeners you started when done.

## 3. Optional — live checks (network + keys)

```bash
npm run smoke -- --live       # exercises a live LLM (needs a provider key or a local agent)
npm run arsenal:doctor        # reports which optional external tools are installed
```

## 4. Arsenal prerequisites (optional external tools)

The bash-only path needs **no** external tools. Specialist operators can use standard offensive
tooling if present on `PATH`; `npm run arsenal:doctor` reports what's installed. Missing tools
degrade gracefully — they never fail the core run.

## 5. ⚠️ Scope & safety

- **Never run live scans or exploitation against a target without an explicit authorization /
  scope receipt.** The default posture is owned / local / synthetic targets only.
- The server binds `127.0.0.1` by default. If you set `T3MP3ST_HOST` to a non-loopback address,
  it prints an **EXPOSURE WARNING** — the API executes commands and has **no built-in auth**. Put
  a Bearer-token reverse proxy in front of it before any LAN / internet exposure.

## 6. Publish

- Verify `repository.url` in `package.json` points at this repo. To retarget it:
  ```bash
  npm pkg set repository.url="git+https://github.com/<owner>/<repo>.git"
  ```
- Tag the release only after Sections 1–2 are green.
