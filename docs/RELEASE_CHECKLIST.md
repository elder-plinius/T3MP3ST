# Release Checklist

A repeatable, artifact-first checklist for cutting a T3MP3ST release. The guiding rule is the
same as the project itself: **every headline number re-derives from committed artifacts** — so a
release isn't cut until the deterministic gates and the local smoke path are green.

A release marks a source commit that passed these quality gates. The only published
release asset is the certified source ZIP: no npm publication, compiled binaries,
container image, or separately rebuilt archive. Retain checksums, logs, and
provenance as certification evidence in CI and record the SHA-256 in the release
notes. This certification covers deterministic software checks; it does not claim
live-provider, optional-tool, or hardware compatibility that was not tested.

## 1. Deterministic gates (must all pass)

```bash
npm ci
npm run test:release         # lint, types, tests/coverage, claims, contracts, local smoke, docs, build, pack inspection
npm audit                   # expect 0 vulnerabilities
```

## 2. Local API smoke (loopback only)

```bash
npm run build
npm run test:release:smoke    # isolated loopback server; server checks must run
```

The release smoke runner starts and stops its own unconfigured server with temporary
state. It runs the core/server smoke, exploit-chain contract, field drill, and arsenal
checks against local synthetic fixtures. `T3MP3ST_CONFIG_DIR` selects an absolute
settings directory and loads only its `.env`, without falling back to home-directory
credentials; the runner sets this to a temporary directory. When unset, normal
configuration discovery remains unchanged. A missing server is a failure. Live-model
checks remain optional and are reported separately; do not count a skipped live
probe as positive provider evidence.

The coverage gate currently requires 100% per file for the three parser modules
listed in `vitest.config.ts`; it is not a claim of 100% repository coverage.
Lint warnings are permitted by existing policy and should be recorded with the
candidate results.

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

- Confirm the release commit is already on `main`, CI is green at that exact
  SHA, the version and changelog agree, and the tag is signed and points to that
  commit. Never move or reuse a failed release tag; correct the release and use
  a new version/tag.
- Verify `repository.url` in `package.json` points at this repo. To retarget it:
  ```bash
  npm pkg set repository.url="git+https://github.com/<owner>/<repo>.git"
  ```
- Tag the release only after Sections 1–2 are green.
- Push the `v*` tag and wait for the tag workflow. It reruns
  `npm run test:release`, the zero-vulnerability dependency audit, and package dry
  run against the exact tag. It then creates one deterministic
  `T3MP3ST-<sha>.zip` directly from that tested Git object.
- The workflow extracts that ZIP into a clean temporary directory, performs a
  locked install and build, and invokes the packaged CLI help path before the
  archive can be retained.
- Verify `release-evidence/source-zip-check.txt`, `SHA256SUMS`, and the retained
  Sigstore provenance bundle. Workspace notes, secrets, ignored files, and
  local artifacts cannot enter a `git archive` snapshot.
- Publish only the retained, checksum-matched source ZIP as the release asset. Do not rebuild a different
  archive from another checkout after certification.

## Mission control semantics

Stop halts backend scheduling; a tool or provider request already in flight may
finish. Pause similarly prevents further scheduling and does not suspend an
external process. Release notes must preserve this limit rather than promise
immediate cancellation of all activity.
