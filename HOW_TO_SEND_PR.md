# How to Send This PR

The repo is at `https://github.com/elder-plinius/t3mp3st`.

## 1. Fork & Clone

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/YOUR_USERNAME/t3mp3st.git
cd t3mp3st
```

## 2. Apply the Fixes

Copy the modified files into your fork:

```bash
# From the working directory /home/kali/Documents/T3MP3ST:
cp docs/index.html /path/to/your/fork/docs/index.html
cp src/server.ts    /path/to/your/fork/src/server.ts
```

Or apply the diff manually (see PR_OPENAI_COMPATIBLE_BASEURL_FIX.md for the exact lines changed).

## 3. Commit & Push

```bash
cd /path/to/your/fork
git checkout -b fix/openai-compatible-baseurl-enforcement
git add docs/index.html src/server.ts
git commit -m "fix: enforce web UI custom baseUrl and API key for OpenAI-compatible providers

- getApiKey() now checks active provider key from UAC settings
- resolveLLMBackend() detects openai/anthropic/custom backends with baseUrl
- _safeLLMCallOnce() uses custom baseUrl from backend object
- startMissionFromDashboard() respects activeProvider and passes cloudBaseUrl
- BackendDispatch.startMission() accepts baseUrl for all providers
- getGeneralConfig() includes cloudBaseUrl for non-local providers
- resolveGeneralLLMConfig() allows per-request baseUrl for OpenAI-compatible providers
- createTempestCommandInstance() honors baseUrl for all providers"
git push origin fix/openai-compatible-baseurl-enforcement
```

## 4. Create the PR on GitHub

Go to `https://github.com/elder-plinius/t3mp3st` — a "Compare & pull request" banner should appear after pushing. Click it.

- **Base branch**: `main`
- **Head branch**: `fix/openai-compatible-baseurl-enforcement`
- **Title**: `fix: enforce web UI custom baseUrl and API key for OpenAI-compatible providers`
- **Body**: Use the content from `PR_OPENAI_COMPATIBLE_BASEURL_FIX.md`

## 5. Verify CI

After creating the PR, check that CI passes:
- `npm run typecheck` — TypeScript compilation
- `npm run lint` — ESLint

If any checks fail, fix and `git push` again to re-trigger.
