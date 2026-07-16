# Pull Request Delivery Guide

Use this checklist before opening or updating a pull request. It is written for
both human contributors and coding agents.

## Contributor Checklist

1. Start from current `main`.

   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

   If the branch has drifted heavily, create a fresh branch from `main` and
   cherry-pick only the commits that belong to the PR.

2. Keep the diff scoped to the PR title.

   ```bash
   git diff --name-status upstream/main...HEAD
   git diff --stat upstream/main...HEAD
   ```

   The changed file list should be easy to explain from the PR title. Do not
   ship stale-base churn, generated artifacts, formatter-only rewrites, or
   unrelated deletions.

3. Stop before pushing if the diff removes protected project evidence.

   These paths should not disappear unless the PR is explicitly about replacing
   them and the PR body explains the replacement:

   - benchmark corpora under `bench/`
   - benchmark scripts under `scripts/*bench*`
   - claim/provenance docs such as `docs/VERIFIED_PROVENANCE.md`
   - redaction, provider, local-agent, and adapter safety tests
   - provider configuration, environment templates, and API-key plumbing

4. Run the smallest meaningful verification set.

   For most code changes:

   ```bash
   npm run typecheck
   npm test
   npm run doctor
   ```

   For docs-only changes, note why code tests were skipped. For UI-only
   `docs/index.html` changes, extract or otherwise parse-check the page scripts.
   For benchmark or headline-claim changes, also run:

   ```bash
   npm run verify-claims
   ```

5. Add a contribution receipt when the change affects behavior, claims, target
   scope, agent execution, evidence, reports, or safety gates.

   Use the template below. The receipt can live in the PR body unless the
   change introduces durable benchmark artifacts.

6. Write the PR body for review, not just for announcement.

   Include:

   - what changed
   - why it changed
   - exact commands run and pass/fail/skipped result
   - any skipped verification and why
   - screenshots or artifacts for UI/reporting changes
   - residual risk or follow-up work

## Coding-Agent Instructions

When an agent prepares a PR, it must perform a final scope audit before posting.

Use this command and inspect every line:

```bash
git diff --name-status upstream/main...HEAD
```

If the output contains an unrelated deletion, stop and repair the branch before
asking for review. Common accidental stale-base deletions include benchmark
fixtures, provenance docs, Gemini/provider tests, local-agent tests, and
adapter-tool safety tests.

Agents should prefer a fresh branch when a rebase produces noisy conflicts. The
repair path is:

1. create a branch from current `main`;
2. copy only the files needed for the requested feature or fix;
3. rerun the focused checks;
4. update the PR body with the resulting receipt.

## Contribution Receipt Template

```markdown
## Contribution Receipt

- Change:
- Scope class: docs_only | static_fixture | local_lab | ctf_range | authorized_live
- Target authority:
- Network use: none | loopback | private_lab | authorized_external
- Run mode labels:
- Model/harness labels:
- Commands run:
  - `npm run typecheck` -> pass/fail/skipped
  - `npm test` -> pass/fail/skipped
  - `npm run doctor` -> pass/fail/skipped
  - `npm run verify-claims` -> pass/fail/skipped
- Artifacts:
- Redaction:
- Claims changed:
- Abstentions/refusals:
- Residual risk:
```

## Maintainer Review Checklist

Before approving a PR, verify:

- `git diff --name-status main...HEAD` matches the PR title and description;
- no unrelated protected evidence, benchmark, provider, redaction, or safety
  tests were removed;
- required checks or documented substitutes were run;
- UI-only changes have at least a static script parse check;
- benchmark, claim, scope, local-agent, Arsenal, or safety-gate changes include
  a contribution receipt;
- risky updater, shell, Docker, network, or local-agent execution changes have
  an explicit degraded-mode and security review note.

If a PR fails the scope audit, ask the submitter to rebase or recreate the
branch from current `main` before deeper review. Do not spend review cycles on
feature details while stale-base deletions remain in the diff.

Only comment on PRs that need action: concrete fixes, missing verification,
missing receipts, or a rebase/scope cleanup. Ready PRs should not receive
process comments.
