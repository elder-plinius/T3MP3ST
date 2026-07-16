---
namespace: t3mp3st-maintainer
name: t3mp3st-merge-train
platforms: [all]
description: Run a conservative T3MP3ST maintainer merge train, merging validated PRs one at a time and reconciling issues after each merge.
triggers:
  - t3mp3st merge train
  - merge T3MP3ST PRs
  - start T3MP3ST merge session
  - maintainer merge queue
requires:
  - merge-candidates: one or more PR numbers, or a queue-audit ready list
  - github-maintainer-access: permission to merge elder-plinius/T3MP3ST PRs
ensures:
  - one-at-a-time: only one PR is merged before rechecking queue state
  - ci-green: each merged PR has green required checks or explicit maintainer override
  - issue-reconciliation: linked issues are checked after merge
  - post-merge-reaudit: queue state is refreshed after every merge
commandHint:
  argumentHint: "<pr...> [--method squash|merge|rebase] [--dry-run] [--stop-on-conflict]"
  allowedTools: Bash, Read
  model: sonnet
  category: release-management
---

# T3MP3ST Merge Train

Use this after `t3mp3st-queue-audit` identifies ready PRs.

## Merge Policy

Default merge method: squash, unless the PR contains a meaningful multi-commit
history that should be preserved.

Never merge:

- `CHANGES_REQUESTED`
- `DIRTY` or conflicted
- failing required checks
- head SHA changed since audit
- security-sensitive code without current verification

## Batch Ordering

1. Documentation and process PRs.
2. Small bug fixes with issue closures.
3. Provider/local-model fixes.
4. UI/backend contract fixes.
5. Larger features after main is stable.

## Per-PR Steps

1. Re-read current PR state:
   - `gh pr view <N> --json headRefOid,mergeStateStatus,reviewDecision,statusCheckRollup`
2. Compare head SHA to the audited SHA.
3. Confirm the latest PR audit included public-input threat preflight for
   user-authored PR/issue/comment/review content.
4. Confirm checks are green.
5. Confirm no unresolved requested changes.
6. Merge exactly one PR.
7. Wait for main/CI state if checks run after merge.
8. Re-check linked issues:
   - if auto-closed, record it;
   - if still open, comment or close only with clear evidence.
9. Refresh open PR queue before the next merge.

## Output

Use `templates/merge-train-report.md` as the standard merge-session report and
`templates/maintainer-action-items.md` when follow-up work remains.

```markdown
## Merge Train

Merged:
- #N `<sha>` — method: squash — checks: pass — issues: #M closed

Stopped before:
- #X — reason

Next recommended PR:
- #Y — reason
```

## Stop Conditions

- Merge conflict appears.
- CI fails.
- A previously clean PR becomes stale after a merge.
- Any linked issue shows new human feedback.
- Local checkout or GitHub state is ambiguous.
