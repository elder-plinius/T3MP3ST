---
name: queue-audit-report
description: Full T3MP3ST maintainer queue audit report for open PRs, issues, readiness, blockers, and suggested merge order.
---

# T3MP3ST Queue Audit

Date: `<YYYY-MM-DD>`
Repository: `elder-plinius/T3MP3ST`
Audit scope: `<all open PRs/issues | filtered scope>`

## Summary

- Ready merge candidates: `<count>`
- Needs re-audit: `<count>`
- Blocked or rebase needed: `<count>`
- Issues needing maintainer action: `<count>`
- Recommended next action: `<one sentence>`

## Ready Merge Candidates

| Order | PR | Title | Head SHA | Evidence | Risk | Linked Issues |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `#` | `<title>` | `<sha>` | `<CI/review/local checks>` | `<low/medium/high>` | `<issues>` |

## Needs Re-Audit

| PR | Reason | Required Checks | Owner |
| --- | --- | --- | --- |
| `#` | `<stale SHA/no CI/new comments/high-risk area>` | `<checks>` | `<maintainer>` |

## Blocked / Rebase Needed

| PR | Blocker | Maintainer Action | Unblock Condition |
| --- | --- | --- | --- |
| `#` | `<conflict/failing CI/changes requested/question>` | `<action>` | `<condition>` |

## Issue Actions

| Issue | Class | Evidence | Next Action |
| --- | --- | --- | --- |
| `#` | `<close-via-pr/needs-response/address-issues/feature-track/defer>` | `<evidence>` | `<action>` |

## Merge Train Recommendation

1. `<PR # and reason>`
2. `<PR # and reason>`
3. `<PR # and reason>`

## Notes And Risks

- `<risk or assumption>`
