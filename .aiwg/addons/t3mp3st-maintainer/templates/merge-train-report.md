---
name: merge-train-report
description: Maintainer merge-session report with per-PR gates, merge results, issue reconciliation, stop reasons, and next candidate.
---

# Merge Train Report

Date: `<YYYY-MM-DD>`
Repository: `elder-plinius/T3MP3ST`
Operator: `<maintainer>`
Method default: `<squash | merge | rebase>`

## Preflight

- Queue audit source: `<date/link/summary>`
- Local branch: `<branch>`
- Main baseline: `<sha>`
- GitHub auth: `<confirmed/not confirmed>`
- Public-input threat preflight: `<confirmed for all candidates | missing for PR #>`

## Merged

| PR | Title | Head SHA | Method | Checks | Linked Issues | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| `#` | `<title>` | `<sha>` | `<method>` | `<pass/evidence>` | `<issues>` | `<merged/closed/commented>` |

## Stopped Before

| PR | Reason | Required Follow-Up |
| --- | --- | --- |
| `#` | `<reason>` | `<follow-up>` |

## Issue Reconciliation

| Issue | Expected Outcome | Actual Outcome | Action Taken |
| --- | --- | --- | --- |
| `#` | `<auto-close/comment/remain open>` | `<actual>` | `<action>` |

## Next Recommended Candidate

- PR: `#<number>`
- Reason: `<why next>`
- Required check before merge: `<check>`

## Session Notes

- `<note>`
