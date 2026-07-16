---
name: pr-audit-review
description: Findings-first maintainer PR audit template with exact SHA, verification evidence, decision, and residual risk.
---

# PR Audit

PR: `#<number>`
Title: `<title>`
Head SHA: `<sha>`
Base: `main`
Reviewer: `<name/tool>`
Date: `<YYYY-MM-DD>`

## Findings

| Severity | File / Area | Finding | Required Change |
| --- | --- | --- | --- |
| `<blocking/non-blocking>` | `<path:line or area>` | `<finding>` | `<change>` |

If there are no blocking findings:

> No blocking findings.

## Verification

| Check | Result | Evidence |
| --- | --- | --- |
| `<CI check or local command>` | `<pass/fail/not run>` | `<URL/output summary>` |

## Public Input Threat Assessment

- Assessment file/template: `public-input-threat-assessment.md`
- Risk: `<low/medium/high>`
- Security-framework routing used: `<none | aiwg discover phrase/result>`
- Notes: `<summary>`

## Review Decision

Decision: `<approve | request changes | comment | hold>`

Reason:

- `<short reason>`

## Residual Risk

- `<risk, assumption, or none>`

## Suggested Maintainer Comment

```markdown
Reviewed PR #<number> at `<sha>`.

<findings or no-blocking-findings statement>

Verification:
- <checks>

Decision: <decision>
```
