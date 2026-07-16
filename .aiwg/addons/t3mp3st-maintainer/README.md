# T3MP3ST Maintainer Addon

Project-local AIWG addon for running T3MP3ST repository maintenance with
repeatable quality gates. It captures the maintainer process for PR audits,
merge trains, issue response, and release-readiness checks.

## What this is

This bundle is intentionally project-local. It encodes the way this repository
should be stewarded now that maintainers are responsible for the full queue, not
only their own PRs.

Use it when:

- Auditing all open PRs before a merge session.
- Reviewing one PR to maintainer standards.
- Running a merge train one PR at a time with CI and issue closure checks.
- Triaging open issues into close, comment, address, defer, or feature-track
  actions.

## Layout

```
.aiwg/addons/t3mp3st-maintainer/
├── manifest.json
├── README.md
├── agents/
├── capabilities/
├── skills/
└── templates/
```

## Skills

- `t3mp3st-queue-audit` — classify the whole PR/issue queue before touching it.
- `t3mp3st-pr-audit` — audit a single PR with current checkout and GitHub state.
- `t3mp3st-merge-train` — merge validated PRs one at a time with post-merge
  checks.
- `t3mp3st-issue-steward` — triage and respond to open issues without jumping
  straight to implementation.

## Agents

- `t3mp3st-maintainer-steward`
- `t3mp3st-pr-auditor`
- `t3mp3st-issue-steward`
- `t3mp3st-release-integrator`

## Flows

- `t3mp3st-pr-audit-flow`
- `t3mp3st-merge-train-flow`
- `t3mp3st-issue-steward-flow`

## Templates

- `queue-audit-report.md` — full PR/issue queue state and suggested merge order.
- `pr-audit-review.md` — findings-first PR audit with SHA, checks, decision, and
  residual risk.
- `issue-response.md` — issue classification, evidence, action, and maintainer
  response draft.
- `merge-train-report.md` — per-PR merge results, stop reason, issue
  reconciliation, and next candidate.
- `maintainer-action-items.md` — owner/action/blocker/follow-up list for user
  communication and handoff.
- `public-input-threat-assessment.md` — hostile public-input preflight for
  issues, PRs, comments, reviews, and other user-authored repo content.

## Usage

Discover and inspect:

```bash
aiwg discover "t3mp3st merge train"
aiwg show skill t3mp3st-merge-train
aiwg discover "t3mp3st pr audit"
aiwg show skill t3mp3st-pr-audit
```

Deploy to configured providers:

```bash
aiwg use t3mp3st-maintainer
aiwg doctor --project-local
```
