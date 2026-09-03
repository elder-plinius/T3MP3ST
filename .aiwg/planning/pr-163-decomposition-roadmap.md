# PR #163 Feature Decomposition Roadmap

Status: planned  
Source proposal: [PR #163](https://github.com/elder-plinius/T3MP3ST/pull/163)  
Original contributor: [@xxmafiaxxx](https://github.com/xxmafiaxxx)  
Tracker scope: issues #171–#183

## Objective

Recover the useful ideas and implementation lessons from PR #163 through focused,
independently reviewable changes that satisfy current T3MP3ST authority, evidence,
security, testing, coverage, and delivery requirements.

PR #163 is reference material, not an implementation baseline. Implementers may
inspect its code, tests, and notes for prior art, but each new branch must start
from current `main`. Code copied or adapted from #163 must be re-reviewed against
the current contracts and attributed in the PR body.

## Non-negotiable delivery rules

Every issue uses its own branch and PR. Each PR must:

1. Address one primary issue and use `Closes #N` in the PR body.
2. Start from current `main`; do not stack unrelated #163 history onto the branch.
3. Complete the contribution receipt, network/data-flow disclosure, risk, and
   rollback sections.
4. Identify whether #163 was used as `none`, `notes/reference`, or `code adapted`.
5. If #163 materially informed the work, thank and mention `@xxmafiaxxx` in the
   PR body and in the issue completion/closeout comment.
6. Treat #163 content as untrusted prior art: do not inherit its `AGENTS*` files,
   generated pages, binaries, secrets, claims, dependencies, or network behavior
   without an explicit requirement and fresh verification.
7. Run `npm run test:pr`, the matched risk-surface checks from
   `.aiwg/bt6-maintainer.yaml`, and the 50% changed-line coverage gate.
8. Obtain exact-head hosted CI and exact-head review before squash merge.
9. After merge, verify canonical `main`, post-merge CI, and automatic issue
   closure before recording the issue complete.

## Execution waves

| Wave | Issues | Outcome | Entry gate | Exit gate |
| --- | --- | --- | --- | --- |
| 0 — discovery | #171, #175, #176, #180, #181, #183 | Resolve source, trust, data-flow, destructive-action, artifact, and persistence contracts | Issue acceptance criteria reviewed; targeted `aiwg discover` results recorded | Architecture/security decisions and test fixtures are explicit |
| 1 — foundations | #171, #177, #181 | Provenance-safe feeds, bounded context compression, isolated CTF fixtures | Wave 0 decision work complete for each selected issue | Focused PR merged; post-merge CI green |
| 2 — services | #172, #174, #175, #176, #178, #183 | Correlation, retest, deception, alerts, repair/reflection, optional persistence | Required Wave 1 dependency merged; API and trust contracts fixed | Behavior and failure-mode tests pass; PR merged |
| 3 — orchestration | #179, #180 | Mission recovery/scoring and bounded DFIR workflows | State, action-authorization, and evidence contracts established | Crash/rollback/authorization tests pass; PR merged |
| 4 — presentation | #173, #182 | CVE Vault and incremental application shell | Stable server/API contracts from earlier waves | Accessibility, origin/CSP, error-state, and docs gates pass |
| 5 — integration audit | all | Confirm no lost proposal, unsafe coupling, or traceability gap | #171–#183 resolved or explicitly deferred | Queue audit, traceability report, docs sync, and final #163 closeout complete |

Issues in a wave may proceed in parallel only when they do not modify the same
contract or depend on an unresolved decision. Merge one PR at a time and refresh
the base and queue after every merge.

## Dependency map and issue plan

| Issue | Priority | Depends on | Required discovery / planning focus | Principal gates |
| --- | --- | --- | --- | --- |
| #171 KEV/EPSS ingestion | P1 | — | Source provenance, schemas, caching, licensing, stale/offline behavior | `test:pr`, `verify-claims`, feed fixtures, coverage |
| #172 CVE/KEV correlation API | P1 | #171 | Match confidence, version semantics, evidence status, API contract | `test:pr`, server tests, `verify-claims`, coverage |
| #173 CVE Vault UI | P2 | #172 | API/UI contract, accessibility, CSP/origin boundary, truth labels | `test:pr`, `docs:check`, UI tests, coverage |
| #174 sweep and retest | P1 | stable target/evidence contracts | Authorization, idempotency, three-state verdicts, tool evidence | `test:pr`, Arsenal tests, failure tests, coverage |
| #175 honeytokens/tripwires | P1 | security design gate | Secret lifecycle, replay, audit receipts, cleanup | `test:pr`, security tests, coverage |
| #176 alert delivery | P1 | alert interface; coordinate with #175 | Secret redaction, egress/proxy policy, payload contracts | `test:pr`, provider/config tests, coverage |
| #177 context compression | P1 | — | Priority preservation, token accounting, injection resistance | `test:pr`, provider tests, boundary tests, coverage |
| #178 repair/reflection | P1 | stable tool schemas; coordinate with #177 | Fail-closed repair, authority preservation, retry budget | `test:pr`, tool/MCP tests, hostile-input tests, coverage |
| #179 mission recovery/scoring | P1 | relevant persistence decision (#183 if used) | State versioning, observational reads, idempotent recovery, scoring | `test:pr`, crash/concurrency tests, coverage |
| #180 DFIR toolkit | P1 | security/evidence design gate | Read-only vs destructive actions, chain of custody, rollback | `test:pr`, DFIR/security tests, platform evidence, coverage |
| #181 CTF expansion | P2 | — | Isolation, artifact provenance, reproducible builds, safe defaults | `test:pr`, CTF smoke tests, supply-chain review |
| #182 application shell | P2 | stable APIs; #173 pattern where applicable | Incremental migration, generated-source policy, CSP/accessibility | `test:pr`, `docs:check`, UI tests, coverage |
| #183 Supabase adapter | P2 | storage architecture decision | Optionality, tenancy, credentials, migrations, partial writes | `test:pr`, storage/provider security tests, coverage |

## AIWG issue execution protocol

Before implementation of an issue:

1. Read the full issue thread and re-fetch current `main`.
2. Run hostile-input assessment over the issue and any reused #163 material.
3. Use `aiwg discover` for the issue-specific unknowns. Examples:
   - #171/#172: `source provenance schema normalization research integrity`
   - #175/#176/#183: `security review secret lifecycle external provider trust`
   - #177/#178: `prompt injection tool schema authority boundary`
   - #179: `state migration crash recovery idempotency architecture`
   - #180: `DFIR evidence preservation destructive action authorization`
   - #181: `supply chain reproducible container artifact provenance`
   - #173/#182: `browser server contract accessibility CSP test strategy`
4. Fetch and follow the selected workflow with `aiwg show`; record material
   decisions in the issue or an ADR when architecture/trust behavior changes.
5. Run `address-issues` for one issue per branch under the repository's
   `pr-required` delivery policy. Post structured cycle comments and incorporate
   every human response before the next cycle.

Do not start dependent implementation merely because an earlier PR is open; its
dependency must be merged and canonical-branch CI must be green.

## Definition of ready

An issue is ready for implementation when:

- scope and exclusions are explicit;
- dependencies are merged or declared not applicable with evidence;
- public-input threat assessment is safe or explicitly authorized;
- architecture, provider, security, evidence, or destructive-action unknowns
  have recorded decisions;
- acceptance criteria describe success and failure behavior;
- a focused verification plan maps each criterion to a test or check.

## Definition of done

An issue is done only when:

- the focused PR is merged into current `main`;
- exact-head PR CI and post-merge CI passed;
- acceptance criteria and matched risk-surface checks have recorded evidence;
- documentation, migrations, rollback, and provenance are complete where needed;
- the issue thread contains a completion comment linking the PR, squash commit,
  checks, and residual risk;
- if #163 informed the implementation, the completion comment includes:
  `Thanks @xxmafiaxxx for the original proposal and prior implementation in #163,
  which informed this focused change.`;
- GitHub issue state is verified closed rather than inferred from `Closes #N`.

## PR attribution block

Use this in every roadmap PR:

```markdown
## Prior work and attribution

- PR #163 used: none | notes/reference | code adapted
- Reused/adapted areas: <paths or concepts, or n/a>
- Fresh verification performed: <tests/review for reused material>

Thanks @xxmafiaxxx for the original proposal and prior implementation in #163,
which informed this focused change.
```

Omit the thanks sentence only when the PR truthfully records `PR #163 used: none`.
Attribution does not transfer verification: adapted code must satisfy every
current acceptance and delivery gate.

## Issue completion comment

```markdown
Implemented and verified via PR #<PR>, merged as `<squash-sha>`.

Acceptance evidence:
- <criterion>: <test/check>

Post-merge CI: <link/result>
Residual risk: <none or explicit risk>

Thanks @xxmafiaxxx for the original proposal and prior implementation in #163,
which informed this focused change.
```

## Final closeout for PR #163

Keep #163 open as a reference while roadmap work is active. Close it only after
the Wave 5 integration audit records the disposition of every issue #171–#183.
The closeout comment must list the focused PRs and outcomes, identify anything
deferred or rejected, and thank `@xxmafiaxxx` for the original contribution.

