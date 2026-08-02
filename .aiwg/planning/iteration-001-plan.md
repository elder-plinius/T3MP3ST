# Iteration 001 Plan — Architecture Alignment

## 1. Iteration Overview

- **Iteration:** 001
- **Phase:** Brownfield Construction / governance alignment
- **Status:** Planned; dates and named staffing require maintainer assignment
- **Goal:** Make current-state architecture, safety traceability, maturity claims, and workload evidence maintainable automated governance assets.

## 2. Goals and Evaluation Criteria

| Goal | Pass condition |
| --- | --- |
| Validate baseline decisions | Maintainer review records accept/amend/supersede outcome for SAD and ADR-001–005. |
| Automate maturity consistency | CI or a documented release check detects contradictory stable/experimental/research/roadmap labels. |
| Complete adapter safety inventory | Every network-capable adapter maps to scope, approval class, credential behavior, timeout, and negative tests. |
| Establish workload evidence | Source-ingest and concurrent-mission baseline receipts state revision, command, workload, environment, samples, and percentiles. |
| Triage debt markers | Each in-scope marker is actionable, intentional, or obsolete with owner/disposition. |

## 3. Scope of Work

**In scope:** SDLC artifact review; canonical repository identity decision; maturity audit design/implementation; adapter safety/test mapping; workload benchmark design/execution; debt-marker triage.

**Out of scope:** Microservice rewrite, hosted multi-tenancy, roadmap feature implementation, unsupported stability promotion, or live offensive testing beyond authorized benchmark environments.

## 4. Task Breakdown

| ID | Task | Owner role | Dependencies | Estimate | Deliverable |
| --- | --- | --- | --- | --- | --- |
| I001-01 | Review SAD and ADR-001–005; record conditions | Architecture steward + maintainer | None | 1 day | Review log / amended ADR status |
| I001-02 | Reconcile package and canonical tracker repository identity | Release integrator | Owner decision | 0.5 day | Metadata ADR/change |
| I001-03 | Specify maturity vocabulary, sources, and conflict rules | Requirements + evaluation steward | ADR-005 | 0.5 day | Decision table/spec |
| I001-04 | Implement maturity consistency audit and seeded tests | Implementer + test engineer | I001-03 | 1–2 days | Script, tests, CI/release hook |
| I001-05 | Inventory network-capable adapters and risk metadata | Safety reviewer | Arsenal catalog | 1 day | Safety coverage matrix |
| I001-06 | Close missing scope/approval/credential/timeout tests | Implementer + safety reviewer | I001-05 | 1–3 days | Tests and adapter fixes |
| I001-07 | Define source-ingest/concurrency workloads and metrics | Test architect | NFR-11 | 0.5 day | Benchmark specification |
| I001-08 | Run baselines and retain receipts | Test engineer | I001-07 | 1 day | Versioned baseline report/receipt |
| I001-09 | Triage source/script TODO/FIXME/HACK markers | Maintainer | Code inventory | 0.5 day | Triage list / issues |

## 5. Milestones and Deliverables

1. **M1 — Baseline accepted:** Review outcomes and repository identity decision recorded.
2. **M2 — Governance automated:** Maturity audit passes valid state and fails seeded contradiction.
3. **M3 — Safety inventory complete:** No unidentified network adapter; test gaps have owners or fixes.
4. **M4 — Measurements retained:** Baseline receipts are reproducible and cited by NFR/test artifacts.

## 6. Resource Allocation

Roles may be combined, but architecture and safety review must be explicit for trust-boundary work. Capacity is not assumed; maintainers must assign names and dates before iteration start. Parallelize I001-03/I001-05/I001-07 only after I001-01 establishes the governing baseline.

## 7. Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Owner review unavailable | Keep retrospective status explicit; do not fabricate approval; defer status promotion. |
| Adapter inventory misses dynamic paths | Derive from catalog plus runtime tool registration and seed a completeness test. |
| Benchmarks vary by host/provider | Record environment and separate deterministic/local/live outcomes. |
| Maturity rules create false positives | Use an explicit decision table, authoritative-source precedence, and seeded examples. |

## 8. Dependencies

- Upstream: accepted requirements/NFRs, SAD, ADR-003/004/005, canonical tracker config.
- External: maintainer decision on repository identity and review conditions.
- Downstream: release quality gates, construction-ready status, future capability promotion.

## 9. Testing and Validation Plan

- Run build/type/lint and affected Vitest/script suites for any implementation change.
- Seed at least one contradictory maturity label and one unclassified network adapter to prove new audits fail.
- Validate benchmark receipts by rerunning their documented command on the recorded environment or classify non-portability.
- Run `git diff --check`, AIWG citation/reference checks, and traceability/index diagnostics before closure.

## 10. Change Control

Scope changes require a recorded rationale, impact on goals/dates/risks, and maintainer approval. A request to implement a hosted/distributed/autonomous architecture exits this iteration and starts new inception/architecture work.

## 11. Review and Retrospective

At iteration close, review each pass condition, unresolved risk, and deferred measurement. Record what automation caught, false positives, missing evidence, and any required template/process updates. Dates are scheduled when maintainers assign capacity.

## References

- @.aiwg/architecture/software-architecture-doc.md — Open architecture questions and review log.
- @.aiwg/architecture/adr-003.md — Adapter safety controls.
- @.aiwg/architecture/adr-005.md — Maturity governance.
- @.aiwg/requirements/nfr-register.md — NFR-09, NFR-11, and NFR-12.
- @.aiwg/testing/test-strategy.md — Required test and measurement policy.
- @.aiwg/intake/risk-screening.md — Risks driving iteration priority.
- @package.json — Repository/package identity and scripts.
- @src/arsenal/catalog.ts — Adapter inventory source.
