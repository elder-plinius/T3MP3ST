# Team Profile for Architecture Stewardship

## Profile Status

The last-year Git history contains more than ten author identities, including likely aliases and agent identities. Exact active human staffing, contact information, availability, and on-call coverage are not established from repository evidence. Unknown names are intentionally not invented.

## Role Roster

| Role | Assigned person / handle | Timezone | Responsibilities | Required review |
| --- | --- | --- | --- | --- |
| Vision / product owner | Unassigned | Unknown | Priorities, capability maturity, roadmap intent | Maturity promotion, scope change |
| Requirements analyst | Unassigned | Unknown | UC/US/NFR quality and traceability | Requirement change |
| Architecture steward | Unassigned | Unknown | SAD, ADR lifecycle, vision alignment | Trust-boundary/persistence/surface change |
| Safety/security reviewer | Unassigned | Unknown | Scope, credentials, approvals, dangerous tools | Network/privilege/security change |
| Evaluation steward | Unassigned | Unknown | Benchmarks, provenance, fitting, claim wording | Public claim or receipt/grader change |
| Software implementer | Contributor assigned per change | Varies | Code and unit/integration tests | Peer review |
| Test architect/engineer | Unassigned | Unknown | Strategy, critical coverage, benchmark methods | Quality-gate/measurement change |
| Release integrator | Unassigned | Unknown | CI, package metadata, release evidence, rollback | Every release |
| Configuration/dependency manager | Unassigned | Unknown | Lockfile, providers, external tools, supply chain | Dependency/tool changes |
| Domain contributor | Contributor assigned per domain | Varies | Target/tool/parser-specific implementation | Domain + safety review |

Roles may be held by the same person, but a trust-boundary change must receive both architecture and safety perspectives, and a capability/benchmark claim must receive evaluation review. Self-review should be disclosed when staffing prevents separation.

## Handoff and Escalation Rules

1. Requirements changes hand off to architecture and test owners with updated identifiers and acceptance criteria.
2. New network/tool/provider paths hand off to safety and test review before release.
3. Candidate findings hand off to evidence verification before external reporting.
4. Maturity promotion hands off to architecture, safety, test, docs, and evaluation review.
5. A Critical safety/secret/claim-integrity issue stops release and escalates to maintainer plus the relevant reviewer.

## Capacity and Knowledge Risks

- Named ownership and response times are unknown, creating review and knowledge-silo risk.
- Provider/tool/benchmark breadth can exceed a single maintainer’s review depth.
- Repository/agent aliases make contribution counts unsuitable as staffing metrics.
- Mitigation: assign owners per iteration/release, record named approvals, maintain citable artifacts/tests, and use explicit handoff checklists.

## Assignment Checklist

- [ ] Assign named people/handles and timezones for the active iteration.
- [ ] Identify backup reviewer for architecture, safety, evaluation, and release.
- [ ] Record availability and response expectations without implying an unsupported SLA.
- [ ] Update iteration/deployment approval tables with the actual assignees.

## References

- @.aiwg/intake/codebase-analysis-report.md — Contributor and repository evidence.
- @.aiwg/architecture/software-architecture-doc.md — Ownership-sensitive architecture areas.
- @.aiwg/planning/iteration-001-plan.md — Role-based task allocation.
- @.aiwg/testing/test-strategy.md — Review and gate ownership.
- @.aiwg/deployment/ci-cd-scaffold.md — Release approval roles.
- @.aiwg/intake/risk-screening.md — Risks requiring explicit owners.
