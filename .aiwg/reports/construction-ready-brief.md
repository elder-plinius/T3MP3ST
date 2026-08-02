# Construction Ready Brief

**Project:** T3MP3ST
**Date:** 2026-07-20
**Status:** CONDITIONALLY CONSTRUCTION READY — brownfield architecture alignment

## Executive Summary

T3MP3ST is baselined as a local-first TypeScript modular monolith with CLI, library, localhost War Room/API, MCP, provider-neutral reasoning, mission/operator orchestration, deterministic target/arsenal safety controls, evidence/reporting, source analysis, and reproducible evaluation. The architecture documents what is implemented and explicitly refuses to equate `VISION.md` with current capability.

The highest-value construction work is architectural governance around existing code: validate the SAD/ADRs, automate maturity-claim consistency, complete the safety-test inventory for network adapters, and establish workload baselines. No rewrite or microservice migration is implied.

## Artifact Index

| Artifact | Status |
| --- | --- |
| Intake form, solution profile, option matrix, risk screening | Baselined |
| LOM gate | PASS |
| UC-001–UC-005, user stories, NFR register | Baselined |
| Current-state SAD | Baselined |
| ADR-001–ADR-005 | Accepted / retrospective |
| Vision-to-code alignment matrix | Baselined |
| Test strategy | Baselined |
| ABM gate | PASS |
| Iteration 001, team profile, CI/CD additions | Ready |

## Key Decisions

1. Retain a local-first modular monolith.
2. Keep reasoning provider-neutral and untrusted.
3. Enforce scope/approval beneath model reasoning.
4. Derive public claims from versioned evidence.
5. Separate implemented current state from research vision.

## Risks to Watch

Scope bypass, secret/evidence leakage, maturity overstatement, nondeterministic false findings, and external-tool supply-chain risk remain the leading concerns. See `intake/risk-screening.md` for controls and residual status.

## First Steps

1. Maintainers review the SAD and mark any ADR amended or superseded.
2. Execute Iteration 001 architecture-alignment work.
3. Preserve current CI gates while adding traceability/maturity checks.
4. Update the alignment matrix whenever a vision capability changes maturity.

## Readiness Conditions

- Named maintainers must review and record accept/amend/supersede outcomes for the SAD and ADRs.
- The adapter safety inventory, maturity consistency audit, and workload baselines remain Iteration 001 work; they are not described as complete controls.
- Any implementation change follows the test and deployment gates; documentation-only readiness does not waive runtime verification.

## References

- @.aiwg/reports/lom-gate-report.md — Lifecycle objective gate and conditions.
- @.aiwg/reports/abm-gate-report.md — Architecture baseline gate and conditions.
- @.aiwg/architecture/software-architecture-doc.md — Current architecture baseline.
- @.aiwg/architecture/vision-alignment.md — Maturity evidence.
- @.aiwg/requirements/nfr-register.md — Quality constraints.
- @.aiwg/testing/test-strategy.md — Construction/release verification.
- @.aiwg/planning/iteration-001-plan.md — First construction-alignment iteration.
- @.aiwg/intake/risk-screening.md — Residual risks.
