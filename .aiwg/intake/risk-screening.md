# Initial Risk Register

## Metadata and Method

- **Owner:** Project manager / safety steward (named assignee pending)
- **Review cadence:** Each iteration, release, trust-boundary change, public claim change, or serious defect
- **Scale:** Impact and likelihood use Critical/High/Medium/Low; exposure reflects pre-control combination; residual risk reflects current controls and evidence.
- **Blocking rule:** Any change that weakens authorization, default scope containment, exact-origin credentials, or required evidence/claim gates without an approved replacement control blocks release.

## Prioritized Risks

| ID | Description | Impact | Likelihood | Exposure | Mitigation / control | Owner role | Status | Residual risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R-001 | Operations exceed authorized target scope | Critical | Medium | Critical | Explicit target/RoE, scope gate, approval, adapter negative tests, release blocking | Safety reviewer | Mitigating continuously | Medium; adapter completeness must remain verified |
| R-002 | Provider/target secrets or engagement evidence leak | Critical | Medium | Critical | Environment/local config, exact-origin headers, redaction, ignored/protected paths, operator retention | Safety + release | Open residual | Medium; local host/storage policy remains operator-controlled |
| R-003 | Aspirational or corpus-scoped capability is represented as generally stable | High | High | High | ADR-004/005, maturity matrix, claim/stub/count tests, planned consistency audit | Evaluation steward | Mitigating | Medium until automated cross-doc audit exists |
| R-004 | Model/tool nondeterminism produces a false finding | High | High | High | Evidence gate, adjudication, verification/refutation, receipts and report state | Evaluation + safety | Open residual | Medium; live evidence can remain incomplete |
| R-005 | External tool/dependency compromises host or supply chain | Critical | Medium | Critical | Narrow structured adapters, approvals, container guidance, lockfile/CI review, future SBOM/signing decision | Configuration manager | Open | Medium/High depending on selected tool |
| R-006 | Modular monolith accumulates unsafe coupling | High | Medium | High | Typed seams, shared safety controls, SAD/ADRs, tests, architecture review triggers | Architecture steward | Mitigating | Medium |
| R-007 | Local artifact loss, corruption, or retention mishandling | High | Medium | High | Protected update paths, local mounts, operator backup/retention, rollback plan | Operator + release | Open | Medium; no centralized durability claim |
| R-008 | Imported code/target content or model output manipulates the agent/runtime | Critical | Medium | Critical | Treat content as untrusted, deterministic execution gates, bounded parsers, prompt audit, evidence verification | Safety reviewer | Mitigating | Medium; evolving agentic attacks require review |
| R-009 | Provider/tool timeout or infrastructure failure is reported as success/model failure | High | Medium | High | Finite timeouts, explicit error classification, fallback records, receipt outcome taxonomy | Test/evaluation | Mitigating | Low/Medium |
| R-010 | Unknown ownership/capacity delays critical review or response | High | Medium | High | Assign role owners per iteration/release; named approvals and backup reviewers | Maintainer | Open | High until roster assigned |

## Review Actions

1. Complete the machine-readable network-adapter safety/test inventory for R-001 and R-005.
2. Implement cross-document maturity consistency for R-003.
3. Define sensitive-artifact backup, retention, encryption, and disposal guidance for R-002/R-007.
4. Assign named architecture, safety, evaluation, test, and release owners for R-010.
5. Re-score after Iteration 001 evidence is available; do not mark residual risk “Low” without a cited test/control result.

## References

- @.aiwg/requirements/nfr-register.md — Risk-linked quality constraints.
- @.aiwg/architecture/adr-003.md — Scope/approval/credential control decision.
- @.aiwg/architecture/adr-004.md — Evidence and claim decision.
- @.aiwg/architecture/adr-005.md — Maturity claim decision.
- @.aiwg/architecture/software-architecture-doc.md — Trust boundaries and residual questions.
- @.aiwg/testing/test-strategy.md — Verification and release-blocking policy.
- @.aiwg/team/team-profile.md — Ownership gaps and handoff rules.
- @SECURITY.md — Authorized use and vulnerability reporting.
- @src/__tests__/arsenal-scope-gate.test.ts — R-001 control evidence.
- @src/__tests__/target-headers-static.test.ts — R-002 control evidence.
- @scripts/verify-claims.mjs — R-003 control evidence.
