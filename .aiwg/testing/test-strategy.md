# Test Strategy — Architecture Baseline

## Metadata

- **Status:** Baselined for brownfield construction
- **Owner:** Test architect / maintainer
- **Scope:** Deterministic product, safety, evidence, claim, adapter, and release verification
- **Review cadence:** Each release and after a trust-boundary, surface, provider, parser, grader, or maturity change

## 1. Context and Objectives

T3MP3ST combines model reasoning, real security tools, local HTTP/MCP/CLI surfaces, imported target/source content, sensitive evidence, and public benchmark claims. Testing therefore prioritizes failures that could cause off-scope action, secret leakage, false findings, misleading claims, or incompatible surfaces.

### Quality Goals

- Zero accepted regressions in target scope, explicit authorization, dangerous-action approval, or exact-origin credential controls.
- Zero unsupported public claims passing deterministic claim/provenance gates.
- All required CI build, lint, type, deterministic test, claim, provenance, anti-fitting, prompt, and smoke jobs pass before release.
- New or changed critical safety logic receives branch-complete positive and negative cases; repository-wide percentage alone cannot waive missing critical-path cases.
- Deterministic CI does not require a live target or paid model.

## 2. Test Levels and Scope

| Level | Scope | Target / pass condition |
| --- | --- | --- |
| Unit | Normalization, predicates, parsers, configuration, provider selection, evidence transforms | All changed logic and critical branches pass |
| Contract | CLI/HTTP/MCP schemas, provider adapters, tool argv/output, receipts/findings | Supported success/error shapes remain compatible or intentionally versioned |
| Integration | Mission lifecycle, connected-agent fallback, server guards, controlled tool execution | Cross-component behavior preserves UC/NFR invariants |
| Security | Scope, approval, credentials, injection, Host/origin, malicious content | All seeded negative cases refuse/redact/fail closed |
| Benchmark/provenance | Claims, grading, ground truth, receipts, fitting | Deterministic recomputation matches declared results and detects seeded defects |
| Operational | Build, doctor, preflight, smoke, Docker health, updater preservation | Commands complete successfully in declared environment |

Live target/provider benchmarks are opt-in and remain separate from deterministic merge gates. Third-party library internals are out of scope; their integration and supply-chain behavior are in scope.

## 3. Automation Strategy and Tools

| Concern | Tool / location | Automation |
| --- | --- | --- |
| TypeScript unit/integration | Vitest, `src/__tests__/` | CI-gated |
| Coverage | V8 coverage | CI-gated according to repository config; critical paths additionally reviewed by case |
| Static quality | TypeScript and ESLint | CI-gated |
| Script/verifier tests | `scripts/test-*.mjs` | CI-gated for required suites |
| Claims/provenance/fitting | Claim/finding/provenance/anti-fitting scripts | CI-gated |
| Operational readiness | doctor, preflight, smoke, Docker health | CI/release-gated as declared |
| Live benchmarks | Benchmark-specific harnesses | Manual/opt-in with receipts, then deterministic grading |

Test fixtures must be versioned, non-secret, minimized, and attributable. Live output never replaces deterministic test data without review and sanitization.

## 4. Test Techniques

- **Risk-based:** Critical trust boundaries receive negative/adversarial cases before breadth features.
- **Boundary and equivalence partitioning:** Hosts/origins, paths, file sizes, timeouts, model/provider options, tool risk classes.
- **Contract testing:** Tool adapters, provider responses, HTTP/MCP shapes, receipt/finding formats.
- **Property/invariant testing where valuable:** Scope relationships, normalization, parser containment, redaction.
- **Seeded-failure testing:** Claim mismatch, provenance loss, self-fitting, prompt-policy regression, malformed output.
- **Regression testing:** Every fixed safety, evidence, or compatibility defect gains a stable reproducer.

## 5. Environment and Test Data Strategy

| Environment | Purpose | Data | External dependencies |
| --- | --- | --- | --- |
| Local development | Fast focused tests and debugging | Fixtures/mocks | None by default |
| CI | Required deterministic gates | Committed fixtures, manifests, receipts | No live target/paid model |
| Local Docker | Application/health smoke | Synthetic/local artifacts | Docker runtime |
| Isolated challenge harness | Tool/benchmark evaluation | Authorized challenge corpora | Explicit containers/tools |
| Live evaluation | Provider/target-specific research | Authorized target and retained receipt | Opt-in; outcome classifies infrastructure separately |

Sensitive target credentials, embargoed evidence, and third-party corpora are not copied into ordinary fixtures. Redacted/minimal reproductions are preferred.

## 6. Defect Management

| Severity | Definition | Release treatment |
| --- | --- | --- |
| Critical | Scope/authorization/credential bypass, destructive unsafe execution, published secret, fabricated required claim | Immediate stop; release blocked |
| High | Core mission/provider/evidence path broken; false verified finding; security control materially weakened | Release blocked until fixed or explicitly removed from release scope |
| Medium | Supported non-critical path degraded with safe workaround | Must be tracked and risk-accepted for release |
| Low | Cosmetic/documentation/ergonomic issue without misleading claim | Backlog or planned release fix |

Every defect record should include reproduction, expected/actual behavior, environment, affected UC/NFR, security/claim impact, and regression test.

## 7. Metrics and Reporting

| Metric | Target | Source |
| --- | --- | --- |
| Required CI gate pass rate | 100% for release commit | CI workflow |
| Critical safety invariant coverage | 100% of cataloged network/approval/credential paths mapped to tests | Safety inventory (open action) |
| Claim/provenance seeded-defect detection | 100% | Verifier self-tests |
| Flaky required tests | 0 tolerated as silently retried success | CI history / issue tracking |
| Source-ingest and mission workload percentiles | Baseline not yet established | Planned benchmark receipts |
| Open Critical/High defects | 0 at release | Canonical tracker |

Percentages must include numerator, denominator, command, revision, and environment. No health score is estimated from missing telemetry.

## 8. Governance and Quality Gates

| Gate | Blocking criteria |
| --- | --- |
| Pull request | Build/type/lint/tests pass; changed contracts/docs/tests align; no new unsupported claim |
| Safety change | Negative scope/approval/credential/argument cases pass; safety review complete |
| Parser/source change | Grammar, adversarial, fallback, multilang, containment, and limit tests pass |
| Claim/benchmark change | Corpus/ground truth/receipt/grader provenance passes; anti-fitting passes |
| Release | Required CI and smoke pass; Critical/High defects absent; maturity labels and docs reviewed |

## 9. Risk-Based Mapping

| Decision / requirement | Primary evidence |
| --- | --- |
| ADR-001 / NFR-04/06/07 | Build/type, entry-surface, local API hardening, Docker configuration |
| ADR-002 / UC-002 | Provider registry, provider-specific, base-URL, local-agent, fallback/timeout tests |
| ADR-003 / NFR-01/02/05 | Scope, approval, exact-origin, argument, proxy, redaction negative tests |
| ADR-004 / NFR-03 | Claims, finding verification/refutation, provenance, grading, anti-fitting |
| ADR-005 / NFR-09/12 | Stub/count honesty, vision alignment, claim audit; maturity consistency automation open |

## 10. Compliance, Retention, and Standards

- Test activity must remain authorized and isolate live/challenge operations.
- Test outputs containing credentials, evidence, or undisclosed vulnerabilities follow local retention/redaction/embargo policy.
- CI and release logs are evidence only for the revision/environment they identify.
- OWASP guidance is relevant to the local HTTP and input-validation surfaces, but no formal certification claim is made.

## 11. Continuous Improvement and Open Gaps

1. Build a machine-readable inventory from every network-capable adapter to scope, approval, argument, timeout, and credential tests.
2. Establish source-ingest and concurrent mission workload/resource percentiles with versioned receipts.
3. Add a machine-checkable maturity-consistency audit across README, FEATURES, SAD, and vision alignment.
4. Record flaky-test and defect-escape trends rather than assuming them from a single run.

Production incidents, benchmark disputes, and escaped defects must produce a test-gap analysis and regression case where reproducible.

## References

- @.aiwg/requirements/UC-001.md — Mission safety acceptance behavior.
- @.aiwg/requirements/UC-002.md — Provider/local-agent acceptance behavior.
- @.aiwg/requirements/UC-003.md — Surface contract behavior.
- @.aiwg/requirements/UC-004.md — Parser and containment behavior.
- @.aiwg/requirements/UC-005.md — Claim reproduction behavior.
- @.aiwg/requirements/nfr-register.md — Measurable quality requirements.
- @.aiwg/architecture/software-architecture-doc.md — Components and test seams.
- @.github/workflows/ci.yml — Automated gate implementation.
- @src/__tests__/arsenal-scope-gate.test.ts — Scope-containment test evidence.
- @src/__tests__/arsenal-approval-gate.test.ts — Approval test evidence.
- @scripts/verify-claims.mjs — Claim-verification implementation.
