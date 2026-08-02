# Non-Functional Requirements Register

## Metadata and Scope

- **Status:** Baselined for the current brownfield architecture
- **Owner:** Architecture and safety stewards
- **Review cadence:** Every iteration and whenever a trust boundary, delivery surface, provider contract, or maturity label changes
- **Measurement rule:** A requirement without a repeatable verification method is aspirational and cannot pass a phase gate.

## Requirement Register

| ID | Category | Measurable requirement | Verification and pass condition | Design source | Status |
| --- | --- | --- | --- | --- | --- |
| NFR-01 | Safety | Built-in network-capable tools must deny unrelated public hosts by default after a mission target is established. | Scope-gate negative tests pass for unrelated public destinations; no adapter bypass is accepted. | ADR-003; SAD §§5, 10 | Active |
| NFR-02 | Authorization | Real target operations require an explicit authorized target context before dispatch. | Mission/API validation and arsenal approval suites reject absent authorization context. | UC-001; ADR-003 | Active |
| NFR-03 | Provenance | Public claims and verified findings must trace to retained evidence or a reproducible versioned receipt. | Claim/finding verifiers and provenance CI gate pass; unsupported claims fail closed. | UC-005; ADR-004 | Active |
| NFR-04 | Local security | HTTP binds to loopback by default and rejects invalid Host/origin combinations. | Server static/behavior tests and Docker binding inspection pass. | UC-003; ADR-001 | Active |
| NFR-05 | Secret isolation | Target credentials and headers may be forwarded only to their configured exact origin and must be redacted from diagnostics. | Target-header and credential-redaction negative tests pass. | UC-001; ADR-003 | Active |
| NFR-06 | Portability | The core build supports Node.js 18+ and the repository’s declared desktop/server environments. | CI install, build, typecheck, and documented platform smoke checks pass. | ADR-001; ADR-002 | Active |
| NFR-07 | Compatibility | CLI, HTTP, library, MCP, provider, and evidence contracts change only with visible documentation, type, and test updates. | Contract/type tests pass and release review identifies breaking changes. | UC-002; UC-003 | Active |
| NFR-08 | Testability | Deterministic safety, parser, provider-routing, evidence, and claim paths run in CI without live targets or paid model dependencies. | Required CI jobs execute from fixtures/committed artifacts and pass. | Test strategy | Active |
| NFR-09 | Claim honesty | Experimental, research, and roadmap capabilities must not be represented as stable; benchmark claims remain corpus-scoped. | Documentation/maturity audit and claim verifier report no contradictory status. | UC-005; ADR-005 | Active; automation gap tracked |
| NFR-10 | Recoverability | Update workflows preserve configured sensitive or expensive local artifact paths and provide a clear failure result. | Update self-tests verify protected-path survival and rollback/failure behavior. | Risk R-07 | Active |
| NFR-11 | Performance | Every local-agent, planning, task, and external-tool operation has a configured finite timeout; percentile workload baselines must be recorded before performance promotion claims. | Timeout/fallback tests pass; benchmark receipt states workload, environment, and percentile when a performance claim is made. | UC-001; UC-002; UC-004 | Partially measured |
| NFR-12 | Maintainability | Any new delivery surface, persistence system, privilege boundary, provider contract, generic execution path, or maturity promotion requires an ADR and traceability update. | Architecture review checklist finds an accepted/proposed ADR and updated UC/US/NFR matrices. | SAD §10; ADR-005 | Active |

## Quality-Attribute Detail

### 1. Usability and Accessibility

- CLI, HTTP, and MCP errors must identify invalid input or unsupported behavior without exposing secrets.
- The browser surface should retain keyboard-accessible core controls; a formal WCAG conformance level is not yet claimed.
- Documentation distinguishes operator, developer, API, and MCP entry paths.

### 2. Reliability and Recoverability

- Authorization, scope, approval, origin, and evidence-verification failures fail closed.
- Timeouts bound external reasoning/tool work; retry is permitted only where a declared fallback avoids duplicate unsafe effects.
- Local reports/evidence require an operator-owned backup and retention policy; the project does not claim centralized durability.

### 3. Performance and Scale

- The current product is local/self-hosted; no hosted fleet SLO or concurrent-user capacity is claimed.
- Any future latency/throughput statement must name workload, hardware/runtime, sample count, percentile, and receipt.
- Source-ingest and concurrent mission baselines remain an explicit construction item.

### 4. Supportability and Observability

- Build, doctor, preflight, smoke, test, claim, and provenance gates provide local diagnostic layers.
- Mission/tool failures must retain enough redacted context to distinguish validation, provider, timeout, process, parse, and verification failures.
- Centralized metrics, traces, paging, and production SLO dashboards are N/A for the current self-hosted baseline; hosted evolution requires a new baseline.

### 5. Security and Privacy

- Model output, target content, imported code, external tools, and browser requests are untrusted inputs.
- Secrets must use supported configuration/environment mechanisms, never committed values.
- Evidence and disclosures may be restricted or embargoed and remain operator-controlled.
- T3MP3ST provides product controls and usage guidance; it does not claim organizational certification or legal authorization on the operator’s behalf.

### 6. Compliance and Legal Constraints

- Authorized use and coordinated disclosure are mandatory operating constraints.
- AGPL-3.0-or-later governs distribution of this repository.
- GDPR, CCPA, PCI DSS, HIPAA, CFAA, and local law applicability depends on deployment and engagement context; repository mention is not certification.

### 7. Environmental and Design Constraints

- Runtime: Node.js 18+ with TypeScript/ESM.
- Default architecture: local-first modular monolith with filesystem artifacts and no application database.
- Default HTTP exposure: loopback.
- Hosted multi-tenancy, distributed workers, or centralized retained customer data require new architecture, threat, retention, and compliance decisions.

### 8. Documentation and Localization

- Stable/experimental/research/roadmap labels must remain consistent across product and SDLC documentation.
- Interface changes update human-facing API/MCP/operator documentation in the same change.
- English is the current maintained documentation language; no localization commitment is claimed.

## Assumptions, Dependencies, and Open Issues

- Operators control host security, authorization records, evidence retention, and disclosure decisions.
- External model/tool availability and behavior are not controlled by T3MP3ST.
- Open measurements: source-ingest percentiles, concurrent mission resource profiles, and startup/shutdown timing.
- Open governance: machine-checkable maturity-label consistency and complete network-adapter safety inventory.

## Traceability Summary

| Requirement group | Use cases | Architecture decisions | Primary test evidence |
| --- | --- | --- | --- |
| Safety / authorization / secrets | UC-001 | ADR-003 | Arsenal scope/approval, target-header, redaction tests |
| Provider / portability / compatibility | UC-002, UC-003 | ADR-001, ADR-002 | Provider registry, local-agent, API hardening, typecheck |
| Evidence / honesty | UC-004, UC-005 | ADR-004, ADR-005 | Finding verification, claim, provenance, anti-fitting gates |
| Maintainability / recoverability | All | ADR-001, ADR-005 | Update self-tests, architecture and release review |

## References

- @.aiwg/requirements/UC-001.md — Scoped mission behavior.
- @.aiwg/requirements/UC-002.md — Provider and local-agent behavior.
- @.aiwg/requirements/UC-003.md — Delivery-surface behavior.
- @.aiwg/requirements/UC-004.md — Source-analysis behavior.
- @.aiwg/requirements/UC-005.md — Claim and benchmark reproducibility.
- @.aiwg/architecture/software-architecture-doc.md — Architectural tactics and traceability matrices.
- @.aiwg/testing/test-strategy.md — Verification layers and quality gates.
- @SECURITY.md — Product safety, vulnerability reporting, and authorized-use policy.
- @.github/workflows/ci.yml — Automated verification implementation.
