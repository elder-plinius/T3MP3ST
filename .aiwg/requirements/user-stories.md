# User Story Register

## Register Metadata

- **Status:** Baselined brownfield stories
- **Owner:** Product/requirements steward
- **Definition of ready:** Actor, value, scope, linked UC/NFR, testable acceptance criteria, and implementation evidence are present.
- **Definition of done:** Acceptance evidence passes; documentation and traceability are updated; no critical safety or security finding remains.

## Summary

| ID | Priority | Parent use case | Status | Story |
| --- | --- | --- | --- | --- |
| US-01 | Critical | UC-001 | Implemented | Define an authorized target and scope before execution. |
| US-02 | High | UC-001, UC-003 | Implemented | Launch and monitor a mission from supported surfaces. |
| US-03 | High | UC-002 | Implemented | Connect an authenticated local coding agent. |
| US-04 | Critical | UC-001 | Implemented | Approve or reject dangerous actions. |
| US-05 | Critical | UC-001 | Implemented | Preserve evidence behind each finding. |
| US-06 | High | UC-003 | Implemented (narrow surface) | Access supported reconnaissance through MCP. |
| US-07 | High | UC-004 | Experimental | Ingest supported source languages safely. |
| US-08 | Critical | UC-005 | Implemented | Reproduce headline claims. |
| US-09 | High | UC-005 | Implemented; continuous review | See capability maturity clearly. |
| US-10 | Critical | UC-005 | Implemented | Detect prompt, provenance, and fitting regressions in CI. |

## Story Cards

### US-01 — Define Authorized Scope

**As an** authorized operator, **I want** to define a target and allowed scope before execution **so that** real operations remain within written authorization.

- **Value:** Prevents off-target activity and creates the context required by every safety gate.
- **Scope:** Target normalization, rules of engagement, scope receipt, and pre-dispatch validation; excludes obtaining legal authorization.
- **NFRs:** NFR-01, NFR-02, NFR-05
- **Acceptance:** Given a valid target, a mission context/receipt is created; given an unrelated public host, execution is refused before dispatch; target credentials never cross origins.
- **Evidence:** Target, scope-gate, and target-header implementation/tests.

### US-02 — Launch and Monitor a Mission

**As an** operator, **I want** to launch and inspect mission state from the CLI or War Room **so that** I can control long-running work through the surface that fits my workflow.

- **Value:** Makes shared mission behavior observable without creating separate execution engines.
- **Scope:** Mission create/start/state/results through supported surfaces; excludes distributed fleet scheduling.
- **NFRs:** NFR-04, NFR-07, NFR-11
- **Acceptance:** Both surfaces reach shared mission state; invalid surface input fails before execution; timeout/failure state is visible and not reported as success.
- **Evidence:** CLI, server, mission, and local-API hardening code/tests.

### US-03 — Connect a Local Coding Agent

**As an** operator, **I want** to use an already-authenticated local coding agent **so that** mission planning can work without a new cloud API key.

- **Value:** Preserves local/keyless operation and provider choice.
- **Scope:** Discovery, selection, path resolution, request/response normalization, tool proposal handling; excludes bypassing tool controls.
- **NFRs:** NFR-05, NFR-06, NFR-08, NFR-11
- **Acceptance:** A supported local agent is resolved and selected; missing executables fail explicitly; tool proposals pass through shared scope/approval controls; credentials are not invented or exposed.
- **Evidence:** Local-agent module plus selection, path-resolution, home, tool-calling, and fallback tests.

### US-04 — Control Dangerous Actions

**As an** operator, **I want** to approve or reject dangerous actions **so that** high-impact execution reflects explicit human intent.

- **Value:** Creates a deterministic human-control boundary below model reasoning.
- **Scope:** Risk classification, approval prompt/decision, and dispatch gate; excludes making an unsafe action safe merely by approval.
- **NFRs:** NFR-01, NFR-02
- **Acceptance:** No dangerous action dispatches without approval; rejection is final for that request; approval does not bypass target scope or validation.
- **Evidence:** Arsenal approval implementation and approval-gate tests.

### US-05 — Preserve Finding Evidence

**As a** researcher, **I want** every finding to retain its evidence and verification state **so that** reports are defensible and candidates are not mistaken for verified vulnerabilities.

- **Value:** Reduces false positives and supports coordinated disclosure.
- **Scope:** Evidence capture, integrity, redaction, candidate/verified/refuted state, and report linkage.
- **NFRs:** NFR-03, NFR-05
- **Acceptance:** Verified findings link to retained evidence; redaction removes sensitive values from report paths; failed verification remains candidate/refuted.
- **Evidence:** Evidence vault/gate, analysis report, verifier/refuter, integrity and redaction tests.

### US-06 — Use Supported MCP Reconnaissance

**As an** integrator, **I want** supported reconnaissance exposed through MCP **so that** an MCP client can invoke a narrow structured capability.

- **Value:** Enables agent/tool interoperability without exposing the full internal runtime.
- **Scope:** Declared MCP tools, input schema, stdio transport, structured response; excludes undocumented mission/arsenal access.
- **NFRs:** NFR-07, NFR-08
- **Acceptance:** Valid input returns the documented structure; invalid input returns an MCP error; unsupported capabilities are not silently routed to broader APIs.
- **Evidence:** MCP server and MCP guide, validated by type/build and interface review.

### US-07 — Ingest Supported Source Languages

**As a** security researcher, **I want** supported source languages converted into bounded structural blocks **so that** white-box analysis can cite the relevant code.

- **Value:** Extends evidence-backed analysis beyond a single source language while preserving honest maturity claims.
- **Scope:** Language detection, grammar selection, bounded parsing, safe fallback, source locations; excludes universal correctness claims.
- **NFRs:** NFR-08, NFR-09, NFR-11
- **Acceptance:** Supported grammars produce located blocks; unsupported/malformed/oversized inputs fail safely; experimental maturity remains explicit.
- **Evidence:** Ingest/parser/white-box modules and grammar, adversarial, fallback, multilang, and containment tests.

### US-08 — Reproduce Headline Claims

**As a** maintainer, **I want** headline claims recomputed from versioned evidence **so that** releases do not publish stale or fabricated performance results.

- **Value:** Makes public claims auditable and regression-sensitive.
- **Scope:** Declared committed claims and receipts; excludes results whose licensed/sensitive raw source cannot be retained unless the reproduction boundary is disclosed.
- **NFRs:** NFR-03, NFR-09
- **Acceptance:** `npm run verify-claims` succeeds for consistent evidence and fails on seeded mismatch or missing required provenance.
- **Evidence:** Claim verifier, benchmark artifacts, and CI claim/provenance gates.

### US-09 — See Capability Maturity

**As a** contributor or user, **I want** each capability labeled stable, experimental, research, or roadmap **so that** I can distinguish implemented guarantees from direction.

- **Value:** Prevents architecture and product decisions from relying on aspirational claims.
- **Scope:** README/features/SAD/vision alignment and promotion criteria.
- **NFRs:** NFR-09, NFR-12
- **Acceptance:** Status is explicit and consistent in authoritative docs; promotion includes safety tests, operational path, documentation, and reproducible evidence.
- **Evidence:** Vision-alignment matrix, ADR-005, claim audit, and planned consistency automation.

### US-10 — Detect Integrity Regressions in CI

**As a** maintainer, **I want** prompt, provenance, claim, and fitting regressions to fail CI **so that** unsafe or misleading changes cannot merge silently.

- **Value:** Converts research/evidence policy into repeatable release gates.
- **Scope:** Deterministic audit jobs and seeded negative tests; excludes paid/live benchmark availability.
- **NFRs:** NFR-03, NFR-08, NFR-09
- **Acceptance:** Seeded prompt/provenance/fitting violations fail the corresponding command and required CI job; infrastructure failures remain distinct from evaluated model results.
- **Evidence:** CI workflow, anti-fitting tests, provenance gate, prompt audit, and claim verifier.

## INVEST and Readiness Assessment

The stories are independently reviewable but share cross-cutting safety constraints; each delivers operator/maintainer value, has bounded scope, and contains pass/fail acceptance signals. Story-point estimates and sprint assignment are intentionally absent because the stories describe a brownfield baseline, not a newly estimated backlog. Future change slices derived from them must be sized in the iteration plan.

## References

- @.aiwg/requirements/UC-001.md — Parent flow for US-01, US-02, US-04, and US-05.
- @.aiwg/requirements/UC-002.md — Parent flow for US-03.
- @.aiwg/requirements/UC-003.md — Parent flow for US-02 and US-06.
- @.aiwg/requirements/UC-004.md — Parent flow for US-07.
- @.aiwg/requirements/UC-005.md — Parent flow for US-08 through US-10.
- @.aiwg/requirements/nfr-register.md — Cross-cutting quality constraints.
- @.aiwg/architecture/software-architecture-doc.md — Implementing components and interfaces.
- @.aiwg/testing/test-strategy.md — Acceptance and regression strategy.
