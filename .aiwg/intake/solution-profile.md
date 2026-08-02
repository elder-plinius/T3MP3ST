# Solution Profile (Current System)

**Document type:** Existing system profile
**Generated:** 2026-07-20

## Current Profile

**Profile:** Established production-grade open-source tool with experimental and research subsystems.

This classification reflects the repository rather than an unknown hosted deployment:

- Stable CLI, mission engine, War Room, HTTP API, MCP, arsenal, and benchmark paths are documented.
- The project has a 1.0.0 package version, active contributors, comprehensive CI, Docker packaging, and release procedures.
- Real network and exploitation operations create materially higher safety and security obligations than an ordinary local developer tool.
- Several domains and coordinated-agent behaviors are still explicitly experimental, scaffolded, or research-stage.

## Current-State Assessment

### Security and Safety

**Level:** Strong for a self-hosted offensive-security project; enterprise certification is unverified.

Strengths include localhost defaults, target-bound authentication, scope containment, approvals, authorization doctrine, secret hygiene, private disclosure, provenance, and deterministic verification gates.

Material risks remain around dangerous tool execution, third-party binaries, target secrets, sensitive evidence, prompt/model behavior, and the gap between declared and technically enforced rules of engagement.

### Reliability and Observability

**Level:** Moderate.

Health endpoints, Docker health checks, timeout controls, structured mission state, smoke tests, preflight checks, and benchmark receipts are present. No repository evidence establishes production SLOs, centralized metrics/traces, alerting, fleet telemetry, backup/restore objectives, or an on-call model.

### Testing and Quality

**Level:** Strong.

GitHub Actions runs broad deterministic gates. The repository includes Vitest tests plus many dedicated script-level self-tests and benchmark verifiers. Coverage thresholds explicitly protect multi-language ingest files. A repository-wide coverage percentage was not assumed because the intake did not execute the full coverage suite and the configuration scopes strict thresholds to selected files.

### Documentation

**Level:** Strong.

The project includes operator and developer guides, API/MCP documentation, security and authorization policies, feature maturity labels, benchmark methodology, release guidance, a whitepaper, and a generated docsite.

### Architecture and Maintainability

**Level:** Moderate-to-strong.

The modular TypeScript structure separates orchestration, operators, tools, targets, evidence, reporting, providers, and delivery surfaces. Complexity is elevated by the broad domain surface, external-tool adapters, multiple model/provider modes, live security actions, benchmark code, and the coexistence of stable and experimental paths.

### Delivery and Operations

**Level:** Moderate.

Docker, GitHub Actions, release checklists, update tooling, doctor/preflight commands, and documentation publishing exist. The application is designed primarily for self-hosting; deployment automation beyond local Docker and CI is not evidenced.

## Recommended Profile

Adopt a **full SDLC rigor level for core safety boundaries and releases**, with **moderate, evidence-driven rigor for experimental modules**.

Core areas needing full rigor:

- Scope and authorization enforcement
- Credential and evidence handling
- Dangerous-tool approvals
- Mission execution and target containment
- Public benchmark and capability claims
- Release provenance and supply-chain controls

Experimental modules should use lighter iteration while retaining explicit maturity labels, threat analysis, tests around shared safety boundaries, and benchmark criteria before promotion to stable.

## Improvement Roadmap

### Immediate

1. Validate owner-only unknowns: users, deployment patterns, support commitments, roadmap, and compliance obligations.
2. Reconcile or document the intentional distinction between package repository metadata and the configured canonical tracker remote.
3. Triage the 18 source/script debt markers and classify each as actionable, intentional, or obsolete.
4. Define promotion criteria for every experimental/scaffolded domain: functional test, safety gate, benchmark receipt, docs, and rollback path.

### Near Term

1. Publish a concise architecture decision record for trust boundaries across UI/API, local agents, model providers, arsenal tools, target systems, and artifact storage.
2. Define measurable reliability targets for local server health, mission/task timeout behavior, provider fallback, and artifact durability.
3. Add a documented sensitive-artifact lifecycle covering retention, redaction, encryption expectations, backups, and coordinated-disclosure material.
4. Map CI gates to risks and public claims so maintainers can see which control prevents which failure.

### Longer Term

1. Establish an explicit maturity/promotion lifecycle from scaffolded → experimental → stable.
2. Add workload and concurrency benchmarks for mission orchestration and source ingestion.
3. Introduce release provenance controls appropriate to the threat model, such as signed tags/artifacts and dependency/SBOM policy, if not already handled outside the repository.
4. Revisit governance rigor when maintainer count, external integrations, hosted operation, contracts, or regulated usage grows.

## Tailoring

Recommended AIWG components:

- Intake, architecture decisions, risk register, security requirements, threat model, test strategy, release/deployment plan, and operational runbook
- Continuous architecture, security-review, requirements-evolution, and risk-management workflows
- Traceability focused on safety controls and externally advertised claims

Lower-value components until owner context changes:

- Enterprise organizational governance, legal RACI, or formal change-control boards
- Multi-region hosted-service artifacts
- Database migration plans for an application database that does not currently exist

Revisit those exclusions if the project becomes a hosted service, assumes contractual SLAs, processes centrally retained customer data, or grows into a larger formal organization.

## Decision Criteria and Verification

| Profile claim | Evidence required to retain classification |
| --- | --- |
| Stable core | Supported operational path, deterministic critical tests, maintained docs, release gate |
| Experimental subsystem | Explicit label, bounded safety controls, test scope, limitations, no stable SLA implication |
| Strong testing | Current required CI passes; critical path mapping is complete; no metric inferred from file counts |
| Moderate reliability | Health/timeout/smoke evidence exists while hosted SLO/telemetry claims remain absent |
| Strong product safety | Scope/approval/origin negative tests pass and adapter inventory has no uncovered path |

## References

- @.aiwg/intake/project-intake.md — Brownfield evidence and constraints.
- @.aiwg/intake/option-matrix.md — Owner priorities and scale context.
- @.aiwg/intake/risk-screening.md — Risk exposure and controls.
- @.aiwg/requirements/nfr-register.md — Measurable quality attributes.
- @.aiwg/architecture/software-architecture-doc.md — Current-state architecture.
- @.aiwg/architecture/vision-alignment.md — Maturity classification.
- @.aiwg/testing/test-strategy.md — Testing profile evidence.
- @.github/workflows/ci.yml — CI implementation.
