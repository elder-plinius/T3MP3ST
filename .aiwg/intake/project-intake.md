# Project Intake Form (Existing System)

**Document type:** Brownfield system documentation
**Generated:** 2026-07-20
**Source:** Codebase analysis of `/home/roctinam/dev/bt6/T3MP3ST`

## Metadata

- **Project:** T3MP3ST — Tactical Execution Multi-agent Platform for Elite Security Testing
- **Repository:** `https://github.com/jmagly/T3MP3ST.git` (`origin`); package metadata references `elder-plinius/T3MP3ST`
- **Version:** 1.0.0 in `package.json`; analyzed revision `186afe6`
- **License:** AGPL-3.0-or-later
- **Runtime:** Node.js 18+; CI uses Node.js 22
- **Last analyzed commit:** 2026-07-20, “add reproducible cross-model benchmark matrix”
- **Stakeholders:** Maintainers, contributors, authorized security operators, security researchers, and users of supported coding agents

## System Overview

T3MP3ST is a self-hosted, multi-agent offensive-security framework for authorized testing, research, and education. It coordinates reconnaissance, exploitation, evidence, and reporting through a CLI, a browser War Room, an HTTP API, and an MCP server. It supports hosted LLM providers, connected local coding-agent CLIs, and local OpenAI-compatible inference servers.

**Current status:** Established open-source product with stable core paths, experimental subsystems, and research/roadmap modules explicitly distinguished in project documentation.

**Known audiences:**

- Authorized penetration testers and red-team operators
- Security researchers and CTF users
- Developers integrating security workflows through HTTP or MCP
- Contributors extending operators, tools, benchmarks, and target adapters

The owner reports a current/expected scale of thousands to tens of thousands of users or installations. This is planning input rather than measured repository telemetry. Commercial use, support commitments, and production fleet topology remain unverified; the owner supplied no additional contractual, funding, compliance, or support commitments.

## Current Scope and Features

Evidence in `README.md`, `FEATURES.md`, `src/`, and `bench/` shows these major capabilities:

- Multi-agent mission planning and execution with an Op Admiral coordinator
- Eight operator archetypes covering the offensive-security kill chain
- Target definition, rules of engagement, and egress-scope containment
- Tool-backed reconnaissance and exploitation adapters
- Evidence collection, findings, reports, verification, and disclosure drafting
- CLI and localhost-only browser War Room
- Express HTTP API and stdio MCP server
- Provider/model abstraction for cloud, local, and connected coding-agent execution
- White-box source ingestion for multiple programming languages
- Benchmark and claim-verification suites for XBEN, Cybench, CVE hunting, cloud, mobile, binary, and evolutionary experiments
- Docker-based runtime and isolated CTF challenge environments

The repository honestly marks cloud, mobile, binary/reverse-engineering, swarm reliability, and some advanced modules as scaffolding, experimental, or research rather than uniformly production-ready.

## Architecture

**Style:** Modular monolith with multiple delivery surfaces and externally executed tools.

**Primary components:**

- `src/cli.ts` and `src/index.ts`: command-line and library entry points
- `src/server.ts`: Express API and static War Room host
- `src/mcp-server.ts`: MCP stdio integration
- `src/orchestration/`, `src/mission/`, `src/admiral/`, `src/operators/`: planning, coordination, and mission lifecycle
- `src/arsenal/`: tool catalog, adapters, parsers, approvals, and post-exploitation support
- `src/target/`, `src/opsec/`, `src/evidence/`, `src/reporting/`: scope, safety, evidence, and deliverables
- `src/llm/`, `src/config/`: provider/model and runtime configuration
- `src/recon/`: black-box and multi-language white-box reconnaissance
- `bench/`: reproducible evaluation data and benchmark harnesses
- `ctf/`: isolated challenge manifests, executor, and containers
- `docs/` and `docsite/`: operator, developer, architecture, and release documentation

**Persistence:** Primarily local configuration and filesystem artifacts. Docker mounts `reports/` and `evidence/`. Browser settings use localStorage. No application database is evident.

**Integration points:**

- Hosted model APIs and local OpenAI-compatible inference endpoints
- Connected local coding-agent CLIs
- MCP-aware clients
- Security command-line tools and network services
- GitHub for source, collaboration, releases, and private security advisories
- Pagenary for documentation publishing

## Scale and Performance

This is primarily a local/self-hosted operator platform rather than a centrally hosted multi-tenant service. Horizontal service scaling, distributed persistence, queue infrastructure, and formal load-balancing configuration were not detected.

Performance-sensitive areas include:

- LLM request latency and provider fallback
- Mission/task timeout management
- External tool execution
- Multi-language source ingestion
- Concurrent agent/operator orchestration
- Benchmark corpus processing

Exact throughput, concurrent-task capacity, p95 latency, and resource profiles are unknown. Installation/user scale is owner-estimated rather than measured. Existing timeout controls and deterministic benchmark harnesses provide a foundation for measuring these characteristics.

## Security, Safety, and Compliance

**Posture:** Strong product-level safety and verification controls for an established open-source offensive-security tool, but not evidence of a certified enterprise control environment.

**Controls found:**

- Explicit authorized-use and written-scope requirements
- Default localhost binding for the HTTP server and Docker port
- Localhost CORS/origin and Host-header guards
- Target-origin-bound credential/header injection
- Egress-scope containment for networked tools
- Approval gating for dangerous or catalog-only tool paths
- Environment-variable secret handling and protected local paths
- Evidence, finding verification, claim provenance, and anti-fitting checks
- Private vulnerability reporting through GitHub Security Advisories
- CI lint, type, test, coverage, claim, provenance, prompt, and smoke gates

**Sensitive data potentially handled:** API keys, target authentication headers, vulnerability evidence, findings, captured credentials, private disclosure drafts, target metadata, and raw model/tool output.

**Compliance context:** The software may be used in environments subject to GDPR, CCPA, PCI DSS, HIPAA, CFAA, and local cybercrime laws, but repository references are usage guidance—not proof that T3MP3ST itself is certified for any regime.

## Team and Process

- **Repository activity:** 151 commits in the last year at analysis time
- **Contributors:** More than ten author identities appear in the last-year history; exact active human team size is unclear because bot/agent and alias identities are mixed
- **Branch/process model:** Pull-request and `main` push CI; exact branch-protection and reviewer requirements are not inferable from the local checkout
- **Tests:** 75 test/spec-named files across `src/` and `scripts/`
- **CI:** GitHub Actions runs install, lint, typecheck, tests, coverage, doctor, claim verification, anti-fitting, provenance, prompt audit, and smoke checks
- **Documentation:** Extensive README, security policy, developer/operator guides, feature status, benchmark methodology, whitepaper, and generated docsite
- **Release/operations:** Release checklist and operational preflight tooling exist; formal on-call, SLA, incident-management, and hosted-service procedures are unknown

## Dependencies and Infrastructure

- TypeScript/ESM on Node.js
- Express and CORS for the local HTTP surface
- Model Context Protocol SDK
- Commander/Inquirer and terminal UI packages for CLI interaction
- AJV for schema validation
- Undici and SOCKS networking
- Tree-sitter WASM for multi-language source ingestion
- Vitest, ESLint, and TypeScript quality tooling
- Docker/Docker Compose for the application and isolated challenge/tool environments
- GitHub Actions CI

No Kubernetes, Terraform, service mesh, managed database, centralized cache, or message queue was detected in the analyzed repository.

## Known Issues and Technical Debt

- Stable, experimental, research, and planned capabilities coexist in one product surface, increasing expectation-management and regression risk.
- Coordinated swarm exploitation remains less proven than the benchmarked single-agent path.
- White-box multi-language ingestion is explicitly experimental.
- Cloud, mobile, binary, and advanced modules remain partially scaffolded.
- The platform can execute real offensive actions, so scope enforcement and approval boundaries are continuously high-risk code.
- Local filesystem artifacts can contain sensitive engagement or pre-disclosure material.
- Eighteen TODO/FIXME/HACK/XXX markers were found in `src/` and `scripts/`; each requires triage rather than being assumed defective.
- Package and canonical tracker repository metadata point to different GitHub owners, which may confuse release provenance unless intentional and documented.

## Why This Intake Now?

The invocation supplied no additional business guidance. The evidenced purpose is to establish a current SDLC baseline from the existing codebase, preserve the distinction between shipped and aspirational capabilities, and provide a reviewable starting point for requirements, architecture, risk, and roadmap decisions.

## Owner-Validated Context and Remaining Unknowns

- Maintainer roles, staffing, and support model
- Funding or commercial model
- Production usage patterns and capacity objectives
- Formal uptime, latency, recovery, or support commitments
- Regulatory or contractual obligations of maintainers
- Near-term milestone, roadmap priority, and desired investment trade-offs

Owner input recorded in `option-matrix.md`: scale is thousands to tens of thousands; stability, expansion, swarm research, and adoption all matter; no extra formal commitments were supplied; execution should fail safely.

## Testing Strategy and Quality Thresholds

- Required CI/release gates are defined in the test strategy and workflow; all required gates must pass for the release revision.
- Scope, authorization, approval, credential routing, evidence integrity, and claim reproduction are critical paths with non-negotiable negative tests.
- Deterministic CI uses fixtures and committed evidence rather than live target or paid-model availability.
- Performance claims require workload, environment, sample, percentile, and receipt; no unmeasured SLO is accepted.

## Decision Heuristics

- Prefer local simplicity over distributed power until an evidenced deployment need justifies a new baseline.
- Prefer operator control and fail-safe refusal over automatic execution when authorization or scope is ambiguous.
- Prefer reproducible, scoped claims over broader marketing language.
- Priority weighting remains quality/security 0.35, reliability/scale 0.25, delivery speed 0.25, cost 0.15 until owners amend it.

## Next Steps

1. Validate the unknowns above with project owners.
2. Review the recommended rigor and roadmap in `solution-profile.md`.
3. Confirm priorities and trade-offs in `option-matrix.md`.
4. If accepted, use the intake as input to an Inception or continuous architecture/risk workflow. `intake-start` is not required for this generated intake.

## References

- @.aiwg/intake/intake-form.md — Concise accelerate intake and owner-validated context.
- @.aiwg/intake/solution-profile.md — Tailored rigor and roadmap.
- @.aiwg/intake/option-matrix.md — Trade-offs and recorded owner answers.
- @.aiwg/intake/risk-screening.md — Initial risks and residual exposure.
- @.aiwg/architecture/software-architecture-doc.md — Implemented architecture baseline.
- @.aiwg/testing/test-strategy.md — Required testing and gate policy.
- @README.md — Product scope and maturity claims.
- @FEATURES.md — Feature inventory.
- @SECURITY.md — Safety and vulnerability-reporting policy.
- @package.json — Package/runtime/license source.
- @.github/workflows/ci.yml — CI evidence.
