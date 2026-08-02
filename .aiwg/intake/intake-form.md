# SDLC Accelerate Intake — T3MP3ST

**Entry mode:** Existing codebase
**Baseline revision:** `186afe6b50e365371774aa2ed7986d73eb0656db`
**Guidance:** Capture architecture and design as current state, emphasize SAD/ADRs, and test alignment between `VISION.md` and implemented code.

**Owner:** Project maintainer / vision owner (name not recorded)
**Stakeholders:** Authorized operators, researchers, maintainers, contributors, integrators, target owners, and finding recipients

## Problem Statement

Offensive-security capability is costly to assemble, difficult to coordinate, and easy to overstate. T3MP3ST provides a local-first orchestration platform that connects an operator's existing coding agent or model provider to scoped reconnaissance, exploitation, evidence, verification, and reporting workflows while retaining authorization and provenance controls.

## Stakeholders

- Authorized security operators and researchers
- Project maintainers and contributors
- Developers integrating through CLI, HTTP, library, or MCP surfaces
- Target/system owners who authorize engagements
- Recipients of verified findings and coordinated disclosures

## Current-State Scope

The implemented system is a TypeScript modular monolith with CLI, localhost War Room/API, MCP server, mission/admiral/operator orchestration, target and OPSEC controls, arsenal adapters, evidence/reporting, provider abstraction, source ingestion, and reproducible benchmarks. Stable, experimental, research, and planned capabilities remain explicitly distinct.

## Success Criteria

1. Every stable public capability claim remains re-derivable through `npm run verify-claims` and CI.
2. Networked operations reject out-of-scope public targets by default and require explicit authorization context.
3. The current-state SAD traces every core use case and names concrete implementation modules.
4. Major implemented design choices have accepted retrospective ADRs with evidence and consequences.
5. Every vision vector is classified as implemented, partial/experimental, research, or future without presenting aspiration as current state.

## Constraints

- Node.js 18+ and TypeScript/ESM
- Local-first and self-hosted operation, including connected local agents
- Real offensive tooling only for authorized targets
- Sensitive credentials/evidence remain operator-controlled
- AGPL-3.0-or-later licensing
- Existing CLI, HTTP, MCP, and benchmark interfaces require compatibility discipline

## Out of Scope for This Baseline

- Redesigning or implementing roadmap features
- Claiming hosted-service scale, enterprise certification, or production SLOs without evidence
- Treating `VISION.md` as an implemented specification

## Testing Strategy

- Required merge/release checks include install/build, lint, typecheck, deterministic tests, coverage, doctor, claims, provenance, anti-fitting, prompt audit, and smoke according to the current workflow.
- Critical scope, authorization, approval, exact-origin credential, and evidence/claim paths require negative tests and are release blocking.
- Live target/provider tests are opt-in and separated from deterministic CI.
- Repository-wide coverage is not inferred from file counts; critical-path cases and configured thresholds are authoritative.

## Data, Integrations, and Operations

- **Data classification:** Public source/docs; internal configuration/mission state; confidential or restricted credentials, target data, evidence, findings, and disclosure material.
- **External integrations:** Hosted/local reasoning providers, authenticated coding-agent CLIs, MCP clients, security tools, authorized targets, GitHub CI/collaboration, and documentation publishing.
- **Operations:** Local/self-hosted Node or Docker process; no hosted service SLO, general on-call model, or centralized telemetry is claimed.

## Owner-Validated Context

- Near-term priority includes stability, domain expansion, swarm research, and adoption; iteration plans must balance them through explicit evidence and safety gates.
- Reported scale expectation is thousands to tens of thousands of users/installations; it is owner-provided planning context, not repository telemetry.
- No additional contractual, funding, compliance, or support commitments were supplied.
- Failure behavior must be fail-safe; this does not mean all failures are acceptable or that safety/evidence defects can be waived.

## References

- @.aiwg/intake/project-intake.md — Detailed brownfield intake.
- @.aiwg/intake/option-matrix.md — Owner-validated intent and trade-offs.
- @.aiwg/intake/risk-screening.md — Initial risk register.
- @.aiwg/requirements/nfr-register.md — Measurable quality constraints.
- @.aiwg/testing/test-strategy.md — Test levels and gates.
- @README.md — Product scope and claims.
- @SECURITY.md — Authorization, safety, and reporting policy.
- @package.json — Runtime, package, and license metadata.
