# Option Matrix (Project Context and Intent)

**Purpose:** Capture what the project is and expose the decisions that owner input must complete.
**Generated:** 2026-07-20

## Project Reality

T3MP3ST is a mature, self-hosted TypeScript offensive-security platform with a local browser UI, CLI, HTTP API, MCP integration, external security-tool adapters, reproducible benchmarks, and extensive documentation. Its stable core operates real tools against authorized targets, while selected multi-agent, domain-specific, and evolutionary capabilities remain experimental or planned.

### Audience and Scale

| Attribute | Current evidence | Confidence |
| --- | --- | --- |
| Audience | Authorized operators, researchers, CTF users, developers, contributors | High |
| Distribution | Open-source package/repository, self-hosted execution | High |
| Active users/installations | Owner reports thousands to tens of thousands; no repository telemetry verifies the count | Owner input / unmeasured |
| Support expectations | Documentation and security-response target exist; no general SLA found | Medium |
| Geographic reach | Public open-source distribution implies global reach | Medium |
| Runtime concurrency | Local missions and agent/tool tasks; fleet scale unknown | Medium |

### Deployment and Infrastructure

| Attribute | Current state |
| --- | --- |
| Deployment model | Hybrid local application: CLI + browser UI/API + MCP + external tools |
| Hosting | Developer/operator workstation or Docker host; HTTP binds to loopback by default |
| Persistence | Local config, browser localStorage, reports, evidence, benchmark artifacts |
| Application database | None detected |
| CI/CD | GitHub Actions quality pipeline; no hosted-production deployment pipeline detected |
| Complexity | Modular monolith with many external integrations and high-risk execution boundaries |

### Technical Complexity

- Approximately 46,129 lines across 111 TypeScript files under `src/`
- 1,665 tracked files, dominated by committed JSON benchmark artifacts
- TypeScript primary; supporting JavaScript/MJS, shell, YAML, Python, C, Java, Go, Rust, Perl, HTML, and container definitions
- 75 test/spec-named files in `src/` and `scripts/`
- 52 Markdown documentation files across `docs/` and `docsite/`
- High-risk factors: real offensive operations, credentials, external tools, network access, sensitive evidence, model nondeterminism, multi-provider compatibility, and public benchmark claims

## Constraints and Context

### Known

- AGPL-3.0-or-later open-source licensing
- Node.js 18+ runtime and Node.js 22 CI
- Local-first/keyless operation is a core product promise
- Authorized use and target scope are non-negotiable safety constraints
- Claims are expected to be reproducible from committed evidence
- Stable versus experimental status must remain explicit
- The project supports a heterogeneous contributor base and multiple provider/runtime environments

### Unknown or Unverified

- Maintainer availability and budget
- Measured user/install telemetry and observed growth rate
- Revenue or funding model
- Contractual obligations and general support SLA
- Formal compliance or certification objectives
- Release cadence and next milestone
- Current highest-priority pain point

## Priorities and Trade-offs

The codebase supports this provisional weighting, which must be validated by owners:

| Criterion | Provisional weight | Evidence-based rationale |
| --- | ---: | --- |
| Quality and security | 0.35 | Real offensive actions, secrets, evidence, authorization, and reputation risk |
| Reliability and scale | 0.25 | Mission orchestration and tool/model execution must fail safely; actual fleet scale is unknown |
| Delivery speed | 0.25 | Active roadmap and competitive research space favor iteration |
| Cost efficiency | 0.15 | Local/keyless operation is a product value, but maintainer budget is unknown |
| **Total** | **1.00** | Provisional only |

**Optimizing for:** Credible, reproducible offensive-security capability that remains safe-by-default and accessible through infrastructure users already possess.

**Likely acceptable trade-off:** Experimental capabilities may iterate before they are fully reliable if maturity is conspicuous and shared safety boundaries remain enforced.

**Non-negotiable:** Authorization, target containment, secret protection, evidence integrity, honest capability claims, and human control over disclosure or materially dangerous actions.

## Decision Options

| Option | Description | Benefits | Risks | Best fit |
| --- | --- | --- | --- | --- |
| A. Stabilize the core | Concentrate on existing stable paths, safety boundaries, docs, and release quality | Highest trust and lower regression surface | Slower domain expansion | Reliability or adoption is the immediate goal |
| B. Incremental expansion | Promote one experimental domain at a time using explicit benchmark and safety gates | Balanced learning and credibility | Requires disciplined promotion criteria | Default recommendation from code evidence |
| C. Swarm-first research | Prioritize multi-agent coordination and evolutionary capability | Differentiated research upside | Cost, nondeterminism, and safety complexity | Research funding and tolerance are explicit |
| D. Hosted/enterprise evolution | Add centralized service operations, tenancy, governance, and compliance | Broader organizational adoption | Major architecture and operating-model change | Real customer demand and resources exist |

## Framework Application

**Recommended now:**

- Full rigor for core safety, release, provenance, and claim-bearing paths
- Moderate rigor for experimental modules
- Architecture decisions for trust boundaries and maturity promotion
- Continuous security, architecture, risk, and test-strategy cycles
- Operational runbooks for local server, agent/provider failures, external tools, and sensitive artifacts

**Defer unless triggered:**

- Enterprise governance and formal change boards
- Hosted multi-tenant architecture
- Multi-region infrastructure and centralized observability
- Formal compliance certification work

**Adaptation triggers:**

- Hosted service or centrally retained user/target data
- Contractual SLA or regulated customer requirement
- Material growth in maintainers or release frequency
- Dangerous-tool surface expansion
- Experimental capability promoted to stable
- Public claims not fully covered by deterministic verification
- Significant user/install growth or recurring production incidents

## Owner Validation Needed

To finalize intent rather than infer it from code, owners should answer:

1. What decision or milestone triggered this intake?
Transition to AIWG memory system

2. Which matters most for the next release: stability, domain expansion, swarm research, or adoption?
all of the above

3. What is the current user/install scale and expected 12-month change?
thousands to tens of thousands

4. What failures would be unacceptable beyond the documented authorization constraints?
none, failsafe patterns always

5. Are there contractual, funding, compliance, or support commitments not represented in the repository?
no

## Decision Record

- **Selected posture:** Balanced portfolio across stability, incremental domain expansion, swarm research, and adoption.
- **Governing constraint:** Fail-safe behavior; authorization, scope, secrets, evidence integrity, and honest claims remain non-negotiable.
- **Scale input:** Thousands to tens of thousands of users/installations, treated as owner-supplied planning context until telemetry supports a measured claim.
- **Commitments:** No additional contractual, funding, compliance, or support commitments supplied.
- **Architecture effect:** Continue local-first modular baseline; hosted/distributed work requires a new decision rather than inference from adoption goals.

## References

- @.aiwg/intake/project-intake.md — Detailed codebase-derived context.
- @.aiwg/intake/solution-profile.md — Recommended rigor and roadmap.
- @.aiwg/intake/risk-screening.md — Non-negotiable risk constraints.
- @.aiwg/architecture/adr-005.md — Maturity/current-state policy.
- @.aiwg/planning/iteration-001-plan.md — Near-term balanced governance work.
- @README.md — Public product scope.
- @VISION.md — Research direction.
