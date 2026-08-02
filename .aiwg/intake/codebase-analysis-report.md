# Codebase Analysis Report

**Project:** T3MP3ST
**Directory:** `/home/roctinam/dev/bt6/T3MP3ST`
**Generated:** 2026-07-20
**Revision:** `186afe6b50e365371774aa2ed7986d73eb0656db`

## Summary

- **Tracked files:** 1,665
- **Primary implementation:** TypeScript/Node.js ESM
- **Source size:** 111 TypeScript files and approximately 46,129 lines under `src/`
- **Test indicators:** 75 test/spec-named files in `src/` and `scripts/`
- **Documentation:** 52 Markdown files in `docs/` and `docsite/`
- **Architecture:** Modular monolith with CLI, localhost web/API, MCP, model/provider, agent orchestration, tool adapters, evidence/reporting, and benchmark subsystems
- **Profile:** Established open-source security product with stable core and explicitly experimental/research modules
- **Team signal:** More than ten author identities and 151 commits in the last year; exact active human team size is unknown

## Evidence-Based Inferences

### High Confidence

- T3MP3ST is an authorized-use offensive-security platform (`README.md`, `SECURITY.md`).
- The runtime is Node.js/TypeScript and package version is 1.0.0 (`package.json`).
- Users can operate through CLI, browser War Room/API, and MCP (`package.json`, `src/`, developer docs).
- The server and Docker deployment bind to loopback by default (`docs/DEVELOPER_GUIDE.md`, `docker-compose.yml`).
- The architecture is a modular monolith rather than microservices (`src/` layout, one application image/service).
- CI has extensive quality, provenance, claim, safety, and smoke gates (`.github/workflows/ci.yml`).
- The repository uses committed benchmark corpora and deterministic claim verification (`bench/`, README, scripts).
- Real offensive tools and sensitive artifacts make scope, approval, credentials, and evidence primary risk domains (`SECURITY.md`, `src/arsenal/`, Docker mounts).

### Medium Confidence

- The contributor community is medium-to-large for an open-source project, but aliases and automated-agent identities prevent an exact human team count.
- The system is production-grade as a distributed open-source tool, while not necessarily operated as a production hosted service.
- Reliability maturity is moderate: strong pre-release verification exists, but no hosted-service SLO/telemetry model is evident.
- Security maturity is strong for the product category, but certification and organization-level controls cannot be inferred.

### Unknown

- Active users, installations, and workload volume
- Maintainer staffing, funding, and availability
- General support/on-call model
- Formal contractual or regulatory obligations
- Production incident rate and recovery objectives
- Near-term product priority and deadline
- Whether package repository metadata intentionally remains pointed at the upstream owner

## Quality Assessment

### Strengths

- Clear stable/experimental/roadmap labeling
- Strong verification culture and reproducible public claims
- Extensive automated CI gates
- Broad documentation for operators, developers, security, benchmarks, releases, and integrations
- Localhost-first deployment and explicit authorization doctrine
- Modular source organization and multiple integration surfaces
- Private vulnerability-reporting process and response target

### Risks and Weaknesses

- Large capability surface and external-tool ecosystem amplify regression and supply-chain risk.
- Stable and experimental code share core execution and brand surfaces.
- Multi-agent/swarm reliability is less demonstrated than single-agent benchmark performance.
- No formal workload/capacity baseline was found.
- Sensitive artifacts rely heavily on operator-controlled local storage.
- Repository ownership references differ between current tracker configuration and `package.json`.
- Eighteen debt markers in implementation/script paths need owner triage.

## Generated Files

- `.aiwg/intake/project-intake.md`
- `.aiwg/intake/solution-profile.md`
- `.aiwg/intake/option-matrix.md`
- `.aiwg/intake/codebase-analysis-report.md`

## Recommended Next Action

Have maintainers validate the five owner questions in `option-matrix.md`, then select incremental expansion, stabilization, research, or hosted evolution as the governing near-term path. The code evidence favors incremental expansion with explicit safety and benchmark promotion gates.

The owner subsequently selected a balanced priority across stability, domain expansion, swarm research, and adoption; supplied a scale estimate of thousands to tens of thousands; required fail-safe behavior; and reported no additional formal commitments. These are owner inputs, not measurements from the analyzed revision.

## Method and Limitations

Counts are point-in-time observations at the stated revision and command environment. File/test counts indicate surface area, not coverage or quality. Contributor identities are not normalized to humans. Architecture and maturity inferences are bounded by the cited files and were reconciled into the SAD and vision-alignment matrix.

## References

- @.aiwg/intake/project-intake.md — Detailed interpretation of the scan.
- @.aiwg/intake/option-matrix.md — Owner answers recorded after analysis.
- @.aiwg/architecture/software-architecture-doc.md — Architecture synthesis.
- @package.json — Runtime, version, scripts, dependencies, and license.
- @README.md — Product scope and claims.
- @FEATURES.md — Capability/maturity inventory.
- @SECURITY.md — Safety and disclosure policy.
- @.github/workflows/ci.yml — CI implementation.
- @src/cli.ts — CLI surface.
- @src/server.ts — HTTP/War Room surface.
- @src/mcp-server.ts — MCP surface.
