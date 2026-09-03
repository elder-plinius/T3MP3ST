# CI/CD Baseline and Deployment Plan

## 1. Introduction

- **Status:** Current CI baseline plus proposed architecture additions
- **Scope:** GitHub Actions validation, local Node/Docker delivery, and release verification for T3MP3ST 1.0.0
- **Owner:** Release integrator / deployment manager
- **Boundary:** No hosted production environment, fleet rollout, or managed service is evidenced by the repository.

## 2. Deployments Table

| Environment | Purpose | Artifact / URL | Scale profile | Owner |
| --- | --- | --- | --- | --- |
| Developer/operator host | Install, CLI/library, optional War Room | npm/repository package; loopback HTTP | Single local process | Operator |
| Local Docker | Reproducible application runtime | Compose service; `127.0.0.1:3333` host binding | Single container | Operator |
| GitHub Actions CI | Quality/evidence verification | Workflow jobs; no user URL | Per workflow matrix | Maintainer |
| Challenge/tool container | Isolated authorized benchmark/tool execution | Harness-specific image/container | Per case/run | Evaluator |
| Hosted staging/production/DR | Not defined | N/A | N/A | Requires new architecture/deployment plan |

## 3. Deployment Strategy

Local installation and Docker are replace-in-place deployments of one versioned codebase. Releases should use an immutable commit/tag and package artifact after all required gates pass. A canary/blue-green strategy is N/A for the current self-hosted baseline; operators may retain the prior version and local artifacts for rollback.

## 4. Environments and Prerequisites

- Node.js 18+ (CI uses Node.js 22), npm, and platform prerequisites for selected external tools.
- Docker/Compose only for container paths.
- Provider credentials or authenticated local agents only when the selected workflow needs them.
- Explicit authorized target context for real operations.
- Writable, access-controlled report/evidence/config paths with adequate disk space.

## 5. Rolling Restart and Disposability

There is no multi-replica rolling deployment. Before replacing a running local server, stop/pause mission activity, allow bounded subprocesses to finish or terminate them, preserve configured local paths, stop the process/container, deploy the new artifact, and run health/preflight checks. Startup and graceful-shutdown timing are not measured; any `<10s` or zero-downtime claim is prohibited until NFR-11 evidence exists.

## 6. Deployment Schedule and Freeze

1. Select release commit and freeze claim/receipt/contract changes.
2. Run required CI and local release checks.
3. Review Critical/High defects, maturity labels, dependency/license changes, and sensitive artifacts.
4. Build/publish signed or checksummed artifacts according to the approved release process.
5. Verify installation/startup/health on a clean supported environment.
6. Publish release notes and known limitations.

Dates and communication windows are release-specific and must be recorded in the release checklist rather than invented here.

## 7. Deployment Steps

| Step | Owner | Evidence / success condition |
| --- | --- | --- |
| Resolve exact commit/tag and clean build input | Release integrator | Revision recorded; no unintended files |
| Install dependencies and build | CI/release integrator | `npm ci` and build/type/lint pass |
| Run deterministic tests/gates | CI | Required workflow jobs pass |
| Run claim/provenance/anti-fitting/prompt checks | CI/evaluation steward | No stale or unsupported claim |
| Build/package/container smoke | Release integrator | Artifact starts and health/preflight passes |
| Inspect protected/sensitive paths | Safety/release reviewer | No secrets/evidence unintentionally packaged |
| Publish and verify | Release integrator | Published artifact/version/checksum matches release input |

## 8. Admin Tasks

The current release has no application database migration or backfill model. Configuration migrations must be versioned implementation paths, not one-off data edits. Key rotation, evidence relocation, or benchmark corpus transformation requires a documented task with ordering, owner, approval, validation, and rollback before a release uses it.

## 9. Data Migration

N/A for a transactional application database. Local configuration migrations are handled by supported code; reports/evidence remain operator-controlled mounts/paths. Before any format-breaking change, provide backup, forward migration, validation, and rollback/read-compatibility steps and update NFR-10.

## 10. Verification and Validation

The pipeline intentionally has two gates. Pull requests run dependency
installation, lint, typecheck, the deterministic test suite, doctor, and a 50%
changed-executable-line coverage floor. Release tags rerun the complete
per-file coverage contract plus claim verification, anti-fitting, provenance,
prompt, smoke, build, dependency-audit, and package-manifest checks. The tested
tag is archived once as a ZIP, checksum-verified, and bound to a retained
Sigstore provenance bundle.

Proposed additions:

1. SDLC artifact/citation/traceability conformance.
2. Cross-document maturity consistency.
3. Network-adapter scope/approval/credential/timeout inventory completeness.
4. CycloneDX SBOM generation bound to the source ZIP.

## 11. Rollback and Contingency

Rollback triggers include safety/credential bypass, corrupt configuration/artifacts, failed startup/health, broken required surface, or invalid public claim. Stop the affected version, preserve diagnostic artifacts without publishing secrets, restore the prior known-good package/image and backed-up configuration, rerun health/smoke, and open a defect with revision/evidence. The release integrator may halt; safety reviewers may block any release weakening deterministic controls.

## 12. Communication Plan

Release notes state version/revision, supported environments, user-visible contract changes, maturity changes, security fixes using coordinated-disclosure policy, known limitations, migration/rollback steps, and claim/benchmark scope. Security-sensitive details are not disclosed before coordination permits.

## 13. Support Handover

Handover includes getting-started, developer, API, MCP, security, release, troubleshooting/preflight, and known-limitations documentation. No general on-call SLA is claimed. Operators remain responsible for host/tool prerequisites, authorization, and local sensitive-artifact retention.

## 14. Risk Management

| Risk | Control | Owner |
| --- | --- | --- |
| Off-scope/dangerous regression | Scope/approval negative tests and safety review | Safety reviewer |
| Secret/evidence packaged | Ignore/denylist review, redaction, artifact inspection | Release integrator |
| Stale capability claim | Claim/provenance/maturity gates | Evaluation steward |
| Supply-chain compromise | Lockfile, CI action/image review; future SBOM/signing decision | Configuration/release manager |
| Update damages local artifacts | Protected-path self-tests and documented rollback | Release integrator |

## 15. Approvals

- [ ] Required CI jobs pass for the exact release commit.
- [ ] Maintainer/release integrator approves artifact and notes.
- [ ] Safety reviewer approves any trust-boundary/tool change.
- [ ] Evaluation reviewer approves any claim/benchmark/maturity change.
- [ ] Named approvals and dates are recorded in the release record; none are inferred here.

## References

- @.aiwg/architecture/software-architecture-doc.md — Deployment/process baseline.
- @.aiwg/requirements/nfr-register.md — Deployment-relevant quality constraints.
- @.aiwg/testing/test-strategy.md — Gate definitions.
- @.aiwg/intake/risk-screening.md — Release risks.
- @.github/workflows/ci.yml — Current CI implementation.
- @docker-compose.yml — Local container deployment.
- @package.json — Engine, scripts, package, and license metadata.
- @scripts/update.mjs — Update behavior.
- @scripts/test-update.mjs — Protected-update regression evidence.
- @docs/RELEASE_CHECKLIST.md — Release-specific operational checklist.
