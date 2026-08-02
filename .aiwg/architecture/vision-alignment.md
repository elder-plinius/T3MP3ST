# Vision-to-Code Alignment Matrix

**Reference:** `VISION.md`
**Rule:** Alignment is directional; only code/tests/receipts establish implementation maturity.

## Assessment Method

- **Implemented:** Supported operational path with current code, deterministic shared-safety tests, and maintained documentation.
- **Partial / experimental:** Working code or bounded benchmark evidence exists, but reliability, breadth, safety coverage, or support is incomplete.
- **Research:** Evidence answers a defined research question but is not a supported general product contract.
- **Future:** Direction is documented without an implemented, tested operational path.

Evidence confidence is bounded by the cited source: source code establishes presence, tests establish behavior under their cases, and a receipt establishes only its declared corpus/harness/model/metric. No row is a substitute for a requirement, threat model, or release decision.

| Vision vector | Current maturity | Current evidence | Gap / next architectural proof |
| --- | --- | --- | --- |
| Cognitive architecture | Partial / experimental | Admiral planning, context packs, prompts, operator roles, adjudication | Demonstrate durable reasoning-state architecture and comparative outcomes beyond prompt composition |
| Swarm dynamics | Partial / experimental | Eight operator archetypes, orchestration, task assignment, shared mission context | Reproducible end-to-end swarm benchmark showing coordination reliability and value over solo baselines |
| Adversarial machine learning | Research / partial | Refusal-frontier probes, model matrices, adversarial benchmarks, anti-fitting | Formal threat model and stable adaptive defenses against prompt/model manipulation |
| Continuous autonomous operations | Future with small foundations | Mission lifecycle, lessons, update/preflight tooling | Persistent scheduler, safe pause/resume, operator governance, resource budgets, and incident controls |
| Knowledge architecture | Partial / research | Evidence, reports, lessons, benchmark corpora, context packs | Unified provenance-aware knowledge model with retention, conflict, and poisoning controls |
| Distributed and edge execution | Future | Local agents, local model servers, Docker, multiple surfaces | Authenticated worker protocol, tenancy, distributed state, failure recovery, and zero-trust execution design |
| Evaluation science | Strongly implemented | `bench/`, `verify-claims`, ground truth, model matrix, anti-fitting/provenance CI | Broaden external replication, workload/cost measures, and statistically powered comparisons |

## Alignment Rules

1. `README.md` and `FEATURES.md` maturity labels are product claims and must remain consistent with this matrix.
2. A benchmark validates only its defined corpus, model, harness, and metric.
3. Promotion to stable requires deterministic safety tests, an operational path, documentation, and a reproducible receipt.
4. Persistent autonomy, distributed execution, or shared knowledge services trigger new threat models and ADRs.
5. The SAD is updated from implementation evidence; the vision is not reverse-engineered into fictitious components.

## Promotion Checklist

A capability may move toward stable only when all applicable items are evidenced:

- [ ] User goal, acceptance behavior, and NFRs are identified.
- [ ] Operational entry path and failure/rollback behavior are documented.
- [ ] Shared authorization, scope, secret, evidence, and approval controls apply.
- [ ] Deterministic positive and adversarial tests cover critical paths.
- [ ] Benchmark/claim evidence is reproducible and scoped.
- [ ] SAD/API/deployment/test documentation and traceability are updated.
- [ ] Architecture, safety, test, and evaluation reviewers record approval.

## Review Triggers

Review this matrix when a public feature label changes, a benchmark/receipt is added or regraded, a new provider/tool/domain is exposed, a roadmap capability gains an operational path, or the SAD/ADRs change a maturity boundary. Persistent autonomy, distributed execution, hosted multi-tenancy, and shared knowledge services require new threat/architecture work before promotion.

## References

- @VISION.md — Directional research source.
- @README.md — Primary product claims and maturity labels.
- @FEATURES.md — Feature inventory and maturity surface.
- @.aiwg/architecture/software-architecture-doc.md — Current implemented architecture.
- @.aiwg/architecture/adr-004.md — Evidence-derived claims policy.
- @.aiwg/architecture/adr-005.md — Current-state/vision separation decision.
- @.aiwg/requirements/UC-005.md — Reproduction and maturity acceptance behavior.
- @.aiwg/requirements/nfr-register.md — NFR-03 and NFR-09.
- @scripts/verify-claims.mjs — Claim derivation implementation.
- @src/__tests__/stub-honesty.test.ts — Stub/maturity regression evidence.
