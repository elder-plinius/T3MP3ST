# Targeted CVE sweep and finding retest

`FindingRetestWorkflow` records idempotent, provenance-bearing retests without mutating the original finding. A request requires valid CVE identifiers and binds one finding to its original target ID, one tool, and one argument set. Target substitution is rejected before probing. `ArsenalRetestProbe` requires an explicit Arsenal scope and delegates execution through the existing schema, egress-scope, and approval gates.

The probe classifier must explicitly label the observation `present`, `absent`, or `inconclusive` and attach tool evidence. `present` becomes `still_vulnerable` only with successful tool-backed evidence. `absent` becomes `fixed` only with successful tool-backed negative evidence. Empty results, failed probes, timeouts, cancellations, retry exhaustion, missing evidence, and ambiguous observations are always `unverifiable`; absence of a finding is never proof of remediation.

Requests support bounded attempts (1–5), bounded timeouts (100 ms–120 seconds), cooperative cancellation, partial-failure retry, and idempotency keys. Reusing a key for different work is rejected. Each attempt retains timestamps, disposition, evidence, and error provenance. Sweep results remain independent, so one failed target cannot rewrite another finding or corrupt canonical Evidence Vault state.
