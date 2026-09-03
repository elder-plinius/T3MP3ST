# Mission recovery and exposure scoring

Mission recovery uses the versioned `t3mp3st_mission_recovery/v1` snapshot. A snapshot records mission ID, monotonic revision, state, save time, and actions with unique idempotency keys, bounded attempts, status, and optional receipt. Writers persist each transition with compare-and-swap; rollback means retaining the prior complete snapshot revision until the newer revision is durably accepted.

Recovery is fail-closed. Completed, aborted, and cancelled missions never resume. Corrupt or unknown schemas execute nothing. An action found `in_progress` after a crash is ambiguous and becomes `blocked`; it is never replayed automatically because the external side effect may already have occurred. Concurrent recovery loses the revision comparison and executes nothing. Pending actions are claimed before execution, execute once, and require a durable receipt before completion. Failed actions require an explicit bounded retry transition. Cancellation before execution performs no action.

| Trigger | Behavior | Notification evidence | Recovery |
| --- | --- | --- | --- |
| corrupt/unknown state | stop with `corrupt` | fixed result, no state mutation | restore a known-good prior revision |
| ambiguous in-flight action | mark blocked, never replay | `ambiguous-after-crash` | operator reconciles the external receipt |
| concurrent recovery | losing worker stops | `concurrent` | reload the winning revision |
| cancellation | stop before the next action | `cancelled` | operator explicitly resumes later |
| retry exhausted | block action | `execution-failed` | investigate; do not override |
| terminal mission | observational no-op | `terminal` | no recovery permitted |

`status()` only loads, validates, and clones state; it never calls an executor or changes a revision. API status routes should expose this observational result and reserve transitions for authenticated POST operations.

Exposure score inputs are normalized 0–1 signals: internet exposure (30%), exploitable finding evidence (30%), credential exposure (25%), and business criticality (15%). The score renormalizes only across known inputs, reports coverage and confidence separately, lists unknown inputs, and refuses to score below 50% known weight. Confidence is the weighted signal confidence multiplied by coverage. This prevents missing evidence from appearing as safety.
