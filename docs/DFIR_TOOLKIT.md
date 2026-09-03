# Bounded DFIR toolkit

The toolkit separates read-only evidence acquisition from containment/remediation. It is a library contract, not authorization to investigate or alter a host. Confirm case authority and legal/privacy handling before collection. Route evidence-bearing work to the installed forensics framework and record production incident coordination separately.

## Acquisition and custody

A collector declares its tested platform (`linux`, `darwin`, or `win32`) and returns bytes plus original source and collection timestamp. The toolkit computes SHA-256, verifies the received bytes, records size, collector, target, case, receipt time, transfer method, and redacted metadata. Start the master custody log before acquisition, preserve volatile sources first, and record every later transfer. Permission or collection failures create no invented evidence record; cancellation retains custody records for artifacts already received.

The core makes no blanket operating-system support claim. `supportedDfirPlatforms()` reports only platforms for which the caller supplied a tested collector adapter. No built-in remote-shell commands, memory acquisition, or cloud mutations are implied.

## Containment and remediation

Containment begins with an immutable preview containing the exact case, target, action, steps, summary, rollback guidance, and SHA-256 digest. Execution requires an unexpired approval receipt bound to every one of those identifiers and the exact digest. Missing, expired, mismatched, or stale approval fails closed and invokes no executor. Completion receipts retain completed/total step counts, timestamps, rollback guidance, and fixed errors for partial, failed, or cancelled actions.

Do not reboot, clean, quarantine, rotate credentials, or patch a suspected system merely to prepare evidence. Preserve evidence first unless the incident commander explicitly accepts the tradeoff and the action has a matching receipt. Executors must be narrow platform adapters, stop promptly on cancellation, and report partial progress truthfully.

## Readiness checklist

- Evidence root: `.aiwg/forensics/evidence/<case-id>/`
- Master custody log: `.aiwg/forensics/chain-of-custody.md`
- Hash: SHA-256
- Required identities: case, target, investigator/approver, collector/action
- Required times: source collection, receipt, approval, execution start/completion
- Redact secrets and customer data from metadata; evidence bytes stay in the controlled case store
- Define retention, access, transfer, legal hold, and deletion policy before an incident
- Test each platform adapter’s permission failure, cancellation, partial execution, and rollback procedure
