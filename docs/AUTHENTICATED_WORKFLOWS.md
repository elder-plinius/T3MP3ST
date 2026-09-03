# Authenticated Workflow Boundaries

T3MP3ST operative instructions influence how an agent plans and selects from its assigned tools. Editing those instructions does not register a new tool, expand the authorized target, or satisfy an approval gate.

The Operatives editor shows the effective callable tool list. When saved instructions clearly request interactive signup but the archetype has no such tool, the API and editor return a deterministic `tool_unavailable` warning. The warning contains a capability identifier and safe guidance; it does not echo the edited text.

## What Works Today

For an application you are authorized to test, T3MP3ST can attach operator-supplied headers to requests for one exact origin. See [Target Header Injection](TARGET_HEADERS.md). This supports an existing authorized session; it does not acquire a new identity, navigate forms, read a mailbox, or verify a newly created account.

If a workflow needs an unsupported interactive step, complete it manually and provide the resulting authorization data through the documented target-header path. Do not paste sensitive values into operative instructions.

## Capability Outcomes

The following stable codes distinguish capability and authorization states in API responses, events, mission feeds, and reports:

| Code | Meaning |
|---|---|
| `configuration_deferred` | A live operative will adopt its configuration revision at the next safe task boundary. |
| `tool_unavailable` | No callable tool assigned to the operative can perform the requested action. |
| `approval_required` | A known callable action needs a valid human approval receipt. |
| `manual_step_required` | Product policy intentionally leaves the action to the operator. |
| `authorization_failed` | Supplied authorization data was attempted and the target rejected it. |

Capability diagnostics are derived from declared tool metadata and deterministic request classes. Model prose is not sufficient to claim that a capability exists or that an action ran.

## Future Interactive Signup Design

Interactive signup is a separate, future workflow—not passive reconnaissance. This document records its minimum design boundary; it does not enable a browser, mailbox, or account-provisioning adapter.

Any future implementation must meet all of these conditions:

1. It is disabled by default and delivered under a separate reviewed change.
2. Written rules of engagement explicitly authorize state-changing signup activity for the exact target origin.
3. Form submission, terms acceptance, mailbox verification, and similar state changes each require an appropriate short-lived human approval receipt.
4. Test identities are operator-controlled or use target-owned aliases. T3MP3ST does not implicitly contact public disposable-mail services.
5. Browser state is isolated per engagement and exact origin. Redirects and navigation cannot transfer authorization data or session state to another origin.
6. Page content is untrusted input and cannot grant tools, scope, or approval.
7. Sensitive values remain out of event streams, findings, reports, receipts, and model transcripts. Storage is memory-bounded with explicit expiry and cleanup.
8. CAPTCHA bypass, bulk signup, promotion farming, and rate-limit evasion are out of scope.
9. Failures are closed and reported with one of the stable outcome codes above; the system never silently claims an authenticated state.
10. Automated tests use a locally controlled fixture. CI never creates accounts on third-party services.

Before executable work begins, the separate change must include a threat model, lifecycle and cleanup design, approval expiry behavior, redirect isolation tests, redaction tests, denied/expired approval tests, and an explicit security/HITL review.
