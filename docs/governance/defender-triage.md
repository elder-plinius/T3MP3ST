# Defender triage

Five questions, scored in process: scope, accepted impact, reproducibility, tool evidence, and PII markers.

Impact acceptance is a human assertion. Scope uses the mission scope list. Reproducibility requires a verbatim quote of at least 8 characters inside tool evidence on that finding.

PII markers are `cookie:`, `authorization:`, `bearer `, and `-----BEGIN`, matched without case sensitivity, across tool evidence only. The check misses secrets that do not contain those markers, and it can flag the word "bearer" in ordinary prose. It does not redact. Redaction stays in `src/redact.ts`.

The question set is original defender wording. The idea of a pre-submit question gate is adapted from Sachin Sharma / Claude-BugHunter, licensed CC BY 4.0: https://github.com/elementalsouls/Claude-BugHunter

This file is not that project's skill text.
