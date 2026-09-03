---
title: "T3MP3ST Documentation"
summary: "Documentation map for operators, developers, benchmarks, and release work."
description: "Documentation map for operators, developers, benchmarks, and release work."
audience: ["operator", "developer"]
category: "overview"
status: "current"
source: "T3MP3ST repository"
sourcePath: "docs/README.md"
updated: "2026-07-20"
---
# T3MP3ST Documentation

Start here when you want to install, run, integrate, or contribute to T3MP3ST.

## For Operators

| Doc | Use it for |
|---|---|
| [Getting Started](#getting-started) | Install, first launch, first safe mission, updates, and troubleshooting |
| [Scope and Authorization](#scope-and-authorization) | Rules of engagement, target receipts, and evidence requirements |
| [Target Headers](#target-headers) | Supplying auth headers for an explicitly authorized target origin |
| [Authenticated Workflow Boundaries](#authenticated-workflows) | Current authenticated-request support and the approval boundary for future interactive workflows |
| [Arsenal Activation Plan](#arsenal-activation-plan) | Installing optional external tools and understanding adapter readiness |
| [Team Preview](#team-preview) | Ten-minute UI walkthrough for preview builds |

## For Developers

| Doc | Use it for |
|---|---|
| [Developer Guide](#developer-guide) | Architecture, local development, scripts, extension points, and release checks |
| [API Reference](#api-reference) | HTTP server endpoints grouped by workflow |
| [MCP Guide](#mcp-guide) | Model Context Protocol setup and the `security_recon` tool |
| [Contribution Receipts](#contribution-receipts) | Evidence template for PRs and claim changes |
| [Pull Request Delivery](#pull-request-delivery) | Contributor and maintainer PR checklist |

Preview this documentation as a Pagenary site:

```bash
npm run docs:serve
```

## Benchmarks And Provenance

| Doc | Use it for |
|---|---|
| [Verified Provenance](#verified-provenance) | How T3MP3ST ties findings to tool evidence |
| [XBOW Baseline](#xbow-baseline) | XBEN benchmark notes |
| [Cybench](#cybench) | Cybench benchmark notes |
| [Wall Forensics](#wall-forensics) | Per-challenge misses and benchmark analysis |
| [Integrity Ledger](#integrity-ledger) | Contamination audit and retractions |
| [Obsidivm](#obsidivm) | Local web range and evaluation notes |
| [Cognitive Architecture](#cognitive-architecture) | Prompt and reasoning architecture boundaries |
| [AI Red-Team Techniques](#ai-redteam-techniques) | Defensive taxonomy and technique map |

## Release And Maintenance

| Doc | Use it for |
|---|---|
| [Install Matrix](#install-matrix) | OS readiness notes |
| [Release Checklist](#release-checklist) | Release gates |
| [Changelog](#changelog) | Project change history |
