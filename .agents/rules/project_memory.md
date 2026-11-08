---
description: Permanent project memory, architectural decisions, and build procedures for MARE threat research portal.
globs: ["**/*"]
always_on: true
---

# MARE Standing Memory & Architecture Reference

## Overview
MARE is an independent malware analysis and reverse engineering research portal maintained by Chandra Kant Bauri ([@Lynk4](https://github.com/Lynk4)).

## Core Knowledge Base

### 1. Categories (4 Canonical Taxonomies)
- `Malware Family Analysis`: Full teardowns of specific malware strains (RATs, stealers, botnets, banking trojans).
- `Threat Intelligence & APTs`: Nation-state campaigns, espionage implants, threat actor attribution.
- `Reverse Engineering Techniques`: Unpacking, driver analysis, anti-debugging, hooking, API resolution.
- `Ransomware & Wipers`: Destructive payloads, MBR wipers, ransomware notes, recovery attempts.

### 2. MalOps Integration
- Source repo: `https://github.com/Lynk4/malops.io.git`
- Synchronization command: `npm run sync:malops`
- Source folder: `external/malops` (git-ignored)
- Naming rule: Always referred to as **"MalOps"** (never "MalOps CTF").

### 3. UI/UX Rules
- **Brand Tagline**: `⚡ BREAK THE BINARY. // INTELLIGENCE BEYOND INDICATORS.` (with terminal blinking cursor).
- **Hero Artwork**: Wide cyber-analyst desk cover with left-to-right balanced lighting for standard and ultrawide monitors.
- **TOC Navigation**: Instant jump (`scroll-behavior: auto !important`) with `@keyframes target-heading-glow` on the destination header.
- **Mobile First**: All tables, code boxes, navigation dropdowns, and figures must be responsive on mobile viewports.
- **Dynamic Pagination**: 9 reports on initial load, "Load more Investigations" button shows dynamic remaining count.

### 4. Build & Deployment Rules
- Build engine: `node scripts/build.js` (`npm run build`).
- Build output `reports/` is generated and git-ignored.
- Report dates must be recorded in `CANONICAL_REPORT_DATES` in `scripts/build.js` to preserve authentic history.
- Never commit `.DS_Store` or binary blobs.
- Always verify all image URLs and check for clean basename rendering.
