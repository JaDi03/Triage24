# IBM Bob Development Log — Triage24

> **Project:** Triage24 — EU Cyber Resilience Act (CRA) Article 14 Compliance & Reachability Agent  
> **Engine:** IBM Bob IDE v2.2.0 (Plan Mode, Agent Mode)  
> **Hackathon:** IBM Bob The Developer Challenge 2 (Lablab.ai)  
> **Session Proofs:** [`./bob_sessions/`](./bob_sessions/)

---

## Executive Summary

Triage24 was built incrementally from scratch using IBM Bob 2.2.0 as the primary AI developer agent. Every phase was planned, implemented, tested, and verified through dedicated Bob task sessions.

| Task | Milestone | Bob Mode | Task ID | Bobcoins | Artifacts | Tests | Evidence |
|:---:|:---|:---:|:---:|:---:|:---|:---:|:---:|
| **00** | Architecture & CRA Strategy | `Plan` | `e4f25191a6cc72e7f76e22569f909c5f` | 0.644 | `triage24-plan.md` | N/A | [`task00_plan.PNG`](./bob_sessions/task00_architecture_plan.PNG) |
| **01** | Project Scaffolding | `Agent` | `e4f25191a6cc72e7f76e22569f909c5f` | 3.380 | Next.js 16, Tailwind, Vitest, Types | Baseline | [`task01_scaffolding.PNG`](./bob_sessions/task01_scaffolding.PNG) |
| **02** | GitHub Repo Fetcher | `Agent` | `7bb8039d3de34f668f56baecd75d78e9` | 0.737 | `lib/github.ts`, SSRF guards | 25/25 ✅ | [`task02_github_fetcher.PNG`](./bob_sessions/task02_github_fetcher.PNG) |
| **03** | Manifest Extractor (npm + Maven) | `Agent` | `c121497e1b7696dcba6fe0381dcccb35` | 0.820 | `lib/deps-extractor.ts` | 50/50 ✅ | [`task03_deps_extractor.PNG`](./bob_sessions/task03_deps_extractor.PNG) |
| **04** | OSV.dev Batch Vuln Client | `Agent` | `7d102c83ba701fd9c1316fc58fd06b32` | 1.410 | `lib/osv.ts`, batch queries | 17/17 ✅ | [`task04_osv_client.PNG`](./bob_sessions/task04_osv_client.PNG) |
| **05** | CISA KEV Catalog Matcher | `Agent` | Pending | Pending | `lib/kev.ts` | Pending | Pending |

---

## Detailed Task Logs

### Task 00: Architecture & CRA Compliance Plan
- **Bob Mode:** `Plan Mode` (via `create-plan` capability)
- **Task ID:** `e4f25191a6cc72e7f76e22569f909c5f`
- **Bobcoin Usage:** `0.644 Bobcoins` (Context: 38.8k / 270.0k tokens — 14%)
- **Objective:** Establish stateless architecture, data flow, and legal mapping for EU CRA Article 14.
- **Key Decisions:**
  - Pluggable batch vulnerability lookup via OSV.dev instead of rate-limited NVD API.
  - Dependency reachability analysis instead of generic SAST (verifying imported vulnerable symbols).
  - Automated 24h Early Warning and 72h Incident Notification drafting for CSIRT/ENISA.
  - Actionable "Fix with IBM Bob" instructions per finding.
- **Evidence:** [`bob_sessions/task00_architecture_plan.PNG`](./bob_sessions/task00_architecture_plan.PNG)

---

### Task 01: Project Scaffolding & Test Baseline
- **Bob Mode:** `Agent Mode`
- **Task ID:** `e4f25191a6cc72e7f76e22569f909c5f`
- **Bobcoin Usage:** `3.380 Bobcoins` (Context: 45.4k / 270.0k tokens — 17%)
- **Objective:** Initialize clean Next.js 16 (App Router), TypeScript, Tailwind CSS, and Vitest test runner.
- **Generated Artifacts:**
  - `package.json`, `tsconfig.json`, `vitest.config.ts`, `tailwind.config.ts`
  - `types/index.ts` (shared domain models: `Dependency`, `CVERecord`, `KevEntry`, `CRAReport`)
  - `.env.example`
- **Verification:** `tsc --noEmit` (0 errors), `npm run test` (Vitest v2.1.9 exit code 0).
- **Evidence:** [`bob_sessions/task01_scaffolding.PNG`](./bob_sessions/task01_scaffolding.PNG)

---

### Task 02: GitHub Repository Fetcher & Tree Parser
- **Bob Mode:** `Agent Mode`
- **Task ID:** `7bb8039d3de34f668f56baecd75d78e9`
- **Bobcoin Usage:** `0.737 Bobcoins` (Context: 36.0k / 270.0k tokens — 13%)
- **Objective:** Safely fetch repository trees and file contents from public GitHub repositories.
- **Engineering Highlights:**
  - **SSRF Protection:** Strict hostname validation enforcing `github.com` only.
  - **Flexible URL Parsing:** Supports `owner/repo`, `.git` suffixes, and `/tree/<ref>` branches.
  - **API Efficiency:** Single recursive tree call (`recursive=1`) to prevent API quota exhaustion.
  - **Rate Limit Resilience:** Graceful 403 handling with `GITHUB_TOKEN` guidance.
- **Verification:** `tests/github.test.ts` — **25 passed of 25 tests** in 17 ms.
- **Evidence:** [`bob_sessions/task02_github_fetcher.PNG`](./bob_sessions/task02_github_fetcher.PNG)

---

### Task 03: Dependency Manifest Extractor (npm & Maven)
- **Bob Mode:** `Agent Mode`
- **Task ID:** `c121497e1b7696dcba6fe0381dcccb35`
- **Bobcoin Usage:** `0.820 Bobcoins` (Context: 37.7k / 270.0k tokens — 14%)
- **Objective:** Parse npm lockfiles and Maven POMs to extract complete dependency trees.
- **Engineering Highlights:**
  - **npm v2/v3 Support:** Extracted direct and transitive packages via the `packages` map; explicit rejection of legacy v1 with descriptive error.
  - **Scoped Package Normalization:** Strips `node_modules/` prefixes while preserving scopes (e.g. `@types/node`).
  - **Maven Property Resolution:** Dynamic recursive expansion of `${...}` property placeholders.
  - **XML Tag Value Safety:** Configured `fast-xml-parser` with `parseTagValue: false` to avoid numeric coercion of semantic versions (e.g. `"2.10"` preserved as string).
  - **BOM Sanitization:** Stripped UTF-8 BOM (`0xFEFF`) to prevent Windows/PowerShell parse failures.
- **Verification:** `tests/deps-extractor.test.ts` — **50 passed of 50 total tests** across the suite in 21 ms.
- **Evidence:** [`bob_sessions/task03_deps_extractor.PNG`](./bob_sessions/task03_deps_extractor.PNG)

---

### Task 04: OSV.dev Batch Vulnerability Client
- **Bob Mode:** `Agent Mode`
- **Task ID:** `7d102c83ba701fd9c1316fc58fd06b32`
- **Bobcoin Usage:** `1.410 Bobcoins` (Context: 45.5k / 270.0k tokens — 17%)
- **Objective:** Query OSV.dev batch vulnerability API with high throughput, alias resolution, and client-side caching.
- **Engineering Highlights:**
  - **Single Batch Network Roundtrip:** `lookupCVEsBatch(deps)` queries `https://api.osv.dev/v1/querybatch` in a single POST with all npm and Maven dependencies index-aligned.
  - **Ecosystem Normalization:** Automatically standardizes `maven` → `Maven` as required by the OSV.dev schema.
  - **CVE Alias Resolution:** Extracts authoritative CVE IDs from OSV `aliases` arrays, prioritizing `CVE-*` entries over proprietary IDs with fallback to OSV identifiers.
  - **CVSS Scoring & Severity Classification:** Maps numeric CVSS vector scores to standard CRA severity bands (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`).
  - **In-Memory Cache:** `Map<string, CVERecord[]>` keyed by `name@version@ecosystem` to eliminate redundant queries for recurring packages across manifests.
  - **Vitest Alias Support:** Configured `@/` path resolution in `vitest.config.ts` matching TypeScript paths.
- **Verification:** `tests/osv.test.ts` — **17 passed of 17 tests** (67 passed across entire project test suite).
- **Evidence:** [`bob_sessions/task04_osv_client.PNG`](./bob_sessions/task04_osv_client.PNG)
