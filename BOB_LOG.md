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
| **05** | CISA KEV Catalog Matcher | `Agent` | `6aeefb91e9e584677b3afcad78fc9a5f` | 0.781 | `lib/kev.ts`, in-memory cache | 18/18 ✅ | [`task05_cisa_kev.PNG`](./bob_sessions/task05_cisa_kev.PNG) |
| **06** | Static Analysis Engine (SAST) | `Agent` | `8618e25b874ee756d73bb30b52fb444a` | 0.719 | `lib/sast.ts`, 5 CRA rules | 48/48 ✅ | [`task06_sast_engine.PNG`](./bob_sessions/task06_sast_engine.PNG) |
| **07** | CRA Compliance Scorer | `Agent` | `429d2db112566f5ad96adf8cc1f2f25c` | 0.911 | `lib/cra-scorer.ts` | 30/30 ✅ | [`task07_cra_scorer.PNG`](./bob_sessions/task07_cra_scorer.PNG) |
| **08** | Audit API Route | `Agent` | `4b5c6ebdfea8bf63e6d3c8bc5d48f453` | 0.996 | `app/api/audit/route.ts` | 12/12 ✅ | [`task08_audit_route.PNG`](./bob_sessions/task08_audit_route.PNG) |
| **09** | Frontend UI & Report Dashboard | `Agent` | `5aa3eb3ea0be08053be705673c1725df` | 1.450 | Next.js Components & Pages | 3/3 ✅ | [`task09_frontend_ui.PNG`](./bob_sessions/task09_frontend_ui.PNG) |
| **10** | Standalone CLI Tool | `Agent` | Pending | Pending | `scripts/cli.ts` | Pending | Pending |

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

---

### Task 05: CISA KEV Catalog Matcher
- **Bob Mode:** `Agent Mode`
- **Task ID:** `6aeefb91e9e584677b3afcad78fc9a5f`
- **Bobcoin Usage:** `0.781 Bobcoins` (Context: 35.4k / 270.0k tokens — 13%)
- **Objective:** Download, validate, and cache the CISA Known Exploited Vulnerabilities (KEV) catalog; cross-reference dependency CVE findings for active exploitation.
- **Engineering Highlights:**
  - **In-Memory TTL Caching:** Module-level `{ entries, fetchedAt }` cache with 1-hour TTL to prevent repeated downloads from CISA during audit runs.
  - **O(1) Set Lookup:** `matchKev(cveIds, catalog)` builds a `Set<string>` from candidate CVEs before filtering, ensuring constant-time lookup over ~1,100 catalog entries.
  - **Graceful Degradation:** Safely handles missing `vulnerabilities` property or empty feeds by returning an empty array without runtime exceptions.
  - **Deterministic Time-Travel Tests:** Uses `vi.spyOn(Date, 'now')` to advance system time and assert cache expiration without real timer delays.
  - **Cache Eviction Hook:** Exports `clearKevCache()` for deterministic test isolation.
- **Verification:** `tests/kev.test.ts` — **18 passed of 18 tests** (85 passed of 85 across full project test suite in 88 ms).
- **Evidence:** [`bob_sessions/task05_cisa_kev.PNG`](./bob_sessions/task05_cisa_kev.PNG)

---

### Task 06: Static Analysis Engine (SAST)
- **Bob Mode:** `Agent Mode`
- **Task ID:** `8618e25b874ee756d73bb30b52fb444a`
- **Bobcoin Usage:** `0.719 Bobcoins` (Context: 34.2k / 270.0k tokens — 13%)
- **Objective:** Build a zero-dependency, lightweight static analysis security testing engine in pure TypeScript implementing CRA Annex I essential requirements.
- **Engineering Highlights:**
  - **Rule Interface & Extensibility:** Created `SastRule` interface with `id`, `name`, `severity`, `description`, `recommendation`, and a deterministic `test(line: string)` evaluation function.
  - **5 Built-In CRA Rules:**
    - `SAST-001` (CRITICAL): Hardcoded API secrets, private keys, bearer tokens, or access credentials.
    - `SAST-002` (HIGH): Dangerous dynamic execution via `eval()` or `new Function()`.
    - `SAST-003` (HIGH): Raw SQL query concatenation prone to SQL injection vulnerabilities.
    - `SAST-004` (MEDIUM): Insecure plaintext `http://` URLs in network requests (`fetch`/`axios`).
    - `SAST-005` (HIGH): Disabled TLS/SSL certificate verification (`rejectUnauthorized: false`).
  - **Single-Pass Line Scanner:** `scanFile(path, content)` conducts 1-based line scanning with automatic 200-character snippet truncation for readable reports.
  - **Safe Repository Traversal:** `scanRepo(files)` automatically filters out third-party/generated folders (`node_modules`, `dist`, `.git`) and ignores oversized files (> 500 KB) to prevent memory exhaustion.
- **Verification:** `tests/sast.test.ts` — **48 passed of 48 tests** (133 passed of 133 across full project test suite in 99 ms).
- **Evidence:** [`bob_sessions/task06_sast_engine.PNG`](./bob_sessions/task06_sast_engine.PNG)

---

### Task 07: CRA Compliance Scorer
- **Bob Mode:** `Agent Mode`
- **Task ID:** `429d2db112566f5ad96adf8cc1f2f25c`
- **Bobcoin Usage:** `0.911 Bobcoins` (Context: 35.7k / 270.0k tokens — 13%)
- **Objective:** Synthesize dependency, vulnerability, KEV active exploitation, and SAST findings into a legal compliance report aligned with EU Cyber Resilience Act (CRA) Article 14 obligations.
- **Engineering Highlights:**
  - **CRA Article 14 Urgency Escalation:**
    - Any vulnerability matched in the CISA KEV catalog escalates to `CRITICAL` risk with `disclosureRequired = true` and `disclosureDeadlineHours = 24` (mandated 24h Early Warning to ENISA/CSIRTs).
    - Unexploited `CRITICAL` or `HIGH` CVEs, or `CRITICAL` SAST findings require notification with `disclosureDeadlineHours = 72`.
    - Repositories without findings resolve to `PASS` with `disclosureRequired = false`.
  - **SBOM & Security Policy Detection:**
    - Detects Software Bill of Materials (SBOM) compliant with CRA Annex I Part II (`sbom.json`, `sbom.xml`, `*.spdx`, `bom.xml`), correctly filtering out tree directory matches.
    - Inspects root and `.github/` directories for official disclosure policies (`SECURITY.md`).
  - **Robust Report Metadata:** Generates RFC 4122 UUID v4 `reportId` via `crypto.randomUUID()` and ISO 8601 timestamps.
- **Verification:** `tests/cra-scorer.test.ts` — **30 passed of 30 tests** (163 passed of 163 across full project test suite in 142 ms).
- **Evidence:** [`bob_sessions/task07_cra_scorer.PNG`](./bob_sessions/task07_cra_scorer.PNG)

---

### Task 08: End-to-End Audit API Route
- **Bob Mode:** `Agent Mode`
- **Task ID:** `4b5c6ebdfea8bf63e6d3c8bc5d48f453`
- **Bobcoin Usage:** `0.996 Bobcoins` (Context: 44.0k / 270.0k tokens — 16%)
- **Objective:** Connect all domain engines (`github`, `deps-extractor`, `osv`, `kev`, `sast`, `cra-scorer`) into a resilient, production-ready Next.js API route (`POST /api/audit`).
- **Engineering Highlights:**
  - **Full Pipeline Orchestration:**
    1. Validates repository URL via `parseRepoUrl` (returns HTTP 400 on malformed or non-GitHub hosts).
    2. Fetches recursive Git tree via `fetchRepoTree` (returns HTTP 404 for missing/private repos, HTTP 429 on GitHub rate limits).
    3. Extracts dependencies with `extractDependencies` supporting npm lockfiles (v2/v3) and Maven POMs.
    4. Batch queries OSV.dev in a single roundtrip via `lookupCVEsBatch`.
    5. Downloads and cross-references active exploitation via `downloadKevCatalog` and `matchKev`.
    6. Conducts static analysis via `scanRepo` across source code files (< 500 KB).
    7. Evaluates CRA compliance status, overall risk, and reporting deadlines via `scoreCRA`.
  - **In-Memory Cache:** Exports `reportCache = new Map<string, CRAReport>()` to store audit results for subsequent frontend consumption.
  - **Strict HTTP Status Semantics:** Returns structured error payloads with appropriate HTTP status codes (400, 404, 429, 500).
- **Verification:** `tests/audit-route.test.ts` — **12 passed of 12 tests** (175 passed of 175 across full project test suite in 211 ms).
- **Evidence:** [`bob_sessions/task08_audit_route.PNG`](./bob_sessions/task08_audit_route.PNG)

---

### Task 09: Frontend UI & Interactive Report Dashboard
- **Bob Mode:** `Agent Mode`
- **Task ID:** `5aa3eb3ea0be08053be705673c1725df`
- **Bobcoin Usage:** `1.450 Bobcoins` (Context: 43.0k / 270.0k tokens — 16%)
- **Objective:** Build a responsive, accessible web interface in Next.js 16 (App Router + Tailwind CSS) enabling one-click repository audits and visual CRA compliance reporting.
- **Engineering Highlights:**
  - **Landing Page (`app/page.tsx`):** Modern hero section highlighting EU CRA Article 14 legal mandates, accompanied by three educational cards covering essential requirements, 24h Early Warning, and 72h Notification deadlines.
  - **Interactive Repo Form (`components/RepoForm.tsx`):** Client component with URL pattern validation, animated SVG loading indicator, and automated redirection to dynamic report view upon audit completion.
  - **Report Data API (`app/api/report/[id]/route.ts`):** Fast GET route querying in-memory `reportCache` by UUID with appropriate 404 handling.
  - **Modular Dashboard Architecture:**
    - `ReportSummary.tsx`: Semantic risk badge (`CRITICAL` red, `HIGH` orange, `MEDIUM` yellow, `LOW` blue, `PASS` green), statutory deadline badges (24h/72h), and status indicators for SBOM presence and security disclosure policy (`SECURITY.md`).
    - `DepsTable.tsx`: Tabular view of vulnerable direct/transitive dependencies with CVSS scores and active `🚨 KEV` alerts for CISA catalog matches.
    - `SastFindings.tsx`: Code-level static analysis findings including file path, line number, code snippet, and actionable mitigation guidance.
  - **Dynamic Report Route (`app/report/[id]/page.tsx`):** Server Component with built-in error boundary fallbacks and `notFound()` handling.
- **Verification:** `tests/report-route.test.ts` — **3 passed of 3 tests** (178 passed of 178 across full project test suite in 271 ms).
- **Evidence:** [`bob_sessions/task09_frontend_ui.PNG`](./bob_sessions/task09_frontend_ui.PNG)
