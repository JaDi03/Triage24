# Triage24 — Plan de Implementación

## Overview

**Goal:** Build Triage24, an AI agent that audits public Git repositories for compliance with the EU Cyber Resilience Act (CRA). A user pastes a repo URL, and the agent returns a structured report covering:

1. Dependency CVEs via OSV.dev batch API, cross-referenced against the CISA KEV catalog
2. Reachability analysis — verify the repo actually imports/calls the vulnerable symbols
3. A CRA compliance summary with disclosure deadlines + auto-generated ENISA/CSIRT notification drafts
4. "Fix with IBM Bob" instructions per finding

**Stack:**
- Next.js 14 (App Router) — frontend (React + Tailwind CSS) + backend (Route Handlers under `/app/api/`)
- TypeScript throughout
- Vitest for automated tests
- Optional CLI script reusing the same analysis logic

**Non-goals:**
- No authentication / user accounts (MVP scope)
- No persistent database (results are ephemeral per request)
- No private repo support (public repos only for MVP)
- No generic SAST (no SQLi, no secrets scanning) — reachability only

---

## CRA Compliance Background (Reference)

Key obligations the agent must verify or surface:

| CRA Requirement | What the agent checks |
|---|---|
| No known exploited vulnerabilities in dependencies | CVEs via OSV.dev batch API + CISA KEV cross-reference |
| Timely disclosure of actively exploited vulns | Flag KEV hits + 24 h / 72 h deadlines + auto-draft notifications |
| SBOM availability | Detect presence of lock files / SBOM files in repo |
| Secure-by-design evidence | Detect presence of security policy files |
| Supply chain transparency | All direct + transitive deps with version, CVE status, reachability |

**Patch timelines mandated by CRA / CVSS severity:**

| Severity | CVSS | Required action window |
|---|---|---|
| Critical | 9.0–10.0 | 24 hours |
| High | 7.0–8.9 | 30 days |
| Medium | 4.0–6.9 | 90 days |
| Low | 0.1–3.9 | Next release |

**KEV-listed CVEs always escalate to the Critical track regardless of CVSS score.**

---

## Architecture

```
triage24/
├── app/
│   ├── page.tsx                      # Landing UI — repo URL input form
│   ├── report/[id]/page.tsx          # Report viewer page
│   └── api/
│       ├── audit/route.ts            # POST /api/audit — triggers full analysis
│       └── report/[id]/route.ts      # GET /api/report/:id — fetch cached result
├── lib/
│   ├── github.ts                     # GitHub API helpers (fetch tree, file contents)
│   ├── deps-extractor.ts             # Parse package-lock.json (npm) + pom.xml (Maven)
│   ├── osv.ts                        # OSV.dev batch API client — CVE lookup
│   ├── kev.ts                        # CISA KEV catalog downloader + matcher
│   ├── reachability.ts               # Import/call-site analysis for vulnerable symbols
│   ├── notification-drafter.ts       # Generate ENISA/CSIRT draft notifications
│   ├── cra-scorer.ts                 # Map findings to CRA obligations + urgency levels
│   └── report-builder.ts            # Assemble final ReportPayload object
├── components/
│   ├── RepoForm.tsx                  # URL input + submit button
│   ├── ReportSummary.tsx             # CRA score card + disclosure deadline alert
│   ├── DepsTable.tsx                 # Table: dep, version, CVE, KEV flag, reachable
│   ├── ReachabilityDetail.tsx        # Per-dep: which symbols are called + file + line
│   └── NotificationDraft.tsx        # Rendered 24 h / 72 h draft for copy-paste
├── types/
│   └── index.ts                      # Shared TypeScript types
├── scripts/
│   └── cli.ts                        # CLI — tsx scripts/cli.ts <repo-url>
└── tests/
    ├── deps-extractor.test.ts
    ├── osv.test.ts
    ├── kev.test.ts
    ├── reachability.test.ts
    └── cra-scorer.test.ts
```

---

## Sub-Tasks

---

### Sub-Task 1 — Project Scaffolding

**Status:** `[ ] pending`

**Intent:**
Bootstrap the Next.js + TypeScript + Tailwind + Vitest project with the correct folder structure, dependencies, and configuration files so every subsequent sub-task has a working base.

**Expected Outcomes:**
- `npx next dev` starts without errors
- `npx vitest run` executes (zero tests, exits cleanly)
- Tailwind classes render correctly on a placeholder home page
- ESLint + TypeScript compiler report zero errors

**Todo List:**
1. Scaffold project with `create-next-app` using TypeScript + Tailwind + App Router + ESLint
2. Add Vitest + `@vitejs/plugin-react` + `@testing-library/react` dev dependencies
3. Add `vitest.config.ts` configured for jsdom environment
4. Create the folder structure: `lib/`, `components/`, `types/`, `scripts/`, `tests/`
5. Add `types/index.ts` with all shared interfaces (see Types section below)
6. Add `.env.example` listing required env vars (`GITHUB_TOKEN`)
7. Commit baseline

**Relevant Context:**
- Next.js 14 App Router
- Vitest needs `globals: true` in config to avoid explicit imports of `describe`/`it`/`expect`

---

### Sub-Task 2 — GitHub Repo Fetcher (`lib/github.ts`)

**Status:** `[ ] pending`

**Intent:**
Given a public GitHub repo URL, fetch the full file tree and retrieve specific file contents. This is the data-ingestion layer for all downstream analysis.

**Expected Outcomes:**
- `fetchRepoTree(owner, repo)` returns flat list of file paths
- `fetchFileContent(owner, repo, path)` returns decoded UTF-8 content
- Graceful error if repo is private or not found (throws typed `GithubError`)
- Uses `GITHUB_TOKEN` env var if set (raises rate limit from 60 → 5000 req/h)

**Todo List:**
1. Implement `parseRepoUrl(url: string): { owner: string; repo: string }` — handles `https://github.com/owner/repo` and `github.com/owner/repo` forms
2. Implement `fetchRepoTree` using GitHub Trees API (`GET /repos/{owner}/{repo}/git/trees/HEAD?recursive=1`)
3. Implement `fetchFileContent` using GitHub Contents API (`GET /repos/{owner}/{repo}/contents/{path}`)
4. Add unit tests in `tests/github.test.ts` using `vi.mock` to stub `fetch`

**Relevant Context:**
- GitHub API base: `https://api.github.com`
- Tree API returns truncated=true if repo > 100k files — handle this with a warning
- File content comes base64-encoded in the `content` field

---

### Sub-Task 3 — Dependency Extractor (`lib/deps-extractor.ts`)

**Status:** `[ ] pending`

**Intent:**
Given the repo file tree and raw file contents, identify all dependency manifest files and extract a normalized list of `{ name, version, ecosystem }` tuples.

**Expected Outcomes:**
- Supports `package-lock.json` v2/v3 (npm) — full transitive dependency tree
- Supports `pom.xml` (Maven) — direct dependencies
- Returns `Dependency[]` array (see shared types)
- Unit tests cover happy path + malformed input

**Todo List:**
1. Implement `extractFromPackageLock(content: string): Dependency[]` — parses `packages` key in lockfile v2/v3 for all transitive deps
2. Implement `extractFromPomXml(content: string): Dependency[]` — lightweight regex for `<dependency>` blocks extracting `groupId:artifactId` + `version`
3. Implement top-level `extractDependencies(tree, fetchFile): Promise<Dependency[]>` — prefers `package-lock.json` over `package.json`, orchestrates both parsers
4. Add unit tests in `tests/deps-extractor.test.ts`

**Relevant Context:**
- `package-lock.json` v2/v3 `packages` key is a flat map of all transitive deps — use this, not `dependencies` from `package.json`
- Maven `groupId:artifactId` becomes the dep name; OSV.dev ecosystem name is `"Maven"`
- Normalized `Dependency` type: `{ name: string; version: string; ecosystem: 'npm' | 'Maven' }`

---

### Sub-Task 4 — CVE Lookup via OSV.dev (`lib/osv.ts`)

**Status:** `[ ] pending`

**Intent:**
Query the OSV.dev batch API to retrieve known CVEs for all dependencies in a single HTTP request, avoiding the rate-limit constraints of NVD. No API key required.

**Expected Outcomes:**
- `lookupCVEsBatch(deps: Dependency[]): Promise<Map<string, CVERecord[]>>` sends one POST and returns a map keyed by `name@version`
- Handles both npm and Maven ecosystems in the same batch call
- Results cached in module-level Map for the process lifetime
- Unit tests mock the OSV.dev HTTP response

**Todo List:**
1. Implement `buildOsvQuery(deps)` — constructs the OSV batch request body: `{ queries: [{ package: { name, ecosystem }, version }] }`
2. Implement `lookupCVEsBatch` — `POST https://api.osv.dev/v1/querybatch` with the query array
3. Map OSV response `vulns[]` to `CVERecord[]`: extract CVE aliases, CVSS score from `severity[]`, summary
4. Implement module-level cache: skip deps already resolved in same process run
5. Add unit tests in `tests/osv.test.ts` with mocked fetch response

**Relevant Context:**
- OSV.dev batch endpoint: `POST https://api.osv.dev/v1/querybatch`
- Request body: `{ "queries": [{ "version": "1.0.0", "package": { "name": "lodash", "ecosystem": "npm" } }] }`
- Response: `{ "results": [ { "vulns": [...] } ] }` — index-aligned with the queries array
- OSV ecosystem names: `"npm"` for Node.js, `"Maven"` for Maven
- CVSS score in OSV lives at `vulns[].severity[0].score` (CVSS_V3 string) — parse with a simple regex

---

### Sub-Task 5 — CISA KEV Catalog Matcher (`lib/kev.ts`)

**Status:** `[ ] pending`

**Intent:**
Download the CISA KEV JSON catalog and cross-reference CVE IDs found in dependencies. Any CVE present in the KEV catalog means the vulnerability is **actively exploited** and must be reported to authorities within 24–72 hours under CRA.

**Expected Outcomes:**
- `downloadKevCatalog(): Promise<KevEntry[]>` fetches and caches the catalog for the process lifetime
- `matchKev(cveIds: string[], catalog: KevEntry[]): KevEntry[]` returns KEV hits
- Unit tests cover matching logic with a fixture catalog slice

**Todo List:**
1. Implement `downloadKevCatalog` fetching `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
2. Cache result in module-level variable (re-download only if older than 1 hour)
3. Implement `matchKev(cveIds, catalog)` — O(1) lookup using a `Set<string>` built from catalog
4. Add `KevEntry` type: `{ cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate }`
5. Add unit tests in `tests/kev.test.ts`

**Relevant Context:**
- KEV catalog URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- The catalog has ~1100 entries as of 2024 — small enough to hold in memory
- CRA Article 14: vendors must notify ENISA within **24 hours** of becoming aware of a KEV-listed vuln

---

### Sub-Task 6 — Static Analysis (`lib/sast.ts`)

**Status:** `[ ] pending`

**Intent:**
Perform lightweight static analysis on source files in the repo to detect common code-level vulnerabilities that must be reported under CRA — no external binary tools, pure TypeScript rule engine.

**Expected Outcomes:**
- Detects at minimum: hardcoded secrets/API keys, use of `eval()`, SQL string concatenation, insecure `http://` URLs in fetch calls, disabled TLS verification (`rejectUnauthorized: false`)
- Returns `SastFinding[]` per file with line number, rule ID, severity, description
- Unit tests cover each rule with a small code snippet fixture

**Todo List:**
1. Define `SastRule` interface: `{ id, name, severity, pattern: RegExp, description, recommendation }`
2. Implement built-in rule set (minimum 5 rules covering the findings above)
3. Implement `scanFile(path, content, rules): SastFinding[]` — line-by-line regex scan
4. Implement `scanRepo(tree, fetchFile): Promise<SastFinding[]>` — filters to `.ts`, `.js`, `.py`, `.java` files, runs `scanFile` on each
5. Add unit tests in `tests/sast.test.ts`

**Relevant Context:**
- Limit SAST scan to files < 500 KB to avoid memory issues
- Only scan source files — skip `node_modules/`, `dist/`, `.git/`
- CRA Annex I Part I requires products to have no known exploitable vulnerabilities at time of release

---

### Sub-Task 7 — CRA Scorer (`lib/cra-scorer.ts`)

**Status:** `[ ] pending`

**Intent:**
Aggregate all findings (CVEs, KEV matches, SAST results) and produce a structured CRA compliance assessment: an overall risk level, per-finding urgency, and required disclosure actions.

**Expected Outcomes:**
- `scoreCRA(deps, cveMap, kevHits, sastFindings): CRAReport` returns a full report object
- Overall score is one of: `CRITICAL | HIGH | MEDIUM | LOW | PASS`
- Each finding includes: urgency level, CRA article reference, recommended action, deadline
- Unit tests cover scoring logic

**Todo List:**
1. Implement urgency escalation logic: KEV hit → CRITICAL regardless of CVSS; else map CVSS → severity
2. Implement SBOM detection: check if repo contains `sbom.json`, `sbom.xml`, `*.spdx`, or `bom.xml`
3. Implement security-policy detection: check for `SECURITY.md`, `.github/SECURITY.md`
4. Implement `scoreCRA` aggregating all inputs into `CRAReport`
5. Add unit tests in `tests/cra-scorer.test.ts`

**Relevant Context:**
- `CRAReport` type: `{ overallRisk, hasSBOM, hasSecurityPolicy, kevFindings, cveFindings, sastFindings, disclosureRequired, disclosureDeadlineHours }`
- CRA Article 14 mandates 24 h initial notification + 72 h detailed report to ENISA for actively exploited vulns
- CRA Annex I Part II item 1: manufacturer must provide SBOM

---

### Sub-Task 8 — API Route (`app/api/audit/route.ts`)

**Status:** `[ ] pending`

**Intent:**
Wire all library modules together into a single HTTP POST endpoint that accepts a repo URL and returns the full `CRAReport` as JSON. This is the backend contract consumed by the frontend.

**Expected Outcomes:**
- `POST /api/audit` with body `{ url: string }` returns `CRAReport` JSON
- Returns 400 for invalid/non-GitHub URLs
- Returns 404 if GitHub repo not found
- Returns 500 with structured error message on unexpected failures
- Response includes `reportId` (UUID) for future reference

**Todo List:**
1. Implement `POST /api/audit/route.ts` handler
2. Validate input URL with `parseRepoUrl` — return 400 if invalid
3. Orchestrate: `fetchRepoTree` → `extractDependencies` → `lookupCVEs` (parallel per dep, max 5 concurrent) → `downloadKevCatalog` → `matchKev` → `scanRepo` → `scoreCRA` → `buildReport`
4. Store result in module-level `Map<reportId, CRAReport>` (in-memory, MVP)
5. Return `{ reportId, report: CRAReport }` with status 200

**Relevant Context:**
- Use `Promise.all` with concurrency limiting (p-limit or manual semaphore) for parallel CVE lookups
- Keep total analysis time < 60 s to avoid Vercel's function timeout

---

### Sub-Task 9 — Frontend UI

**Status:** `[ ] pending`

**Intent:**
Build the user-facing interface: a landing page with the repo URL form, and a report page that renders the full CRA audit results in a clear, actionable layout.

**Expected Outcomes:**
- Landing page (`/`) has a URL input + "Audit" button
- Submitting calls `POST /api/audit` and redirects to `/report/[id]`
- Report page shows: overall risk badge, KEV findings table, CVE table, SAST findings, CRA checklist
- Fully responsive with Tailwind CSS
- Loading state shown during analysis

**Todo List:**
1. Build `components/RepoForm.tsx` — controlled input, validation, loading spinner, calls API
2. Build `app/page.tsx` — hero section + `RepoForm` centered
3. Build `components/ReportSummary.tsx` — color-coded risk badge (red/orange/yellow/green), disclosure deadline alert if KEV hits present
4. Build `components/DepsTable.tsx` — sortable table: dep name, version, CVE count, KEV flag, severity badge
5. Build `components/SastFindings.tsx` — list of code findings with file path, line, rule, recommendation
6. Build `app/report/[id]/page.tsx` — fetches `GET /api/report/[id]` and renders all components
7. Implement `GET /api/report/[id]/route.ts` to serve cached reports

**Relevant Context:**
- Use Tailwind semantic colors: red-600 for CRITICAL, orange-500 for HIGH, yellow-400 for MEDIUM, green-500 for PASS
- The report page should be shareable (static URL with ID)

---

### Sub-Task 10 — CLI Script (`scripts/cli.ts`)

**Status:** `[ ] pending`

**Intent:**
Provide a standalone TypeScript CLI that reuses the same `lib/` analysis logic and prints a human-readable CRA report to stdout — usable locally or in a GitHub Actions workflow.

**Expected Outcomes:**
- `npx tsx scripts/cli.ts https://github.com/owner/repo` prints the report
- Exit code 0 if PASS/LOW, exit code 1 if MEDIUM/HIGH/CRITICAL (for CI gating)
- Output includes the same KEV, CVE, and SAST sections as the web UI

**Todo List:**
1. Implement `scripts/cli.ts` importing directly from `lib/`
2. Parse CLI argument, validate URL
3. Run the same orchestration as the API route
4. Print formatted output using `console.log` with ANSI colors
5. Set `process.exit(1)` if `overallRisk` is MEDIUM or above

**Relevant Context:**
- Use `tsx` (already available as Next.js dev dependency) to run TypeScript directly
- Add `"audit": "tsx scripts/cli.ts"` to `package.json` scripts

---

### Sub-Task 11 — Documentation (`docs/`)

**Status:** `[ ] pending`

**Intent:**
Create the `docs/` folder with a thorough reference document covering CRA obligations, how Triage24 maps to them, and usage instructions.

**Expected Outcomes:**
- `docs/cra-reference.md` — full CRA compliance mapping, article references, disclosure timelines
- `docs/architecture.md` — system design, API contract, data flow
- `README.md` — quick start, env vars, usage

**Todo List:**
1. Write `docs/cra-reference.md` — cover CRA Articles 13, 14, Annex I Parts I & II; CVSS → urgency table; KEV escalation rule; SBOM requirement; security policy requirement
2. Write `docs/architecture.md` — folder structure, API contract, data flow description
3. Write `README.md` — prerequisites, setup, env vars, `npm run dev`, `npm run audit <url>`, test command

**Relevant Context:**
- CRA entered into force December 2024; full applicability from December 2027 with intermediate deadlines
- ENISA is the EU reporting authority for CRA Article 14 notifications

---

## Shared TypeScript Types (`types/index.ts`)

```typescript
export type Ecosystem = 'npm' | 'pypi' | 'maven' | 'unknown'

export interface Dependency {
  name: string
  version: string
  ecosystem: Ecosystem
}

export interface CVERecord {
  cveId: string
  description: string
  cvssScore: number
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'
  publishedDate: string
}

export interface KevEntry {
  cveID: string
  vendorProject: string
  product: string
  vulnerabilityName: string
  dateAdded: string
  shortDescription: string
  requiredAction: string
  dueDate: string
}

export interface SastFinding {
  ruleId: string
  ruleName: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  filePath: string
  line: number
  snippet: string
  description: string
  recommendation: string
}

export interface CRAReport {
  reportId: string
  repoUrl: string
  analyzedAt: string
  overallRisk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'PASS'
  hasSBOM: boolean
  hasSecurityPolicy: boolean
  disclosureRequired: boolean
  disclosureDeadlineHours: 24 | 72 | null
  kevFindings: Array<{ dep: Dependency; cve: CVERecord; kev: KevEntry }>
  cveFindings: Array<{ dep: Dependency; cves: CVERecord[] }>
  sastFindings: SastFinding[]
}
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `NVD_API_KEY` | Recommended | NIST NVD API key — increases rate limit to 50 req/s |
| `GITHUB_TOKEN` | Recommended | GitHub PAT — raises API rate limit to 5000 req/h |

---

## External APIs Used

| API | Purpose | Docs |
|---|---|---|
| GitHub Trees API | Fetch repo file tree | https://docs.github.com/en/rest/git/trees |
| GitHub Contents API | Fetch individual file content | https://docs.github.com/en/rest/repos/contents |
| NIST NVD API v2 | CVE lookup by package name + version | https://nvd.nist.gov/developers/vulnerabilities |
| CISA KEV Catalog | Known exploited vulnerabilities JSON | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
