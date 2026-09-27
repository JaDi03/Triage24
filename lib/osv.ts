import type { AffectedRange, Dependency, CVERecord } from '@/types'
import { cvss3BaseScore } from '@/lib/cvss'
import { depKey, hasResolvedVersion } from '@/lib/dep-key'

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns'

/** OSV accepts at most 1000 queries per querybatch request. */
const MAX_QUERIES_PER_BATCH = 1000
/** Follow-up requests for queries whose results are paginated. */
const MAX_PAGE_ROUNDS = 5
/** Parallel GET /v1/vulns/{id} requests. */
const DETAIL_CONCURRENCY = 10
/** Advisory text kept per finding: enough to name the vulnerable functions. */
const MAX_DETAILS_LENGTH = 4000

// ─── OSV Request / Response Types ────────────────────────────────────────────

interface OsvQuery {
  version: string
  package: {
    name: string
    ecosystem: string
  }
  page_token?: string
}

interface OsvSeverity {
  type: string
  score: string
}

interface OsvAffected {
  package?: { name: string; ecosystem: string }
  ranges?: AffectedRange[]
  versions?: string[]
}

interface OsvVuln {
  id: string
  aliases?: string[]
  summary?: string
  details?: string
  affected?: OsvAffected[]
  published?: string
  severity?: OsvSeverity[]
  database_specific?: {
    severity?: string
    cwe_ids?: string[]
  }
}

interface OsvBatchRequest {
  queries: OsvQuery[]
}

/** querybatch only returns the ID and modification date of each vulnerability. */
interface OsvBatchResponse {
  results: Array<{ vulns?: Array<{ id: string; modified?: string }>; next_page_token?: string }>
}

export interface OsvLookupResult {
  /** Findings keyed by depKey(dep); dependencies without vulnerabilities map to []. */
  byDependency: Map<string, CVERecord[]>
  /** Problems that did not stop the lookup (for example an advisory that could not be fetched). */
  warnings: string[]
}

// ─── Caches (process lifetime) ───────────────────────────────────────────────

/** depKey -> OSV IDs returned by querybatch. */
const idCache = new Map<string, string[]>()
/** OSV ID -> full OSV record. */
const detailCache = new Map<string, OsvVuln>()

/** Clears the module-level caches. Useful for testing. */
export function clearOsvCache(): void {
  idCache.clear()
  detailCache.clear()
}

// ─── Query building ──────────────────────────────────────────────────────────

/**
 * Builds the OSV batch request body from a list of dependencies.
 * Exported for unit-testing purposes.
 */
export function buildOsvQuery(deps: Dependency[]): OsvBatchRequest {
  return {
    queries: deps.map((dep) => ({
      version: dep.version,
      package: {
        name: dep.name,
        ecosystem: osvEcosystem(dep),
      },
    })),
  }
}

async function postQueryBatch(queries: OsvQuery[]): Promise<OsvBatchResponse> {
  const response = await fetch(OSV_BATCH_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ queries }),
  })
  if (!response.ok) {
    throw new Error(`OSV.dev batch API error: ${response.status} ${response.statusText}`)
  }
  return response.json()
}

/** Returns the OSV IDs affecting each dependency, index-aligned with `deps`. */
async function fetchVulnIds(deps: Dependency[], warnings: string[]): Promise<string[][]> {
  const idsPerDep: string[][] = deps.map(() => [])
  const allQueries = buildOsvQuery(deps).queries

  for (let start = 0; start < allQueries.length; start += MAX_QUERIES_PER_BATCH) {
    // Each pending entry remembers which dependency the query belongs to.
    let pending = allQueries
      .slice(start, start + MAX_QUERIES_PER_BATCH)
      .map((query, offset) => ({ index: start + offset, query }))

    for (let round = 0; pending.length > 0; round++) {
      if (round === MAX_PAGE_ROUNDS) {
        warnings.push(
          `OSV returned more pages than expected for ${pending.length} dependencies; some advisories may be missing.`,
        )
        break
      }

      const data = await postQueryBatch(pending.map((p) => p.query))
      const next: typeof pending = []
      pending.forEach((p, i) => {
        const result = data.results[i]
        for (const vuln of result?.vulns ?? []) idsPerDep[p.index].push(vuln.id)
        if (result?.next_page_token) {
          next.push({ index: p.index, query: { ...p.query, page_token: result.next_page_token } })
        }
      })
      pending = next
    }
  }

  return idsPerDep
}

/** Fetches the full OSV record for each ID not cached yet, with bounded concurrency. */
async function fetchDetails(ids: string[], warnings: string[]): Promise<void> {
  const queue = ids.filter((id) => !detailCache.has(id))

  async function worker() {
    for (let id = queue.shift(); id !== undefined; id = queue.shift()) {
      try {
        const response = await fetch(`${OSV_VULN_URL}/${encodeURIComponent(id)}`)
        if (!response.ok) throw new Error(`${response.status} ${response.statusText}`)
        detailCache.set(id, await response.json())
      } catch (err) {
        warnings.push(
          `Could not load OSV advisory ${id} (${err instanceof Error ? err.message : String(err)}); it is listed without details.`,
        )
        detailCache.set(id, { id })
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(DETAIL_CONCURRENCY, queue.length) }, worker))
}

// ─── Mapping ─────────────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<CVERecord['severity'], number> = {
  NONE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
}

function cvssToSeverity(score: number): CVERecord['severity'] {
  if (score >= 9.0) return 'CRITICAL'
  if (score >= 7.0) return 'HIGH'
  if (score >= 4.0) return 'MEDIUM'
  if (score > 0) return 'LOW'
  return 'NONE'
}

/** GitHub advisories label severity CRITICAL / HIGH / MODERATE / LOW. */
function labelToSeverity(label: string | undefined): CVERecord['severity'] {
  switch (label?.toUpperCase()) {
    case 'CRITICAL':
      return 'CRITICAL'
    case 'HIGH':
      return 'HIGH'
    case 'MODERATE':
    case 'MEDIUM':
      return 'MEDIUM'
    case 'LOW':
      return 'LOW'
    default:
      return 'NONE'
  }
}

/** CVSS v3 score from the vector when present; otherwise the advisory's severity label. */
function scoreVuln(vuln: OsvVuln): { cvssScore: number | null; severity: CVERecord['severity'] } {
  for (const entry of vuln.severity ?? []) {
    const score = cvss3BaseScore(entry.score)
    if (score !== null) return { cvssScore: score, severity: cvssToSeverity(score) }
  }
  return { cvssScore: null, severity: labelToSeverity(vuln.database_specific?.severity) }
}

function isMalicious(vuln: OsvVuln): boolean {
  return (
    vuln.id.startsWith('MAL-') ||
    (vuln.aliases ?? []).some((alias) => alias.startsWith('MAL-')) ||
    (vuln.database_specific?.cwe_ids ?? []).includes('CWE-506')
  )
}

/** Groups records that describe the same issue (they share an ID or an alias). */
function groupByAlias(vulns: OsvVuln[]): OsvVuln[][] {
  const parent = new Map<string, string>()
  const find = (x: string): string => {
    let root = x
    while (parent.get(root) !== root) root = parent.get(root)!
    parent.set(x, root)
    return root
  }
  const union = (a: string, b: string) => {
    for (const x of [a, b]) if (!parent.has(x)) parent.set(x, x)
    parent.set(find(a), find(b))
  }

  for (const vuln of vulns) {
    union(vuln.id, vuln.id)
    for (const alias of vuln.aliases ?? []) union(vuln.id, alias)
  }

  const groups = new Map<string, OsvVuln[]>()
  for (const vuln of vulns) {
    const root = find(vuln.id)
    groups.set(root, [...(groups.get(root) ?? []), vuln])
  }
  return [...groups.values()]
}

function osvEcosystem(dep: Dependency): string {
  return dep.ecosystem === 'maven' ? 'Maven' : dep.ecosystem
}

/** The advisory's "affected" entries for this exact package (npm names are case-sensitive, Maven's are not). */
function affectedEntriesFor(vuln: OsvVuln, dep: Dependency): OsvAffected[] {
  const normalize = (name: string) => (dep.ecosystem === 'maven' ? name.toLowerCase() : name)
  return (vuln.affected ?? []).filter(
    (entry) => entry.package?.ecosystem === osvEcosystem(dep) && normalize(entry.package.name) === normalize(dep.name),
  )
}

/** Merges the records of one issue into a single finding for `dep`. */
function mergeGroup(group: OsvVuln[], dep: Dependency): CVERecord {
  const osvIds = [...new Set(group.map((v) => v.id))].sort()
  const aliases = [...new Set(group.flatMap((v) => [v.id, ...(v.aliases ?? [])]))].sort()
  const cves = aliases.filter((id) => id.startsWith('CVE-'))
  const cveId = cves[0] ?? osvIds.find((id) => !id.startsWith('MAL-')) ?? osvIds[0]

  let severity: CVERecord['severity'] = 'NONE'
  let cvssScore: number | null = null
  for (const vuln of group) {
    const scored = scoreVuln(vuln)
    if (SEVERITY_RANK[scored.severity] > SEVERITY_RANK[severity]) severity = scored.severity
    if (scored.cvssScore !== null && (cvssScore === null || scored.cvssScore > cvssScore)) {
      cvssScore = scored.cvssScore
    }
  }

  // GitHub advisory summaries are more descriptive than MAL-* ones.
  const described =
    group.find((v) => v.summary && !v.id.startsWith('MAL-')) ?? group.find((v) => v.summary)
  const published = group
    .map((v) => v.published)
    .filter((date): date is string => Boolean(date))
    .sort()[0]

  const entries = group.flatMap((v) => affectedEntriesFor(v, dep))
  const details = group.map((v) => v.details ?? '').find((text) => text.trim() !== '') ?? ''

  return {
    cveId,
    osvIds,
    aliases,
    description: described?.summary ?? '',
    cvssScore,
    severity,
    publishedDate: published ?? '',
    malicious: group.some(isMalicious),
    details: details.slice(0, MAX_DETAILS_LENGTH),
    affectedRanges: entries.flatMap((entry) => entry.ranges ?? []).filter((range) => range.type !== 'GIT'),
    affectedVersions: [...new Set(entries.flatMap((entry) => entry.versions ?? []))],
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Looks up the known vulnerabilities of each dependency on OSV.dev.
 *
 * querybatch only returns vulnerability IDs, so the full record of each ID is fetched
 * from /v1/vulns/{id} to get its aliases (CVE IDs) and severity. Advisories that are
 * aliases of each other are merged into one finding. Dependencies whose version is not
 * resolved are not queried: OSV would match them against every version.
 */
export async function lookupCVEsBatch(deps: Dependency[]): Promise<OsvLookupResult> {
  const warnings: string[] = []
  const byDependency = new Map<string, CVERecord[]>()

  const queryable = [...new Map(deps.filter(hasResolvedVersion).map((d) => [depKey(d), d])).values()]
  if (queryable.length === 0) return { byDependency, warnings }

  const uncached = queryable.filter((dep) => !idCache.has(depKey(dep)))
  if (uncached.length > 0) {
    const idsPerDep = await fetchVulnIds(uncached, warnings)
    uncached.forEach((dep, i) => idCache.set(depKey(dep), [...new Set(idsPerDep[i])]))
  }

  const allIds = [...new Set(queryable.flatMap((dep) => idCache.get(depKey(dep)) ?? []))]
  await fetchDetails(allIds, warnings)

  for (const dep of queryable) {
    const vulns = (idCache.get(depKey(dep)) ?? []).map((id) => detailCache.get(id) ?? { id })
    byDependency.set(depKey(dep), groupByAlias(vulns).map((group) => mergeGroup(group, dep)))
  }

  return { byDependency, warnings }
}
