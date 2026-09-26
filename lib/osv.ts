import type { Dependency, CVERecord } from '@/types'

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'

// Module-level cache: key = "name@version@ecosystem"
const cache = new Map<string, CVERecord[]>()

// ─── OSV Request / Response Types ────────────────────────────────────────────

interface OsvQuery {
  version: string
  package: {
    name: string
    ecosystem: string
  }
}

interface OsvSeverity {
  type: string
  score: string
}

interface OsvVuln {
  id: string
  aliases?: string[]
  summary?: string
  published?: string
  severity?: OsvSeverity[]
}

interface OsvBatchRequest {
  queries: OsvQuery[]
}

interface OsvBatchResponse {
  results: Array<{ vulns?: OsvVuln[] }>
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Cache key for a dependency. */
function cacheKey(dep: Dependency): string {
  return `${dep.name}@${dep.version}@${dep.ecosystem}`
}

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
        // OSV uses 'npm' and 'Maven'; our Ecosystem type already matches those strings.
        ecosystem: dep.ecosystem === 'maven' ? 'Maven' : dep.ecosystem,
      },
    })),
  }
}

/**
 * Parses a CVSS_V3 vector string like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
 * and returns the base score from the E:X component, or falls back to extracting
 * the numeric score directly from "CVSS:3.x/..." entries reported by OSV as plain scores.
 */
function parseCvssScore(scoreStr: string): number {
  // OSV sometimes returns just a numeric string, sometimes a full vector.
  const plain = parseFloat(scoreStr)
  if (!isNaN(plain)) return plain
  // Full CVSS vector — score is not encoded in the string; return 0 to signal unavailable.
  return 0
}

function cvssToSeverity(score: number): CVERecord['severity'] {
  if (score >= 9.0) return 'CRITICAL'
  if (score >= 7.0) return 'HIGH'
  if (score >= 4.0) return 'MEDIUM'
  if (score > 0) return 'LOW'
  return 'NONE'
}

/** Maps a single OSV vuln object to a CVERecord. */
function mapVuln(vuln: OsvVuln): CVERecord {
  // Prefer a CVE alias; fall back to the OSV ID itself.
  const cveId =
    vuln.aliases?.find((a) => a.startsWith('CVE-')) ?? vuln.id

  const cvssScore = vuln.severity?.[0]
    ? parseCvssScore(vuln.severity[0].score)
    : 0

  return {
    cveId,
    description: vuln.summary ?? '',
    cvssScore,
    severity: cvssToSeverity(cvssScore),
    publishedDate: vuln.published ?? '',
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Queries the OSV.dev batch endpoint for all supplied dependencies in a single
 * HTTP POST request and returns a Map keyed by "name@version" → CVERecord[].
 *
 * Results are cached at module level for the lifetime of the process.
 */
export async function lookupCVEsBatch(
  deps: Dependency[],
): Promise<Map<string, CVERecord[]>> {
  const result = new Map<string, CVERecord[]>()
  if (deps.length === 0) return result

  // Split deps into uncached and already-cached.
  const uncached: Dependency[] = []
  for (const dep of deps) {
    const key = cacheKey(dep)
    if (cache.has(key)) {
      result.set(`${dep.name}@${dep.version}`, cache.get(key)!)
    } else {
      uncached.push(dep)
    }
  }

  if (uncached.length === 0) return result

  const body = buildOsvQuery(uncached)

  const response = await fetch(OSV_BATCH_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    throw new Error(`OSV.dev batch API error: ${response.status} ${response.statusText}`)
  }

  const data: OsvBatchResponse = await response.json()

  // Results are index-aligned with the queries array.
  for (let i = 0; i < uncached.length; i++) {
    const dep = uncached[i]
    const vulns = data.results[i]?.vulns ?? []
    const cves = vulns.map(mapVuln)
    const key = cacheKey(dep)
    cache.set(key, cves)
    result.set(`${dep.name}@${dep.version}`, cves)
  }

  return result
}

/** Clears the module-level cache. Useful for testing. */
export function clearOsvCache(): void {
  cache.clear()
}
