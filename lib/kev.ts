import type { KevEntry } from '@/types'

const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

const CACHE_TTL_MS = 60 * 60 * 1000 // 1 hour

// ─── In-memory cache ─────────────────────────────────────────────────────────

interface KevCache {
  entries: KevEntry[]
  fetchedAt: number
}

let _cache: KevCache | null = null

// ─── CISA KEV JSON shape ──────────────────────────────────────────────────────

interface KevCatalogResponse {
  vulnerabilities: KevEntry[]
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Downloads the CISA Known Exploited Vulnerabilities catalog and caches it
 * in memory for {@link CACHE_TTL_MS} ms (1 hour). Subsequent calls within
 * the TTL window return the cached result without making a network request.
 */
export async function downloadKevCatalog(): Promise<KevEntry[]> {
  const now = Date.now()

  if (_cache !== null && now - _cache.fetchedAt < CACHE_TTL_MS) {
    return _cache.entries
  }

  const response = await fetch(KEV_URL)

  if (!response.ok) {
    throw new Error(
      `CISA KEV catalog fetch failed: ${response.status} ${response.statusText}`,
    )
  }

  const data: KevCatalogResponse = await response.json()
  const entries = data.vulnerabilities ?? []

  _cache = { entries, fetchedAt: now }

  return entries
}

/**
 * Returns every {@link KevEntry} whose `cveID` field is present in
 * {@link cveIds}. Uses a {@link Set} for O(1) per-lookup performance.
 */
export function matchKev(cveIds: string[], catalog: KevEntry[]): KevEntry[] {
  const idSet = new Set(cveIds)
  return catalog.filter((entry) => idSet.has(entry.cveID))
}

/** Resets the in-memory cache. Intended for use in tests only. */
export function clearKevCache(): void {
  _cache = null
}
