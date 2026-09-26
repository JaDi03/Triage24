import { readFileSync, existsSync } from 'fs'
import path from 'path'
import { vi } from 'vitest'

const FIXTURES = path.resolve(__dirname, '..', 'fixtures')

interface RecordedQuery {
  package: { name: string; ecosystem: string }
  version: string
}

interface RecordedBatch {
  request: { queries: RecordedQuery[] }
  response: { results: Array<{ vulns?: Array<{ id: string; modified?: string }> }> }
}

function readJson<T>(...segments: string[]): T {
  return JSON.parse(readFileSync(path.join(FIXTURES, ...segments), 'utf8')) as T
}

/** The KEV catalog excerpt recorded from CISA (CVE-2021-44228 and CVE-2021-45046). */
export function recordedKevCatalog() {
  return readJson<{ vulnerabilities: unknown[] }>('kev', 'kev-excerpt.json')
}

/**
 * A fetch replacement that serves the responses recorded by scripts/record-fixtures.mjs:
 * OSV querybatch (per query, so any subset or order works), OSV /v1/vulns/{id} and the
 * CISA KEV excerpt. Queries that were not recorded return no vulnerabilities.
 */
export function recordedFetch() {
  const batch = readJson<RecordedBatch>('osv', 'querybatch.json')
  const byQuery = new Map<string, Array<{ id: string; modified?: string }>>()
  batch.request.queries.forEach((q, i) => {
    byQuery.set(`${q.package.ecosystem}|${q.package.name}|${q.version}`, batch.response.results[i]?.vulns ?? [])
  })

  return vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input)

    if (url === 'https://api.osv.dev/v1/querybatch') {
      const { queries } = JSON.parse(String(init?.body)) as { queries: RecordedQuery[] }
      const results = queries.map((q) => {
        const vulns = byQuery.get(`${q.package.ecosystem}|${q.package.name}|${q.version}`) ?? []
        return vulns.length > 0 ? { vulns } : {}
      })
      return Response.json({ results })
    }

    const vulnMatch = url.match(/^https:\/\/api\.osv\.dev\/v1\/vulns\/(.+)$/)
    if (vulnMatch) {
      const id = decodeURIComponent(vulnMatch[1])
      const file = path.join(FIXTURES, 'osv', 'vulns', `${id}.json`)
      if (!existsSync(file)) return new Response('not found', { status: 404, statusText: 'Not Found' })
      return new Response(readFileSync(file, 'utf8'), { headers: { 'Content-Type': 'application/json' } })
    }

    if (url.includes('known_exploited_vulnerabilities.json')) {
      return Response.json(recordedKevCatalog())
    }

    throw new Error(`Unexpected fetch in test: ${url}`)
  })
}
