import { describe, it, expect, vi, beforeEach } from 'vitest'
import { buildOsvQuery, lookupCVEsBatch, clearOsvCache } from '@/lib/osv'
import { depKey } from '@/lib/dep-key'
import type { Dependency } from '@/types'
import { recordedFetch } from './helpers/osv-fixtures'

// ─── Fixtures ────────────────────────────────────────────────────────────────

const log4jDep: Dependency = { name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1', ecosystem: 'maven' }
const debugDep: Dependency = { name: 'debug', version: '4.4.2', ecosystem: 'npm' }
const lodashDep: Dependency = { name: 'lodash', version: '4.17.20', ecosystem: 'npm' }
const expressDep: Dependency = { name: 'express', version: '4.18.2', ecosystem: 'npm' }

// ─── buildOsvQuery ────────────────────────────────────────────────────────────

describe('buildOsvQuery', () => {
  it('produces one query entry per dependency', () => {
    const result = buildOsvQuery([lodashDep, expressDep])
    expect(result.queries).toHaveLength(2)
  })

  it('maps npm ecosystem correctly', () => {
    const result = buildOsvQuery([lodashDep])
    expect(result.queries[0]).toEqual({
      version: '4.17.20',
      package: { name: 'lodash', ecosystem: 'npm' },
    })
  })

  it('normalises "maven" to "Maven" for OSV', () => {
    const result = buildOsvQuery([log4jDep])
    expect(result.queries[0].package.ecosystem).toBe('Maven')
  })

  it('returns empty queries array for empty deps list', () => {
    const result = buildOsvQuery([])
    expect(result.queries).toHaveLength(0)
  })
})

// ─── lookupCVEsBatch with recorded OSV responses ─────────────────────────────

describe('lookupCVEsBatch', () => {
  let fetchMock: ReturnType<typeof recordedFetch>

  beforeEach(() => {
    vi.unstubAllGlobals()
    clearOsvCache()
    fetchMock = recordedFetch()
    vi.stubGlobal('fetch', fetchMock)
  })

  it('resolves the CVE ID and severity of Log4Shell from the full OSV record', async () => {
    const { byDependency, warnings } = await lookupCVEsBatch([log4jDep])
    const findings = byDependency.get(depKey(log4jDep))!

    const log4shell = findings.find((f) => f.cveId === 'CVE-2021-44228')
    expect(log4shell).toBeDefined()
    expect(log4shell!.osvIds).toEqual(['GHSA-jfh8-c2jp-5v3q'])
    expect(log4shell!.cvssScore).toBe(10)
    expect(log4shell!.severity).toBe('CRITICAL')
    expect(log4shell!.malicious).toBe(false)
    expect(warnings).toEqual([])
  })

  it('finds CVE-2021-45046, the second Log4j CVE in KEV', async () => {
    const { byDependency } = await lookupCVEsBatch([log4jDep])
    const finding = byDependency.get(depKey(log4jDep))!.find((f) => f.cveId === 'CVE-2021-45046')
    expect(finding?.severity).toBe('CRITICAL')
    expect(finding?.cvssScore).toBe(9)
  })

  it('uses the advisory severity label when only a CVSS v4 vector is available', async () => {
    const { byDependency } = await lookupCVEsBatch([log4jDep])
    const finding = byDependency.get(depKey(log4jDep))!.find((f) => f.cveId === 'CVE-2026-34480')
    expect(finding?.cvssScore).toBeNull()
    expect(finding?.severity).toBe('MEDIUM')
  })

  it('merges the GHSA and MAL records of debug 4.4.2 into one malicious finding', async () => {
    const { byDependency } = await lookupCVEsBatch([debugDep])
    const findings = byDependency.get(depKey(debugDep))!

    expect(findings).toHaveLength(1)
    expect(findings[0].malicious).toBe(true)
    expect(findings[0].cveId).toBe('CVE-2025-59144')
    expect(findings[0].osvIds).toEqual(['GHSA-4x49-vf9v-38px', 'MAL-2025-46974'])
    expect(findings[0].aliases).toContain('MAL-2025-46974')
  })

  it('merges lodash advisories that are aliases of each other (5 records, 3 issues)', async () => {
    const { byDependency } = await lookupCVEsBatch([lodashDep])
    const findings = byDependency.get(depKey(lodashDep))!

    expect(findings).toHaveLength(3)
    const commandInjection = findings.find((f) => f.aliases.includes('CVE-2021-23337'))!
    expect(commandInjection.osvIds).toEqual(['GHSA-35jh-r3h4-6jhm', 'GHSA-r5fr-rjxr-66jc'])
    // The highest score of the merged records (7.2 and 8.1).
    expect(commandInjection.cvssScore).toBe(8.1)
  })

  it('keys results by ecosystem, name and version', async () => {
    const { byDependency } = await lookupCVEsBatch([lodashDep, expressDep])
    expect([...byDependency.keys()].sort()).toEqual(['npm:express@4.18.2', 'npm:lodash@4.17.20'])
    expect(byDependency.get('npm:express@4.18.2')).toEqual([])
  })

  it('does not query dependencies whose version is unresolved', async () => {
    const unresolved: Dependency = { name: 'org.springframework.boot:spring-boot-starter-web', version: 'unknown', ecosystem: 'maven' }
    const { byDependency } = await lookupCVEsBatch([unresolved])

    expect(fetchMock).not.toHaveBeenCalled()
    expect(byDependency.size).toBe(0)
  })

  it('serves repeated lookups from the cache', async () => {
    await lookupCVEsBatch([log4jDep])
    const calls = fetchMock.mock.calls.length
    await lookupCVEsBatch([log4jDep])
    expect(fetchMock.mock.calls.length).toBe(calls)
  })

  it('keeps the finding and adds a warning when an advisory cannot be fetched', async () => {
    const failing = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      if (String(input).includes('/v1/vulns/')) return new Response('boom', { status: 500, statusText: 'Internal Server Error' })
      return fetchMock(input, init)
    })
    vi.stubGlobal('fetch', failing)

    const { byDependency, warnings } = await lookupCVEsBatch([debugDep])
    expect(byDependency.get(depKey(debugDep))!.length).toBeGreaterThan(0)
    expect(warnings.some((w) => w.includes('MAL-2025-46974'))).toBe(true)
  })

  it('throws when the OSV batch endpoint fails', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('down', { status: 503, statusText: 'Service Unavailable' })))
    await expect(lookupCVEsBatch([lodashDep])).rejects.toThrow(/OSV\.dev batch API error: 503/)
  })

  it('splits more than 1000 dependencies into several querybatch requests', async () => {
    const many: Dependency[] = Array.from({ length: 1001 }, (_, i) => ({ name: `pkg-${i}`, version: '1.0.0', ecosystem: 'npm' }))
    await lookupCVEsBatch(many)

    const batchCalls = fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/querybatch'))
    expect(batchCalls).toHaveLength(2)
    expect(JSON.parse(String(batchCalls[0][1]!.body)).queries).toHaveLength(1000)
    expect(JSON.parse(String(batchCalls[1][1]!.body)).queries).toHaveLength(1)
  })

  it('follows next_page_token for paginated results', async () => {
    const paged = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/querybatch')) {
        const { queries } = JSON.parse(String(init?.body))
        if (queries[0].page_token === 'page-2') {
          return Response.json({ results: [{ vulns: [{ id: 'GHSA-p6xc-xr62-6r2g' }] }] })
        }
        return Response.json({ results: [{ vulns: [{ id: 'GHSA-jfh8-c2jp-5v3q' }], next_page_token: 'page-2' }] })
      }
      return fetchMock(input, init)
    })
    vi.stubGlobal('fetch', paged)

    const { byDependency } = await lookupCVEsBatch([log4jDep])
    expect(byDependency.get(depKey(log4jDep))!.map((f) => f.cveId).sort()).toEqual(['CVE-2021-44228', 'CVE-2021-45105'])
  })
})
