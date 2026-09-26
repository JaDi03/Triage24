import { describe, it, expect, vi, beforeEach } from 'vitest'
import { buildOsvQuery, lookupCVEsBatch, clearOsvCache } from '@/lib/osv'
import type { Dependency } from '@/types'

// ─── Fixtures ────────────────────────────────────────────────────────────────

const lodashDep: Dependency = { name: 'lodash', version: '4.17.20', ecosystem: 'npm' }
const expressDep: Dependency = { name: 'express', version: '4.18.2', ecosystem: 'npm' }
const mavenDep: Dependency = { name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1', ecosystem: 'maven' }

const lodashVuln = {
  id: 'GHSA-xxxx-1111',
  aliases: ['CVE-2021-23337'],
  summary: 'Prototype pollution in lodash',
  published: '2021-02-15T00:00:00Z',
  severity: [{ type: 'CVSS_V3', score: '7.2' }],
}

const log4jVuln = {
  id: 'GHSA-yyyy-2222',
  aliases: ['CVE-2021-44228'],
  summary: 'Log4Shell RCE vulnerability',
  published: '2021-12-10T00:00:00Z',
  severity: [{ type: 'CVSS_V3', score: '10.0' }],
}

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
    const result = buildOsvQuery([mavenDep])
    expect(result.queries[0].package.ecosystem).toBe('Maven')
  })

  it('returns empty queries array for empty deps list', () => {
    const result = buildOsvQuery([])
    expect(result.queries).toHaveLength(0)
  })
})

// ─── lookupCVEsBatch ─────────────────────────────────────────────────────────

describe('lookupCVEsBatch', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    clearOsvCache()
  })

  function mockFetch(responseBody: object, ok = true) {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok,
        status: ok ? 200 : 500,
        statusText: ok ? 'OK' : 'Internal Server Error',
        json: async () => responseBody,
      }),
    )
  }

  // ── happy path: one dep with one CVE ──────────────────────────────────────

  it('returns CVEs for a dependency that has vulnerabilities', async () => {
    mockFetch({ results: [{ vulns: [lodashVuln] }] })

    const map = await lookupCVEsBatch([lodashDep])
    const cves = map.get('lodash@4.17.20')

    expect(cves).toHaveLength(1)
    expect(cves![0].cveId).toBe('CVE-2021-23337')
    expect(cves![0].description).toBe('Prototype pollution in lodash')
    expect(cves![0].cvssScore).toBe(7.2)
    expect(cves![0].severity).toBe('HIGH')
    expect(cves![0].publishedDate).toBe('2021-02-15T00:00:00Z')
  })

  // ── no vulnerabilities ───────────────────────────────────────────────────

  it('returns an empty array for a dependency with no vulnerabilities', async () => {
    mockFetch({ results: [{ vulns: [] }] })

    const map = await lookupCVEsBatch([expressDep])
    expect(map.get('express@4.18.2')).toEqual([])
  })

  it('returns an empty array when OSV omits the vulns field', async () => {
    mockFetch({ results: [{}] })

    const map = await lookupCVEsBatch([expressDep])
    expect(map.get('express@4.18.2')).toEqual([])
  })

  // ── multiple deps in one batch ───────────────────────────────────────────

  it('handles a mixed batch (npm + maven) in one request', async () => {
    mockFetch({
      results: [
        { vulns: [lodashVuln] },
        { vulns: [log4jVuln] },
      ],
    })

    const map = await lookupCVEsBatch([lodashDep, mavenDep])

    expect(fetch).toHaveBeenCalledOnce()
    expect(map.get('lodash@4.17.20')![0].cveId).toBe('CVE-2021-23337')
    expect(map.get('org.apache.logging.log4j:log4j-core@2.14.1')![0].cveId).toBe('CVE-2021-44228')
  })

  it('sends a single POST request regardless of dep count', async () => {
    mockFetch({ results: [{ vulns: [] }, { vulns: [] }] })

    await lookupCVEsBatch([lodashDep, expressDep])
    expect(fetch).toHaveBeenCalledOnce()

    const [url, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0]
    expect(url).toBe('https://api.osv.dev/v1/querybatch')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body).queries).toHaveLength(2)
  })

  // ── severity mapping ─────────────────────────────────────────────────────

  it('maps CVSS 10.0 to CRITICAL severity', async () => {
    mockFetch({ results: [{ vulns: [log4jVuln] }] })

    const map = await lookupCVEsBatch([mavenDep])
    const cve = map.get('org.apache.logging.log4j:log4j-core@2.14.1')![0]
    expect(cve.severity).toBe('CRITICAL')
    expect(cve.cvssScore).toBe(10.0)
  })

  it('maps CVSS 4.0 to MEDIUM severity', async () => {
    const vuln = { ...lodashVuln, severity: [{ type: 'CVSS_V3', score: '4.0' }] }
    mockFetch({ results: [{ vulns: [vuln] }] })

    const map = await lookupCVEsBatch([lodashDep])
    expect(map.get('lodash@4.17.20')![0].severity).toBe('MEDIUM')
  })

  it('maps missing severity to NONE with cvssScore 0', async () => {
    const vuln = { id: 'GHSA-no-score', aliases: ['CVE-2020-0001'], summary: 'No CVSS' }
    mockFetch({ results: [{ vulns: [vuln] }] })

    const map = await lookupCVEsBatch([lodashDep])
    const cve = map.get('lodash@4.17.20')![0]
    expect(cve.severity).toBe('NONE')
    expect(cve.cvssScore).toBe(0)
  })

  // ── CVE alias fallback ───────────────────────────────────────────────────

  it('falls back to OSV ID when no CVE alias exists', async () => {
    const vuln = { id: 'GHSA-only-1234', summary: 'No CVE alias' }
    mockFetch({ results: [{ vulns: [vuln] }] })

    const map = await lookupCVEsBatch([lodashDep])
    expect(map.get('lodash@4.17.20')![0].cveId).toBe('GHSA-only-1234')
  })

  // ── module-level cache ───────────────────────────────────────────────────

  it('returns cached results without making a second HTTP call', async () => {
    mockFetch({ results: [{ vulns: [lodashVuln] }] })

    // First call — populates cache.
    await lookupCVEsBatch([lodashDep])
    // Second call — should hit cache.
    const map2 = await lookupCVEsBatch([lodashDep])

    expect(fetch).toHaveBeenCalledOnce()
    expect(map2.get('lodash@4.17.20')![0].cveId).toBe('CVE-2021-23337')
  })

  it('only requests uncached deps in a subsequent batch call', async () => {
    // Use a single spy with two sequential responses.
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({ results: [{ vulns: [lodashVuln] }] }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({ results: [{ vulns: [] }] }),
      })
    vi.stubGlobal('fetch', fetchSpy)

    // First call — seeds cache with lodash.
    await lookupCVEsBatch([lodashDep])

    // Second batch includes lodash (cached) + express (uncached).
    const map = await lookupCVEsBatch([lodashDep, expressDep])

    // fetch called a second time, but only for express.
    expect(fetchSpy).toHaveBeenCalledTimes(2)
    const secondCallBody = JSON.parse(fetchSpy.mock.calls[1][1].body)
    expect(secondCallBody.queries).toHaveLength(1)
    expect(secondCallBody.queries[0].package.name).toBe('express')

    // Both deps present in result.
    expect(map.get('lodash@4.17.20')![0].cveId).toBe('CVE-2021-23337')
    expect(map.get('express@4.18.2')).toEqual([])
  })

  // ── empty input ──────────────────────────────────────────────────────────

  it('returns an empty map when given no dependencies', async () => {
    vi.stubGlobal('fetch', vi.fn())

    const map = await lookupCVEsBatch([])
    expect(map.size).toBe(0)
    expect(fetch).not.toHaveBeenCalled()
  })

  // ── API error ────────────────────────────────────────────────────────────

  it('throws when the OSV API responds with a non-OK status', async () => {
    mockFetch({}, false)

    await expect(lookupCVEsBatch([lodashDep])).rejects.toThrow('OSV.dev batch API error: 500')
  })
})
