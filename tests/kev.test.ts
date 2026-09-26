import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { downloadKevCatalog, matchKev, clearKevCache } from '@/lib/kev'
import type { KevEntry } from '@/types'

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const FIXTURE_ENTRIES: KevEntry[] = [
  {
    cveID: 'CVE-2021-44228',
    vendorProject: 'Apache',
    product: 'Log4j2',
    vulnerabilityName: 'Apache Log4j2 Remote Code Execution Vulnerability',
    dateAdded: '2021-12-10',
    shortDescription: 'Apache Log4j2 JNDI RCE vulnerability.',
    requiredAction: 'Apply updates per vendor instructions.',
    dueDate: '2021-12-24',
  },
  {
    cveID: 'CVE-2022-22965',
    vendorProject: 'VMware',
    product: 'Spring Framework',
    vulnerabilityName: 'Spring Framework RCE Vulnerability',
    dateAdded: '2022-04-01',
    shortDescription: 'Spring4Shell RCE via DataBinder.',
    requiredAction: 'Apply updates per vendor instructions.',
    dueDate: '2022-04-25',
  },
  {
    cveID: 'CVE-2023-12345',
    vendorProject: 'AcmeCorp',
    product: 'WidgetLib',
    vulnerabilityName: 'AcmeCorp WidgetLib Arbitrary Code Execution',
    dateAdded: '2023-06-01',
    shortDescription: 'Arbitrary code execution via crafted input.',
    requiredAction: 'Update to version 2.0.',
    dueDate: '2023-06-22',
  },
]

const MOCK_RESPONSE = { vulnerabilities: FIXTURE_ENTRIES }

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeFetchMock(body: unknown, ok = true, status = 200) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? 'OK' : 'Internal Server Error',
    json: () => Promise.resolve(body),
  })
}

// ─── downloadKevCatalog ───────────────────────────────────────────────────────

describe('downloadKevCatalog', () => {
  beforeEach(() => {
    clearKevCache()
    vi.unstubAllGlobals()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('fetches the CISA KEV URL and returns entries', async () => {
    const fetchMock = makeFetchMock(MOCK_RESPONSE)
    vi.stubGlobal('fetch', fetchMock)

    const result = await downloadKevCatalog()

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(fetchMock).toHaveBeenCalledWith(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    )
    expect(result).toHaveLength(3)
    expect(result[0].cveID).toBe('CVE-2021-44228')
  })

  it('returns all fields of each KevEntry faithfully', async () => {
    vi.stubGlobal('fetch', makeFetchMock(MOCK_RESPONSE))

    const result = await downloadKevCatalog()
    const log4j = result.find((e) => e.cveID === 'CVE-2021-44228')!

    expect(log4j.vendorProject).toBe('Apache')
    expect(log4j.product).toBe('Log4j2')
    expect(log4j.dateAdded).toBe('2021-12-10')
    expect(log4j.dueDate).toBe('2021-12-24')
  })

  it('caches the result — second call does not fetch again', async () => {
    const fetchMock = makeFetchMock(MOCK_RESPONSE)
    vi.stubGlobal('fetch', fetchMock)

    await downloadKevCatalog()
    const second = await downloadKevCatalog()

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(second).toHaveLength(3)
  })

  it('re-fetches after the TTL expires', async () => {
    const fetchMock = makeFetchMock(MOCK_RESPONSE)
    vi.stubGlobal('fetch', fetchMock)

    // Prime the cache.
    await downloadKevCatalog()

    // Advance Date.now() beyond the 1-hour TTL.
    const nowSpy = vi
      .spyOn(Date, 'now')
      .mockReturnValue(Date.now() + 61 * 60 * 1000)

    await downloadKevCatalog()

    expect(fetchMock).toHaveBeenCalledTimes(2)
    nowSpy.mockRestore()
  })

  it('throws when the HTTP response is not OK', async () => {
    vi.stubGlobal('fetch', makeFetchMock(null, false, 503))

    await expect(downloadKevCatalog()).rejects.toThrow(
      'CISA KEV catalog fetch failed: 503',
    )
  })

  it('handles an empty vulnerabilities array gracefully', async () => {
    vi.stubGlobal('fetch', makeFetchMock({ vulnerabilities: [] }))

    const result = await downloadKevCatalog()
    expect(result).toEqual([])
  })

  it('handles a missing vulnerabilities key gracefully', async () => {
    vi.stubGlobal('fetch', makeFetchMock({}))

    const result = await downloadKevCatalog()
    expect(result).toEqual([])
  })

  it('clearKevCache() forces a fresh fetch on next call', async () => {
    const fetchMock = makeFetchMock(MOCK_RESPONSE)
    vi.stubGlobal('fetch', fetchMock)

    await downloadKevCatalog()
    clearKevCache()
    await downloadKevCatalog()

    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

// ─── matchKev ─────────────────────────────────────────────────────────────────

describe('matchKev', () => {
  it('returns matching entries when CVE IDs overlap', () => {
    const ids = ['CVE-2021-44228', 'CVE-2099-99999']
    const result = matchKev(ids, FIXTURE_ENTRIES)

    expect(result).toHaveLength(1)
    expect(result[0].cveID).toBe('CVE-2021-44228')
  })

  it('returns all entries when all IDs match', () => {
    const ids = FIXTURE_ENTRIES.map((e) => e.cveID)
    const result = matchKev(ids, FIXTURE_ENTRIES)

    expect(result).toHaveLength(FIXTURE_ENTRIES.length)
  })

  it('returns an empty array when no IDs match', () => {
    const result = matchKev(['CVE-9999-0001', 'CVE-9999-0002'], FIXTURE_ENTRIES)
    expect(result).toEqual([])
  })

  it('returns an empty array for an empty cveIds list', () => {
    const result = matchKev([], FIXTURE_ENTRIES)
    expect(result).toEqual([])
  })

  it('returns an empty array for an empty catalog', () => {
    const result = matchKev(['CVE-2021-44228'], [])
    expect(result).toEqual([])
  })

  it('returns an empty array when both inputs are empty', () => {
    const result = matchKev([], [])
    expect(result).toEqual([])
  })

  it('does not duplicate entries for repeated CVE IDs in the input list', () => {
    const ids = ['CVE-2021-44228', 'CVE-2021-44228']
    const result = matchKev(ids, FIXTURE_ENTRIES)

    // catalog.filter is linear over catalog — one match → one result
    expect(result).toHaveLength(1)
    expect(result[0].cveID).toBe('CVE-2021-44228')
  })

  it('matches multiple entries correctly', () => {
    const ids = ['CVE-2021-44228', 'CVE-2023-12345']
    const result = matchKev(ids, FIXTURE_ENTRIES)

    expect(result).toHaveLength(2)
    const matched = result.map((e) => e.cveID).sort()
    expect(matched).toEqual(['CVE-2021-44228', 'CVE-2023-12345'])
  })

  it('is case-sensitive and does not match IDs with wrong casing', () => {
    const result = matchKev(['cve-2021-44228'], FIXTURE_ENTRIES)
    expect(result).toEqual([])
  })

  it('preserves the full KevEntry structure for matched entries', () => {
    const result = matchKev(['CVE-2022-22965'], FIXTURE_ENTRIES)

    expect(result[0]).toEqual(FIXTURE_ENTRIES[1])
  })
})
