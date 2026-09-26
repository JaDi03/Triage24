import { describe, it, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

// ─── Mock all external lib modules BEFORE importing the route ────────────────

vi.mock('@/lib/github', () => ({
  GithubError: class GithubError extends Error {
    status: number
    constructor(message: string, status: number) {
      super(message)
      this.name = 'GithubError'
      this.status = status
    }
  },
  parseRepoUrl: vi.fn(),
  fetchRepoTree: vi.fn(),
  fetchFileContent: vi.fn(),
}))

vi.mock('@/lib/deps-extractor', () => ({
  extractDependencies: vi.fn(),
}))

vi.mock('@/lib/osv', () => ({
  lookupCVEsBatch: vi.fn(),
}))

vi.mock('@/lib/kev', () => ({
  downloadKevCatalog: vi.fn(),
  matchKev: vi.fn(),
}))

vi.mock('@/lib/sast', () => ({
  scanRepo: vi.fn(),
}))

vi.mock('@/lib/cra-scorer', () => ({
  scoreCRA: vi.fn(),
}))

// Import mocked modules and the route AFTER setting up mocks
import { parseRepoUrl, fetchRepoTree, fetchFileContent, GithubError } from '@/lib/github'
import { extractDependencies } from '@/lib/deps-extractor'
import { lookupCVEsBatch } from '@/lib/osv'
import { downloadKevCatalog, matchKev } from '@/lib/kev'
import { scanRepo } from '@/lib/sast'
import { scoreCRA } from '@/lib/cra-scorer'
import { POST, reportCache } from '@/app/api/audit/route'
import type { CRAReport } from '@/types'

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const MOCK_TREE = [
  { path: 'package-lock.json', type: 'blob' as const, sha: 'abc', size: 1000 },
  { path: 'src/index.ts', type: 'blob' as const, sha: 'def', size: 2000 },
]

const MOCK_REPORT: CRAReport = {
  reportId: 'test-report-id-1234',
  repoUrl: 'https://github.com/owner/repo',
  analyzedAt: '2024-01-01T00:00:00.000Z',
  overallRisk: 'PASS',
  craStatus: 'not_required',
  notifications: [],
  deadlines: null,
  hasSBOM: false,
  hasSecurityPolicy: false,
  disclosureRequired: false,
  disclosureDeadlineHours: null,
  kevFindings: [],
  maliciousFindings: [],
  cveFindings: [],
  sastFindings: [],
  unresolvedDeps: [],
  warnings: [],
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeRequest(body: unknown): NextRequest {
  return new NextRequest('http://localhost/api/audit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

function setupHappyPath() {
  vi.mocked(parseRepoUrl).mockReturnValue({ owner: 'owner', repo: 'repo' })
  vi.mocked(fetchRepoTree).mockResolvedValue(MOCK_TREE)
  vi.mocked(fetchFileContent).mockResolvedValue('{}')
  vi.mocked(extractDependencies).mockResolvedValue([])
  vi.mocked(lookupCVEsBatch).mockResolvedValue({ byDependency: new Map(), warnings: [] })
  vi.mocked(downloadKevCatalog).mockResolvedValue([])
  vi.mocked(matchKev).mockReturnValue([])
  vi.mocked(scanRepo).mockReturnValue([])
  vi.mocked(scoreCRA).mockReturnValue(MOCK_REPORT)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('POST /api/audit', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    reportCache.clear()
  })

  // ── Success path ─────────────────────────────────────────────────────────────

  it('returns 200 with reportId and report on success', async () => {
    setupHappyPath()

    const res = await POST(makeRequest({ url: 'https://github.com/owner/repo' }))
    const body = await res.json()

    expect(res.status).toBe(200)
    expect(body.reportId).toBe(MOCK_REPORT.reportId)
    expect(body.report).toEqual(MOCK_REPORT)
  })

  it('stores the report in the cache after success', async () => {
    setupHappyPath()

    await POST(makeRequest({ url: 'https://github.com/owner/repo' }))

    expect(reportCache.has(MOCK_REPORT.reportId)).toBe(true)
    expect(reportCache.get(MOCK_REPORT.reportId)).toEqual(MOCK_REPORT)
  })

  it('calls the full orchestration pipeline in order', async () => {
    setupHappyPath()
    const order: string[] = []

    vi.mocked(fetchRepoTree).mockImplementation(async () => { order.push('fetchRepoTree'); return MOCK_TREE })
    vi.mocked(extractDependencies).mockImplementation(async () => { order.push('extractDependencies'); return [] })
    vi.mocked(lookupCVEsBatch).mockImplementation(async () => { order.push('lookupCVEsBatch'); return { byDependency: new Map(), warnings: [] } })
    vi.mocked(downloadKevCatalog).mockImplementation(async () => { order.push('downloadKevCatalog'); return [] })
    vi.mocked(scanRepo).mockImplementation(() => { order.push('scanRepo'); return [] })
    vi.mocked(scoreCRA).mockImplementation(() => { order.push('scoreCRA'); return MOCK_REPORT })

    await POST(makeRequest({ url: 'https://github.com/owner/repo' }))

    expect(order).toEqual([
      'fetchRepoTree',
      'extractDependencies',
      'lookupCVEsBatch',
      'downloadKevCatalog',
      'scanRepo',
      'scoreCRA',
    ])
  })

  // ── Invalid URL / 400 errors ─────────────────────────────────────────────────

  it('returns 400 when "url" field is missing from body', async () => {
    const res = await POST(makeRequest({}))
    const body = await res.json()

    expect(res.status).toBe(400)
    expect(body.error).toBeTruthy()
  })

  it('returns 400 when "url" field is not a string', async () => {
    const res = await POST(makeRequest({ url: 42 }))
    const body = await res.json()

    expect(res.status).toBe(400)
    expect(body.error).toBeTruthy()
  })

  it('returns 400 when body is not valid JSON', async () => {
    const req = new NextRequest('http://localhost/api/audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not json {',
    })
    const res = await POST(req)
    const body = await res.json()

    expect(res.status).toBe(400)
    expect(body.error).toBeTruthy()
  })

  it('returns 400 when parseRepoUrl throws GithubError(400)', async () => {
    vi.mocked(parseRepoUrl).mockImplementation(() => {
      throw new GithubError('Only github.com URLs are supported', 400)
    })

    const res = await POST(makeRequest({ url: 'https://evil.com/owner/repo' }))
    const body = await res.json()

    expect(res.status).toBe(400)
    expect(body.error).toContain('github.com')
  })

  it('returns 400 for an invalid URL format', async () => {
    vi.mocked(parseRepoUrl).mockImplementation(() => {
      throw new GithubError('Invalid URL: "not-a-url"', 400)
    })

    const res = await POST(makeRequest({ url: 'not-a-url' }))

    expect(res.status).toBe(400)
  })

  // ── 404 — repo not found ──────────────────────────────────────────────────────

  it('returns 404 when fetchRepoTree throws GithubError(404)', async () => {
    vi.mocked(parseRepoUrl).mockReturnValue({ owner: 'owner', repo: 'private-repo' })
    vi.mocked(fetchRepoTree).mockRejectedValue(
      new GithubError('Repository not found or is private (404).', 404),
    )

    const res = await POST(makeRequest({ url: 'https://github.com/owner/private-repo' }))
    const body = await res.json()

    expect(res.status).toBe(404)
    expect(body.error).toBeTruthy()
  })

  // ── 429 — rate limiting ───────────────────────────────────────────────────────

  it('returns 429 when fetchRepoTree throws GithubError(403) — rate limit', async () => {
    vi.mocked(parseRepoUrl).mockReturnValue({ owner: 'owner', repo: 'repo' })
    vi.mocked(fetchRepoTree).mockRejectedValue(
      new GithubError('GitHub API rate limit exceeded (403).', 403),
    )

    const res = await POST(makeRequest({ url: 'https://github.com/owner/repo' }))
    const body = await res.json()

    expect(res.status).toBe(429)
    expect(body.error).toBeTruthy()
  })

  // ── 500 — unexpected errors ───────────────────────────────────────────────────

  it('returns 500 when an unexpected error occurs during tree fetch', async () => {
    vi.mocked(parseRepoUrl).mockReturnValue({ owner: 'owner', repo: 'repo' })
    vi.mocked(fetchRepoTree).mockRejectedValue(new Error('Network timeout'))

    const res = await POST(makeRequest({ url: 'https://github.com/owner/repo' }))
    const body = await res.json()

    expect(res.status).toBe(500)
    expect(body.error).toBeTruthy()
  })

  // ── SAST skips files with size >= 500 KB ─────────────────────────────────────

  it('excludes files >= 500 KB from SAST analysis', async () => {
    const largeTree = [
      { path: 'src/big.ts', type: 'blob' as const, sha: 'xxx', size: 500 * 1024 },
      { path: 'src/small.ts', type: 'blob' as const, sha: 'yyy', size: 1024 },
    ]
    vi.mocked(parseRepoUrl).mockReturnValue({ owner: 'owner', repo: 'repo' })
    vi.mocked(fetchRepoTree).mockResolvedValue(largeTree)
    vi.mocked(fetchFileContent).mockResolvedValue('// code')
    vi.mocked(extractDependencies).mockResolvedValue([])
    vi.mocked(lookupCVEsBatch).mockResolvedValue({ byDependency: new Map(), warnings: [] })
    vi.mocked(downloadKevCatalog).mockResolvedValue([])
    vi.mocked(matchKev).mockReturnValue([])
    vi.mocked(scanRepo).mockReturnValue([])
    vi.mocked(scoreCRA).mockReturnValue(MOCK_REPORT)

    await POST(makeRequest({ url: 'https://github.com/owner/repo' }))

    // Only the small file should be passed to scanRepo
    const scanCall = vi.mocked(scanRepo).mock.calls[0][0]
    expect(scanCall).toHaveLength(1)
    expect(scanCall[0].path).toBe('src/small.ts')
  })
})
