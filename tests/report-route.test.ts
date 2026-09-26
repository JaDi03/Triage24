import { describe, it, expect, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import { reportCache } from '@/app/api/audit/route'
import { GET } from '@/app/api/report/[id]/route'
import type { CRAReport } from '@/types'

// ─── Fixture ─────────────────────────────────────────────────────────────────

const MOCK_REPORT: CRAReport = {
  reportId: 'report-abc-123',
  repoUrl: 'https://github.com/owner/repo',
  analyzedAt: '2024-01-01T00:00:00.000Z',
  overallRisk: 'HIGH',
  hasSBOM: false,
  hasSecurityPolicy: true,
  disclosureRequired: true,
  disclosureDeadlineHours: 72,
  kevFindings: [],
  cveFindings: [],
  sastFindings: [],
  unresolvedDeps: [],
  warnings: [],
}

function makeGetRequest(id: string): [NextRequest, { params: Promise<{ id: string }> }] {
  return [
    new NextRequest(`http://localhost/api/report/${id}`),
    { params: Promise.resolve({ id }) },
  ]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('GET /api/report/[id]', () => {
  beforeEach(() => {
    reportCache.clear()
  })

  it('returns 200 with the cached report when it exists', async () => {
    reportCache.set(MOCK_REPORT.reportId, MOCK_REPORT)
    const [req, ctx] = makeGetRequest(MOCK_REPORT.reportId)

    const res = await GET(req, ctx)
    const body = await res.json()

    expect(res.status).toBe(200)
    expect(body).toEqual(MOCK_REPORT)
  })

  it('returns 404 when the report id is not in the cache', async () => {
    const [req, ctx] = makeGetRequest('nonexistent-id')

    const res = await GET(req, ctx)
    const body = await res.json()

    expect(res.status).toBe(404)
    expect(body.error).toBeTruthy()
  })

  it('returns 404 for an empty cache', async () => {
    const [req, ctx] = makeGetRequest('any-id')

    const res = await GET(req, ctx)

    expect(res.status).toBe(404)
  })
})
