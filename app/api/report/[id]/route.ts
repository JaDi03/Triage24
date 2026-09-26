import { NextRequest, NextResponse } from 'next/server'
import { reportCache } from '@/app/api/audit/route'

// ─── GET /api/report/[id] ─────────────────────────────────────────────────────

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
): Promise<NextResponse> {
  const { id } = await params
  const report = reportCache.get(id)

  if (!report) {
    return NextResponse.json({ error: 'Report not found.' }, { status: 404 })
  }

  return NextResponse.json(report, { status: 200 })
}
