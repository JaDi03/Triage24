import type { CRAReport } from '@/types'

/**
 * Best-effort, in-memory copy of recent reports for GET /api/report/[id].
 * It only lives as long as one server instance: on serverless platforms the request
 * that reads a report may land on another instance, so the report page reads the copy
 * kept in the browser first (see lib/report-storage.ts).
 */
const MAX_REPORTS = 50

export const reportCache = new Map<string, CRAReport>()

export function cacheReport(report: CRAReport): void {
  reportCache.set(report.reportId, report)
  while (reportCache.size > MAX_REPORTS) {
    const oldest = reportCache.keys().next().value
    if (oldest === undefined) break
    reportCache.delete(oldest)
  }
}
