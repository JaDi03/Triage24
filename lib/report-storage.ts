import type { CRAReport } from '@/types'

const KEY_PREFIX = 'triage24:report:'

/** Keeps a report in the browser session so the report page never depends on server memory. */
export function saveReportInBrowser(report: CRAReport): void {
  try {
    sessionStorage.setItem(KEY_PREFIX + report.reportId, JSON.stringify(report))
  } catch {
    // Storage full or disabled: the report page falls back to the API.
  }
}

export function loadReportFromBrowser(id: string): CRAReport | null {
  try {
    const raw = sessionStorage.getItem(KEY_PREFIX + id)
    return raw ? normalizeReport(JSON.parse(raw)) : null
  } catch {
    return null
  }
}

/**
 * Reports saved by an earlier version of Triage24 (in this browser session, or by a
 * server instance still running the previous code) lack newer fields. Fill them with
 * empty values so the page renders what the report does contain instead of crashing.
 */
export function normalizeReport(report: Partial<CRAReport> & Pick<CRAReport, 'reportId'>): CRAReport {
  return {
    repoUrl: '',
    analyzedAt: new Date(0).toISOString(),
    overallRisk: 'PASS',
    craStatus: 'not_required',
    deadlines: null,
    hasSBOM: false,
    hasSecurityPolicy: false,
    disclosureRequired: false,
    disclosureDeadlineHours: null,
    ...report,
    notifications: report.notifications ?? [],
    drafts: report.drafts ?? [],
    remediations: report.remediations ?? [],
    kevFindings: report.kevFindings ?? [],
    maliciousFindings: report.maliciousFindings ?? [],
    cveFindings: report.cveFindings ?? [],
    sastFindings: report.sastFindings ?? [],
    unresolvedDeps: report.unresolvedDeps ?? [],
    warnings: report.warnings ?? [],
  }
}
