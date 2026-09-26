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
    return raw ? (JSON.parse(raw) as CRAReport) : null
  } catch {
    return null
  }
}
