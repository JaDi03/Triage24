import type { CRAReport, CVERecord, Dependency } from '@/types'

export interface FindingRow {
  dep: Dependency
  cve: CVERecord
  isKev: boolean
}

const SEVERITY_RANK: Record<CVERecord['severity'], number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  NONE: 0,
}

/** Malicious releases first, then CISA KEV, then severity and CVSS score. */
function priority(row: FindingRow): number[] {
  return [row.cve.malicious ? 1 : 0, row.isKev ? 1 : 0, SEVERITY_RANK[row.cve.severity], row.cve.cvssScore ?? -1]
}

/** One row per (dependency, vulnerability), most urgent first. */
export function toFindingRows(report: Pick<CRAReport, 'cveFindings' | 'kevFindings'>): FindingRow[] {
  const kevKeys = new Set(report.kevFindings.map((k) => `${k.dep.ecosystem}:${k.dep.name}@${k.dep.version}|${k.cve.cveId}`))
  const rows = report.cveFindings.flatMap(({ dep, cves }) =>
    cves.map((cve) => ({
      dep,
      cve,
      isKev: kevKeys.has(`${dep.ecosystem}:${dep.name}@${dep.version}|${cve.cveId}`),
    })),
  )

  return rows.sort((a, b) => {
    const pa = priority(a)
    const pb = priority(b)
    for (let i = 0; i < pa.length; i++) if (pa[i] !== pb[i]) return pb[i] - pa[i]
    return a.dep.name.localeCompare(b.dep.name)
  })
}
