import type { CRAReport, CVERecord } from '@/types'

type Severity = CVERecord['severity']

const SEV_CONFIG: Record<Severity, { bg: string; text: string }> = {
  CRITICAL: { bg: 'bg-red-600',    text: 'text-white' },
  HIGH:     { bg: 'bg-orange-500', text: 'text-white' },
  MEDIUM:   { bg: 'bg-yellow-400', text: 'text-yellow-900' },
  LOW:      { bg: 'bg-blue-400',   text: 'text-white' },
  NONE:     { bg: 'bg-gray-300',   text: 'text-gray-700' },
}

interface Props {
  cveFindings: CRAReport['cveFindings']
  kevFindings: CRAReport['kevFindings']
}

export default function DepsTable({ cveFindings, kevFindings }: Props) {
  // Build a set of CVE IDs that are in the KEV catalog
  const kevCveIds = new Set(kevFindings.map((k) => k.cve.cveId))

  // Flatten into rows: one row per (dep, cve) pair
  const rows = cveFindings.flatMap(({ dep, cves }) =>
    cves.map((cve) => ({ dep, cve, isKev: kevCveIds.has(cve.cveId) })),
  )

  // Also add KEV-only findings that may not appear in cveFindings
  const cveIdsInFindings = new Set(rows.map((r) => r.cve.cveId))
  for (const { dep, cve } of kevFindings) {
    if (!cveIdsInFindings.has(cve.cveId)) {
      rows.push({ dep, cve, isKev: true })
    }
  }

  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-green-200 bg-green-50 p-4 text-sm text-green-800">
        ✅ No vulnerable dependencies detected.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200">
      <table className="min-w-full text-sm">
        <thead className="bg-gray-50 text-xs font-semibold text-gray-600 uppercase tracking-wide">
          <tr>
            <th className="px-4 py-3 text-left">Dependency</th>
            <th className="px-4 py-3 text-left">Version</th>
            <th className="px-4 py-3 text-left">Ecosystem</th>
            <th className="px-4 py-3 text-left">CVE</th>
            <th className="px-4 py-3 text-left">Severity</th>
            <th className="px-4 py-3 text-left">CVSS</th>
            <th className="px-4 py-3 text-left">CISA KEV</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100 bg-white">
          {rows.map((row, i) => {
            const sev = SEV_CONFIG[row.cve.severity]
            return (
              <tr key={`${row.dep.name}-${row.cve.cveId}-${i}`} className="hover:bg-gray-50 transition-colors">
                <td className="px-4 py-3 font-medium text-gray-900 whitespace-nowrap">{row.dep.name}</td>
                <td className="px-4 py-3 font-mono text-gray-600 whitespace-nowrap">{row.dep.version}</td>
                <td className="px-4 py-3 text-gray-500 capitalize">{row.dep.ecosystem}</td>
                <td className="px-4 py-3 font-mono whitespace-nowrap">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${row.cve.cveId}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-600 hover:underline"
                  >
                    {row.cve.cveId}
                  </a>
                </td>
                <td className="px-4 py-3">
                  <span
                    className={[
                      'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-bold',
                      sev.bg, sev.text,
                    ].join(' ')}
                  >
                    {row.cve.severity}
                  </span>
                </td>
                <td className="px-4 py-3 text-gray-700 whitespace-nowrap">
                  {row.cve.cvssScore !== null ? row.cve.cvssScore.toFixed(1) : '—'}
                </td>
                <td className="px-4 py-3">
                  {row.isKev ? (
                    <span className="inline-flex items-center gap-1 rounded-full bg-red-100 text-red-700 px-2.5 py-0.5 text-xs font-bold">
                      🚨 KEV
                    </span>
                  ) : (
                    <span className="text-gray-400 text-xs">—</span>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
