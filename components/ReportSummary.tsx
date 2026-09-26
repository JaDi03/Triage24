import type { CRAReport } from '@/types'

type Risk = CRAReport['overallRisk']

const RISK_CONFIG: Record<Risk, { label: string; bg: string; text: string; border: string }> = {
  CRITICAL: { label: 'CRITICAL', bg: 'bg-red-600',    text: 'text-white',      border: 'border-red-700' },
  HIGH:     { label: 'HIGH',     bg: 'bg-orange-500',  text: 'text-white',      border: 'border-orange-600' },
  MEDIUM:   { label: 'MEDIUM',   bg: 'bg-yellow-400',  text: 'text-yellow-900', border: 'border-yellow-500' },
  LOW:      { label: 'LOW',      bg: 'bg-blue-500',    text: 'text-white',      border: 'border-blue-600' },
  PASS:     { label: 'PASS',     bg: 'bg-green-500',   text: 'text-white',      border: 'border-green-600' },
}

interface Props {
  report: CRAReport
}

export default function ReportSummary({ report }: Props) {
  const risk = RISK_CONFIG[report.overallRisk]

  return (
    <section className="space-y-5">
      {/* ── Overall risk badge ── */}
      <div className="flex items-center gap-4">
        <span
          className={[
            'inline-flex items-center rounded-full px-4 py-1.5 text-sm font-bold tracking-wide border',
            risk.bg, risk.text, risk.border,
          ].join(' ')}
        >
          {risk.label}
        </span>
        <p className="text-gray-600 text-sm">
          Overall CRA Art. 14 risk for{' '}
          <a
            href={report.repoUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-600 hover:underline break-all"
          >
            {report.repoUrl}
          </a>
        </p>
      </div>

      {/* ── Disclosure deadline alert ── */}
      {report.disclosureRequired && report.disclosureDeadlineHours !== null && (
        <div
          role="alert"
          className={[
            'rounded-lg border-l-4 p-4',
            report.disclosureDeadlineHours === 24
              ? 'border-red-500 bg-red-50 text-red-800'
              : 'border-orange-400 bg-orange-50 text-orange-800',
          ].join(' ')}
        >
          <p className="font-semibold text-sm">
            ⚠️ CRA Art. 14 §{report.disclosureDeadlineHours === 24 ? '3' : '4'} — Disclosure required within{' '}
            <strong>{report.disclosureDeadlineHours} hours</strong>
          </p>
          <p className="text-sm mt-1">
            {report.disclosureDeadlineHours === 24
              ? 'One or more actively exploited vulnerabilities (CISA KEV) were detected. You must notify ENISA within 24 hours of discovery.'
              : 'Vulnerabilities requiring disclosure were detected. Submit a complete notification to ENISA and relevant national CSIRTs within 72 hours.'}
          </p>
        </div>
      )}

      {/* ── SBOM / SECURITY.md status ── */}
      <div className="grid sm:grid-cols-2 gap-3">
        <StatusCard
          label="SBOM"
          present={report.hasSBOM}
          presentText="SBOM file detected in the repository."
          absentText="No SBOM file found. CRA Art. 14 recommends maintaining an up-to-date SBOM."
        />
        <StatusCard
          label="SECURITY.md"
          present={report.hasSecurityPolicy}
          presentText="Security policy (SECURITY.md) is present."
          absentText="No SECURITY.md found. A vulnerability disclosure policy is strongly recommended."
        />
      </div>
    </section>
  )
}

function StatusCard({
  label,
  present,
  presentText,
  absentText,
}: {
  label: string
  present: boolean
  presentText: string
  absentText: string
}) {
  return (
    <div
      className={[
        'flex items-start gap-3 rounded-lg border p-3',
        present ? 'border-green-200 bg-green-50' : 'border-gray-200 bg-gray-50',
      ].join(' ')}
    >
      <span
        className={[
          'mt-0.5 flex-shrink-0 rounded-full w-5 h-5 flex items-center justify-center text-xs font-bold',
          present ? 'bg-green-500 text-white' : 'bg-gray-300 text-gray-600',
        ].join(' ')}
        aria-hidden="true"
      >
        {present ? '✓' : '✗'}
      </span>
      <div>
        <p className="text-xs font-semibold text-gray-700 uppercase tracking-wide">{label}</p>
        <p className="text-sm text-gray-600 mt-0.5">{present ? presentText : absentText}</p>
      </div>
    </div>
  )
}
