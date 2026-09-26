import type { CRAReport, CraNotification, CraStatus } from '@/types'

type Risk = CRAReport['overallRisk']

const RISK_CONFIG: Record<Risk, { label: string; bg: string; text: string; border: string }> = {
  CRITICAL: { label: 'CRITICAL', bg: 'bg-red-600',    text: 'text-white',      border: 'border-red-700' },
  HIGH:     { label: 'HIGH',     bg: 'bg-orange-500',  text: 'text-white',      border: 'border-orange-600' },
  MEDIUM:   { label: 'MEDIUM',   bg: 'bg-yellow-400',  text: 'text-yellow-900', border: 'border-yellow-500' },
  LOW:      { label: 'LOW',      bg: 'bg-blue-500',    text: 'text-white',      border: 'border-blue-600' },
  PASS:     { label: 'PASS',     bg: 'bg-green-500',   text: 'text-white',      border: 'border-green-600' },
}

const STATUS_CONFIG: Record<CraStatus, { title: string; body: string; classes: string }> = {
  report_required: {
    title: 'CRA Art. 14 — notification required',
    body: 'The product contains an actively exploited vulnerability or a severe incident. Send the early warning and the notification to the CSIRT designated as coordinator and to ENISA via the single reporting platform (Art. 14(7)), and inform impacted users (Art. 14(8)).',
    classes: 'border-red-500 bg-red-50 text-red-800',
  },
  review_required: {
    title: 'CRA Art. 14 — review required',
    body: 'A finding falls under Art. 14, but it may not be contained in the product. Confirm before the deadlines below.',
    classes: 'border-orange-400 bg-orange-50 text-orange-800',
  },
  not_required: {
    title: 'No CRA Art. 14 notification indicated',
    body: 'No actively exploited vulnerability or malicious release was found in the dependencies. Vulnerabilities that are not actively exploited do not trigger Art. 14 notifications, but should still be fixed.',
    classes: 'border-green-500 bg-green-50 text-green-800',
  },
}

const CATEGORY_LABEL: Record<CraNotification['category'], string> = {
  actively_exploited_vulnerability: 'Actively exploited vulnerability',
  severe_incident: 'Severe incident (malicious release)',
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

interface Props {
  report: CRAReport
}

export default function ReportSummary({ report }: Props) {
  const risk = RISK_CONFIG[report.overallRisk]
  const status = STATUS_CONFIG[report.craStatus]

  return (
    <section className="space-y-5">
      {/* ── Technical risk badge ── */}
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
          Technical risk for{' '}
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

      {/* ── CRA Art. 14 status ── */}
      <div role={report.craStatus === 'not_required' ? 'status' : 'alert'} className={`rounded-lg border-l-4 p-4 ${status.classes}`}>
        <p className="font-semibold text-sm">{status.title}</p>
        <p className="text-sm mt-1">{status.body}</p>

        {report.deadlines && (
          <dl className="mt-3 grid gap-2 sm:grid-cols-3 text-sm">
            <div>
              <dt className="text-xs uppercase tracking-wide opacity-75">Became aware</dt>
              <dd className="font-medium">{formatDate(report.deadlines.awareAt)}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide opacity-75">Early warning due (24 h)</dt>
              <dd className="font-medium">{formatDate(report.deadlines.earlyWarningDueAt)}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide opacity-75">Notification due (72 h)</dt>
              <dd className="font-medium">{formatDate(report.deadlines.notificationDueAt)}</dd>
            </div>
          </dl>
        )}
        {report.deadlines && (
          <p className="mt-2 text-xs opacity-80">
            These are maximums: both are due without undue delay (Art. 14(2)(a)-(b), 14(4)(a)-(b)). The clock
            starts when the manufacturer becomes aware; the time of this analysis is used as the default.
          </p>
        )}
      </div>

      {/* ── Findings that fall under Art. 14 ── */}
      {report.notifications.length > 0 && (
        <ul className="space-y-2">
          {report.notifications.map((n, i) => (
            <li key={`${n.dep.name}-${n.cve.cveId}-${i}`} className="rounded-lg border border-gray-200 bg-white p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono font-semibold text-gray-900">{n.cve.cveId}</span>
                <span className="text-gray-600">
                  in {n.dep.name} {n.dep.version}
                </span>
                <span className="rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-700">
                  {CATEGORY_LABEL[n.category]}
                </span>
                <span
                  className={[
                    'rounded-full px-2 py-0.5 text-xs font-bold',
                    n.status === 'report_required' ? 'bg-red-100 text-red-700' : 'bg-orange-100 text-orange-700',
                  ].join(' ')}
                >
                  {n.status === 'report_required' ? 'Report required' : 'Review required'}
                </span>
              </div>
              <p className="mt-1 text-gray-700">{n.reason}</p>
              <p className="mt-1 text-xs text-gray-500">{n.legalBasis}</p>
            </li>
          ))}
        </ul>
      )}

      {/* ── SBOM / SECURITY.md status ── */}
      <div className="grid sm:grid-cols-2 gap-3">
        <StatusCard
          label="SBOM"
          present={report.hasSBOM}
          presentText="SBOM file detected in the repository."
          absentText="No SBOM file found. The CRA requires an SBOM covering at least the top-level dependencies (Annex I, Part II(1)), applicable from 11 December 2027."
        />
        <StatusCard
          label="SECURITY.md"
          present={report.hasSecurityPolicy}
          presentText="Security policy (SECURITY.md) is present."
          absentText="No SECURITY.md found. The CRA requires a coordinated vulnerability disclosure policy (Annex I, Part II(5)), applicable from 11 December 2027."
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
