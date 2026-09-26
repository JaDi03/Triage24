import type { SastFinding } from '@/types'

const SEV_CONFIG: Record<SastFinding['severity'], { bg: string; text: string }> = {
  CRITICAL: { bg: 'bg-red-600',    text: 'text-white' },
  HIGH:     { bg: 'bg-orange-500', text: 'text-white' },
  MEDIUM:   { bg: 'bg-yellow-400', text: 'text-yellow-900' },
  LOW:      { bg: 'bg-blue-400',   text: 'text-white' },
}

interface Props {
  findings: SastFinding[]
}

export default function SastFindings({ findings }: Props) {
  if (findings.length === 0) {
    return (
      <div className="rounded-lg border border-green-200 bg-green-50 p-4 text-sm text-green-800">
        ✅ No SAST findings detected.
      </div>
    )
  }

  return (
    <ul className="space-y-3" role="list">
      {findings.map((finding, i) => {
        const sev = SEV_CONFIG[finding.severity]
        return (
          <li
            key={`${finding.filePath}-${finding.line}-${finding.ruleId}-${i}`}
            className="rounded-lg border border-gray-200 bg-white overflow-hidden"
          >
            {/* ── Header ── */}
            <div className="flex flex-wrap items-center gap-2 bg-gray-50 px-4 py-2 border-b border-gray-200">
              <span
                className={[
                  'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-bold',
                  sev.bg, sev.text,
                ].join(' ')}
              >
                {finding.severity}
              </span>
              <code className="text-xs font-mono text-gray-700 bg-gray-100 rounded px-1.5 py-0.5">
                {finding.ruleId}
              </code>
              <span className="text-xs font-semibold text-gray-800">{finding.ruleName}</span>
            </div>

            {/* ── Body ── */}
            <div className="px-4 py-3 space-y-2">
              {/* File + line */}
              <div className="flex items-center gap-2 text-xs text-gray-500">
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-3-3v6M4 6h16M4 18h16" />
                </svg>
                <code className="font-mono break-all">{finding.filePath}</code>
                <span className="text-gray-400">line {finding.line}</span>
              </div>

              {/* Snippet */}
              {finding.snippet && (
                <pre className="text-xs font-mono bg-gray-900 text-green-400 rounded p-3 overflow-x-auto whitespace-pre-wrap break-all">
                  {finding.snippet}
                </pre>
              )}

              {/* Description */}
              <p className="text-sm text-gray-700">{finding.description}</p>

              {/* Recommendation */}
              <div className="rounded-md border border-blue-100 bg-blue-50 px-3 py-2">
                <p className="text-xs font-semibold text-blue-700 mb-0.5">💡 Recommendation</p>
                <p className="text-sm text-blue-800">{finding.recommendation}</p>
              </div>
            </div>
          </li>
        )
      })}
    </ul>
  )
}
