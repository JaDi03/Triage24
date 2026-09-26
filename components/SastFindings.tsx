'use client'

import { useState } from 'react'
import { FileCode2, Lightbulb } from 'lucide-react'
import type { SastFinding } from '@/types'
import { EmptyState, Tag, type Tone } from '@/components/ui'

const PAGE_SIZE = 10

const SEVERITY_TONE: Record<SastFinding['severity'], Tone> = {
  CRITICAL: 'danger',
  HIGH: 'warning',
  MEDIUM: 'caution',
  LOW: 'primary',
}

export default function SastFindings({ findings }: { findings: SastFinding[] }) {
  const [limit, setLimit] = useState(PAGE_SIZE)

  if (findings.length === 0) {
    return <EmptyState>No code findings detected.</EmptyState>
  }

  return (
    <div className="space-y-3">
      <ul className="space-y-3" role="list">
        {findings.slice(0, limit).map((finding, i) => (
          <li
            key={`${finding.filePath}-${finding.line}-${finding.ruleId}-${i}`}
            className="border border-line bg-layer"
          >
            <div className="flex flex-wrap items-center gap-2 border-b border-line bg-canvas px-4 py-2">
              <Tag tone={SEVERITY_TONE[finding.severity]}>{finding.severity}</Tag>
              <code className="text-xs text-ink-helper">{finding.ruleId}</code>
              <span className="text-sm font-medium text-ink">{finding.ruleName}</span>
            </div>

            <div className="space-y-3 px-4 py-3">
              <p className="flex items-center gap-2 text-xs text-ink-secondary">
                <FileCode2 className="h-3.5 w-3.5 flex-shrink-0" aria-hidden="true" />
                <code className="break-all font-mono">{finding.filePath}</code>
                <span className="text-ink-helper">line {finding.line}</span>
              </p>

              {finding.snippet && (
                <pre className="overflow-x-auto whitespace-pre-wrap break-all bg-header p-3 font-mono text-xs text-ink-inverse">
                  {finding.snippet}
                </pre>
              )}

              <p className="text-sm text-ink-secondary">{finding.description}</p>

              <div className="flex gap-2 border-l-4 border-primary bg-primary-soft px-3 py-2">
                <Lightbulb className="mt-0.5 h-4 w-4 flex-shrink-0 text-primary" aria-hidden="true" />
                <p className="text-sm text-ink">
                  <span className="font-medium">Recommendation: </span>
                  {finding.recommendation}
                </p>
              </div>
            </div>
          </li>
        ))}
      </ul>

      {findings.length > limit && (
        <button
          type="button"
          onClick={() => setLimit((n) => n + PAGE_SIZE)}
          className="text-sm text-primary hover:text-primary-hover hover:underline"
        >
          Show more ({findings.length - limit} remaining)
        </button>
      )}
    </div>
  )
}
