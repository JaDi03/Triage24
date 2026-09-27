'use client'

import { useState } from 'react'
import { ArrowRight, Wrench } from 'lucide-react'
import type { Remediation } from '@/types'
import CopyButton from '@/components/CopyButton'
import { EmptyState } from '@/components/ui'

const PAGE_SIZE = 5

/** One card per dependency to fix: target release and the ready-to-paste prompt for IBM Bob. */
export default function FixWithBob({ remediations }: { remediations: Remediation[] }) {
  const [limit, setLimit] = useState(PAGE_SIZE)
  const [open, setOpen] = useState<number | null>(0)

  if (remediations.length === 0) {
    return <EmptyState>Nothing to fix: no vulnerability that the code may reach.</EmptyState>
  }

  return (
    <div className="space-y-3">
      <ul className="divide-y divide-line border border-line bg-layer">
        {remediations.slice(0, limit).map((fix, i) => (
          <li key={`${fix.dep.name}@${fix.dep.version}`}>
            <button
              type="button"
              aria-expanded={open === i}
              onClick={() => setOpen(open === i ? null : i)}
              className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3 text-left text-sm hover:bg-canvas"
            >
              <Wrench className="h-4 w-4 flex-shrink-0 text-link" aria-hidden="true" />
              <span className="font-mono font-medium text-ink">{fix.dep.name}</span>
              <span className="inline-flex items-center gap-1.5 font-mono text-ink-secondary">
                {fix.dep.version}
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                <span className={fix.recommendedVersion ? 'font-semibold text-success-ink' : 'text-ink-helper'}>
                  {fix.recommendedVersion ?? 'no fixed release listed'}
                </span>
              </span>
              <span className="text-xs text-ink-helper">
                {fix.cveIds.length} {fix.cveIds.length === 1 ? 'vulnerability' : 'vulnerabilities'}
                {fix.alignedWith.length > 0 && ` · upgrade together with ${fix.alignedWith.join(', ')}`}
              </span>
            </button>

            {open === i && (
              <div className="space-y-3 border-t border-line bg-canvas px-4 py-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-xs text-ink-secondary">
                    Paste this instruction into IBM Bob. It upgrades the dependency, points to the code to review and asks
                    for a summary to record as the corrective measure.
                  </p>
                  <CopyButton text={fix.fixPrompt} label="Copy prompt for IBM Bob" />
                </div>
                <pre className="overflow-x-auto whitespace-pre-wrap break-words border border-line bg-layer p-3 font-mono text-xs leading-relaxed text-ink">
                  {fix.fixPrompt}
                </pre>
              </div>
            )}
          </li>
        ))}
      </ul>

      {remediations.length > limit && (
        <button
          type="button"
          onClick={() => setLimit((n) => n + PAGE_SIZE * 2)}
          className="text-sm text-link hover:text-link-hover hover:underline"
        >
          Show more ({remediations.length - limit} remaining)
        </button>
      )}
    </div>
  )
}
