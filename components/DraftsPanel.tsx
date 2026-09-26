'use client'

import { useState } from 'react'
import { CalendarClock } from 'lucide-react'
import type { CraDrafts } from '@/types'
import CopyButton from '@/components/CopyButton'

const CATEGORY_LABEL: Record<CraDrafts['category'], string> = {
  actively_exploited_vulnerability: 'Actively exploited vulnerability',
  severe_incident: 'Severe incident',
}

const DOCUMENTS = [
  { key: 'earlyWarning', label: 'Early warning', article: '24 h' },
  { key: 'notification', label: 'Notification', article: '72 h' },
  { key: 'userAdvisory', label: 'User advisory', article: 'Art. 14(8)' },
] as const

type DocumentKey = (typeof DOCUMENTS)[number]['key']

/** Article 14 drafts: one set per duty, one tab per document, ready to copy. */
export default function DraftsPanel({ drafts }: { drafts: CraDrafts[] }) {
  const [categoryIndex, setCategoryIndex] = useState(0)
  const [document, setDocument] = useState<DocumentKey>('earlyWarning')
  const current = drafts[Math.min(categoryIndex, drafts.length - 1)]
  if (!current) return null

  const text = current[document]

  return (
    <div className="border border-line bg-layer">
      {drafts.length > 1 && (
        <div className="flex flex-wrap gap-px border-b border-line bg-line" role="tablist" aria-label="Notification duty">
          {drafts.map((d, i) => (
            <button
              key={d.category}
              type="button"
              role="tab"
              aria-selected={i === categoryIndex}
              onClick={() => setCategoryIndex(i)}
              className={[
                'px-4 py-2 text-sm',
                i === categoryIndex ? 'bg-layer font-semibold text-ink' : 'bg-canvas text-ink-secondary hover:text-ink',
              ].join(' ')}
            >
              {CATEGORY_LABEL[d.category]}
            </button>
          ))}
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-2">
        <div className="flex flex-wrap gap-4" role="tablist" aria-label="Document">
          {DOCUMENTS.map((doc) => (
            <button
              key={doc.key}
              type="button"
              role="tab"
              aria-selected={document === doc.key}
              onClick={() => setDocument(doc.key)}
              className={[
                'border-b-2 py-1.5 text-sm',
                document === doc.key ? 'border-primary font-medium text-ink' : 'border-transparent text-ink-secondary hover:text-ink',
              ].join(' ')}
            >
              {doc.label} <span className="text-xs text-ink-helper">· {doc.article}</span>
            </button>
          ))}
        </div>
        <CopyButton text={text} label="Copy draft" />
      </div>

      <pre className="max-h-[28rem] overflow-auto whitespace-pre-wrap break-words p-4 font-mono text-xs leading-relaxed text-ink">
        {text}
      </pre>

      <div className="flex gap-2 border-t border-line px-4 py-3 text-xs text-ink-secondary">
        <CalendarClock className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
        <p>
          {current.finalReportRule} Fill in the [PLACEHOLDERS] before sending; Triage24 never sends anything to ENISA or a
          CSIRT.
        </p>
      </div>
    </div>
  )
}
