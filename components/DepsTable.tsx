'use client'

import { useMemo, useState } from 'react'
import { Bug, ExternalLink, Skull } from 'lucide-react'
import type { CRAReport } from '@/types'
import { toFindingRows } from '@/lib/findings'
import { EmptyState, SeverityTag, Tag } from '@/components/ui'
import { ReachabilityTag } from '@/components/Reachability'

const PAGE_SIZE = 25

type Filter = 'all' | 'article14'

interface Props {
  report: Pick<CRAReport, 'cveFindings' | 'kevFindings'>
}

export default function DepsTable({ report }: Props) {
  const allRows = useMemo(() => toFindingRows(report), [report])
  const [filter, setFilter] = useState<Filter>('all')
  const [hideDev, setHideDev] = useState(false)
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = allRows.filter(
    (row) => (filter === 'all' || row.isKev || row.cve.malicious) && !(hideDev && row.dep.dev),
  )
  const article14Count = allRows.filter((row) => row.isKev || row.cve.malicious).length
  const hasDev = allRows.some((row) => row.dep.dev)

  if (allRows.length === 0) {
    return <EmptyState>No vulnerable dependencies detected.</EmptyState>
  }

  return (
    <div className="space-y-3">
      {/* ── Toolbar ── */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="inline-flex border border-line-strong" role="group" aria-label="Filter findings">
          {(
            [
              ['all', `All (${allRows.length})`],
              ['article14', `Article 14 (${article14Count})`],
            ] as const
          ).map(([value, label]) => (
            <button
              key={value}
              type="button"
              aria-pressed={filter === value}
              onClick={() => {
                setFilter(value)
                setLimit(PAGE_SIZE)
              }}
              className={[
                'px-3 py-1.5 text-sm',
                filter === value ? 'bg-primary text-ink-inverse' : 'bg-layer text-ink-secondary hover:bg-layer-hover',
              ].join(' ')}
            >
              {label}
            </button>
          ))}
        </div>
        {hasDev && (
          <label className="flex items-center gap-2 text-sm text-ink-secondary">
            <input
              type="checkbox"
              checked={hideDev}
              onChange={(e) => setHideDev(e.target.checked)}
              className="h-4 w-4 accent-primary"
            />
            Hide development dependencies
          </label>
        )}
      </div>

      {rows.length === 0 ? (
        <EmptyState>No findings match this filter.</EmptyState>
      ) : (
        <div className="overflow-x-auto border border-line bg-layer">
          <table className="min-w-full text-sm">
            <thead className="bg-line/60 text-left text-xs font-semibold text-ink">
              <tr>
                <th className="px-4 py-3">Dependency</th>
                <th className="px-4 py-3">Version</th>
                <th className="px-4 py-3">Vulnerability</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3 text-right">CVSS</th>
                <th className="px-4 py-3">Exploitation</th>
                <th className="px-4 py-3">Reachability</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.slice(0, limit).map((row, i) => (
                <tr key={`${row.dep.name}-${row.dep.version}-${row.cve.cveId}-${i}`} className="hover:bg-canvas">
                  <td className="px-4 py-3 font-medium text-ink">
                    <span className="font-mono">{row.dep.name}</span>
                    {row.dep.dev && (
                      <span className="ml-2 rounded-full bg-line px-2 py-0.5 text-xs font-normal text-ink-secondary">dev</span>
                    )}
                    <span className="ml-2 text-xs font-normal text-ink-helper">{row.dep.ecosystem}</span>
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 font-mono text-ink-secondary">{row.dep.version}</td>
                  <td className="whitespace-nowrap px-4 py-3">
                    <a
                      href={`https://osv.dev/vulnerability/${encodeURIComponent(row.cve.osvIds[0] ?? row.cve.cveId)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      title={row.cve.description}
                      className="inline-flex items-center gap-1 font-mono text-link hover:text-link-hover hover:underline"
                    >
                      {row.cve.cveId}
                      <ExternalLink className="h-3 w-3" aria-hidden="true" />
                    </a>
                  </td>
                  <td className="px-4 py-3">
                    <SeverityTag severity={row.cve.severity} />
                  </td>
                  <td className="px-4 py-3 text-right font-mono text-ink-secondary">
                    {row.cve.cvssScore !== null ? row.cve.cvssScore.toFixed(1) : '—'}
                  </td>
                  <td className="px-4 py-3">
                    {row.cve.malicious ? (
                      <Tag tone="malicious" icon={Skull}>
                        Malicious release
                      </Tag>
                    ) : row.isKev ? (
                      <Tag tone="danger" icon={Bug}>
                        CISA KEV
                      </Tag>
                    ) : (
                      <span className="text-xs text-ink-helper">Not known</span>
                    )}
                  </td>
                  <td className="px-4 py-3" title={row.cve.reachability?.reasoning}>
                    <ReachabilityTag reachability={row.cve.reachability} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {rows.length > limit && (
        <button
          type="button"
          onClick={() => setLimit((n) => n + PAGE_SIZE * 4)}
          className="text-sm text-link hover:text-link-hover hover:underline"
        >
          Show more ({rows.length - limit} remaining)
        </button>
      )}
    </div>
  )
}
