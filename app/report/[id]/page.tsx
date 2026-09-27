'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { ArrowLeft, Download, Loader2, Plus, SearchX } from 'lucide-react'
import type { CRAReport } from '@/types'
import ReportSummary from '@/components/ReportSummary'
import DepsTable from '@/components/DepsTable'
import SastFindings from '@/components/SastFindings'
import DraftsPanel from '@/components/DraftsPanel'
import FixWithBob from '@/components/FixWithBob'
import { AppFooter, AppHeader, InlineNotification, Section } from '@/components/ui'
import { formatDateTime } from '@/lib/format'
import { loadReportFromBrowser, normalizeReport, saveReportInBrowser } from '@/lib/report-storage'

type LoadState =
  | { status: 'loading' }
  | { status: 'ready'; report: CRAReport }
  | { status: 'missing' }
  | { status: 'error' }

/**
 * Reports are not stored on a server. The page reads the copy saved in the browser
 * when the analysis finished, and falls back to the API, which only knows reports
 * produced by the same server instance.
 */
async function loadReport(id: string): Promise<LoadState> {
  const local = loadReportFromBrowser(id)
  if (local) return { status: 'ready', report: local }

  try {
    const res = await fetch(`/api/report/${encodeURIComponent(id)}`, { cache: 'no-store' })
    if (res.status === 404) return { status: 'missing' }
    if (!res.ok) return { status: 'error' }
    const report = normalizeReport((await res.json()) as CRAReport)
    saveReportInBrowser(report)
    return { status: 'ready', report }
  } catch {
    return { status: 'error' }
  }
}

/** Saves the full report as JSON, as a record of what was found and when. */
function downloadReport(report: CRAReport) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `triage24-report-${report.analyzedAt.slice(0, 10)}-${report.reportId.slice(0, 8)}.json`
  link.click()
  URL.revokeObjectURL(url)
}

function repoLabel(url: string): string {
  return url.replace(/^https?:\/\/(www\.)?github\.com\//i, '').replace(/\/$/, '')
}

export default function ReportPage() {
  const { id } = useParams<{ id: string }>()
  const [state, setState] = useState<LoadState>({ status: 'loading' })

  useEffect(() => {
    let cancelled = false
    loadReport(id).then((next) => {
      if (!cancelled) setState(next)
    })
    return () => {
      cancelled = true
    }
  }, [id])

  return (
    <div className="flex min-h-screen flex-col">
      <AppHeader>
        <Link href="/" className="flex items-center gap-1.5 text-sm text-ink-inverse/80 hover:text-ink-inverse">
          <Plus className="h-4 w-4" aria-hidden="true" />
          New analysis
        </Link>
      </AppHeader>

      <main className="mx-auto w-full min-w-0 max-w-6xl flex-1 px-4 py-8 sm:px-6">
        {state.status === 'loading' && (
          <p className="flex items-center gap-2 text-sm text-ink-secondary">
            <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            Loading report…
          </p>
        )}

        {(state.status === 'missing' || state.status === 'error') && (
          <div className="max-w-2xl space-y-4">
            <InlineNotification
              kind={state.status === 'missing' ? 'info' : 'error'}
              title={state.status === 'missing' ? 'This report is not available' : 'The report could not be loaded'}
            >
              <p>
                {state.status === 'missing'
                  ? 'Reports are kept only in the browser session where the analysis ran. Run the analysis again to see it.'
                  : 'An unexpected error occurred. Please try again.'}
              </p>
            </InlineNotification>
            <Link href="/" className="inline-flex items-center gap-1.5 text-sm text-link hover:underline">
              <ArrowLeft className="h-4 w-4" aria-hidden="true" />
              Back to the analysis
            </Link>
          </div>
        )}

        {state.status === 'ready' && <Report report={state.report} />}
      </main>

      <AppFooter />
    </div>
  )
}

function Report({ report }: { report: CRAReport }) {
  const totalVulns = report.cveFindings.reduce((acc, f) => acc + f.cves.length, 0)
  const article14 = report.notifications.filter((n) => n.status !== 'not_required').length
  const reachable = report.cveFindings.reduce(
    (acc, f) => acc + f.cves.filter((cve) => cve.reachability?.verdict === 'affected').length,
    0,
  )
  const tiles = [
    { label: 'Article 14 findings', value: article14, alert: article14 > 0 },
    { label: 'Actively exploited (KEV)', value: report.kevFindings.length, alert: report.kevFindings.length > 0 },
    { label: 'Malicious releases', value: report.maliciousFindings.length, alert: report.maliciousFindings.length > 0 },
    { label: 'Reachable by the code', value: reachable, alert: reachable > 0 },
    { label: 'Vulnerable dependencies', value: report.cveFindings.length, alert: false },
    { label: 'Code findings', value: report.sastFindings.length, alert: false },
  ]

  return (
    <div className="space-y-10">
      {/* ── Title ── */}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-xs text-ink-helper">CRA Article 14 report · analyzed {formatDateTime(report.analyzedAt)}</p>
          <h1 className="mt-1 break-all text-2xl font-semibold text-ink sm:text-3xl">
            <a href={report.repoUrl} target="_blank" rel="noopener noreferrer" className="hover:text-link">
              {repoLabel(report.repoUrl)}
            </a>
          </h1>
        </div>
        <button
          type="button"
          onClick={() => downloadReport(report)}
          className="flex h-10 items-center gap-6 border border-primary px-4 text-sm font-medium text-link hover:bg-primary hover:text-ink-inverse"
        >
          Download JSON
          <Download className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>

      {/* ── Key figures ── */}
      <dl className="grid grid-cols-2 gap-px border border-line bg-line sm:grid-cols-3 lg:grid-cols-6">
        {tiles.map((tile) => (
          <div key={tile.label} className="bg-layer p-4">
            <dt className="text-xs text-ink-helper">{tile.label}</dt>
            <dd className={`mt-1 text-3xl font-light ${tile.alert ? 'text-danger' : 'text-ink'}`}>{tile.value}</dd>
          </div>
        ))}
      </dl>

      <Section title="Article 14 assessment">
        <ReportSummary report={report} />
      </Section>

      {report.drafts.length > 0 && (
        <Section
          title="Draft notifications"
          description="Early warning, notification and user advisory for each Article 14 duty, ready to complete and send."
        >
          <DraftsPanel drafts={report.drafts} />
        </Section>
      )}

      <Section
        title="Fix with IBM Bob"
        count={report.remediations.length}
        description="Dependencies to upgrade, most urgent first, with the release that fixes every advisory and an instruction for IBM Bob."
      >
        <FixWithBob remediations={report.remediations} />
      </Section>

      <Section
        title="Known vulnerabilities"
        count={totalVulns}
        description="Most urgent first: malicious releases, then actively exploited vulnerabilities, then by severity."
      >
        <DepsTable report={report} />
      </Section>

      {(report.unresolvedDeps.length > 0 || report.warnings.length > 0) && (
        <Section title="Not checked">
          <InlineNotification kind="warning" title="Part of the repository could not be analyzed">
            {report.unresolvedDeps.length > 0 && (
              <p>
                {report.unresolvedDeps.length} dependencies have a version that could not be resolved (for example,
                one inherited from a parent POM):{' '}
                <span className="font-mono text-xs">{report.unresolvedDeps.join(', ')}</span>
              </p>
            )}
            {report.warnings.map((warning, i) => (
              <p key={i} className="mt-1">
                {warning}
              </p>
            ))}
          </InlineNotification>
        </Section>
      )}

      <Section
        title="Code findings"
        count={report.sastFindings.length}
        description="Pattern-based checks of the source code. They do not trigger Article 14 notifications on their own."
      >
        <SastFindings findings={report.sastFindings} />
      </Section>

      {report.cveFindings.length === 0 && report.notifications.length === 0 && report.sastFindings.length === 0 && (
        <p className="flex items-center gap-2 text-sm text-ink-helper">
          <SearchX className="h-4 w-4" aria-hidden="true" />
          Nothing to report for this repository.
        </p>
      )}
    </div>
  )
}
