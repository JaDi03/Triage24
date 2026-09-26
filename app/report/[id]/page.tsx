import { notFound } from 'next/navigation'
import Link from 'next/link'
import type { CRAReport } from '@/types'
import ReportSummary from '@/components/ReportSummary'
import DepsTable from '@/components/DepsTable'
import SastFindings from '@/components/SastFindings'

interface Props {
  params: Promise<{ id: string }>
}

async function getReport(id: string): Promise<CRAReport | null> {
  // Use absolute URL for server-side fetch in Next.js App Router
  const baseUrl =
    process.env.NEXT_PUBLIC_BASE_URL ??
    (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : 'http://localhost:3000')

  const res = await fetch(`${baseUrl}/api/report/${id}`, {
    cache: 'no-store',
  })

  if (res.status === 404) return null
  if (!res.ok) throw new Error(`Failed to fetch report: ${res.status}`)

  return res.json() as Promise<CRAReport>
}

export default async function ReportPage({ params }: Props) {
  const { id } = await params

  let report: CRAReport | null
  try {
    report = await getReport(id)
  } catch {
    return (
      <ErrorLayout>
        <p className="text-red-700 font-medium">
          An unexpected error occurred while loading this report. Please try again.
        </p>
        <Link href="/" className="mt-4 inline-block text-sm text-blue-600 hover:underline">
          ← Back to home
        </Link>
      </ErrorLayout>
    )
  }

  if (!report) {
    notFound()
  }

  const totalVulns = report.cveFindings.reduce((acc, f) => acc + f.cves.length, 0)

  return (
    <div className="flex flex-col min-h-screen bg-gray-50">
      {/* ── Header ── */}
      <header className="bg-white border-b border-gray-200 px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <Link href="/" className="text-xl font-bold text-blue-700 tracking-tight hover:opacity-80 transition-opacity">
            triage24
          </Link>
          <span className="text-xs text-gray-500">
            Report ID: <code className="font-mono">{report.reportId}</code>
          </span>
        </div>
      </header>

      <main className="flex-1 px-6 py-10">
        <div className="max-w-4xl mx-auto space-y-10">
          {/* ── Meta ── */}
          <div>
            <p className="text-xs text-gray-400 mb-1">
              Analyzed at {new Date(report.analyzedAt).toLocaleString()}
            </p>
            <h1 className="text-2xl font-bold text-gray-900">CRA Art. 14 Compliance Report</h1>
          </div>

          {/* ── Summary ── */}
          <Section title="Summary">
            <ReportSummary report={report} />
          </Section>

          {/* ── Vulnerable dependencies ── */}
          <Section
            title="Vulnerable Dependencies"
            badge={totalVulns > 0 ? String(totalVulns) : undefined}
            badgeColor={totalVulns > 0 ? 'red' : 'green'}
          >
            <DepsTable
              cveFindings={report.cveFindings}
              kevFindings={report.kevFindings}
            />
          </Section>

          {/* ── Coverage notes ── */}
          {(report.unresolvedDeps.length > 0 || report.warnings.length > 0) && (
            <Section title="Not checked">
              <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900 space-y-2">
                {report.unresolvedDeps.length > 0 && (
                  <p>
                    {report.unresolvedDeps.length} dependencies have a version that could not be resolved (for
                    example, one inherited from a parent POM) and were not checked:{' '}
                    <span className="font-mono text-xs">{report.unresolvedDeps.join(', ')}</span>
                  </p>
                )}
                {report.warnings.map((warning, i) => (
                  <p key={i}>{warning}</p>
                ))}
              </div>
            </Section>
          )}

          {/* ── SAST findings ── */}
          <Section
            title="SAST Findings"
            badge={report.sastFindings.length > 0 ? String(report.sastFindings.length) : undefined}
            badgeColor={report.sastFindings.length > 0 ? 'orange' : 'green'}
          >
            <SastFindings findings={report.sastFindings} />
          </Section>
        </div>
      </main>

      {/* ── Footer ── */}
      <footer className="border-t border-gray-200 bg-white py-6 text-center text-xs text-gray-400">
        <p>triage24 — EU Cyber Resilience Act Article 14 compliance agent</p>
        <p className="mt-1 font-medium text-gray-500">Drafting and triage assistant. Not legal advice.</p>
      </footer>
    </div>
  )
}

// ── Reusable section wrapper ───────────────────────────────────────────────────

function Section({
  title,
  badge,
  badgeColor = 'gray',
  children,
}: {
  title: string
  badge?: string
  badgeColor?: 'red' | 'orange' | 'green' | 'gray'
  children: React.ReactNode
}) {
  const badgeClasses: Record<string, string> = {
    red:    'bg-red-100 text-red-700',
    orange: 'bg-orange-100 text-orange-700',
    green:  'bg-green-100 text-green-700',
    gray:   'bg-gray-100 text-gray-600',
  }

  return (
    <section className="space-y-4">
      <div className="flex items-center gap-2">
        <h2 className="text-lg font-semibold text-gray-800">{title}</h2>
        {badge !== undefined && (
          <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-bold ${badgeClasses[badgeColor]}`}>
            {badge}
          </span>
        )}
      </div>
      {children}
    </section>
  )
}

// ── Error layout helper ────────────────────────────────────────────────────────

function ErrorLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-col min-h-screen bg-gray-50 items-center justify-center px-6">
      <div className="max-w-md w-full bg-white rounded-xl border border-red-200 p-8 text-center space-y-3">
        <p className="text-2xl font-bold text-red-600">Error</p>
        {children}
      </div>
    </div>
  )
}
