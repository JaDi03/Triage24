import { BellRing, Clock, FileText, Scale } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import RepoForm from '@/components/RepoForm'
import { AppFooter, AppHeader } from '@/components/ui'
import { CRA_ARTICLE_14_URL } from '@/lib/regulation'

const DUTIES: Array<{ icon: LucideIcon; article: string; title: string; body: string }> = [
  {
    icon: BellRing,
    article: 'Art. 14(1) and 14(3)',
    title: 'What must be notified',
    body: 'Actively exploited vulnerabilities and severe incidents affecting the product, to the CSIRT designated as coordinator and to ENISA, through the single reporting platform.',
  },
  {
    icon: Clock,
    article: 'Art. 14(2)(a) and 14(4)(a)',
    title: 'Early warning: 24 hours',
    body: 'Without undue delay and in any event within 24 hours of the manufacturer becoming aware.',
  },
  {
    icon: FileText,
    article: 'Art. 14(2)(b) and 14(4)(b)',
    title: 'Notification: 72 hours',
    body: 'A vulnerability or incident notification without undue delay and in any event within 72 hours of becoming aware.',
  },
]

export default function Home() {
  return (
    <div className="flex min-h-screen flex-col">
      <AppHeader />

      <main className="min-w-0 flex-1">
        {/* ── Hero ── */}
        <section className="border-b border-line bg-layer">
          <div className="mx-auto max-w-6xl px-4 py-14 sm:px-6 sm:py-20">
            <a
              href={CRA_ARTICLE_14_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 border border-primary-muted bg-primary-soft px-3 py-1 text-sm font-medium text-primary-active hover:border-primary"
            >
              <Scale className="h-4 w-4" aria-hidden="true" />
              EU Cyber Resilience Act — Article 14
              <span className="sr-only">(opens the official text in a new tab)</span>
            </a>

            <h1 className="mt-6 max-w-3xl text-4xl font-light leading-tight text-ink sm:text-5xl">
              Know in minutes whether your code triggers a{' '}
              <span className="font-semibold">24-hour reporting duty</span>.
            </h1>

            <p className="mt-5 max-w-2xl text-base leading-relaxed text-ink-secondary">
              Triage24 checks the dependencies of a public GitHub repository against OSV.dev, flags the ones
              actively exploited (CISA KEV) or published with malicious code, and tells you whether they fall under
              the reporting duties of the EU Cyber Resilience Act.
            </p>

            <div className="mt-8 max-w-3xl">
              <RepoForm />
            </div>
          </div>
        </section>

        {/* ── Article 14 duties ── */}
        <section className="mx-auto max-w-6xl px-4 py-12 sm:px-6">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-ink-helper">What Article 14 requires</h2>
          <div className="mt-4 grid gap-px border border-line bg-line sm:grid-cols-3">
            {DUTIES.map(({ icon: Icon, article, title, body }) => (
              <div key={article} className="bg-layer p-5">
                <Icon className="h-6 w-6 text-primary" aria-hidden="true" />
                <p className="mt-4 text-xs font-medium text-ink-helper">{article}</p>
                <h3 className="mt-1 text-base font-semibold text-ink">{title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-ink-secondary">{body}</p>
              </div>
            ))}
          </div>
          <p className="mt-4 text-xs text-ink-helper">
            Only public repositories are supported. Nothing is stored on a server: the report stays in your browser
            session.
          </p>
        </section>
      </main>

      <AppFooter />
    </div>
  )
}
