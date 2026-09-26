import RepoForm from '@/components/RepoForm'

export default function Home() {
  return (
    <div className="flex flex-col min-h-screen bg-gray-50">
      {/* ── Header ── */}
      <header className="bg-white border-b border-gray-200 px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center gap-2">
          <span className="text-xl font-bold text-blue-700 tracking-tight">triage24</span>
          <span className="text-xs bg-blue-100 text-blue-700 rounded-full px-2 py-0.5 font-medium">
            CRA Art. 14
          </span>
        </div>
      </header>

      {/* ── Hero ── */}
      <main className="flex-1 flex flex-col items-center justify-center px-6 py-20">
        <div className="max-w-3xl w-full text-center space-y-6">
          <div className="inline-flex items-center gap-2 rounded-full bg-amber-50 border border-amber-200 px-4 py-1.5 text-sm text-amber-800 font-medium">
            <span aria-hidden="true">⚖️</span>
            EU Cyber Resilience Act — Article 14 Compliance
          </div>

          <h1 className="text-4xl sm:text-5xl font-extrabold text-gray-900 leading-tight">
            Automatic CRA Art. 14<br />
            <span className="text-blue-600">Vulnerability Triage</span>
          </h1>

          <p className="text-lg text-gray-600 max-w-2xl mx-auto leading-relaxed">
            Scan any public GitHub repository in seconds. Get a full compliance report
            covering open-source vulnerabilities, CISA KEV cross-reference, static analysis
            (SAST), SBOM presence and mandatory{' '}
            <strong className="text-gray-800">24 h / 72 h disclosure deadlines</strong> to
            ENISA and national CSIRTs.
          </p>

          {/* ── CRA Info Box ── */}
          <div className="grid sm:grid-cols-3 gap-4 text-left mt-2">
            <div className="bg-white rounded-xl border border-gray-200 p-4 space-y-1">
              <p className="text-xs font-semibold text-blue-700 uppercase tracking-wide">Art. 14 §1–2</p>
              <p className="text-sm text-gray-700">
                Manufacturers must <strong>actively monitor</strong> vulnerabilities in their
                products&apos; components and dependencies.
              </p>
            </div>
            <div className="bg-white rounded-xl border border-gray-200 p-4 space-y-1">
              <p className="text-xs font-semibold text-amber-700 uppercase tracking-wide">Art. 14 §3 — 24 h</p>
              <p className="text-sm text-gray-700">
                <strong>Actively exploited</strong> vulnerabilities (CISA KEV) must be
                notified to ENISA within <strong>24 hours</strong> of discovery.
              </p>
            </div>
            <div className="bg-white rounded-xl border border-gray-200 p-4 space-y-1">
              <p className="text-xs font-semibold text-purple-700 uppercase tracking-wide">Art. 14 §4 — 72 h</p>
              <p className="text-sm text-gray-700">
                A more complete <strong>vulnerability notification</strong> must follow
                within <strong>72 hours</strong> to ENISA and relevant CSIRTs.
              </p>
            </div>
          </div>

          {/* ── Form ── */}
          <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-8 mt-4">
            <p className="text-sm text-gray-500 mb-4">
              Enter a public GitHub repository URL to start the CRA Art. 14 audit:
            </p>
            <RepoForm />
          </div>

          <p className="text-xs text-gray-400">
            Only public repositories are supported. No data is stored permanently.
          </p>
        </div>
      </main>

      {/* ── Footer ── */}
      <footer className="border-t border-gray-200 bg-white py-6 text-center text-xs text-gray-400">
        triage24 — EU Cyber Resilience Act Article 14 compliance agent
      </footer>
    </div>
  )
}
