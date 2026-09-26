'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import { ArrowRight, Loader2 } from 'lucide-react'
import { parseRepoUrl } from '@/lib/github'
import { saveReportInBrowser } from '@/lib/report-storage'
import type { CRAReport } from '@/types'

/** Public repositories with known results, for a quick first run. */
const EXAMPLES = [
  { label: 'Log4Shell demo (Java)', url: 'https://github.com/aaronm-sysdig/log4j-vuln-demo' },
  { label: 'WebVulnLab (Spring + Log4j)', url: 'https://github.com/sil3ntH4ck3r/WebVulnLab' },
  { label: 'OWASP NodeGoat (Node.js)', url: 'https://github.com/OWASP/NodeGoat' },
]

const STEPS = [
  'Downloading the repository',
  'Reading package-lock.json and pom.xml',
  'Checking OSV.dev and the CISA KEV catalog',
  'Applying CRA Article 14',
]

function validate(value: string): string | null {
  if (!value.trim()) return 'Enter a GitHub repository URL.'
  try {
    // Same rules as the API: github.com only, with or without https://, .git or /tree/<ref>.
    parseRepoUrl(value)
    return null
  } catch {
    return 'Enter a github.com repository URL, for example https://github.com/owner/repo'
  }
}

export default function RepoForm() {
  const router = useRouter()
  const [url, setUrl] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    if (!loading) return
    const started = Date.now()
    const timer = setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000)
    return () => clearInterval(timer)
  }, [loading])

  async function analyze(value: string) {
    const validationError = validate(value)
    if (validationError) {
      setError(validationError)
      return
    }
    setError(null)
    setElapsed(0)
    setLoading(true)

    try {
      const res = await fetch('/api/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: value.trim() }),
      })

      const data = (await res.json().catch(() => null)) as
        | { reportId: string; report: CRAReport; error?: undefined }
        | { error?: string }
        | null

      if (!res.ok || !data || !('reportId' in data)) {
        setError(data?.error ?? `Server error (${res.status}). Please try again.`)
        setLoading(false)
        return
      }

      saveReportInBrowser(data.report)
      router.push(`/report/${data.reportId}`)
    } catch {
      setError('Network error. Please try again.')
      setLoading(false)
    }
  }

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    void analyze(url)
  }

  return (
    <div className="space-y-4">
      <form onSubmit={handleSubmit} noValidate>
        <label htmlFor="repo-url" className="mb-2 block text-xs font-medium text-ink-secondary">
          Public GitHub repository
        </label>
        <div className="flex flex-col gap-px sm:flex-row">
          <input
            id="repo-url"
            type="url"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value)
              if (error) setError(null)
            }}
            placeholder="https://github.com/owner/repo"
            disabled={loading}
            aria-invalid={!!error}
            aria-describedby={error ? 'repo-url-error' : undefined}
            className={[
              'h-12 flex-1 border-b-2 bg-canvas px-4 text-sm text-ink outline-none placeholder:text-ink-helper',
              'focus:border-primary disabled:cursor-not-allowed disabled:opacity-60',
              error ? 'border-danger' : 'border-line-strong',
            ].join(' ')}
          />
          <button
            type="submit"
            disabled={loading}
            className="flex h-12 items-center justify-between gap-8 bg-primary px-4 text-sm font-medium text-ink-inverse hover:bg-primary-hover active:bg-primary-active disabled:cursor-not-allowed disabled:opacity-70"
          >
            {loading ? 'Analyzing…' : 'Analyze repository'}
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <ArrowRight className="h-4 w-4" aria-hidden="true" />
            )}
          </button>
        </div>

        {error && (
          <p id="repo-url-error" role="alert" className="mt-2 text-sm text-danger">
            {error}
          </p>
        )}
      </form>

      {loading ? (
        <div role="status" className="border border-line bg-canvas p-4 text-sm text-ink-secondary">
          <p className="font-medium text-ink">Analyzing — usually 5 to 20 seconds ({elapsed} s)</p>
          <ul className="mt-2 space-y-1">
            {STEPS.map((step) => (
              <li key={step} className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-primary" aria-hidden="true" />
                {step}
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-ink-helper">Try an example:</span>
          {EXAMPLES.map((example) => (
            <button
              key={example.url}
              type="button"
              onClick={() => {
                setUrl(example.url)
                void analyze(example.url)
              }}
              className="border border-line bg-layer px-3 py-1 text-ink-secondary hover:border-primary hover:text-primary"
            >
              {example.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
