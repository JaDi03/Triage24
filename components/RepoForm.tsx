'use client'

import { useState, FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import { parseRepoUrl } from '@/lib/github'
import { saveReportInBrowser } from '@/lib/report-storage'
import type { CRAReport } from '@/types'

export default function RepoForm() {
  const router = useRouter()
  const [url, setUrl] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  function validate(value: string): string | null {
    if (!value.trim()) return 'Please enter a GitHub repository URL.'
    try {
      // Same rules as the API: github.com only, with or without https://, .git or /tree/<ref>.
      parseRepoUrl(value)
      return null
    } catch {
      return 'Must be a valid GitHub URL, e.g. https://github.com/owner/repo'
    }
  }

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const validationError = validate(url)
    if (validationError) {
      setError(validationError)
      return
    }
    setError(null)
    setLoading(true)

    try {
      const res = await fetch('/api/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
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
      setError('Network error — please try again.')
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} noValidate className="w-full max-w-xl mx-auto">
      <div className="flex flex-col gap-3">
        <label htmlFor="repo-url" className="sr-only">
          GitHub repository URL
        </label>
        <div className="flex gap-2">
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
              'flex-1 rounded-lg border px-4 py-3 text-sm outline-none transition-colors',
              'bg-white text-gray-900 placeholder:text-gray-400',
              'focus:ring-2 focus:ring-blue-500 focus:border-blue-500',
              error ? 'border-red-400' : 'border-gray-300',
              loading ? 'opacity-60 cursor-not-allowed' : '',
            ].join(' ')}
          />
          <button
            type="submit"
            disabled={loading}
            className={[
              'flex items-center gap-2 rounded-lg px-5 py-3 text-sm font-semibold text-white transition-colors',
              'bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2',
              loading ? 'opacity-70 cursor-not-allowed' : '',
            ].join(' ')}
          >
            {loading && (
              <svg
                className="animate-spin h-4 w-4"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                aria-hidden="true"
              >
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
              </svg>
            )}
            {loading ? 'Scanning…' : 'Scan Repository'}
          </button>
        </div>

        {error && (
          <p id="repo-url-error" role="alert" className="text-sm text-red-600">
            {error}
          </p>
        )}
      </div>
    </form>
  )
}
