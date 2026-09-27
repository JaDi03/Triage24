import { CircleHelp, ShieldCheck, Target } from 'lucide-react'
import type { Evidence, Reachability } from '@/types'
import { Tag } from '@/components/ui'

const VERDICT = {
  affected: { label: 'Reachable', tone: 'danger', icon: Target },
  not_affected: { label: 'Not reachable', tone: 'success', icon: ShieldCheck },
  uncertain: { label: 'Uncertain', tone: 'neutral', icon: CircleHelp },
} as const

export function ReachabilityTag({ reachability }: { reachability?: Reachability }) {
  if (!reachability) return <span className="text-xs text-ink-helper">Not analyzed</span>
  const verdict = VERDICT[reachability.verdict]
  return (
    <Tag tone={verdict.tone} icon={verdict.icon}>
      {verdict.label}
    </Tag>
  )
}

/** Link to a line of the analyzed commit on GitHub, when the commit is known. */
function lineUrl(repoUrl: string, commitSha: string | undefined, evidence: Evidence): string | undefined {
  if (!commitSha) return undefined
  const path = evidence.file.split('/').map(encodeURIComponent).join('/')
  return `${repoUrl.replace(/\/$/, '')}/blob/${commitSha}/${path}#L${evidence.line}`
}

/** The code or manifest lines behind a verdict, each linked to GitHub. */
export function EvidenceList({
  evidence,
  repoUrl,
  commitSha,
}: {
  evidence: Evidence[]
  repoUrl: string
  commitSha?: string
}) {
  if (evidence.length === 0) return null
  return (
    <ul className="mt-2 space-y-1">
      {evidence.map((item) => {
        const href = lineUrl(repoUrl, commitSha, item)
        const location = `${item.file}:${item.line}`
        return (
          <li key={location} className="overflow-x-auto bg-canvas px-3 py-1.5 font-mono text-xs">
            {href ? (
              <a href={href} target="_blank" rel="noopener noreferrer" className="text-link hover:text-link-hover hover:underline">
                {location}
              </a>
            ) : (
              <span className="text-ink-secondary">{location}</span>
            )}
            <span className="ml-3 whitespace-pre text-ink">{item.snippet}</span>
          </li>
        )
      })}
    </ul>
  )
}
