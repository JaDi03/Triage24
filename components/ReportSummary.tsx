'use client'

import { useEffect, useState } from 'react'
import { Bug, CircleCheck, CircleSlash, FileCheck2, FileX2, Gauge, Scale, ShieldAlert, Skull } from 'lucide-react'
import type { CRAReport, CraNotification, CraStatus } from '@/types'
import { ExternalTextLink, InlineNotification, Tag, type NotificationKind } from '@/components/ui'
import { EvidenceList, ReachabilityTag } from '@/components/Reachability'
import { formatDateTime, formatRemaining } from '@/lib/format'
import { CRA_ARTICLE_14_URL } from '@/lib/regulation'

const STATUS: Record<CraStatus, { kind: NotificationKind; title: string; body: string }> = {
  report_required: {
    kind: 'error',
    title: 'Notification required under CRA Article 14',
    body: 'The product contains an actively exploited vulnerability or a severe incident. Send the early warning and the notification to the CSIRT designated as coordinator and to ENISA via the single reporting platform (Art. 14(7)), and inform impacted users (Art. 14(8)).',
  },
  review_required: {
    kind: 'warning',
    title: 'Review required under CRA Article 14',
    body: 'A finding falls under Article 14, but it may not be contained in the product. Confirm it before the deadlines below.',
  },
  not_required: {
    kind: 'success',
    title: 'No Article 14 notification indicated',
    body: 'No actively exploited vulnerability that the code reaches and no malicious release were found in the dependencies. Vulnerabilities that are not actively exploited do not trigger Article 14 notifications, but should still be fixed.',
  },
}

const CATEGORY: Record<CraNotification['category'], { label: string; icon: typeof Bug; tone: 'danger' | 'malicious' }> = {
  actively_exploited_vulnerability: { label: 'Actively exploited vulnerability', icon: Bug, tone: 'danger' },
  severe_incident: { label: 'Severe incident: malicious release', icon: Skull, tone: 'malicious' },
}

const RISK_TONE = {
  CRITICAL: 'danger',
  HIGH: 'warning',
  MEDIUM: 'caution',
  LOW: 'primary',
  PASS: 'success',
} as const

const STATUS_RANK: Record<CraStatus, number> = { report_required: 2, review_required: 1, not_required: 0 }

/** Reports first, then reviews, then malicious releases, then by CVSS score. */
function sortNotifications(notifications: CraNotification[]): CraNotification[] {
  const rank = (n: CraNotification) => [
    STATUS_RANK[n.status],
    n.cve.malicious ? 1 : 0,
    n.cve.cvssScore ?? -1,
  ]
  return [...notifications].sort((a, b) => {
    const ra = rank(a)
    const rb = rank(b)
    for (let i = 0; i < ra.length; i++) if (ra[i] !== rb[i]) return rb[i] - ra[i]
    return 0
  })
}

/** Re-renders every 30 seconds so the countdowns stay current. */
function useNow(intervalMs = 30_000): Date {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), intervalMs)
    return () => clearInterval(timer)
  }, [intervalMs])
  return now
}

export default function ReportSummary({ report }: { report: CRAReport }) {
  const status = STATUS[report.craStatus]
  const now = useNow()

  return (
    <div className="space-y-6">
      <InlineNotification kind={status.kind} title={status.title} role={report.craStatus === 'not_required' ? 'status' : 'alert'}>
        <p>{status.body}</p>
      </InlineNotification>

      {/* ── Deadlines ── */}
      {report.deadlines && (
        <div>
          <div className="grid gap-px border border-line bg-line sm:grid-cols-3">
            <Deadline label="Became aware" value={formatDateTime(report.deadlines.awareAt)} />
            <Deadline
              label="Early warning · 24 h"
              value={formatDateTime(report.deadlines.earlyWarningDueAt)}
              remaining={formatRemaining(report.deadlines.earlyWarningDueAt, now)}
              article="Art. 14(2)(a) / 14(4)(a)"
            />
            <Deadline
              label="Notification · 72 h"
              value={formatDateTime(report.deadlines.notificationDueAt)}
              remaining={formatRemaining(report.deadlines.notificationDueAt, now)}
              article="Art. 14(2)(b) / 14(4)(b)"
            />
          </div>
          <p className="mt-2 text-xs text-ink-helper">
            Both are maximums: each is due without undue delay. The clock starts when the manufacturer becomes aware;
            the time of this analysis is used as the default.{' '}
            <ExternalTextLink href={CRA_ARTICLE_14_URL}>Read Article 14</ExternalTextLink>
          </p>
        </div>
      )}

      {/* ── Findings under Article 14 ── */}
      {report.notifications.length > 0 && (
        <ul className="divide-y divide-line border border-line bg-layer">
          {sortNotifications(report.notifications).map((n, i) => {
            const category = CATEGORY[n.category]
            return (
              <li key={`${n.dep.name}-${n.cve.cveId}-${i}`} className="p-4 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono font-semibold text-ink">{n.cve.cveId}</span>
                  <span className="min-w-0 break-all text-ink-secondary">
                    in <span className="font-mono">{n.dep.name}</span> {n.dep.version}
                  </span>
                  <Tag tone={category.tone} icon={category.icon}>
                    {category.label}
                  </Tag>
                  <StatusTag status={n.status} />
                  <ReachabilityTag reachability={n.cve.reachability} />
                </div>
                <p className="mt-2 text-ink-secondary">{n.reason}</p>
                <EvidenceList evidence={n.cve.reachability?.evidence ?? []} repoUrl={report.repoUrl} commitSha={report.commitSha} />
                {n.interpretation && (
                  <p className="mt-2 flex gap-2 text-xs text-ink-secondary">
                    <Scale className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" aria-hidden="true" />
                    {n.interpretation}
                  </p>
                )}
                <p className="mt-2 text-xs text-ink-helper">{n.legalBasis}</p>
              </li>
            )
          })}
        </ul>
      )}

      {/* ── Other signals ── */}
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="flex items-start gap-3 border border-line bg-layer p-4">
          <Gauge className="mt-0.5 h-5 w-5 text-ink-helper" aria-hidden="true" />
          <div>
            <p className="text-xs font-medium text-ink-helper">Technical risk</p>
            <div className="mt-1">
              <Tag tone={RISK_TONE[report.overallRisk]}>{report.overallRisk}</Tag>
            </div>
            <p className="mt-1 text-xs text-ink-helper">From severities, KEV and malicious releases. Not a legal status.</p>
          </div>
        </div>
        <ArtifactCard
          label="SBOM"
          present={report.hasSBOM}
          presentText="An SBOM file is present in the repository."
          absentText="No SBOM found. Required by Annex I, Part II(1), from 11 December 2027."
        />
        <ArtifactCard
          label="Security policy"
          present={report.hasSecurityPolicy}
          presentText="SECURITY.md is present."
          absentText="No SECURITY.md found. A coordinated vulnerability disclosure policy is required by Annex I, Part II(5), from 11 December 2027."
        />
      </div>
    </div>
  )
}

function StatusTag({ status }: { status: CraStatus }) {
  if (status === 'report_required') {
    return (
      <Tag tone="danger" icon={ShieldAlert}>
        Report required
      </Tag>
    )
  }
  if (status === 'review_required') {
    return (
      <Tag tone="warning" icon={CircleSlash}>
        Review required
      </Tag>
    )
  }
  return (
    <Tag tone="success" icon={CircleCheck}>
      No notification indicated
    </Tag>
  )
}

function Deadline({ label, value, remaining, article }: { label: string; value: string; remaining?: string; article?: string }) {
  const overdue = remaining?.startsWith('overdue')
  return (
    <div className="bg-layer p-4">
      <p className="text-xs font-medium text-ink-helper">{label}</p>
      <p className="mt-1 text-base font-semibold text-ink">{value}</p>
      {remaining && <p className={`mt-0.5 text-sm ${overdue ? 'font-semibold text-danger' : 'text-ink-secondary'}`}>{remaining}</p>}
      {article && <p className="mt-1 text-xs text-ink-helper">{article}</p>}
    </div>
  )
}

function ArtifactCard({ label, present, presentText, absentText }: { label: string; present: boolean; presentText: string; absentText: string }) {
  const Icon = present ? FileCheck2 : FileX2
  return (
    <div className="flex items-start gap-3 border border-line bg-layer p-4">
      <Icon className={`mt-0.5 h-5 w-5 ${present ? 'text-success' : 'text-ink-helper'}`} aria-hidden="true" />
      <div>
        <p className="text-xs font-medium text-ink-helper">{label}</p>
        <p className="mt-1 text-sm text-ink-secondary">{present ? presentText : absentText}</p>
      </div>
    </div>
  )
}
