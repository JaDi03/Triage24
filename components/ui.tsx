import Link from 'next/link'
import type { ReactNode } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Info,
  ShieldAlert,
  type LucideIcon,
} from 'lucide-react'
import type { CVERecord } from '@/types'
import { CRA_ARTICLE_14_URL, CRA_OFFICIAL_URL } from '@/lib/regulation'

// ─── Shell ───────────────────────────────────────────────────────────────────

export function AppHeader({ children }: { children?: ReactNode }) {
  return (
    <header className="bg-header text-ink-inverse">
      <div className="mx-auto flex h-12 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
        <Link href="/" className="flex items-baseline gap-2 text-sm hover:opacity-90">
          <span className="font-semibold tracking-tight">Triage24</span>
          <span className="hidden text-xs text-ink-inverse/70 sm:inline">CRA Article 14 compliance agent</span>
        </Link>
        {children}
      </div>
    </header>
  )
}

export function AppFooter() {
  return (
    <footer className="border-t border-line bg-layer">
      <div className="mx-auto flex max-w-6xl flex-col gap-2 px-4 py-6 text-xs text-ink-helper sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <p>
          Based on{' '}
          <ExternalTextLink href={CRA_OFFICIAL_URL}>Regulation (EU) 2024/2847</ExternalTextLink> (Cyber
          Resilience Act),{' '}
          <ExternalTextLink href={CRA_ARTICLE_14_URL}>Article 14</ExternalTextLink>. Data: OSV.dev and the CISA
          Known Exploited Vulnerabilities catalog.
        </p>
        <p className="font-medium text-ink-secondary">Drafting and triage assistant. Not legal advice.</p>
      </div>
    </footer>
  )
}

export function ExternalTextLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-0.5 text-primary underline-offset-2 hover:text-primary-hover hover:underline"
    >
      {children}
      <ExternalLink className="h-3 w-3" aria-hidden="true" />
      <span className="sr-only">(opens in a new tab)</span>
    </a>
  )
}

// ─── Tags ────────────────────────────────────────────────────────────────────

export type Tone = 'danger' | 'warning' | 'caution' | 'success' | 'malicious' | 'primary' | 'neutral'

const TAG_TONES: Record<Tone, string> = {
  danger: 'bg-danger text-ink-inverse',
  warning: 'bg-warning text-ink',
  caution: 'bg-caution text-ink',
  success: 'bg-success-soft text-success-ink',
  malicious: 'bg-malicious text-ink-inverse',
  primary: 'bg-primary-muted text-primary-active',
  neutral: 'bg-line text-ink-secondary',
}

export function Tag({ tone, icon: Icon, children }: { tone: Tone; icon?: LucideIcon; children: ReactNode }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap ${TAG_TONES[tone]}`}
    >
      {Icon && <Icon className="h-3.5 w-3.5" aria-hidden="true" />}
      {children}
    </span>
  )
}

const SEVERITY_TONE: Record<CVERecord['severity'], Tone> = {
  CRITICAL: 'danger',
  HIGH: 'warning',
  MEDIUM: 'caution',
  LOW: 'primary',
  NONE: 'neutral',
}

export function SeverityTag({ severity }: { severity: CVERecord['severity'] }) {
  return <Tag tone={SEVERITY_TONE[severity]}>{severity === 'NONE' ? 'UNSCORED' : severity}</Tag>
}

// ─── Inline notification ─────────────────────────────────────────────────────

export type NotificationKind = 'error' | 'warning' | 'success' | 'info'

const NOTIFICATION_STYLES: Record<NotificationKind, { box: string; icon: LucideIcon; iconColor: string }> = {
  error: { box: 'border-danger bg-danger-soft', icon: ShieldAlert, iconColor: 'text-danger' },
  warning: { box: 'border-warning bg-warning-soft', icon: AlertTriangle, iconColor: 'text-warning-ink' },
  success: { box: 'border-success bg-success-soft', icon: CheckCircle2, iconColor: 'text-success' },
  info: { box: 'border-primary bg-primary-soft', icon: Info, iconColor: 'text-primary' },
}

export function InlineNotification({
  kind,
  title,
  children,
  role,
}: {
  kind: NotificationKind
  title: string
  children?: ReactNode
  role?: 'alert' | 'status'
}) {
  const style = NOTIFICATION_STYLES[kind]
  const Icon = style.icon
  return (
    <div role={role} className={`flex gap-3 border-l-4 p-4 ${style.box}`}>
      <Icon className={`mt-0.5 h-5 w-5 flex-shrink-0 ${style.iconColor}`} aria-hidden="true" />
      <div className="min-w-0 flex-1 text-sm text-ink">
        <p className="font-semibold">{title}</p>
        {children && <div className="mt-1 text-ink-secondary">{children}</div>}
      </div>
    </div>
  )
}

// ─── Sections ────────────────────────────────────────────────────────────────

export function Section({
  title,
  description,
  count,
  actions,
  children,
}: {
  title: string
  description?: string
  count?: number
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-semibold text-ink">
            {title}
            {count !== undefined && (
              <span className="rounded-full bg-line px-2 py-0.5 text-xs font-medium text-ink-secondary">{count}</span>
            )}
          </h2>
          {description && <p className="mt-0.5 text-sm text-ink-helper">{description}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  )
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-center gap-2 border border-line bg-layer p-4 text-sm text-ink-secondary">
      <CheckCircle2 className="h-4 w-4 text-success" aria-hidden="true" />
      {children}
    </div>
  )
}
