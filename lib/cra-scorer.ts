import { randomUUID } from 'crypto'
import type {
  GitHubTreeItem,
  Dependency,
  CVERecord,
  KevEntry,
  SastFinding,
  CRAReport,
  CraNotification,
  CraStatus,
} from '@/types'
import { depKey } from '@/lib/dep-key'
import { buildDrafts } from '@/lib/cra-drafts'
import { buildRemediations } from '@/lib/remediation'

// ─── SBOM / Policy detection patterns ────────────────────────────────────────

const SBOM_PATTERNS = [
  /^sbom\.json$/i,
  /^sbom\.xml$/i,
  /\.spdx$/i,
  /^bom\.xml$/i,
]

const SECURITY_POLICY_PATHS = new Set(['SECURITY.md', '.github/SECURITY.md'])

// ─── Helpers ──────────────────────────────────────────────────────────────────

function hasSBOM(tree: GitHubTreeItem[]): boolean {
  return tree.some(
    (item) =>
      item.type === 'blob' &&
      SBOM_PATTERNS.some((re) => re.test(item.path.split('/').pop() ?? item.path))
  )
}

function hasSecurityPolicy(tree: GitHubTreeItem[]): boolean {
  return tree.some(
    (item) => item.type === 'blob' && SECURITY_POLICY_PATHS.has(item.path)
  )
}

type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'PASS'

function maxSeverity(severities: Array<CVERecord['severity']>): RiskLevel {
  if (severities.includes('CRITICAL')) return 'CRITICAL'
  if (severities.includes('HIGH')) return 'HIGH'
  if (severities.includes('MEDIUM')) return 'MEDIUM'
  if (severities.includes('LOW')) return 'LOW'
  return 'PASS'
}

// ─── CRA Article 14 classification ───────────────────────────────────────────

const HOUR_MS = 60 * 60 * 1000

const LEGAL_BASIS: Record<CraNotification['category'], string> = {
  actively_exploited_vulnerability: 'Regulation (EU) 2024/2847, Art. 14(1)-(2); Art. 3(42)',
  severe_incident: 'Regulation (EU) 2024/2847, Art. 14(3)-(4); Art. 14(5)(b)',
}

const DEV_ONLY_REASON =
  'It is a development or test dependency and may not be contained in the product (Art. 14(1) and (3) cover what affects the product); confirm whether it ships.'

/** Why a finding under Art. 14 may not concern the product, or null when it does. */
function reviewReason(dep: Dependency): string | null {
  if (dep.dev) return DEV_ONLY_REASON
  const onlyOn = dep.os?.filter((os) => !os.startsWith('!'))
  if (onlyOn && onlyOn.length > 0) {
    return `It is only installed on ${onlyOn.join(', ')}; confirm whether the product is built or distributed for that platform (Art. 14(1) and (3) cover what affects the product).`
  }
  return null
}

const NOT_REACHABLE_INTERPRETATION =
  "Treating a vulnerability that the product's code does not reach as not notifiable relies on the definition of " +
  '"vulnerability" in Art. 3(40) ("can be exploited"). This is an interpretation, not a rule stated in Article 14; ' +
  'the manufacturer decides.'

function classifyKev(dep: Dependency, cve: CVERecord, kev: KevEntry): CraNotification {
  const base = {
    category: 'actively_exploited_vulnerability' as const,
    dep,
    cve,
    kev,
    legalBasis: LEGAL_BASIS.actively_exploited_vulnerability,
  }
  const listed = `${kev.cveID} is listed in the CISA Known Exploited Vulnerabilities catalog (reliable evidence of active exploitation, Art. 3(42))`
  const verdict = cve.reachability?.verdict

  if (verdict === 'not_affected') {
    return {
      ...base,
      status: 'not_required',
      reason: `${listed}, but the product's code does not reach the vulnerable functionality: ${cve.reachability!.reasoning}`,
      interpretation: NOT_REACHABLE_INTERPRETATION,
    }
  }
  const review = reviewReason(dep)
  if (review) return { ...base, status: 'review_required', reason: review }
  if (verdict === 'affected') {
    return {
      ...base,
      status: 'report_required',
      reason: `${listed} and the product's code reaches it: ${cve.reachability!.reasoning}`,
    }
  }
  return {
    ...base,
    status: 'review_required',
    reason: `${listed}. ${cve.reachability?.reasoning ?? 'Whether the product reaches it was not analyzed.'} Confirm whether the product is affected.`,
  }
}

function classifyMalicious(dep: Dependency, cve: CVERecord): CraNotification {
  const review = reviewReason(dep)
  return {
    category: 'severe_incident',
    status: review ? 'review_required' : 'report_required',
    dep,
    cve,
    legalBasis: LEGAL_BASIS.severe_incident,
    reason:
      review ??
      `${dep.name} ${dep.version} is a release published with malicious code, which "has led or is capable of leading to the introduction or execution of malicious code in a product" (Art. 14(5)(b)).`,
  }
}

function mostUrgent(notifications: CraNotification[]): CraStatus {
  if (notifications.some((n) => n.status === 'report_required')) return 'report_required'
  if (notifications.some((n) => n.status === 'review_required')) return 'review_required'
  return 'not_required'
}

// ─── scoreCRA ────────────────────────────────────────────────────────────────

export interface ScoreCRAParams {
  repoUrl: string
  tree: GitHubTreeItem[]
  deps: Dependency[]
  cveMap: Map<string, CVERecord[]>
  kevHits: KevEntry[]
  sastFindings: SastFinding[]
  /** Dependencies whose version could not be resolved; they were not checked. */
  unresolvedDeps?: Dependency[]
  /** Non-fatal problems found during the analysis. */
  warnings?: string[]
  /** When the manufacturer became aware; defaults to the time of the analysis. */
  awareAt?: Date
  /** Short commit SHA of the analyzed revision. */
  commitSha?: string
}

/**
 * Builds the report. Two things are kept apart:
 * - overallRisk: a technical rating (CVSS severities, KEV, malicious releases, SAST);
 * - craStatus / notifications: the CRA Article 14 duties, which only cover actively exploited
 *   vulnerabilities (Art. 14(1)) and severe incidents (Art. 14(3)). A high CVSS score or a code
 *   finding alone does not trigger a notification.
 */
export function scoreCRA(params: ScoreCRAParams): CRAReport {
  const { repoUrl, tree, deps, cveMap, kevHits, sastFindings, unresolvedDeps = [], warnings = [] } = params
  const analyzedAt = params.awareAt ?? new Date()

  const kevById = new Map(kevHits.map((k) => [k.cveID, k]))
  const kevFindings: CRAReport['kevFindings'] = []
  const maliciousFindings: CRAReport['maliciousFindings'] = []
  const cveFindings: CRAReport['cveFindings'] = []
  const notifications: CraNotification[] = []

  for (const dep of deps) {
    const cves = cveMap.get(depKey(dep)) ?? []
    if (cves.length > 0) cveFindings.push({ dep, cves })

    for (const cve of cves) {
      if (cve.malicious) {
        maliciousFindings.push({ dep, cve })
        notifications.push(classifyMalicious(dep, cve))
        continue
      }
      // A merged finding can carry several CVE IDs; any of them may be in KEV.
      const kev = cve.aliases.map((id) => kevById.get(id)).find((k) => k !== undefined)
      if (kev) {
        kevFindings.push({ dep, cve, kev })
        notifications.push(classifyKev(dep, cve, kev))
      }
    }
  }

  const craStatus = mostUrgent(notifications)
  const deadlines =
    craStatus !== 'not_required'
      ? {
          awareAt: analyzedAt.toISOString(),
          earlyWarningDueAt: new Date(analyzedAt.getTime() + 24 * HOUR_MS).toISOString(),
          notificationDueAt: new Date(analyzedAt.getTime() + 72 * HOUR_MS).toISOString(),
        }
      : null
  const remediations = buildRemediations(cveFindings, new Set(kevById.keys()))
  const drafts = deadlines
    ? buildDrafts(notifications, {
        repoLabel: repoUrl.replace(/^https?:\/\/(www\.)?github\.com\//i, ''),
        ...(params.commitSha ? { commitSha: params.commitSha } : {}),
        deadlines,
        remediations,
      })
    : []

  // Technical risk: KEV and malicious releases always rank as CRITICAL.
  const severities: Array<CVERecord['severity']> = cveFindings.flatMap((f) => f.cves.map((c) => c.severity))
  for (const finding of sastFindings) severities.push(finding.severity)
  const overallRisk: RiskLevel =
    kevFindings.length > 0 || maliciousFindings.length > 0 ? 'CRITICAL' : maxSeverity(severities)

  return {
    reportId: randomUUID(),
    repoUrl,
    ...(params.commitSha ? { commitSha: params.commitSha } : {}),
    analyzedAt: analyzedAt.toISOString(),
    overallRisk,
    craStatus,
    notifications,
    deadlines,
    drafts,
    remediations,
    hasSBOM: hasSBOM(tree),
    hasSecurityPolicy: hasSecurityPolicy(tree),
    disclosureRequired: craStatus === 'report_required',
    disclosureDeadlineHours: deadlines ? 24 : null,
    kevFindings,
    maliciousFindings,
    cveFindings,
    sastFindings,
    unresolvedDeps: unresolvedDeps.map((d) => `${d.name}${d.version ? ` (${d.version})` : ''}`),
    warnings,
  }
}
