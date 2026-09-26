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

function classifyKev(dep: Dependency, cve: CVERecord, kev: KevEntry): CraNotification {
  return {
    category: 'actively_exploited_vulnerability',
    status: dep.dev ? 'review_required' : 'report_required',
    dep,
    cve,
    kev,
    legalBasis: LEGAL_BASIS.actively_exploited_vulnerability,
    reason: dep.dev
      ? DEV_ONLY_REASON
      : `${kev.cveID} is listed in the CISA Known Exploited Vulnerabilities catalog (reliable evidence of active exploitation, Art. 3(42)) and ${dep.name} ${dep.version} is a dependency of the product.`,
  }
}

function classifyMalicious(dep: Dependency, cve: CVERecord): CraNotification {
  return {
    category: 'severe_incident',
    status: dep.dev ? 'review_required' : 'report_required',
    dep,
    cve,
    legalBasis: LEGAL_BASIS.severe_incident,
    reason: dep.dev
      ? DEV_ONLY_REASON
      : `${dep.name} ${dep.version} is a release published with malicious code, which "has led or is capable of leading to the introduction or execution of malicious code in a product" (Art. 14(5)(b)).`,
  }
}

function mostUrgent(notifications: CraNotification[]): CraStatus {
  if (notifications.some((n) => n.status === 'report_required')) return 'report_required'
  if (notifications.length > 0) return 'review_required'
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

  // Technical risk: KEV and malicious releases always rank as CRITICAL.
  const severities: Array<CVERecord['severity']> = cveFindings.flatMap((f) => f.cves.map((c) => c.severity))
  for (const finding of sastFindings) severities.push(finding.severity)
  const overallRisk: RiskLevel =
    kevFindings.length > 0 || maliciousFindings.length > 0 ? 'CRITICAL' : maxSeverity(severities)

  return {
    reportId: randomUUID(),
    repoUrl,
    analyzedAt: analyzedAt.toISOString(),
    overallRisk,
    craStatus,
    notifications,
    deadlines:
      notifications.length > 0
        ? {
            awareAt: analyzedAt.toISOString(),
            earlyWarningDueAt: new Date(analyzedAt.getTime() + 24 * HOUR_MS).toISOString(),
            notificationDueAt: new Date(analyzedAt.getTime() + 72 * HOUR_MS).toISOString(),
          }
        : null,
    hasSBOM: hasSBOM(tree),
    hasSecurityPolicy: hasSecurityPolicy(tree),
    disclosureRequired: craStatus === 'report_required',
    disclosureDeadlineHours: notifications.length > 0 ? 24 : null,
    kevFindings,
    maliciousFindings,
    cveFindings,
    sastFindings,
    unresolvedDeps: unresolvedDeps.map((d) => `${d.name}${d.version ? ` (${d.version})` : ''}`),
    warnings,
  }
}
