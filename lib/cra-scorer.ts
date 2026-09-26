import { randomUUID } from 'crypto'
import type {
  GitHubTreeItem,
  Dependency,
  CVERecord,
  KevEntry,
  SastFinding,
  CRAReport,
} from '@/types'

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

// ─── scoreCRA ────────────────────────────────────────────────────────────────

export interface ScoreCRAParams {
  repoUrl: string
  tree: GitHubTreeItem[]
  deps: Dependency[]
  cveMap: Map<string, CVERecord[]>
  kevHits: KevEntry[]
  sastFindings: SastFinding[]
}

export function scoreCRA(params: ScoreCRAParams): CRAReport {
  const { repoUrl, tree, deps, cveMap, kevHits, sastFindings } = params

  // ── Artifact detection ──────────────────────────────────────────────────────
  const hasSbom = hasSBOM(tree)
  const hasPolicy = hasSecurityPolicy(tree)

  // ── Build kevFindings (dep + cve + kev triples) ─────────────────────────────
  const kevIdSet = new Set(kevHits.map((k) => k.cveID))
  const kevFindings: CRAReport['kevFindings'] = []
  const cveFindings: CRAReport['cveFindings'] = []

  for (const dep of deps) {
    const cves = cveMap.get(dep.name) ?? []
    if (cves.length > 0) {
      cveFindings.push({ dep, cves })
    }
    for (const cve of cves) {
      if (kevIdSet.has(cve.cveId)) {
        const kev = kevHits.find((k) => k.cveID === cve.cveId)!
        kevFindings.push({ dep, cve, kev })
      }
    }
  }

  // ── Risk escalation (CRA Article 14) ────────────────────────────────────────
  let overallRisk: RiskLevel
  let disclosureRequired: boolean
  let disclosureDeadlineHours: CRAReport['disclosureDeadlineHours']

  if (kevFindings.length > 0) {
    // CISA KEV hit → immediate CRITICAL, 24 h early warning
    overallRisk = 'CRITICAL'
    disclosureRequired = true
    disclosureDeadlineHours = 24
  } else {
    // Collect all CVE severities
    const allCveSeverities = [...cveFindings.flatMap((f) => f.cves.map((c) => c.severity))]

    // SAST CRITICAL findings count as escalation triggers
    const hasSastCritical = sastFindings.some((f) => f.severity === 'CRITICAL')
    if (hasSastCritical) allCveSeverities.push('CRITICAL')

    // SAST HIGH findings count as HIGH if no higher severity present
    const hasSastHigh = sastFindings.some((f) => f.severity === 'HIGH')
    if (hasSastHigh) allCveSeverities.push('HIGH')

    overallRisk = maxSeverity(allCveSeverities)

    if (overallRisk === 'CRITICAL' || overallRisk === 'HIGH') {
      disclosureRequired = true
      disclosureDeadlineHours = 72
    } else {
      disclosureRequired = false
      disclosureDeadlineHours = null
    }
  }

  return {
    reportId: randomUUID(),
    repoUrl,
    analyzedAt: new Date().toISOString(),
    overallRisk,
    hasSBOM: hasSbom,
    hasSecurityPolicy: hasPolicy,
    disclosureRequired,
    disclosureDeadlineHours,
    kevFindings,
    cveFindings,
    sastFindings,
  }
}
