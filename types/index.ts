export interface GitHubTreeItem {
  path: string
  type: 'blob' | 'tree'
  sha?: string
  size?: number
  url?: string
}

export type Ecosystem = 'npm' | 'pypi' | 'maven' | 'unknown'

export interface Dependency {
  name: string
  version: string
  ecosystem: Ecosystem
}

export interface CVERecord {
  /** Display ID: the CVE when one exists, otherwise the OSV ID (GHSA-..., MAL-...). */
  cveId: string
  /** OSV records merged into this finding (advisories that are aliases of each other). */
  osvIds: string[]
  /** Every known identifier of the issue (CVE, GHSA, MAL...), cveId included. */
  aliases: string[]
  description: string
  /** CVSS v3 base score computed from the vector; null when OSV provides no CVSS v3 vector. */
  cvssScore: number | null
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'
  publishedDate: string
  /** The release contains malicious code (OSV MAL-* record or CWE-506). */
  malicious: boolean
}

export interface KevEntry {
  cveID: string
  vendorProject: string
  product: string
  vulnerabilityName: string
  dateAdded: string
  shortDescription: string
  requiredAction: string
  dueDate: string
}

export interface SastFinding {
  ruleId: string
  ruleName: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  filePath: string
  line: number
  snippet: string
  description: string
  recommendation: string
}

export interface CRAReport {
  reportId: string
  repoUrl: string
  analyzedAt: string
  overallRisk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'PASS'
  hasSBOM: boolean
  hasSecurityPolicy: boolean
  disclosureRequired: boolean
  disclosureDeadlineHours: 24 | 72 | null
  kevFindings: Array<{ dep: Dependency; cve: CVERecord; kev: KevEntry }>
  cveFindings: Array<{ dep: Dependency; cves: CVERecord[] }>
  sastFindings: SastFinding[]
  /** Dependencies whose version could not be resolved (for example a Maven version set by a parent POM); not checked. */
  unresolvedDeps: string[]
  /** Non-fatal problems found during the analysis. */
  warnings: string[]
}
