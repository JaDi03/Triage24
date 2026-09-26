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
  cveId: string
  description: string
  cvssScore: number
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'
  publishedDate: string
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
}
