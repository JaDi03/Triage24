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
  /** Development or test-only dependency (npm "dev": true, Maven scope "test"); may not ship in the product. */
  dev?: boolean
  /** Only installed on these operating systems (npm lockfile "os", e.g. ["darwin"]). */
  os?: string[]
  /** Manifest that declares it (package-lock.json or pom.xml path). */
  manifestPath?: string
  /** Declared by the project itself rather than pulled in by another dependency. */
  direct?: boolean
}

/** An OSV range for one package: events in the order OSV lists them. */
export interface AffectedRange {
  type: string
  events: Array<{ introduced?: string; fixed?: string; last_affected?: string; limit?: string }>
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
  /** Advisory text (trimmed), used to find the vulnerable functions. */
  details?: string
  /** Affected ranges and explicit versions for this package, from every merged advisory. */
  affectedRanges?: AffectedRange[]
  affectedVersions?: string[]
  /** Whether the project's code reaches the vulnerable functionality. */
  reachability?: Reachability
}

export interface Evidence {
  file: string
  line: number
  snippet: string
}

export interface Reachability {
  verdict: 'affected' | 'not_affected' | 'uncertain'
  /** 0 to 1. */
  confidence: number
  reasoning: string
  /** Code or manifest lines behind the verdict. */
  evidence: Evidence[]
  method: 'static'
  /** Functions or classes searched for, and where their names came from. */
  symbols: string[]
  symbolSource: 'curated' | 'advisory' | 'none'
  importCount: number
  usageCount: number
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

/**
 * The two separate notification duties of CRA Article 14:
 * - actively exploited vulnerability: Art. 14(1)-(2), "actively exploited" as defined in Art. 3(42);
 * - severe incident having an impact on the security of the product: Art. 14(3)-(5).
 */
export type CraCategory = 'actively_exploited_vulnerability' | 'severe_incident'

/**
 * report_required: the finding falls under Art. 14 and the product contains it.
 * review_required: it falls under Art. 14 but may not ship in the product (development dependency).
 * not_required: nothing indicates an Art. 14 notification duty.
 */
export type CraStatus = 'report_required' | 'review_required' | 'not_required'

export interface CraNotification {
  category: CraCategory
  /** not_required: actively exploited, but the code does not reach it (an interpretation of Art. 3(40)). */
  status: CraStatus
  dep: Dependency
  cve: CVERecord
  /** CISA KEV entry, for actively exploited vulnerabilities. */
  kev?: KevEntry
  /** Articles of Regulation (EU) 2024/2847 that apply. */
  legalBasis: string
  /** Why the finding was classified this way. */
  reason: string
  /** Set when the classification relies on an interpretation of the Regulation. */
  interpretation?: string
}

/** The three documents for one Article 14 duty, with placeholders for what only the manufacturer knows. */
export interface CraDrafts {
  category: CraCategory
  /** Art. 14(2)(a) or 14(4)(a). */
  earlyWarning: string
  /** Art. 14(2)(b) or 14(4)(b). */
  notification: string
  /** Art. 14(8). */
  userAdvisory: string
  /** When the final report is due: Art. 14(2)(c) or 14(4)(c). */
  finalReportRule: string
}

/** A dependency that needs action, with its fix and the instruction for IBM Bob. */
export interface Remediation {
  dep: Dependency
  /** Vulnerabilities that are not ruled out by the reachability analysis. */
  cveIds: string[]
  /** Lowest release not affected by any of its advisories; undefined when none is known. */
  recommendedVersion?: string
  /** Other artifacts of the same Maven group and version that must move together. */
  alignedWith: string[]
  /** Ready-to-paste instruction for IBM Bob. */
  fixPrompt: string
}

/** Art. 14(2)(a)-(b) and 14(4)(a)-(b): maximum periods, counted from when the manufacturer becomes aware. */
export interface CraDeadlines {
  /** When the manufacturer became aware; by default, the time of this analysis. */
  awareAt: string
  /** Early warning: without undue delay and in any event within 24 hours. */
  earlyWarningDueAt: string
  /** Vulnerability or incident notification: without undue delay and in any event within 72 hours. */
  notificationDueAt: string
}

export interface CRAReport {
  reportId: string
  repoUrl: string
  /** Short commit SHA of the analyzed revision, for links to the code. */
  commitSha?: string
  analyzedAt: string
  /** Technical risk from severities, KEV and malicious releases. Not a legal classification. */
  overallRisk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'PASS'
  /** Most urgent Art. 14 status across all notifications. */
  craStatus: CraStatus
  /** One entry per finding that falls under an Art. 14 notification duty. */
  notifications: CraNotification[]
  /** Deadlines of the early warning and the notification; null when nothing falls under Art. 14. */
  deadlines: CraDeadlines | null
  /** One set of drafts per Art. 14 duty that applies. */
  drafts: CraDrafts[]
  /** Dependencies to fix, most urgent first. */
  remediations: Remediation[]
  hasSBOM: boolean
  hasSecurityPolicy: boolean
  /** craStatus === 'report_required'. */
  disclosureRequired: boolean
  /** Hours to the Art. 14 early warning (24) when a notification applies; null otherwise. */
  disclosureDeadlineHours: 24 | null
  kevFindings: Array<{ dep: Dependency; cve: CVERecord; kev: KevEntry }>
  maliciousFindings: Array<{ dep: Dependency; cve: CVERecord }>
  cveFindings: Array<{ dep: Dependency; cves: CVERecord[] }>
  sastFindings: SastFinding[]
  /** Dependencies whose version could not be resolved (for example a Maven version set by a parent POM); not checked. */
  unresolvedDeps: string[]
  /** Non-fatal problems found during the analysis. */
  warnings: string[]
}
