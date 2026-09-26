import { describe, it, expect } from 'vitest'
import { scoreCRA } from '../lib/cra-scorer'
import type {
  GitHubTreeItem,
  Dependency,
  CVERecord,
  KevEntry,
  SastFinding,
} from '../types'

// â”€â”€â”€ Fixtures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const REPO_URL = 'https://github.com/example/repo'

function blob(path: string): GitHubTreeItem {
  return { path, type: 'blob' }
}

const DEP_A: Dependency = { name: 'lodash', version: '4.17.0', ecosystem: 'npm' }
const DEP_B: Dependency = { name: 'axios', version: '0.21.0', ecosystem: 'npm' }

function makeCVE(
  cveId: string,
  severity: CVERecord['severity'],
  cvssScore = 7.0
): CVERecord {
  return {
    cveId,
    description: `Test ${cveId}`,
    cvssScore,
    severity,
    publishedDate: '2024-01-01',
  }
}

function makeKev(cveID: string): KevEntry {
  return {
    cveID,
    vendorProject: 'TestVendor',
    product: 'TestProduct',
    vulnerabilityName: 'Test Vuln',
    dateAdded: '2024-01-01',
    shortDescription: 'Test',
    requiredAction: 'Patch immediately',
    dueDate: '2024-01-15',
  }
}

function makeSast(severity: SastFinding['severity']): SastFinding {
  return {
    ruleId: 'SAST-001',
    ruleName: 'Test Rule',
    severity,
    filePath: 'src/file.ts',
    line: 1,
    snippet: 'test snippet',
    description: 'test description',
    recommendation: 'fix it',
  }
}

// â”€â”€â”€ SBOM detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe('SBOM detection', () => {
  it('detects sbom.json at root', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [blob('sbom.json')],
      deps: [],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.hasSBOM).toBe(true)
  })

  it('detects sbom.xml at root', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [blob('sbom.xml')],
      deps: [],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.hasSBOM).toBe(true)
  })

  it('detects *.spdx file', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [blob('project.spdx')],
      deps: [],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.hasSBOM).toBe(true)
  })

  it('detects .spdx in a subdirectory', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [blob('docs/project.spdx')],
      deps: [],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.hasSBOM).toBe(true)
  })

  it('detects bom.xml at root', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [blob('bom.xml')],
      deps: [],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.hasSBOM).toBe(true)
  })

  it('returns hasSBOM=false when no SBOM file is present', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [blob('README.md'), blob('package.json')],
      deps: [],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.hasSBOM).toBe(false)
  })

  it('ignores tree entries of type "tree" (directories)', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [{ path: 'sbom.json', type: 'tree' }],
      deps: [],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.hasSBOM).toBe(false)
  })
})

// â”€â”€â”€ Security policy detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe('Security policy detection', () => {
  it('detects SECURITY.md at root', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [blob('SECURITY.md')],
      deps: [],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.hasSecurityPolicy).toBe(true)
  })

  it('detects .github/SECURITY.md', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [blob('.github/SECURITY.md')],
      deps: [],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.hasSecurityPolicy).toBe(true)
  })

  it('returns hasSecurityPolicy=false when absent', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [blob('README.md')],
      deps: [],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.hasSecurityPolicy).toBe(false)
  })
})

// â”€â”€â”€ KEV escalation â†’ CRITICAL + 24h â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe('KEV escalation (CRA Article 14 early warning)', () => {
  it('escalates to CRITICAL when a dep has a KEV hit', () => {
    const cve = makeCVE('CVE-2024-9999', 'LOW', 2.0)
    const kev = makeKev('CVE-2024-9999')
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [DEP_A],
      cveMap: new Map([[DEP_A.name, [cve]]]),
      kevHits: [kev],
      sastFindings: [],
    })
    expect(report.overallRisk).toBe('CRITICAL')
    expect(report.disclosureRequired).toBe(true)
    expect(report.disclosureDeadlineHours).toBe(24)
  })

  it('populates kevFindings with the correct dep/cve/kev triple', () => {
    const cve = makeCVE('CVE-2024-1111', 'MEDIUM', 5.0)
    const kev = makeKev('CVE-2024-1111')
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [DEP_A],
      cveMap: new Map([[DEP_A.name, [cve]]]),
      kevHits: [kev],
      sastFindings: [],
    })
    expect(report.kevFindings).toHaveLength(1)
    expect(report.kevFindings[0].dep).toEqual(DEP_A)
    expect(report.kevFindings[0].cve.cveId).toBe('CVE-2024-1111')
    expect(report.kevFindings[0].kev.cveID).toBe('CVE-2024-1111')
  })

  it('escalates even when the CVE severity is LOW (KEV takes precedence)', () => {
    const cve = makeCVE('CVE-2024-0001', 'LOW', 1.0)
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [DEP_A],
      cveMap: new Map([[DEP_A.name, [cve]]]),
      kevHits: [makeKev('CVE-2024-0001')],
      sastFindings: [],
    })
    expect(report.overallRisk).toBe('CRITICAL')
    expect(report.disclosureDeadlineHours).toBe(24)
  })

  it('does NOT escalate when KEV CVE does not match any dep CVE', () => {
    const cve = makeCVE('CVE-2024-1234', 'HIGH', 8.0)
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [DEP_A],
      cveMap: new Map([[DEP_A.name, [cve]]]),
      kevHits: [makeKev('CVE-2024-9999')], // different CVE ID
      sastFindings: [],
    })
    // No kev triple â†’ falls through to CVE-based risk
    expect(report.overallRisk).toBe('HIGH')
    expect(report.disclosureDeadlineHours).toBe(72)
    expect(report.kevFindings).toHaveLength(0)
  })
})

// â”€â”€â”€ CVE severity escalation â†’ 72h â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe('CVE severity escalation (no KEV)', () => {
  it('returns CRITICAL + 72h when a dep has a CRITICAL CVE', () => {
    const cve = makeCVE('CVE-2024-CRIT', 'CRITICAL', 9.8)
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [DEP_A],
      cveMap: new Map([[DEP_A.name, [cve]]]),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.overallRisk).toBe('CRITICAL')
    expect(report.disclosureRequired).toBe(true)
    expect(report.disclosureDeadlineHours).toBe(72)
  })

  it('returns HIGH + 72h when a dep has a HIGH CVE', () => {
    const cve = makeCVE('CVE-2024-HIGH', 'HIGH', 7.5)
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [DEP_A],
      cveMap: new Map([[DEP_A.name, [cve]]]),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.overallRisk).toBe('HIGH')
    expect(report.disclosureRequired).toBe(true)
    expect(report.disclosureDeadlineHours).toBe(72)
  })

  it('returns MEDIUM with no disclosure when only MEDIUM CVEs', () => {
    const cve = makeCVE('CVE-2024-MED', 'MEDIUM', 5.3)
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [DEP_A],
      cveMap: new Map([[DEP_A.name, [cve]]]),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.overallRisk).toBe('MEDIUM')
    expect(report.disclosureRequired).toBe(false)
    expect(report.disclosureDeadlineHours).toBeNull()
  })

  it('returns LOW with no disclosure when only LOW CVEs', () => {
    const cve = makeCVE('CVE-2024-LOW', 'LOW', 2.0)
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [DEP_A],
      cveMap: new Map([[DEP_A.name, [cve]]]),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.overallRisk).toBe('LOW')
    expect(report.disclosureRequired).toBe(false)
    expect(report.disclosureDeadlineHours).toBeNull()
  })

  it('selects the highest severity across multiple deps', () => {
    const cveLow = makeCVE('CVE-2024-L', 'LOW', 2.0)
    const cveCrit = makeCVE('CVE-2024-C', 'CRITICAL', 9.9)
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [DEP_A, DEP_B],
      cveMap: new Map([
        [DEP_A.name, [cveLow]],
        [DEP_B.name, [cveCrit]],
      ]),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.overallRisk).toBe('CRITICAL')
    expect(report.disclosureDeadlineHours).toBe(72)
  })
})

// â”€â”€â”€ SAST severity escalation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe('SAST severity escalation', () => {
  it('escalates to CRITICAL + 72h when SAST has CRITICAL finding (no CVEs)', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [DEP_A],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [makeSast('CRITICAL')],
    })
    expect(report.overallRisk).toBe('CRITICAL')
    expect(report.disclosureRequired).toBe(true)
    expect(report.disclosureDeadlineHours).toBe(72)
  })

  it('escalates to HIGH + 72h when SAST has HIGH finding (no CVEs)', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [DEP_A],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [makeSast('HIGH')],
    })
    expect(report.overallRisk).toBe('HIGH')
    expect(report.disclosureRequired).toBe(true)
    expect(report.disclosureDeadlineHours).toBe(72)
  })

  it('does not escalate for SAST MEDIUM alone', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [makeSast('MEDIUM')],
    })
    expect(report.overallRisk).toBe('PASS')
    expect(report.disclosureRequired).toBe(false)
    expect(report.disclosureDeadlineHours).toBeNull()
  })

  it('passes through sastFindings unchanged', () => {
    const finding = makeSast('CRITICAL')
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [finding],
    })
    expect(report.sastFindings).toHaveLength(1)
    expect(report.sastFindings[0]).toEqual(finding)
  })
})

// â”€â”€â”€ Clean repo â†’ PASS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe('Clean repo with no vulnerabilities', () => {
  it('returns PASS with disclosureRequired=false and null deadline', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [DEP_A],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.overallRisk).toBe('PASS')
    expect(report.disclosureRequired).toBe(false)
    expect(report.disclosureDeadlineHours).toBeNull()
  })

  it('returns empty kevFindings and cveFindings when clean', () => {
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [],
      cveMap: new Map(),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.kevFindings).toHaveLength(0)
    expect(report.cveFindings).toHaveLength(0)
  })
})

// â”€â”€â”€ Report metadata â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe('Report metadata', () => {
  it('generates a unique reportId (UUID v4 format) on each call', () => {
    const r1 = scoreCRA({ repoUrl: REPO_URL, tree: [], deps: [], cveMap: new Map(), kevHits: [], sastFindings: [] })
    const r2 = scoreCRA({ repoUrl: REPO_URL, tree: [], deps: [], cveMap: new Map(), kevHits: [], sastFindings: [] })
    const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    expect(r1.reportId).toMatch(uuidRe)
    expect(r2.reportId).toMatch(uuidRe)
    expect(r1.reportId).not.toBe(r2.reportId)
  })

  it('includes analyzedAt as a valid ISO 8601 timestamp', () => {
    const report = scoreCRA({ repoUrl: REPO_URL, tree: [], deps: [], cveMap: new Map(), kevHits: [], sastFindings: [] })
    expect(() => new Date(report.analyzedAt)).not.toThrow()
    expect(new Date(report.analyzedAt).toISOString()).toBe(report.analyzedAt)
  })

  it('echoes back the provided repoUrl', () => {
    const url = 'https://github.com/org/my-project'
    const report = scoreCRA({ repoUrl: url, tree: [], deps: [], cveMap: new Map(), kevHits: [], sastFindings: [] })
    expect(report.repoUrl).toBe(url)
  })
})

// â”€â”€â”€ cveFindings structure â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe('cveFindings structure', () => {
  it('groups multiple CVEs under the same dep', () => {
    const cve1 = makeCVE('CVE-2024-A', 'HIGH', 7.0)
    const cve2 = makeCVE('CVE-2024-B', 'MEDIUM', 5.0)
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [DEP_A],
      cveMap: new Map([[DEP_A.name, [cve1, cve2]]]),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.cveFindings).toHaveLength(1)
    expect(report.cveFindings[0].dep).toEqual(DEP_A)
    expect(report.cveFindings[0].cves).toHaveLength(2)
  })

  it('only includes deps that have CVEs in cveFindings', () => {
    const cve = makeCVE('CVE-2024-X', 'LOW', 2.0)
    const report = scoreCRA({
      repoUrl: REPO_URL,
      tree: [],
      deps: [DEP_A, DEP_B],
      cveMap: new Map([[DEP_A.name, [cve]]]),
      kevHits: [],
      sastFindings: [],
    })
    expect(report.cveFindings).toHaveLength(1)
    expect(report.cveFindings[0].dep.name).toBe(DEP_A.name)
  })
})
