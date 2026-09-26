import { describe, it, expect } from 'vitest'
import { scoreCRA, type ScoreCRAParams } from '../lib/cra-scorer'
import { depKey } from '../lib/dep-key'
import type { GitHubTreeItem, Dependency, CVERecord, KevEntry, SastFinding } from '../types'

// ─── Fixtures ────────────────────────────────────────────────────────────────

const REPO_URL = 'https://github.com/example/repo'
const AWARE_AT = new Date('2026-09-26T08:00:00.000Z')

function blob(path: string): GitHubTreeItem {
  return { path, type: 'blob' }
}

const DEP_A: Dependency = { name: 'lodash', version: '4.17.0', ecosystem: 'npm' }
const DEP_B: Dependency = { name: 'axios', version: '0.21.0', ecosystem: 'npm' }
const DEV_DEP: Dependency = { name: 'jest-util', version: '1.0.0', ecosystem: 'npm', dev: true }

function makeCVE(
  cveId: string,
  severity: CVERecord['severity'],
  cvssScore: number | null = 7.0,
  malicious = false,
): CVERecord {
  return {
    cveId,
    osvIds: [`GHSA-test-${cveId}`],
    aliases: [cveId, `GHSA-test-${cveId}`],
    description: `Test ${cveId}`,
    cvssScore,
    severity,
    publishedDate: '2024-01-01',
    malicious,
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

function score(overrides: Partial<ScoreCRAParams> = {}) {
  return scoreCRA({
    repoUrl: REPO_URL,
    tree: [],
    deps: [],
    cveMap: new Map(),
    kevHits: [],
    sastFindings: [],
    awareAt: AWARE_AT,
    ...overrides,
  })
}

// ─── SBOM and security policy detection ──────────────────────────────────────

describe('SBOM detection', () => {
  it.each(['sbom.json', 'sbom.xml', 'bom.xml', 'app.spdx', 'docs/app.spdx'])('detects %s', (path) => {
    expect(score({ tree: [blob(path)] }).hasSBOM).toBe(true)
  })

  it('returns hasSBOM=false when no SBOM file is present', () => {
    expect(score({ tree: [blob('README.md')] }).hasSBOM).toBe(false)
  })

  it('ignores directories', () => {
    expect(score({ tree: [{ path: 'sbom.json', type: 'tree' }] }).hasSBOM).toBe(false)
  })
})

describe('Security policy detection', () => {
  it.each(['SECURITY.md', '.github/SECURITY.md'])('detects %s', (path) => {
    expect(score({ tree: [blob(path)] }).hasSecurityPolicy).toBe(true)
  })

  it('returns hasSecurityPolicy=false when absent', () => {
    expect(score({ tree: [blob('README.md')] }).hasSecurityPolicy).toBe(false)
  })
})

// ─── Art. 14(1)-(2): actively exploited vulnerabilities ──────────────────────

describe('Actively exploited vulnerability (CISA KEV)', () => {
  it('requires a report when a product dependency has a KEV-listed CVE', () => {
    const cve = makeCVE('CVE-2021-44228', 'CRITICAL', 10)
    const report = score({
      deps: [DEP_A],
      cveMap: new Map([[depKey(DEP_A), [cve]]]),
      kevHits: [makeKev('CVE-2021-44228')],
    })

    expect(report.craStatus).toBe('report_required')
    expect(report.disclosureRequired).toBe(true)
    expect(report.disclosureDeadlineHours).toBe(24)
    expect(report.overallRisk).toBe('CRITICAL')
    expect(report.notifications).toHaveLength(1)
    expect(report.notifications[0]).toMatchObject({
      category: 'actively_exploited_vulnerability',
      status: 'report_required',
      legalBasis: expect.stringContaining('Art. 14(1)-(2)'),
    })
    expect(report.kevFindings[0].kev.cveID).toBe('CVE-2021-44228')
  })

  it('matches KEV against every CVE alias of a merged finding', () => {
    const cve = { ...makeCVE('CVE-2024-0001', 'HIGH'), aliases: ['CVE-2024-0001', 'CVE-2024-0002'] }
    const report = score({
      deps: [DEP_A],
      cveMap: new Map([[depKey(DEP_A), [cve]]]),
      kevHits: [makeKev('CVE-2024-0002')],
    })
    expect(report.kevFindings).toHaveLength(1)
  })

  it('escalates even when the CVE severity is LOW', () => {
    const report = score({
      deps: [DEP_A],
      cveMap: new Map([[depKey(DEP_A), [makeCVE('CVE-2024-0001', 'LOW', 2.0)]]]),
      kevHits: [makeKev('CVE-2024-0001')],
    })
    expect(report.overallRisk).toBe('CRITICAL')
    expect(report.craStatus).toBe('report_required')
  })

  it('asks for a review when the dependency is development-only', () => {
    const report = score({
      deps: [DEV_DEP],
      cveMap: new Map([[depKey(DEV_DEP), [makeCVE('CVE-2024-0001', 'HIGH')]]]),
      kevHits: [makeKev('CVE-2024-0001')],
    })
    expect(report.craStatus).toBe('review_required')
    expect(report.disclosureRequired).toBe(false)
    expect(report.notifications[0].reason).toMatch(/development or test dependency/)
  })

  it('does not escalate when the KEV CVE does not match any dependency CVE', () => {
    const report = score({
      deps: [DEP_A],
      cveMap: new Map([[depKey(DEP_A), [makeCVE('CVE-2024-0001', 'HIGH')]]]),
      kevHits: [makeKev('CVE-2024-9999')],
    })
    expect(report.kevFindings).toHaveLength(0)
    expect(report.craStatus).toBe('not_required')
  })
})

// ─── Art. 14(3)-(5): severe incidents (malicious releases) ───────────────────

describe('Severe incident (malicious release)', () => {
  it('classifies a malicious release as a severe incident under Art. 14(5)(b)', () => {
    const cve = makeCVE('CVE-2025-59144', 'HIGH', null, true)
    const report = score({ deps: [DEP_B], cveMap: new Map([[depKey(DEP_B), [cve]]]) })

    expect(report.craStatus).toBe('report_required')
    expect(report.overallRisk).toBe('CRITICAL')
    expect(report.maliciousFindings).toHaveLength(1)
    expect(report.kevFindings).toHaveLength(0)
    expect(report.notifications[0]).toMatchObject({
      category: 'severe_incident',
      status: 'report_required',
      legalBasis: expect.stringContaining('Art. 14(5)(b)'),
    })
  })

  it('asks for a review when the malicious release is a development dependency', () => {
    const report = score({
      deps: [DEV_DEP],
      cveMap: new Map([[depKey(DEV_DEP), [makeCVE('MAL-2025-1', 'NONE', null, true)]]]),
    })
    expect(report.craStatus).toBe('review_required')
  })
})

// ─── What does NOT trigger Art. 14 ────────────────────────────────────────────

describe('Findings outside Art. 14', () => {
  it('does not require a notification for a CRITICAL CVE that is not actively exploited', () => {
    const report = score({
      deps: [DEP_A],
      cveMap: new Map([[depKey(DEP_A), [makeCVE('CVE-2024-0001', 'CRITICAL', 9.8)]]]),
    })
    expect(report.overallRisk).toBe('CRITICAL')
    expect(report.craStatus).toBe('not_required')
    expect(report.disclosureRequired).toBe(false)
    expect(report.disclosureDeadlineHours).toBeNull()
    expect(report.deadlines).toBeNull()
  })

  it('does not require a notification for SAST findings', () => {
    const report = score({ sastFindings: [makeSast('CRITICAL')] })
    expect(report.overallRisk).toBe('CRITICAL')
    expect(report.craStatus).toBe('not_required')
  })

  it('does not escalate for SAST MEDIUM alone', () => {
    expect(score({ sastFindings: [makeSast('MEDIUM')] }).overallRisk).toBe('MEDIUM')
  })

  it('selects the highest technical severity across dependencies', () => {
    const report = score({
      deps: [DEP_A, DEP_B],
      cveMap: new Map([
        [depKey(DEP_A), [makeCVE('CVE-2024-0001', 'LOW', 2.0)]],
        [depKey(DEP_B), [makeCVE('CVE-2024-0002', 'HIGH', 7.5)]],
      ]),
    })
    expect(report.overallRisk).toBe('HIGH')
  })

  it('returns PASS with no notification when clean', () => {
    const report = score({ deps: [DEP_A] })
    expect(report.overallRisk).toBe('PASS')
    expect(report.craStatus).toBe('not_required')
    expect(report.notifications).toEqual([])
    expect(report.cveFindings).toEqual([])
  })
})

// ─── Deadlines ───────────────────────────────────────────────────────────────

describe('Art. 14 deadlines', () => {
  it('counts 24 h and 72 h from when the manufacturer became aware', () => {
    const report = score({
      deps: [DEP_A],
      cveMap: new Map([[depKey(DEP_A), [makeCVE('CVE-2021-44228', 'CRITICAL', 10)]]]),
      kevHits: [makeKev('CVE-2021-44228')],
    })
    expect(report.deadlines).toEqual({
      awareAt: '2026-09-26T08:00:00.000Z',
      earlyWarningDueAt: '2026-09-27T08:00:00.000Z',
      notificationDueAt: '2026-09-29T08:00:00.000Z',
    })
  })
})

// ─── Report metadata ─────────────────────────────────────────────────────────

describe('Report metadata', () => {
  it('generates a unique reportId (UUID v4) on each call', () => {
    const a = score()
    const b = score()
    expect(a.reportId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    expect(a.reportId).not.toBe(b.reportId)
  })

  it('uses the awareness time as analyzedAt', () => {
    expect(score().analyzedAt).toBe('2026-09-26T08:00:00.000Z')
  })

  it('echoes back the repoUrl, unresolved dependencies and warnings', () => {
    const report = score({
      unresolvedDeps: [{ name: 'org.example:lib', version: 'unknown', ecosystem: 'maven' }],
      warnings: ['something'],
    })
    expect(report.repoUrl).toBe(REPO_URL)
    expect(report.unresolvedDeps).toEqual(['org.example:lib (unknown)'])
    expect(report.warnings).toEqual(['something'])
  })

  it('only includes dependencies that have CVEs in cveFindings', () => {
    const report = score({
      deps: [DEP_A, DEP_B],
      cveMap: new Map([[depKey(DEP_A), [makeCVE('CVE-2024-0001', 'MEDIUM'), makeCVE('CVE-2024-0002', 'LOW')]]]),
    })
    expect(report.cveFindings).toHaveLength(1)
    expect(report.cveFindings[0].cves).toHaveLength(2)
  })
})

describe('Platform-specific dependencies', () => {
  const macOnly: Dependency = { name: 'fsevents', version: '1.2.9', ecosystem: 'npm', os: ['darwin'] }

  it('asks for a review when a malicious release is only installed on one OS', () => {
    const report = score({
      deps: [macOnly],
      cveMap: new Map([[depKey(macOnly), [makeCVE('MAL-2023-462', 'CRITICAL', null, true)]]]),
    })
    expect(report.craStatus).toBe('review_required')
    expect(report.notifications[0].reason).toContain('only installed on darwin')
  })

  it('ignores negated OS entries such as "!win32"', () => {
    const notWindows: Dependency = { ...macOnly, os: ['!win32'] }
    const report = score({
      deps: [notWindows],
      cveMap: new Map([[depKey(notWindows), [makeCVE('MAL-2023-462', 'CRITICAL', null, true)]]]),
    })
    expect(report.craStatus).toBe('report_required')
  })
})
