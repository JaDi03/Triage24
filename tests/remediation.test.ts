import { describe, it, expect } from 'vitest'
import { compareVersions } from '@/lib/remediation/versions'
import { recommendUpgrade } from '@/lib/remediation/fix-version'
import { buildRemediations } from '@/lib/remediation'
import type { CVERecord, Dependency } from '@/types'

function cve(id: string, fixed: string, introduced = '0'): CVERecord {
  return {
    cveId: id,
    osvIds: [`GHSA-${id}`],
    aliases: [id],
    description: '',
    cvssScore: 9,
    severity: 'CRITICAL',
    publishedDate: '',
    malicious: false,
    affectedRanges: [{ type: 'ECOSYSTEM', events: [{ introduced }, { fixed }] }],
    affectedVersions: [],
    reachability: {
      verdict: 'affected',
      confidence: 0.85,
      reasoning: '',
      evidence: [{ file: 'src/App.java', line: 13, snippet: 'logger.info(user)' }],
      method: 'static',
      symbols: ['info'],
      symbolSource: 'curated',
      importCount: 1,
      usageCount: 1,
    },
  }
}

describe('compareVersions', () => {
  it.each([
    ['2.17.1', '2.17.0', 1],
    ['2.0-beta9', '2.0', -1],
    ['1.0', '1.0.0', 0],
    ['1.0-rc1', '1.0-beta2', 1],
    ['1.2-jre17', '1.2', 1],
    ['4.17.21', '4.17.3', 1],
  ])('compares %s and %s', (a, b, expected) => {
    expect(Math.sign(compareVersions(a, b))).toBe(expected)
  })
})

describe('recommendUpgrade', () => {
  const dep: Dependency = { name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1', ecosystem: 'maven' }

  it('picks the lowest release that fixes every advisory', () => {
    expect(recommendUpgrade(dep, [cve('CVE-1', '2.15.0'), cve('CVE-2', '2.17.1', '2.13.0')])).toBe('2.17.1')
  })

  it('returns undefined when no listed release fixes everything', () => {
    const unfixed: CVERecord = { ...cve('CVE-3', '9.9.9'), affectedRanges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }] }] }
    expect(recommendUpgrade(dep, [cve('CVE-1', '2.15.0'), unfixed])).toBeUndefined()
  })
})

describe('buildRemediations', () => {
  it('aligns Maven artifacts of the same group and version on the highest recommendation', () => {
    const core: Dependency = { name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1', ecosystem: 'maven', manifestPath: 'pom.xml' }
    const api: Dependency = { name: 'org.apache.logging.log4j:log4j-api', version: '2.14.1', ecosystem: 'maven', manifestPath: 'pom.xml' }
    const remediations = buildRemediations(
      [
        { dep: core, cves: [cve('CVE-1', '2.25.5')] },
        { dep: api, cves: [cve('CVE-2', '2.25.4')] },
      ],
      new Set(),
    )

    expect(remediations.map((r) => r.recommendedVersion)).toEqual(['2.25.5', '2.25.5'])
    const coreFix = remediations.find((r) => r.dep === core)!
    expect(coreFix.alignedWith).toEqual(['org.apache.logging.log4j:log4j-api'])
    expect(coreFix.fixPrompt).toContain(
      'In pom.xml, upgrade org.apache.logging.log4j:log4j-core and org.apache.logging.log4j:log4j-api from 2.14.1 to 2.25.5.',
    )
  })

  it('tells how to override a transitive npm dependency', () => {
    const qs: Dependency = { name: 'qs', version: '6.5.2', ecosystem: 'npm', manifestPath: 'package-lock.json' }
    const [fix] = buildRemediations([{ dep: qs, cves: [cve('CVE-9', '6.5.3')] }], new Set())
    expect(fix.fixPrompt).toContain('"overrides" entry in package.json that forces qs to 6.5.3')
  })
})
