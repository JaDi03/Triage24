import { describe, it, expect } from 'vitest'
import { toFindingRows } from '@/lib/findings'
import { formatRemaining } from '@/lib/format'
import type { CVERecord, Dependency } from '@/types'

function cve(cveId: string, severity: CVERecord['severity'], cvssScore: number | null, malicious = false): CVERecord {
  return { cveId, osvIds: [cveId], aliases: [cveId], description: '', cvssScore, severity, publishedDate: '', malicious }
}

const lodash: Dependency = { name: 'lodash', version: '4.17.20', ecosystem: 'npm' }
const log4j: Dependency = { name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1', ecosystem: 'maven' }
const debug: Dependency = { name: 'debug', version: '4.4.2', ecosystem: 'npm' }

describe('toFindingRows', () => {
  it('orders malicious releases first, then KEV, then severity and CVSS', () => {
    const log4shell = cve('CVE-2021-44228', 'CRITICAL', 10)
    const rows = toFindingRows({
      cveFindings: [
        { dep: lodash, cves: [cve('CVE-2020-28500', 'MEDIUM', 5.3), cve('CVE-2021-23337', 'HIGH', 8.1)] },
        { dep: log4j, cves: [cve('CVE-2021-44832', 'MEDIUM', 6.6), log4shell, cve('CVE-2021-45105', 'HIGH', 8.6)] },
        { dep: debug, cves: [cve('CVE-2025-59144', 'HIGH', null, true)] },
      ],
      kevFindings: [
        {
          dep: log4j,
          cve: log4shell,
          kev: {
            cveID: 'CVE-2021-44228',
            vendorProject: '',
            product: '',
            vulnerabilityName: '',
            dateAdded: '',
            shortDescription: '',
            requiredAction: '',
            dueDate: '',
          },
        },
      ],
    })

    expect(rows.map((r) => r.cve.cveId)).toEqual([
      'CVE-2025-59144',
      'CVE-2021-44228',
      'CVE-2021-45105',
      'CVE-2021-23337',
      'CVE-2021-44832',
      'CVE-2020-28500',
    ])
    expect(rows[1].isKev).toBe(true)
    expect(rows.filter((r) => r.isKev)).toHaveLength(1)
  })
})

describe('formatRemaining', () => {
  const now = new Date('2026-09-26T08:00:00Z')

  it('shows hours and minutes left', () => {
    expect(formatRemaining('2026-09-27T07:05:00Z', now)).toBe('23 h 5 min left')
  })

  it('shows only minutes under one hour', () => {
    expect(formatRemaining('2026-09-26T08:45:30Z', now)).toBe('45 min left')
  })

  it('shows how long a deadline is overdue', () => {
    expect(formatRemaining('2026-09-26T05:57:00Z', now)).toBe('overdue by 2 h 3 min')
  })
})
