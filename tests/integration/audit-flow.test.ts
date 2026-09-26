import { describe, it, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import { strToU8, zipSync } from 'fflate'
import { POST } from '@/app/api/audit/route'
import { clearOsvCache } from '@/lib/osv'
import { clearKevCache } from '@/lib/kev'
import type { CRAReport } from '@/types'
import { recordedFetch } from '../helpers/osv-fixtures'

// The whole pipeline, with only the network replaced: GitHub serves an in-memory ZIP,
// OSV.dev and CISA KEV serve the responses recorded from the live APIs.

const POM = `<project>
  <properties><log4j2.version>2.14.1</log4j2.version></properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>\${log4j2.version}</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
  </dependencies>
</project>`

const LOCKFILE = JSON.stringify({
  name: 'web',
  lockfileVersion: 3,
  packages: {
    '': { name: 'web' },
    'node_modules/debug': { version: '4.4.2' },
    'node_modules/lodash': { version: '4.17.20', dev: true },
  },
})

function repoZip(): Response {
  return new Response(
    zipSync({
      'acme-portal-0123abc/pom.xml': strToU8(POM),
      'acme-portal-0123abc/web/package-lock.json': strToU8(LOCKFILE),
      'acme-portal-0123abc/src/main/java/App.java': strToU8('class App { void run(String q) { log.info(q); } }'),
    }),
  )
}

async function audit(url: string): Promise<{ status: number; body: { report?: CRAReport; error?: string } }> {
  const res = await POST(
    new NextRequest('http://localhost/api/audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    }),
  )
  return { status: res.status, body: await res.json() }
}

describe('audit flow with recorded OSV and KEV data', () => {
  beforeEach(() => {
    clearOsvCache()
    clearKevCache()
    const recorded = recordedFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        if (String(input).endsWith('/zipball')) return repoZip()
        return recorded(input, init)
      }),
    )
  })

  it('reports Log4Shell as an actively exploited vulnerability and debug 4.4.2 as a severe incident', async () => {
    const { status, body } = await audit('https://github.com/acme/portal')
    expect(status).toBe(200)
    const report = body.report!

    expect(report.craStatus).toBe('report_required')
    expect(report.overallRisk).toBe('CRITICAL')

    const exploited = report.notifications.filter((n) => n.category === 'actively_exploited_vulnerability')
    expect(exploited.map((n) => n.cve.cveId)).toEqual(expect.arrayContaining(['CVE-2021-44228', 'CVE-2021-45046']))
    expect(exploited.every((n) => n.status === 'report_required')).toBe(true)

    const incidents = report.notifications.filter((n) => n.category === 'severe_incident')
    expect(incidents).toHaveLength(1)
    expect(incidents[0].dep.name).toBe('debug')
    expect(incidents[0].cve.osvIds).toEqual(['GHSA-4x49-vf9v-38px', 'MAL-2025-46974'])

    expect(report.deadlines).not.toBeNull()
  })

  it('lists the Maven dependency without a version as not checked', async () => {
    const { body } = await audit('https://github.com/acme/portal')
    expect(body.report!.unresolvedDeps).toEqual(['org.springframework.boot:spring-boot-starter-web (unknown)'])
  })

  it('keeps development dependencies out of the notification duties', async () => {
    const { body } = await audit('https://github.com/acme/portal')
    const lodash = body.report!.cveFindings.find((f) => f.dep.name === 'lodash')
    expect(lodash?.dep.dev).toBe(true)
    expect(body.report!.notifications.some((n) => n.dep.name === 'lodash')).toBe(false)
  })
})
