import { describe, it, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import { strToU8, zipSync } from 'fflate'
import { POST } from '@/app/api/audit/route'
import { clearOsvCache } from '@/lib/osv'
import { clearKevCache } from '@/lib/kev'
import { isVersionAffected } from '@/lib/remediation/fix-version'
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
    '': { name: 'web', dependencies: { debug: '^4.4.0', lodash: '^4.17.0' } },
    'node_modules/debug': { version: '4.4.2' },
    'node_modules/lodash': { version: '4.17.20' },
  },
})

// A service that logs a query parameter and a header: Log4Shell is reachable (lines 13 and 14).
const APP_JAVA = `package com.acme.portal;

import com.sun.net.httpserver.HttpExchange;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    static void handle(HttpExchange exchange) {
        String user = exchange.getRequestURI().getRawQuery();
        String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
        logger.info("Greeting requested by user: " + user);
        logger.info("Client user agent: {}", userAgent);
        logger.info("Server started on port 8080");
    }
}
`

// lodash is imported, but only _.get is used: none of its vulnerable functions.
const INDEX_JS = `const _ = require("lodash");
const port = _.get({ server: { port: 3000 } }, "server.port", 8080);
console.log(port);
`

function repoZip(): Response {
  return new Response(
    zipSync({
      'acme-portal-0123abc/pom.xml': strToU8(POM),
      'acme-portal-0123abc/web/package-lock.json': strToU8(LOCKFILE),
      'acme-portal-0123abc/src/main/java/com/acme/portal/App.java': strToU8(APP_JAVA),
      'acme-portal-0123abc/web/index.js': strToU8(INDEX_JS),
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
    expect(report.commitSha).toBe('0123abc')
  })

  it('finds where external input reaches the vulnerable logging calls', async () => {
    const { body } = await audit('https://github.com/acme/portal')
    const log4shell = body.report!.notifications.find((n) => n.cve.cveId === 'CVE-2021-44228')!

    expect(log4shell.cve.reachability?.verdict).toBe('affected')
    expect(log4shell.cve.reachability?.evidence.map((e) => `${e.file}:${e.line}`)).toEqual([
      'src/main/java/com/acme/portal/App.java:13',
      'src/main/java/com/acme/portal/App.java:14',
    ])
  })

  it('rules out lodash vulnerabilities whose functions the code never calls', async () => {
    const { body } = await audit('https://github.com/acme/portal')
    const lodash = body.report!.cveFindings.find((f) => f.dep.name === 'lodash')!

    expect(lodash.cves.every((cve) => cve.reachability?.verdict === 'not_affected')).toBe(true)
    expect(body.report!.remediations.some((r) => r.dep.name === 'lodash')).toBe(false)
  })

  it('recommends a Log4j release that fixes every advisory and prepares the instruction for IBM Bob', async () => {
    const { body } = await audit('https://github.com/acme/portal')
    const report = body.report!
    const log4j = report.remediations.find((r) => r.dep.name === 'org.apache.logging.log4j:log4j-core')!
    const cves = report.cveFindings.find((f) => f.dep.name === log4j.dep.name)!.cves

    expect(log4j.recommendedVersion).toBeDefined()
    expect(cves.every((cve) => !isVersionAffected(cve, log4j.recommendedVersion!))).toBe(true)
    expect(log4j.fixPrompt).toContain(`to ${log4j.recommendedVersion}`)
    expect(log4j.fixPrompt).toContain('src/main/java/com/acme/portal/App.java:13')

    // The malicious release comes first and asks for credentials to be rotated.
    expect(report.remediations[0].dep.name).toBe('debug')
    expect(report.remediations[0].fixPrompt).toContain('rotated')
  })

  it('writes drafts for both Article 14 duties', async () => {
    const { body } = await audit('https://github.com/acme/portal')
    expect(body.report!.drafts.map((d) => d.category).sort()).toEqual(['actively_exploited_vulnerability', 'severe_incident'])
    expect(body.report!.drafts.find((d) => d.category === 'severe_incident')!.earlyWarning).toContain('debug 4.4.2')
  })

  it('lists the Maven dependency without a version as not checked', async () => {
    const { body } = await audit('https://github.com/acme/portal')
    expect(body.report!.unresolvedDeps).toEqual(['org.springframework.boot:spring-boot-starter-web (unknown)'])
  })

  it('keeps vulnerabilities that are not actively exploited out of the notification duties', async () => {
    const { body } = await audit('https://github.com/acme/portal')
    expect(body.report!.notifications.some((n) => n.dep.name === 'lodash')).toBe(false)
  })
})
