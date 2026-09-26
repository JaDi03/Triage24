// Records real OSV.dev and CISA KEV responses as test fixtures.
// Nothing is edited by hand: every file is exactly what the live API returned.
//
// Usage: npm run record:fixtures
// (behind a TLS-inspecting proxy or antivirus: node --use-system-ca scripts/record-fixtures.mjs)

import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const OSV_DIR = path.join(ROOT, 'tests', 'fixtures', 'osv')
const KEV_DIR = path.join(ROOT, 'tests', 'fixtures', 'kev')

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns'
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

// Packages recorded for the tests: an actively exploited vulnerability (Log4Shell),
// a malicious release (npm account takeover, September 2025) and several advisories
// that are aliases of each other (lodash).
const QUERIES = [
  { package: { name: 'org.apache.logging.log4j:log4j-core', ecosystem: 'Maven' }, version: '2.14.1' },
  { package: { name: 'debug', ecosystem: 'npm' }, version: '4.4.2' },
  { package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' },
]

const KEV_IDS = ['CVE-2021-44228', 'CVE-2021-45046']

async function getJson(url, init) {
  const res = await fetch(url, init)
  if (!res.ok) throw new Error(`${url} -> ${res.status} ${res.statusText}`)
  return res.json()
}

async function save(file, data) {
  await mkdir(path.dirname(file), { recursive: true })
  await writeFile(file, JSON.stringify(data, null, 2) + '\n', 'utf8')
  console.log(`saved ${path.relative(ROOT, file)}`)
}

async function main() {
  const request = { queries: QUERIES }
  const response = await getJson(OSV_BATCH_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })
  await save(path.join(OSV_DIR, 'querybatch.json'), { request, response })

  const ids = new Set()
  for (const result of response.results ?? []) {
    for (const vuln of result.vulns ?? []) ids.add(vuln.id)
  }
  for (const id of [...ids].sort()) {
    const vuln = await getJson(`${OSV_VULN_URL}/${encodeURIComponent(id)}`)
    await save(path.join(OSV_DIR, 'vulns', `${id}.json`), vuln)
  }

  const catalog = await getJson(KEV_URL)
  const vulnerabilities = catalog.vulnerabilities.filter((entry) => KEV_IDS.includes(entry.cveID))
  if (vulnerabilities.length !== KEV_IDS.length) {
    throw new Error(`Expected ${KEV_IDS.length} KEV entries, found ${vulnerabilities.length}`)
  }
  await save(path.join(KEV_DIR, 'kev-excerpt.json'), {
    title: catalog.title,
    catalogVersion: catalog.catalogVersion,
    dateReleased: catalog.dateReleased,
    count: vulnerabilities.length,
    vulnerabilities,
  })
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
