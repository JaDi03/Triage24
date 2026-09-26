import type { CRAReport, CVERecord, Dependency, Evidence, Remediation } from '@/types'
import { compareVersions } from './versions'
import { recommendUpgrade } from './fix-version'

const MAX_LOCATIONS = 5

const SEVERITY_RANK: Record<CVERecord['severity'], number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 }

interface Candidate {
  dep: Dependency
  cves: CVERecord[]
  needsAction: CVERecord[]
  recommendedVersion?: string
}

/**
 * One entry per dependency whose vulnerabilities are not ruled out by the reachability
 * analysis: the release to upgrade to and a ready-to-paste instruction for IBM Bob.
 * Most urgent first (malicious releases, then actively exploited, then severity).
 */
export function buildRemediations(
  cveFindings: CRAReport['cveFindings'],
  kevIds: Set<string>,
): Remediation[] {
  const candidates: Candidate[] = cveFindings
    .map(({ dep, cves }) => ({
      dep,
      cves,
      needsAction: cves.filter((cve) => cve.reachability?.verdict !== 'not_affected'),
      // The upgrade has to fix every advisory of the release, reachable or not.
      recommendedVersion: recommendUpgrade(dep, cves),
    }))
    .filter((c) => c.needsAction.length > 0)

  alignFamilies(candidates)

  return candidates
    .map((candidate) => {
      const alignedWith = siblings(candidate, candidates)
      return {
        dep: candidate.dep,
        cveIds: candidate.needsAction.map((cve) => cve.cveId),
        ...(candidate.recommendedVersion ? { recommendedVersion: candidate.recommendedVersion } : {}),
        alignedWith,
        fixPrompt: buildFixPrompt(candidate, alignedWith),
      }
    })
    .sort((a, b) => urgency(b, candidates, kevIds) - urgency(a, candidates, kevIds))
}

/**
 * Maven artifacts of the same group and release (log4j-api and log4j-core 2.14.1) must be
 * upgraded together. Each gets its own recommendation from its own advisories, so they can
 * differ; this raises all of them to the highest one in the family.
 */
function alignFamilies(candidates: Candidate[]) {
  const highest = new Map<string, string>()
  for (const c of candidates) {
    const key = familyKey(c.dep)
    if (!key || !c.recommendedVersion) continue
    const current = highest.get(key)
    if (!current || compareVersions(c.recommendedVersion, current) > 0) highest.set(key, c.recommendedVersion)
  }
  for (const c of candidates) {
    const key = familyKey(c.dep)
    if (key && c.recommendedVersion) c.recommendedVersion = highest.get(key)
  }
}

function familyKey(dep: Dependency): string | undefined {
  return dep.ecosystem === 'maven' ? `${dep.name.split(':')[0]}|${dep.version}` : undefined
}

function siblings(candidate: Candidate, all: Candidate[]): string[] {
  const key = familyKey(candidate.dep)
  if (!key) return []
  return all.filter((c) => c !== candidate && familyKey(c.dep) === key).map((c) => c.dep.name)
}

function urgency(remediation: Remediation, candidates: Candidate[], kevIds: Set<string>): number {
  const cves = candidates.find((c) => c.dep === remediation.dep)?.needsAction ?? []
  const malicious = cves.some((cve) => cve.malicious) ? 1000 : 0
  const exploited = cves.some((cve) => cve.aliases.some((id) => kevIds.has(id))) ? 100 : 0
  const affected = cves.some((cve) => cve.reachability?.verdict === 'affected') ? 10 : 0
  return malicious + exploited + affected + Math.max(0, ...cves.map((cve) => SEVERITY_RANK[cve.severity]))
}

// ─── Fix with IBM Bob ────────────────────────────────────────────────────────

/** A ready-to-paste instruction for IBM Bob, in English, for one dependency. */
function buildFixPrompt(candidate: Candidate, alignedWith: string[]): string {
  const { dep, needsAction } = candidate
  const malicious = needsAction.some((cve) => cve.malicious)
  const confirmed = needsAction.some((cve) => cve.reachability?.verdict === 'affected')
  const ids = [...new Set(needsAction.map((cve) => cve.cveId))]
  const lines: string[] = []

  lines.push(
    malicious
      ? `${dep.name}@${dep.version} is a compromised release that contains malicious code (${ids.join(', ')}).`
      : `${dep.name}@${dep.version} has known vulnerabilities that ${confirmed ? 'affect' : 'may affect'} this project: ${ids.join(', ')}.`,
  )

  lines.push('', 'Please make these changes:')
  lines.push(`1. ${upgradeStep(dep, candidate.recommendedVersion, alignedWith)}`)

  // Code to review, only when the problem is in how the code uses the package. Confirmed
  // findings point at the risky calls; import lines add nothing to review.
  const reviewable = needsAction.filter((cve) => !cve.malicious)
  const affected = reviewable.filter((cve) => cve.reachability?.verdict === 'affected')
  const locations = [
    ...new Set(
      (affected.length > 0 ? affected : reviewable)
        .flatMap((cve) => cve.reachability?.evidence ?? [])
        .filter((e) => !isManifest(e) && !isImportLine(e))
        .map((e) => `${e.file}:${e.line}  ${e.snippet}`),
    ),
  ].slice(0, MAX_LOCATIONS)

  let step = 2
  if (locations.length > 0) {
    lines.push(
      `${step++}. Review these locations, where the vulnerable functionality is used, and make sure no untrusted input reaches it (validate or sanitize it):`,
      ...locations.map((location) => `   - ${location}`),
    )
  }
  if (malicious) {
    lines.push(
      `${step++}. List every CI pipeline, build server and developer machine that may have installed ${dep.name}@${dep.version}, ` +
        'and the credentials, tokens and secrets available there, so they can be rotated.',
    )
  }

  lines.push(
    '',
    'Then build the project and run the tests. Summarize what you changed so it can be recorded as the corrective measure for the EU Cyber Resilience Act report.',
  )
  return lines.join('\n')
}

function upgradeStep(dep: Dependency, target: string | undefined, alignedWith: string[]): string {
  const to = target
    ? `to ${target}`
    : "to a release that is not affected (none is listed in the advisory data; check the package's release notes)"
  const manifest = dep.manifestPath ?? (dep.ecosystem === 'maven' ? 'pom.xml' : 'package-lock.json')

  if (dep.ecosystem === 'maven') {
    const names = [dep.name, ...alignedWith].join(' and ')
    return (
      `In ${manifest}, upgrade ${names} from ${dep.version} ${to}. ` +
      'If the version comes from a <properties> entry, update the property so all artifacts stay aligned.'
    )
  }
  if (dep.direct) {
    return `Upgrade ${dep.name} from ${dep.version} ${to} in package.json and regenerate ${manifest} with npm install.`
  }
  return (
    `${dep.name} is a transitive dependency. Upgrade the direct dependency that pulls it in, or add an "overrides" ` +
    `entry in package.json that forces ${dep.name} ${to}, then regenerate ${manifest}.`
  )
}

function isManifest(evidence: Evidence): boolean {
  return /(^|\/)(package-lock\.json|package\.json|pom\.xml)$/.test(evidence.file)
}

function isImportLine(evidence: Evidence): boolean {
  return /^\s*import\b|\brequire\(/.test(evidence.snippet)
}
