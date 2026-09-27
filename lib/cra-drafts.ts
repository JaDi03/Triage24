import type { CraCategory, CraDeadlines, CraDrafts, CraNotification, Remediation } from '@/types'

/** Art. 14(1) and 14(3): both duties go to the same recipients; Art. 14(7) picks the CSIRT. */
const RECIPIENTS =
  'To: the CSIRT designated as coordinator of [MEMBER STATE OF MAIN ESTABLISHMENT IN THE EU] and ENISA, ' +
  'via the single reporting platform (Art. 14(7) and Art. 16)'

const FINAL_REPORT_RULES: Record<CraCategory, string> = {
  actively_exploited_vulnerability:
    'Final report: no later than 14 days after a corrective or mitigating measure is available (Art. 14(2)(c)). ' +
    'It must describe the vulnerability (severity and impact), any information on the malicious actor where ' +
    'available, and the security update or other corrective measures made available.',
  severe_incident:
    'Final report: within one month after the submission of the incident notification (Art. 14(4)(c)). It must ' +
    'describe the incident (severity and impact), the type of threat or root cause, and the applied and ongoing ' +
    'mitigation measures.',
}

export interface DraftContext {
  repoLabel: string
  commitSha?: string
  deadlines: CraDeadlines
  remediations: Remediation[]
}

interface Item {
  ids: string
  component: string
  summary: string
  exploitation: string
  exposure: string
  confirmed: boolean
  fixedVersion?: string
  dependency: string
  version: string
}

/**
 * Deterministic Article 14 drafts, one set per duty that applies. Placeholders in square
 * brackets mark what only the manufacturer knows; nothing is stated as done.
 */
export function buildDrafts(notifications: CraNotification[], context: DraftContext): CraDrafts[] {
  const categories: CraCategory[] = ['actively_exploited_vulnerability', 'severe_incident']
  return categories.flatMap((category) => {
    const relevant = notifications.filter((n) => n.category === category && n.status !== 'not_required')
    if (relevant.length === 0) return []
    const items = relevant.map((n) => toItem(n, context.remediations))
    const incident = category === 'severe_incident'
    return [
      {
        category,
        earlyWarning: incident ? incidentEarlyWarning(items, context) : vulnerabilityEarlyWarning(items, context),
        notification: incident ? incidentNotification(items, context) : vulnerabilityNotification(items, context),
        userAdvisory: userAdvisory(items, incident),
        finalReportRule: FINAL_REPORT_RULES[category],
      },
    ]
  })
}

function toItem(n: CraNotification, remediations: Remediation[]): Item {
  const cves = n.cve.aliases.filter((id) => id.startsWith('CVE-'))
  const fix = remediations.find((r) => r.dep.name === n.dep.name && r.dep.version === n.dep.version)
  return {
    ids: cves.length > 0 ? cves.join(', ') : n.cve.cveId,
    component: `${n.dep.name} ${n.dep.version}`,
    summary: n.cve.description || 'no summary in the advisory',
    exploitation: n.kev
      ? `listed in the CISA Known Exploited Vulnerabilities catalog since ${n.kev.dateAdded}`
      : `release published with malicious code (${n.cve.osvIds.join(', ')})`,
    exposure:
      n.cve.reachability?.verdict === 'affected'
        ? 'Code analysis shows that the product uses the vulnerable functionality.'
        : 'Whether the product uses the vulnerable functionality is under investigation.',
    confirmed: n.status === 'report_required',
    ...(fix?.recommendedVersion ? { fixedVersion: fix.recommendedVersion } : {}),
    dependency: n.dep.name,
    version: n.dep.version,
  }
}

// ─── Actively exploited vulnerability: Art. 14(2) ───────────────────────────

function vulnerabilityEarlyWarning(items: Item[], ctx: DraftContext): string {
  return [
    'EARLY WARNING NOTIFICATION - ACTIVELY EXPLOITED VULNERABILITY',
    'Regulation (EU) 2024/2847 (Cyber Resilience Act), Article 14(2)(a)',
    RECIPIENTS,
    '',
    ...productLines(ctx),
    `Became aware at: ${ctx.deadlines.awareAt}`,
    `Due without undue delay and in any event by: ${ctx.deadlines.earlyWarningDueAt} (24 hours)`,
    '',
    ...splitByConfirmation(
      items,
      'Actively exploited vulnerabilities contained in the product:',
      'Actively exploited vulnerabilities under investigation (not yet confirmed to affect the product):',
      (i) => `- ${i.ids}: ${i.component} - ${i.summary}. Evidence of exploitation: ${i.exploitation}.`,
    ),
    'Member States on the territory of which the product has been made available: [LIST OF MEMBER STATES]',
    '',
    'A vulnerability notification will follow within 72 hours of becoming aware (Art. 14(2)(b)).',
  ].join('\n')
}

function vulnerabilityNotification(items: Item[], ctx: DraftContext): string {
  return [
    'VULNERABILITY NOTIFICATION',
    'Regulation (EU) 2024/2847 (Cyber Resilience Act), Article 14(2)(b)',
    RECIPIENTS,
    '',
    '1. General information about the product with digital elements concerned',
    ...productLines(ctx).map((line) => `   ${line}`),
    `   Became aware at: ${ctx.deadlines.awareAt} | Due without undue delay and in any event by: ${ctx.deadlines.notificationDueAt} (72 hours)`,
    '',
    '2. General nature of the exploit and of the vulnerability concerned',
    ...items.map((i) =>
      [
        `- ${i.ids} in ${i.component}: ${i.summary}`,
        `  Evidence of exploitation: ${i.exploitation}.`,
        `  Exposure in the product: ${i.exposure}`,
        `  Available fix for the component: ${i.fixedVersion ? `${i.dependency} ${i.fixedVersion} or later.` : 'no fixed component version is listed in the advisory data.'}`,
      ].join('\n'),
    ),
    '',
    '3. Corrective or mitigating measures taken',
    ...measureLines(items, false).map((line) => `   ${line}`),
    '   [OTHER MEASURES TAKEN, IF ANY]',
    '',
    '4. Corrective or mitigating measures that users can take',
    `   ${userUpdateLine(items, false)}`,
    '   [INTERIM MITIGATIONS USERS CAN APPLY, IF ANY]',
    '',
    '5. How sensitive the manufacturer considers the notified information to be',
    '   [INDICATE THE SENSITIVITY AND ANY SHARING RESTRICTIONS]',
    '',
    'A final report will follow no later than 14 days after a corrective or mitigating measure is available (Art. 14(2)(c)).',
  ].join('\n')
}

// ─── Severe incident: Art. 14(4) ─────────────────────────────────────────────

function incidentEarlyWarning(items: Item[], ctx: DraftContext): string {
  return [
    'EARLY WARNING NOTIFICATION - SEVERE INCIDENT HAVING AN IMPACT ON THE SECURITY OF THE PRODUCT',
    'Regulation (EU) 2024/2847 (Cyber Resilience Act), Article 14(4)(a)',
    RECIPIENTS,
    '',
    ...productLines(ctx),
    `Became aware at: ${ctx.deadlines.awareAt}`,
    `Due without undue delay and in any event by: ${ctx.deadlines.earlyWarningDueAt} (24 hours)`,
    '',
    'Suspected of being caused by unlawful or malicious acts: YES. The following dependency releases were',
    'published with malicious code.',
    ...splitByConfirmation(
      items,
      'Included in the product:',
      'Under investigation (not yet confirmed to reach the product):',
      (i) => `- ${i.ids}: ${i.component} - ${i.summary}`,
    ),
    'Why the incident is considered severe: it is capable of leading to the introduction or execution of',
    'malicious code in a product with digital elements (Art. 14(5)(b)).',
    '',
    'Member States on the territory of which the product has been made available: [LIST OF MEMBER STATES]',
    '',
    'An incident notification will follow within 72 hours of becoming aware (Art. 14(4)(b)).',
  ].join('\n')
}

function incidentNotification(items: Item[], ctx: DraftContext): string {
  return [
    'INCIDENT NOTIFICATION',
    'Regulation (EU) 2024/2847 (Cyber Resilience Act), Article 14(4)(b)',
    RECIPIENTS,
    '',
    '1. General information about the product with digital elements concerned',
    ...productLines(ctx).map((line) => `   ${line}`),
    `   Became aware at: ${ctx.deadlines.awareAt} | Due without undue delay and in any event by: ${ctx.deadlines.notificationDueAt} (72 hours)`,
    '',
    '2. Nature of the incident',
    ...items.map((i) => `- ${i.ids}: ${i.component} - ${i.summary} (${i.exploitation}).`),
    '   The malicious code runs when the package is installed or loaded.',
    '',
    '3. Initial assessment of the incident',
    '   [SCOPE: WHICH PRODUCT RELEASES, BUILD SYSTEMS AND DEVELOPER MACHINES INSTALLED THESE VERSIONS, AND WHEN]',
    "   [IMPACT: WHETHER MALICIOUS CODE REACHED DISTRIBUTED PRODUCT RELEASES OR USERS' SYSTEMS]",
    '',
    '4. Corrective or mitigating measures taken',
    ...measureLines(items, true).map((line) => `   ${line}`),
    '   Rotation of credentials and tokens exposed on systems that installed the compromised releases - status: [PLANNED / IN PROGRESS / DONE]',
    '   [OTHER MEASURES TAKEN, E.G. CLEAN REBUILD OF AFFECTED RELEASES]',
    '',
    '5. Corrective or mitigating measures that users can take',
    `   ${userUpdateLine(items, true)}`,
    '   [ADDITIONAL MEASURES FOR USERS, E.G. ROTATING CREDENTIALS IF AFFECTED RELEASES WERE INSTALLED]',
    '',
    '6. How sensitive the manufacturer considers the notified information to be',
    '   [INDICATE THE SENSITIVITY AND ANY SHARING RESTRICTIONS]',
    '',
    'A final report will follow within one month after the submission of this incident notification (Art. 14(4)(c)).',
  ].join('\n')
}

// ─── Users: Art. 14(8) ───────────────────────────────────────────────────────

function userAdvisory(items: Item[], incident: boolean): string {
  const confirmed = items.filter((i) => i.confirmed)
  return [
    'SECURITY ADVISORY FOR USERS OF [PRODUCT NAME]',
    'Information to impacted users under Regulation (EU) 2024/2847, Article 14(8)',
    '',
    'What happened',
    ...splitByConfirmation(
      items,
      incident
        ? '[PRODUCT NAME] was built with third-party components whose published releases contained malicious code:'
        : '[PRODUCT NAME] includes third-party components affected by actively exploited vulnerabilities:',
      'Still under investigation (not yet confirmed to affect [PRODUCT NAME]):',
      (i) => `- ${i.ids} (${i.component}): ${i.summary}`,
    ),
    'What you should do',
    `- ${userUpdateLine(confirmed.length > 0 ? confirmed : items, incident)}`,
    ...(incident
      ? ['- If you installed an affected release, treat those systems as potentially compromised and rotate credentials and access tokens used on them.']
      : []),
    '- Until you can update: [RISK MITIGATION MEASURES, IF ANY].',
    '',
    'Contact: [SECURITY CONTACT]',
    '',
    '[WHERE APPROPRIATE, ALSO PUBLISH THIS ADVISORY IN A STRUCTURED, MACHINE-READABLE FORMAT (Art. 14(8))]',
  ].join('\n')
}

// ─── Shared lines ────────────────────────────────────────────────────────────

/**
 * The component change per dependency, with a status for the manufacturer to choose: the
 * Regulation asks for measures "taken" and Triage24 cannot know whether they were.
 */
function measureLines(items: Item[], incident: boolean): string[] {
  const status = ' - status: [PLANNED / IN PROGRESS / DONE]'
  const lines = items.map((i) => {
    if (incident) {
      return i.fixedVersion
        ? `Replacement of the compromised ${i.component} with ${i.fixedVersion}${status}`
        : `Replacement of the compromised ${i.component} with a release not listed as compromised${status}`
    }
    return i.fixedVersion
      ? `Upgrade of ${i.dependency} from ${i.version} to ${i.fixedVersion} or later${status}`
      : `Upgrade of ${i.dependency} from ${i.version} to a version that fixes ${i.ids}${status}`
  })
  return [...new Set(lines)]
}

/**
 * What users do: update the product. [PATCHED PRODUCT VERSION] is the manufacturer's
 * release, which users install; the component version it contains is stated separately.
 */
function userUpdateLine(items: Item[], incident: boolean): string {
  const components = [
    ...new Set(
      items.map((i) =>
        incident ? i.component : i.fixedVersion ? `${i.dependency} ${i.fixedVersion} or later` : `a fixed version of ${i.dependency}`,
      ),
    ),
  ]
  const detail = incident ? `, which no longer includes ${joinList(components)}` : `, which includes ${joinList(components)}`
  return `Update [PRODUCT NAME] to [PATCHED PRODUCT VERSION]${detail}, as soon as it is available.`
}

/** Lists confirmed items apart from those still under review, so nothing is overstated. */
function splitByConfirmation(items: Item[], confirmedTitle: string, reviewTitle: string, line: (i: Item) => string): string[] {
  const confirmed = items.filter((i) => i.confirmed)
  const review = items.filter((i) => !i.confirmed)
  return [
    ...(confirmed.length > 0 ? [confirmedTitle, ...confirmed.map(line), ''] : []),
    ...(review.length > 0 ? [reviewTitle, ...review.map(line), ''] : []),
  ]
}

function productLines(ctx: DraftContext): string[] {
  return [
    'Manufacturer: [MANUFACTURER NAME]',
    `Product with digital elements: [PRODUCT NAME AND VERSION] (source repository: ${ctx.repoLabel}${ctx.commitSha ? `, commit ${ctx.commitSha}` : ''})`,
  ]
}

function joinList(items: string[]): string {
  return items.length <= 1 ? (items[0] ?? '') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`
}
