// CVSS v3.x base score calculation (FIRST CVSS v3.1 specification, section 7).
// OSV publishes severities as vectors ("CVSS:3.1/AV:N/..."), never as numbers.

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
const AC: Record<string, number> = { L: 0.77, H: 0.44 }
const UI: Record<string, number> = { N: 0.85, R: 0.62 }
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 }

function privilegesRequired(value: string, scopeChanged: boolean): number | undefined {
  if (value === 'N') return 0.85
  if (value === 'L') return scopeChanged ? 0.68 : 0.62
  if (value === 'H') return scopeChanged ? 0.5 : 0.27
  return undefined
}

/** CVSS v3.1 "Roundup": smallest number with one decimal that is >= the input. */
function roundUp(value: number): number {
  const intInput = Math.round(value * 100000)
  if (intInput % 10000 === 0) return intInput / 100000
  return (Math.floor(intInput / 10000) + 1) / 10
}

/**
 * Returns the base score of a CVSS v3.0/v3.1 vector, or null when the vector is not
 * CVSS v3 or is missing a base metric.
 */
export function cvss3BaseScore(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null

  const metrics: Record<string, string> = {}
  for (const part of vector.split('/').slice(1)) {
    const [key, value] = part.split(':')
    if (key && value) metrics[key] = value
  }

  const scopeChanged = metrics.S === 'C'
  if (metrics.S !== 'U' && metrics.S !== 'C') return null

  const av = AV[metrics.AV]
  const ac = AC[metrics.AC]
  const pr = privilegesRequired(metrics.PR, scopeChanged)
  const ui = UI[metrics.UI]
  const c = CIA[metrics.C]
  const i = CIA[metrics.I]
  const a = CIA[metrics.A]
  if ([av, ac, pr, ui, c, i, a].some((v) => v === undefined)) return null

  const iss = 1 - (1 - c) * (1 - i) * (1 - a)
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss
  if (impact <= 0) return 0

  const exploitability = 8.22 * av * ac * pr! * ui
  const raw = scopeChanged ? 1.08 * (impact + exploitability) : impact + exploitability
  return roundUp(Math.min(raw, 10))
}
