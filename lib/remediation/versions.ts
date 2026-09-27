/**
 * Lenient version comparison for semver (npm) and common Maven version strings such as
 * "2.0-beta9", "2.17.1" or "1.2.1.2-jre17". It is not a full implementation of either
 * spec, but it orders real-world release numbers and pre-release qualifiers correctly.
 */

type Token = number | string

/** Pre-release qualifiers sort before the release they precede, in this order. */
const PRE_RELEASE_ORDER = ['alpha', 'a', 'beta', 'b', 'milestone', 'm', 'rc', 'cr', 'snapshot']
/** Qualifiers that mean "the release itself". */
const RELEASE_ALIASES = new Set(['', 'final', 'ga', 'release'])

export function compareVersions(a: string, b: string): number {
  const left = tokenize(a)
  const right = tokenize(b)
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const result = compareTokens(left[i], right[i])
    if (result !== 0) return result
  }
  return 0
}

function tokenize(version: string): Token[] {
  const clean = version.trim().toLowerCase().replace(/^v/, '').split('+')[0]
  const parsed = (clean.match(/\d+|[a-z]+/g) ?? []).map((token) => (/^\d+$/.test(token) ? Number(token) : token))
  // Drop trailing zeros and release aliases so that "1.0", "1.0.0" and "1.0-final" are equal.
  while (parsed.length > 0) {
    const last = parsed[parsed.length - 1]
    if (last === 0 || (typeof last === 'string' && RELEASE_ALIASES.has(last))) parsed.pop()
    else break
  }
  return parsed
}

/**
 * A missing token counts as 0 next to a number (1.0 == 1.0.0) and as "the release" next
 * to a qualifier: pre-release qualifiers sort before it (1.0-rc1 < 1.0) and any other
 * qualifier after it (1.2-jre17 > 1.2).
 */
function compareTokens(a: Token | undefined, b: Token | undefined): number {
  if (a === undefined) a = typeof b === 'number' ? 0 : ''
  if (b === undefined) b = typeof a === 'number' ? 0 : ''
  if (a === b) return 0

  if (typeof a === 'number' && typeof b === 'number') return Math.sign(a - b)
  if (typeof a === 'number') return 1 // 1.0.1 > 1.0-beta
  if (typeof b === 'number') return -1

  if (a === '') return PRE_RELEASE_ORDER.includes(b) ? 1 : -1
  if (b === '') return PRE_RELEASE_ORDER.includes(a) ? -1 : 1

  const rankA = PRE_RELEASE_ORDER.indexOf(a)
  const rankB = PRE_RELEASE_ORDER.indexOf(b)
  if (rankA !== -1 && rankB !== -1) return Math.sign(rankA - rankB)
  if (rankA !== -1) return -1 // known pre-release < unknown qualifier
  if (rankB !== -1) return 1
  return a < b ? -1 : 1
}
