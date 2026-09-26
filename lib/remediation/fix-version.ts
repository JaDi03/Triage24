import type { AffectedRange, CVERecord, Dependency } from '@/types'
import { compareVersions } from './versions'

/** True when `version` falls inside any affected range or explicit version of the finding. */
export function isVersionAffected(cve: CVERecord, version: string): boolean {
  if (cve.affectedVersions?.includes(version)) return true
  return (cve.affectedRanges ?? []).some((range) => isInRange(range.events, version))
}

/**
 * The lowest release above the current one that none of the findings affects. Candidates
 * are the findings' own "fixed" versions, so the suggestion is always a release the
 * advisory data knows about. Undefined when no candidate fixes everything.
 */
export function recommendUpgrade(dep: Dependency, cves: CVERecord[]): string | undefined {
  const candidates = new Set<string>()
  for (const cve of cves) {
    for (const range of cve.affectedRanges ?? []) {
      for (const event of range.events) {
        if (event.fixed && compareVersions(event.fixed, dep.version) > 0) candidates.add(event.fixed)
      }
    }
  }
  return [...candidates]
    .sort(compareVersions)
    .find((candidate) => cves.every((cve) => !isVersionAffected(cve, candidate)))
}

/**
 * Evaluates OSV range events in order: a version is affected once it reaches an
 * "introduced" event, until it reaches a "fixed" or passes a "last_affected" event.
 */
function isInRange(events: AffectedRange['events'], version: string): boolean {
  const sorted = [...events].sort((a, b) => compareVersions(eventVersion(a), eventVersion(b)))
  let affected = false
  for (const event of sorted) {
    if (event.introduced !== undefined) {
      if (event.introduced === '0' || compareVersions(version, event.introduced) >= 0) affected = true
    } else if (event.fixed !== undefined) {
      if (compareVersions(version, event.fixed) >= 0) affected = false
    } else if (event.last_affected !== undefined) {
      if (compareVersions(version, event.last_affected) > 0) affected = false
    } else if (event.limit !== undefined) {
      if (compareVersions(version, event.limit) >= 0) affected = false
    }
  }
  return affected
}

function eventVersion(event: AffectedRange['events'][number]): string {
  return event.introduced ?? event.fixed ?? event.last_affected ?? event.limit ?? '0'
}
