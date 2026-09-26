import type { Dependency } from '@/types'

/** Single key for a dependency, shared by the OSV lookup and the CRA scorer. */
export function depKey(dep: Pick<Dependency, 'ecosystem' | 'name' | 'version'>): string {
  return `${dep.ecosystem}:${dep.name}@${dep.version}`
}

/** A version OSV can evaluate: unresolved Maven versions ("unknown", "${...}") are not. */
export function hasResolvedVersion(dep: Pick<Dependency, 'version'>): boolean {
  const version = dep.version.trim()
  return version !== '' && version !== 'unknown' && !version.includes('${')
}
