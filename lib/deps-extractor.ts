import { XMLParser } from 'fast-xml-parser'
import type { Dependency } from '../types'

// ─── npm (package-lock.json v2/v3) ────────────────────────────────────────────

interface PackageLock {
  lockfileVersion: number
  packages?: Record<string, { version?: string; dev?: boolean }>
}

/** Strip UTF-8 BOM (0xFEFF) that some tools prepend to JSON files. */
function stripBom(content: string): string {
  return content.charCodeAt(0) === 0xfeff ? content.slice(1) : content
}

/**
 * Parse a package-lock.json v2/v3 string and return all transitive
 * dependencies (direct + indirect) as a deduplicated `Dependency[]`.
 *
 * Throws a descriptive error for lockfile v1 (missing `packages` map).
 */
export function extractFromPackageLock(content: string): Dependency[] {
  const lock: PackageLock = JSON.parse(stripBom(content))

  if (lock.lockfileVersion === 1 || !lock.packages) {
    throw new Error(
      `package-lock.json v1 is not supported. ` +
        `Re-generate the lockfile with npm >= 7 (lockfileVersion 2 or 3) ` +
        `and commit the updated file.`,
    )
  }

  const deps: Dependency[] = []
  const seen = new Set<string>()

  for (const [key, entry] of Object.entries(lock.packages)) {
    // The root package ("") has no name to extract
    if (key === '') continue
    // key format: "node_modules/foo" or "node_modules/foo/node_modules/bar"
    const name = key.replace(/^.*node_modules\//, '')
    const version = entry.version
    if (!name || !version) continue

    const id = `${name}@${version}`
    if (seen.has(id)) continue
    seen.add(id)

    deps.push({ name, version, ecosystem: 'npm' })
  }

  return deps
}

// ─── Maven (pom.xml) ──────────────────────────────────────────────────────────

interface PomDependency {
  groupId?: string | number
  artifactId?: string | number
  version?: string | number
}

interface PomProject {
  project?: {
    properties?: Record<string, unknown>
    dependencies?: { dependency?: PomDependency | PomDependency[] }
  }
}

/**
 * Parse a pom.xml string and return all `<dependency>` entries as
 * `Dependency[]`.  Property placeholders (`${foo}`) are resolved from
 * `<properties>`.  Version-like values that fast-xml-parser might
 * coerce to numbers (e.g. "2.10" → 2.1) are prevented by setting
 * `parseTagValue: false`.
 */
export function extractFromPomXml(content: string): Dependency[] {
  const parser = new XMLParser({ parseTagValue: false, ignoreAttributes: false })
  const parsed: PomProject = parser.parse(content)

  const project = parsed?.project
  if (!project) return []

  // Build property map for ${...} resolution
  const props: Record<string, string> = {}
  if (project.properties) {
    for (const [k, v] of Object.entries(project.properties)) {
      props[k] = String(v)
    }
  }

  function resolve(val: string | number | undefined): string {
    if (val === undefined) return ''
    const str = String(val)
    return str.replace(/\$\{([^}]+)\}/g, (_, key) => props[key] ?? '')
  }

  const rawDeps = project.dependencies?.dependency
  if (!rawDeps) return []

  const list: PomDependency[] = Array.isArray(rawDeps) ? rawDeps : [rawDeps]
  const deps: Dependency[] = []

  for (const dep of list) {
    const groupId = resolve(dep.groupId)
    const artifactId = resolve(dep.artifactId)
    const version = resolve(dep.version)

    if (!groupId || !artifactId) continue

    deps.push({
      name: `${groupId}:${artifactId}`,
      version: version || 'unknown',
      ecosystem: 'maven',
    })
  }

  return deps
}

// ─── Top-level orchestrator ───────────────────────────────────────────────────

type TreeEntry = { path: string; type: string }
type FetchFile = (path: string) => Promise<string>

/**
 * Given the flat repo tree and a file-fetching callback, find all supported
 * manifest files and return a merged, deduplicated `Dependency[]`.
 *
 * Priority: package-lock.json > package.json (lock preferred), pom.xml.
 */
export async function extractDependencies(
  tree: TreeEntry[],
  fetchFile: FetchFile,
): Promise<Dependency[]> {
  const paths = tree.filter((e) => e.type === 'blob').map((e) => e.path)
  const all: Dependency[] = []

  // npm: prefer package-lock.json (v2/v3) over bare package.json
  const lockPath = paths.find((p) => p === 'package-lock.json' || p.endsWith('/package-lock.json'))
  if (lockPath) {
    const content = await fetchFile(lockPath)
    all.push(...extractFromPackageLock(content))
  }

  // Maven
  const pomPaths = paths.filter((p) => p === 'pom.xml' || p.endsWith('/pom.xml'))
  for (const pomPath of pomPaths) {
    const content = await fetchFile(pomPath)
    all.push(...extractFromPomXml(content))
  }

  // Deduplicate across ecosystems
  const seen = new Set<string>()
  return all.filter((d) => {
    const id = `${d.ecosystem}:${d.name}@${d.version}`
    if (seen.has(id)) return false
    seen.add(id)
    return true
  })
}
