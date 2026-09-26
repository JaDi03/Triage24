import { XMLParser } from 'fast-xml-parser'
import type { Dependency } from '../types'

// ─── npm (package-lock.json v2/v3) ────────────────────────────────────────────

interface PackageLock {
  lockfileVersion: number
  packages?: Record<
    string,
    {
      version?: string
      dev?: boolean
      os?: string[]
      dependencies?: Record<string, string>
      devDependencies?: Record<string, string>
      optionalDependencies?: Record<string, string>
      peerDependencies?: Record<string, string>
    }
  >
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
  const seen = new Map<string, Dependency>()

  // Packages the project declares itself (the lockfile's root entry).
  const root = lock.packages[''] ?? {}
  const declared = new Set(
    [root.dependencies, root.devDependencies, root.optionalDependencies, root.peerDependencies].flatMap((group) =>
      Object.keys(group ?? {}),
    ),
  )

  for (const [key, entry] of Object.entries(lock.packages)) {
    // The root package ("") has no name to extract
    if (key === '') continue
    // key format: "node_modules/foo" or "node_modules/foo/node_modules/bar"
    const name = key.replace(/^.*node_modules\//, '')
    const version = entry.version
    if (!name || !version) continue

    const id = `${name}@${version}`
    const existing = seen.get(id)
    if (existing) {
      // The same release installed for production and for development ships in the product.
      if (existing.dev && !entry.dev) delete existing.dev
      continue
    }

    // Only the top-level install of a declared package is the direct dependency.
    const direct = declared.has(name) && key === `node_modules/${name}`
    const dep: Dependency = {
      name,
      version,
      ecosystem: 'npm',
      ...(direct ? { direct: true } : {}),
      ...(entry.dev ? { dev: true } : {}),
      ...(Array.isArray(entry.os) && entry.os.length > 0 ? { os: entry.os } : {}),
    }
    seen.set(id, dep)
    deps.push(dep)
  }

  return deps
}

// ─── Maven (pom.xml) ──────────────────────────────────────────────────────────

interface PomDependency {
  groupId?: string | number
  artifactId?: string | number
  version?: string | number
  scope?: string | number
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
      direct: true,
      // Test-scoped artifacts are not packaged with the product.
      ...(resolve(dep.scope) === 'test' ? { dev: true } : {}),
    })
  }

  return deps
}

// ─── Top-level orchestrator ───────────────────────────────────────────────────

type TreeEntry = { path: string; type: string }
type FetchFile = (path: string) => Promise<string>

const IGNORED_MANIFEST_DIRS = /(^|\/)(node_modules|target|build|dist)\//

/**
 * Given the flat repo tree and a file-fetching callback, find all supported
 * manifest files and return a merged, deduplicated `Dependency[]`.
 *
 * Every package-lock.json (v2/v3) and pom.xml is read, except those inside
 * installed or build output folders. A manifest that cannot be read or parsed is
 * skipped and reported in `warnings` instead of stopping the analysis.
 */
export async function extractDependencies(
  tree: TreeEntry[],
  fetchFile: FetchFile,
  warnings: string[] = [],
): Promise<Dependency[]> {
  const paths = tree
    .filter((e) => e.type === 'blob')
    .map((e) => e.path)
    .filter((p) => !IGNORED_MANIFEST_DIRS.test(p))
  const all: Dependency[] = []

  const manifests: Array<{ path: string; parse: (content: string) => Dependency[] }> = [
    ...paths
      .filter((p) => p === 'package-lock.json' || p.endsWith('/package-lock.json'))
      .map((path) => ({ path, parse: extractFromPackageLock })),
    ...paths
      .filter((p) => p === 'pom.xml' || p.endsWith('/pom.xml'))
      .map((path) => ({ path, parse: extractFromPomXml })),
  ]

  for (const manifest of manifests) {
    try {
      const parsed = manifest.parse(await fetchFile(manifest.path))
      all.push(...parsed.map((dep) => ({ ...dep, manifestPath: manifest.path })))
    } catch (err) {
      warnings.push(
        `${manifest.path} was skipped: ${err instanceof Error ? err.message : String(err)}`,
      )
    }
  }

  // Deduplicate across manifests; a release used outside development ships in the product.
  const byId = new Map<string, Dependency>()
  for (const dep of all) {
    const id = `${dep.ecosystem}:${dep.name}@${dep.version}`
    const existing = byId.get(id)
    if (!existing) {
      byId.set(id, { ...dep })
      continue
    }
    if (existing.dev && !dep.dev) delete existing.dev
    if (dep.direct) existing.direct = true
  }
  return [...byId.values()]
}
