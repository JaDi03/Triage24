import type { CVERecord, Dependency, Evidence, Reachability } from '@/types'
import { depKey } from '@/lib/dep-key'
import { findImports, findUsages, type CodeMatch, type ImportSearchResult, type SourceFile } from './search'
import { extractSymbols, type SymbolHints } from './symbols'

export type { SourceFile } from './search'

const MAX_EVIDENCE = 10

/**
 * Static reachability analysis. For each vulnerability of each dependency it finds the
 * source files that import the package, the uses of the vulnerable functions or classes,
 * and where each call's arguments come from (see dataflow.ts). Clear cases get a final
 * verdict; the rest stay "uncertain", which is never treated as safe.
 *
 * Returns the findings with `reachability` set; the input is not modified.
 */
export function analyzeReachability(
  files: SourceFile[],
  deps: Dependency[],
  byDependency: Map<string, CVERecord[]>,
  kevIds: Set<string>,
): Map<string, CVERecord[]> {
  const importCache = new Map<string, ImportSearchResult>()
  const result = new Map<string, CVERecord[]>()

  for (const dep of deps) {
    const key = depKey(dep)
    const cves = byDependency.get(key)
    if (!cves) continue

    result.set(
      key,
      cves.map((cve) => {
        if (cve.malicious) return { ...cve, reachability: maliciousVerdict(files, dep) }

        const hints = extractSymbols(cve, dep)
        const cacheKey = `${key}|${hints.importPrefixes.join(',')}`
        let imports = importCache.get(cacheKey)
        if (!imports) {
          imports = findImports(files, dep, hints.importPrefixes)
          importCache.set(cacheKey, imports)
        }
        const usages = findUsages(imports, dep, hints.symbols)
        const activelyExploited = cve.aliases.some((id) => kevIds.has(id))
        return { ...cve, reachability: staticVerdict(dep, activelyExploited, hints, imports.imports, usages) }
      }),
    )
  }
  return result
}

/**
 * Malicious code runs when the package is installed or loaded, so which functions the
 * project calls is irrelevant: having the release is enough. The evidence is the
 * manifest entry that pins it.
 */
function maliciousVerdict(files: SourceFile[], dep: Dependency): Reachability {
  const platform = dep.os?.length
    ? ` It is only installed on ${dep.os.join(', ')}, so only machines running that operating system are exposed.`
    : ''
  return {
    verdict: 'affected',
    confidence: dep.os?.length ? 0.8 : 0.95,
    reasoning:
      `${dep.name} ${dep.version} is a compromised release that contains malicious code. The code runs when the ` +
      'package is installed or loaded, so any machine that installed it (developer laptops, CI runners, build ' +
      `servers) should be treated as compromised, whichever functions the project calls.${platform}`,
    evidence: manifestEntry(files, dep),
    method: 'static',
    symbols: [],
    symbolSource: 'none',
    importCount: 0,
    usageCount: 0,
  }
}

/** The manifest line that declares this exact dependency. */
function manifestEntry(files: SourceFile[], dep: Dependency): Evidence[] {
  const manifest = files.find((file) => file.path === dep.manifestPath)
  if (!manifest) return []

  const lines = manifest.content.split(/\r?\n/)
  const marker = dep.ecosystem === 'npm' ? `"node_modules/${dep.name}"` : `<artifactId>${dep.name.split(':')[1]}</artifactId>`
  const evidence: Evidence[] = []
  lines.forEach((text, index) => {
    if (!text.includes(marker)) return
    // For npm the version is on one of the following lines of the same entry.
    if (dep.ecosystem === 'npm' && !lines.slice(index, index + 4).join(' ').includes(`"${dep.version}"`)) return
    evidence.push({ file: manifest.path, line: index + 1, snippet: text.trim() })
  })
  return evidence.slice(0, MAX_EVIDENCE)
}

function staticVerdict(
  dep: Dependency,
  activelyExploited: boolean,
  hints: SymbolHints,
  imports: CodeMatch[],
  usages: CodeMatch[],
): Reachability {
  const base = {
    method: 'static' as const,
    symbols: hints.symbols,
    symbolSource: hints.source,
    importCount: imports.length,
    usageCount: usages.length,
    evidence: toEvidence([...usages, ...imports]),
  }
  const symbolList = hints.symbols.join(', ')

  // Not importing a package does not mean it is unused: frameworks call libraries on the
  // application's behalf (Spring deserializes request bodies with Jackson, for example).
  if (imports.length === 0) {
    return {
      ...base,
      verdict: 'uncertain',
      confidence: dep.direct ? 0.4 : 0.3,
      reasoning: dep.direct
        ? `${dep.name} is declared as a direct dependency, but no source file imports it. It may be unused, or used ` +
          'through a framework (for example request (de)serialization), which this code search does not see.'
        : `${dep.name} is a transitive dependency that the project's code does not import directly. It may still be ` +
          "called by another dependency; this analysis only inspects the repository's own code.",
    }
  }

  if (hints.symbols.length === 0) {
    return {
      ...base,
      verdict: 'uncertain',
      confidence: 0.3,
      reasoning:
        `The project imports ${dep.name} in ${imports.length} place(s), but the advisory does not name specific ` +
        'vulnerable functions, so a code search alone cannot decide.',
    }
  }

  if (usages.length === 0) {
    // Names taken from advisory prose can be mitigations or examples rather than the
    // vulnerable API, so for actively exploited issues their absence is not proof enough.
    if (activelyExploited && hints.source !== 'curated') {
      return {
        ...base,
        verdict: 'uncertain',
        confidence: 0.4,
        reasoning:
          `The project imports ${dep.name} and none of the names found in the advisory (${symbolList}) are used, but ` +
          'those names may describe mitigations rather than the vulnerable API. Because this issue is actively ' +
          'exploited, it needs a review before it can be ruled out.',
      }
    }
    return {
      ...base,
      verdict: 'not_affected',
      confidence: 0.7,
      reasoning:
        `The project imports ${dep.name}, but none of the vulnerable functions or classes (${symbolList}) are used in ` +
        'its source code.',
    }
  }

  // A trace from an external input source (HTTP request, headers...) to the call is
  // concrete evidence; "not a literal" alone never is.
  const untrusted = usages.filter((u) => u.dataFlow?.label === 'untrusted')
  if (untrusted.length > 0) {
    return {
      ...base,
      evidence: toEvidence(untrusted),
      verdict: 'affected',
      confidence: 0.85,
      reasoning:
        `The vulnerable functions (${symbolList}) receive external input in ${untrusted.length} place(s): ` +
        untrusted
          .slice(0, 3)
          .map((u) => `${u.file}:${u.line} (${u.dataFlow!.detail})`)
          .join('; ') +
        '. Attacker-controlled data reaches the vulnerable code.',
    }
  }
  if (usages.every((u) => u.dataFlow?.label === 'internal')) {
    return {
      ...base,
      verdict: 'not_affected',
      confidence: 0.75,
      reasoning:
        `The vulnerable functions (${symbolList}) are used in ${usages.length} place(s), but only with literals, ` +
        'constants or values computed inside the application, so no external input reaches them.',
    }
  }
  return {
    ...base,
    verdict: 'uncertain',
    confidence: 0.5,
    reasoning:
      `The vulnerable functions or classes (${symbolList}) are used in ${usages.length} place(s). Whether ` +
      'attacker-controlled data reaches them needs a review of the data flow.',
  }
}

function toEvidence(matches: CodeMatch[]): Evidence[] {
  return matches.slice(0, MAX_EVIDENCE).map(({ file, line, code }) => ({ file, line, snippet: code }))
}
