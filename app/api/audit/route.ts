import { NextRequest, NextResponse } from 'next/server'
import { parseRepoUrl, fetchRepoTree, fetchFileContent, GithubError } from '@/lib/github'
import { extractDependencies } from '@/lib/deps-extractor'
import { lookupCVEsBatch } from '@/lib/osv'
import { hasResolvedVersion } from '@/lib/dep-key'
import { downloadKevCatalog, matchKev } from '@/lib/kev'
import { scanRepo } from '@/lib/sast'
import { scoreCRA } from '@/lib/cra-scorer'
import { cacheReport } from '@/lib/report-cache'

export const runtime = 'nodejs'
// Large repositories need more than the default function duration on Vercel.
export const maxDuration = 60

const CODE_EXTENSIONS = /\.(js|jsx|ts|tsx|mjs|cjs|java|py|rb|go|php|cs|cpp|c|h)$/i
const MAX_FILE_BYTES = 500 * 1024

/** A failure of one of the vulnerability databases (OSV.dev or CISA KEV). */
class UpstreamError extends Error {}

function errorResponse(err: unknown): NextResponse {
  if (err instanceof GithubError) {
    // 403 from GitHub = rate limit → expose as 429
    const status = err.status === 403 ? 429 : err.status
    return NextResponse.json({ error: err.message }, { status })
  }
  if (err instanceof UpstreamError) {
    return NextResponse.json({ error: err.message }, { status: 502 })
  }
  console.error('[triage24] Unexpected error during audit', err)
  return NextResponse.json(
    { error: 'The analysis failed unexpectedly. Please try again.' },
    { status: 500 },
  )
}

async function upstream<T>(source: string, task: () => Promise<T>): Promise<T> {
  try {
    return await task()
  } catch (err) {
    throw new UpstreamError(
      `${source} is unavailable right now (${err instanceof Error ? err.message : String(err)}). Please try again in a few minutes.`,
    )
  }
}

// ─── POST /api/audit ──────────────────────────────────────────────────────────

export async function POST(req: NextRequest): Promise<NextResponse> {
  // 1. Parse request body
  let url: string
  try {
    const body = await req.json()
    url = body?.url
    if (typeof url !== 'string' || !url.trim()) {
      return NextResponse.json(
        { error: 'Missing or invalid "url" field in request body.' },
        { status: 400 },
      )
    }
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body.' }, { status: 400 })
  }

  // 2. Validate URL
  let owner: string
  let repo: string
  try {
    ;({ owner, repo } = parseRepoUrl(url))
  } catch (err) {
    if (err instanceof GithubError) {
      return NextResponse.json({ error: err.message }, { status: 400 })
    }
    return NextResponse.json({ error: 'Invalid repository URL.' }, { status: 400 })
  }

  try {
    const warnings: string[] = []

    // 3. Fetch repo tree
    const tree = await fetchRepoTree(owner, repo)

    // 4. Extract dependencies (a manifest that cannot be parsed becomes a warning)
    const deps = await extractDependencies(
      tree,
      (path) => fetchFileContent(owner, repo, path),
      warnings,
    )
    if (!tree.some((e) => /(^|\/)(package-lock\.json|pom\.xml)$/.test(e.path))) {
      warnings.push(
        'No supported dependency manifest was found. Triage24 reads package-lock.json (v2/v3) and pom.xml.',
      )
    }

    // 5. Lookup CVEs via OSV.dev (dependencies with an unresolved version are not queried)
    const unresolvedDeps = deps.filter((d) => !hasResolvedVersion(d))
    const osv = await upstream('OSV.dev', () => lookupCVEsBatch(deps))
    warnings.push(...osv.warnings)

    // 6. Cross-reference with CISA KEV, using every CVE alias of each finding
    const kevCatalog = await upstream('The CISA KEV catalog', () => downloadKevCatalog())
    const allCveIds = [...osv.byDependency.values()]
      .flat()
      .flatMap((c) => c.aliases.filter((id) => id.startsWith('CVE-')))
    const kevHits = matchKev(allCveIds, kevCatalog)

    // 7. SAST analysis — fetch code files < 500 KB
    const codeFiles = tree.filter(
      (entry) =>
        CODE_EXTENSIONS.test(entry.path) &&
        (entry.size === undefined || entry.size < MAX_FILE_BYTES),
    )
    const fetchedFiles = await Promise.all(
      codeFiles.map(async (entry) => {
        try {
          const content = await fetchFileContent(owner, repo, entry.path)
          return { path: entry.path, content }
        } catch {
          return null
        }
      }),
    )
    const scannedFiles = fetchedFiles.filter((f): f is { path: string; content: string } => f !== null)
    if (scannedFiles.length < codeFiles.length) {
      warnings.push(
        `${codeFiles.length - scannedFiles.length} of ${codeFiles.length} source files could not be downloaded; the code findings are incomplete.`,
      )
    }
    const sastFindings = scanRepo(scannedFiles)

    // 8. Score CRA
    const report = scoreCRA({
      repoUrl: url,
      tree,
      deps,
      cveMap: osv.byDependency,
      kevHits,
      sastFindings,
      unresolvedDeps,
      warnings,
    })

    // 9. Cache and respond
    cacheReport(report)
    return NextResponse.json({ reportId: report.reportId, report }, { status: 200 })
  } catch (err) {
    return errorResponse(err)
  }
}
