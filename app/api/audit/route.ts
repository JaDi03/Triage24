import { NextRequest, NextResponse } from 'next/server'
import { parseRepoUrl, fetchRepoTree, fetchFileContent, GithubError } from '@/lib/github'
import { extractDependencies } from '@/lib/deps-extractor'
import { lookupCVEsBatch } from '@/lib/osv'
import { downloadKevCatalog, matchKev } from '@/lib/kev'
import { scanRepo } from '@/lib/sast'
import { scoreCRA } from '@/lib/cra-scorer'
import type { CRAReport } from '@/types'

// ─── In-memory report cache ───────────────────────────────────────────────────

export const reportCache = new Map<string, CRAReport>()

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
    return NextResponse.json(
      { error: 'Invalid JSON body.' },
      { status: 400 },
    )
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

  // 3. Fetch repo tree
  let tree: Awaited<ReturnType<typeof fetchRepoTree>>
  try {
    tree = await fetchRepoTree(owner, repo)
  } catch (err) {
    if (err instanceof GithubError) {
      // 403 from GitHub = rate limit → expose as 429
      const status = err.status === 403 ? 429 : err.status
      return NextResponse.json({ error: err.message }, { status })
    }
    return NextResponse.json({ error: 'Failed to fetch repository tree.' }, { status: 500 })
  }

  // 4. Extract dependencies
  const deps = await extractDependencies(tree, (path) =>
    fetchFileContent(owner, repo, path),
  )

  // 5. Lookup CVEs via OSV.dev
  const cveMap = await lookupCVEsBatch(deps)

  // 6. Cross-reference with CISA KEV
  const kevCatalog = await downloadKevCatalog()
  const allCveIds = [...cveMap.values()].flat().map((c) => c.cveId)
  const kevHits = matchKev(allCveIds, kevCatalog)

  // 7. SAST analysis — fetch code files < 500 KB
  const CODE_EXTENSIONS = /\.(js|jsx|ts|tsx|mjs|cjs|java|py|rb|go|php|cs|cpp|c|h)$/i
  const MAX_FILE_BYTES = 500 * 1024

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

  const sastFindings = scanRepo(
    fetchedFiles.filter((f): f is { path: string; content: string } => f !== null),
  )

  // 8. Score CRA
  const report = scoreCRA({ repoUrl: url, tree, deps, cveMap, kevHits, sastFindings })

  // 9. Cache and respond
  reportCache.set(report.reportId, report)

  return NextResponse.json({ reportId: report.reportId, report }, { status: 200 })
}
