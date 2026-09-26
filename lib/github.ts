const GITHUB_API = 'https://api.github.com'

// ─── Error type ──────────────────────────────────────────────────────────────

export class GithubError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message)
    this.name = 'GithubError'
  }
}

// ─── URL parser ──────────────────────────────────────────────────────────────

/**
 * Parses a GitHub repository URL into owner and repo components.
 *
 * Accepted formats:
 *   - https://github.com/owner/repo
 *   - https://github.com/owner/repo.git
 *   - https://github.com/owner/repo/tree/<ref>
 *   - github.com/owner/repo
 *   - owner/repo  (bare shorthand)
 *
 * Only github.com is accepted to prevent SSRF attacks.
 *
 * @throws {GithubError} with status 400 if the URL is invalid or not from github.com.
 */
export function parseRepoUrl(url: string): { owner: string; repo: string } {
  const trimmed = url.trim()

  let pathname: string

  // Bare shorthand: owner/repo (no protocol, no host)
  if (/^[^/\s]+\/[^/\s]+$/.test(trimmed)) {
    pathname = trimmed
  } else {
    // Normalise: add protocol if missing so URL can be parsed
    const withProto = /^https?:\/\//i.test(trimmed)
      ? trimmed
      : `https://${trimmed}`

    let parsed: URL
    try {
      parsed = new URL(withProto)
    } catch {
      throw new GithubError(`Invalid URL: "${url}"`, 400)
    }

    // SSRF guard — only github.com is allowed
    if (parsed.hostname.toLowerCase() !== 'github.com') {
      throw new GithubError(
        `Only github.com URLs are supported (got "${parsed.hostname}")`,
        400,
      )
    }

    pathname = parsed.pathname
  }

  // Strip leading slash, optional trailing .git, and optional /tree/<ref>
  const clean = pathname
    .replace(/^\//, '')
    .replace(/\.git$/, '')
    .replace(/\/tree\/.*$/, '')

  const parts = clean.split('/')
  if (parts.length < 2 || !parts[0] || !parts[1]) {
    throw new GithubError(
      `Could not extract owner/repo from URL: "${url}"`,
      400,
    )
  }

  return { owner: parts[0], repo: parts[1] }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function authHeaders(): HeadersInit {
  const token = process.env.GITHUB_TOKEN
  return {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }
}

async function githubFetch(url: string): Promise<unknown> {
  const res = await fetch(url, { headers: authHeaders() })

  if (res.status === 404) {
    throw new GithubError(
      'Repository not found or is private (404). Make sure the repo is public.',
      404,
    )
  }

  if (res.status === 403) {
    throw new GithubError(
      'GitHub API rate limit exceeded (403). Set the GITHUB_TOKEN environment variable to raise the limit to 5000 req/h.',
      403,
    )
  }

  if (!res.ok) {
    throw new GithubError(
      `GitHub API error: ${res.status} ${res.statusText}`,
      res.status,
    )
  }

  return res.json()
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface TreeEntry {
  path: string
  type: 'blob' | 'tree'
  sha: string
  size?: number
}

/**
 * Returns the flat file tree of a public GitHub repository.
 * Uses the Git Trees API with recursive=1 to get all files in one call.
 *
 * @throws {GithubError} on 404 (not found / private) or 403 (rate limit).
 */
export async function fetchRepoTree(
  owner: string,
  repo: string,
): Promise<TreeEntry[]> {
  const url = `${GITHUB_API}/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`
  const data = (await githubFetch(url)) as {
    tree: TreeEntry[]
    truncated: boolean
  }

  if (data.truncated) {
    console.warn(
      `[triage24] Warning: the file tree for ${owner}/${repo} was truncated by GitHub (repo > 100 000 files). Analysis may be incomplete.`,
    )
  }

  return data.tree.filter((e) => e.type === 'blob')
}

/**
 * Fetches the UTF-8 decoded content of a single file in a public GitHub repository.
 * Uses the Contents API, which returns the file content base64-encoded.
 *
 * @throws {GithubError} on 404 (file not found / repo private) or 403 (rate limit).
 */
export async function fetchFileContent(
  owner: string,
  repo: string,
  path: string,
): Promise<string> {
  const url = `${GITHUB_API}/repos/${owner}/${repo}/contents/${path}`
  const data = (await githubFetch(url)) as {
    content: string
    encoding: string
  }

  if (data.encoding !== 'base64') {
    throw new GithubError(
      `Unexpected encoding from GitHub Contents API: "${data.encoding}"`,
      500,
    )
  }

  // Node / browser compatible base64 decode
  return Buffer.from(data.content.replace(/\n/g, ''), 'base64').toString(
    'utf-8',
  )
}
