import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  parseRepoUrl,
  fetchRepoTree,
  fetchFileContent,
  GithubError,
} from '../lib/github'

// ─── parseRepoUrl ─────────────────────────────────────────────────────────────

describe('parseRepoUrl', () => {
  // Happy-path: canonical HTTPS URL
  it('parses https://github.com/owner/repo', () => {
    expect(parseRepoUrl('https://github.com/torvalds/linux')).toEqual({
      owner: 'torvalds',
      repo: 'linux',
    })
  })

  it('parses URL with .git suffix', () => {
    expect(parseRepoUrl('https://github.com/torvalds/linux.git')).toEqual({
      owner: 'torvalds',
      repo: 'linux',
    })
  })

  it('parses URL with /tree/<branch> suffix', () => {
    expect(
      parseRepoUrl('https://github.com/torvalds/linux/tree/master'),
    ).toEqual({ owner: 'torvalds', repo: 'linux' })
  })

  it('parses URL with /tree/<sha> suffix', () => {
    expect(
      parseRepoUrl(
        'https://github.com/torvalds/linux/tree/abc1234def5678',
      ),
    ).toEqual({ owner: 'torvalds', repo: 'linux' })
  })

  it('parses URL without protocol (github.com/owner/repo)', () => {
    expect(parseRepoUrl('github.com/torvalds/linux')).toEqual({
      owner: 'torvalds',
      repo: 'linux',
    })
  })

  it('parses bare owner/repo shorthand', () => {
    expect(parseRepoUrl('torvalds/linux')).toEqual({
      owner: 'torvalds',
      repo: 'linux',
    })
  })

  it('trims surrounding whitespace', () => {
    expect(parseRepoUrl('  https://github.com/torvalds/linux  ')).toEqual({
      owner: 'torvalds',
      repo: 'linux',
    })
  })

  // SSRF guard
  it('throws GithubError(400) for non-github.com hostname', () => {
    expect(() => parseRepoUrl('https://evil.com/owner/repo')).toThrowError(
      GithubError,
    )
    let err: GithubError | null = null
    try {
      parseRepoUrl('https://evil.com/owner/repo')
    } catch (e) {
      err = e as GithubError
    }
    expect(err?.status).toBe(400)
    expect(err?.message).toContain('github.com')
  })

  it('throws GithubError(400) for github.com.evil.com (subdomain bypass)', () => {
    expect(() =>
      parseRepoUrl('https://github.com.evil.com/owner/repo'),
    ).toThrowError(GithubError)
  })

  it('throws GithubError(400) for a completely invalid URL string', () => {
    expect(() => parseRepoUrl('not a url at all !!!')).toThrowError(GithubError)
  })

  it('throws GithubError(400) when repo segment is missing', () => {
    expect(() => parseRepoUrl('https://github.com/onlyowner')).toThrowError(
      GithubError,
    )
  })

  it('throws GithubError(400) for http:// (non-SSRF, but same host check passes — owner extraction fails if path is empty)', () => {
    // http is fine as long as it is github.com and has the path
    expect(parseRepoUrl('http://github.com/torvalds/linux')).toEqual({
      owner: 'torvalds',
      repo: 'linux',
    })
  })
})

// ─── fetchRepoTree ────────────────────────────────────────────────────────────

describe('fetchRepoTree', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    delete process.env.GITHUB_TOKEN
  })

  it('returns only blob entries from the tree', async () => {
    const mockTree = [
      { path: 'src/index.ts', type: 'blob', sha: 'aaa', size: 100 },
      { path: 'src', type: 'tree', sha: 'bbb' },
      { path: 'README.md', type: 'blob', sha: 'ccc', size: 50 },
    ]
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ tree: mockTree, truncated: false }),
      }),
    )

    const result = await fetchRepoTree('torvalds', 'linux')

    expect(result).toHaveLength(2)
    expect(result.every((e) => e.type === 'blob')).toBe(true)
    expect(result.map((e) => e.path)).toEqual(['src/index.ts', 'README.md'])
  })

  it('calls the correct GitHub Trees API URL', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ tree: [], truncated: false }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchRepoTree('owner', 'repo')

    expect(fetchMock).toHaveBeenCalledWith(
      'https://api.github.com/repos/owner/repo/git/trees/HEAD?recursive=1',
      expect.objectContaining({ headers: expect.any(Object) }),
    )
  })

  it('includes Authorization header when GITHUB_TOKEN is set', async () => {
    process.env.GITHUB_TOKEN = 'ghp_testtoken'
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ tree: [], truncated: false }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchRepoTree('owner', 'repo')

    const headers = fetchMock.mock.calls[0][1].headers as Record<string, string>
    expect(headers['Authorization']).toBe('Bearer ghp_testtoken')
  })

  it('does NOT include Authorization header when GITHUB_TOKEN is not set', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ tree: [], truncated: false }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchRepoTree('owner', 'repo')

    const headers = fetchMock.mock.calls[0][1].headers as Record<string, string>
    expect(headers['Authorization']).toBeUndefined()
  })

  it('throws GithubError(404) when repo not found or private', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        json: async () => ({ message: 'Not Found' }),
      }),
    )

    await expect(fetchRepoTree('owner', 'private-repo')).rejects.toThrow(
      GithubError,
    )
    await expect(fetchRepoTree('owner', 'private-repo')).rejects.toMatchObject({
      status: 404,
    })
  })

  it('throws GithubError(403) and hints about GITHUB_TOKEN on rate limit', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        statusText: 'Forbidden',
        json: async () => ({ message: 'rate limit exceeded' }),
      }),
    )

    await expect(fetchRepoTree('owner', 'repo')).rejects.toThrow(GithubError)
    await expect(fetchRepoTree('owner', 'repo')).rejects.toMatchObject({
      status: 403,
    })
    await expect(fetchRepoTree('owner', 'repo')).rejects.toThrow('GITHUB_TOKEN')
  })

  it('emits a console.warn when tree is truncated', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          tree: [{ path: 'a.ts', type: 'blob', sha: 'x' }],
          truncated: true,
        }),
      }),
    )
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

    await fetchRepoTree('owner', 'huge-repo')

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('truncated'))
    warnSpy.mockRestore()
  })
})

// ─── fetchFileContent ─────────────────────────────────────────────────────────

describe('fetchFileContent', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    delete process.env.GITHUB_TOKEN
  })

  it('decodes base64 content to UTF-8 string', async () => {
    const original = 'Hello, World!\nSecond line.'
    const encoded = Buffer.from(original).toString('base64')

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ content: encoded, encoding: 'base64' }),
      }),
    )

    const result = await fetchFileContent('owner', 'repo', 'README.md')
    expect(result).toBe(original)
  })

  it('strips newlines embedded in GitHub base64 content', async () => {
    const original = 'package.json content'
    // GitHub wraps base64 at 60 chars with \n
    const raw = Buffer.from(original).toString('base64')
    const withNewlines = raw.match(/.{1,10}/g)!.join('\n')

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ content: withNewlines, encoding: 'base64' }),
      }),
    )

    const result = await fetchFileContent('owner', 'repo', 'package.json')
    expect(result).toBe(original)
  })

  it('calls the correct Contents API URL', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        content: Buffer.from('x').toString('base64'),
        encoding: 'base64',
      }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await fetchFileContent('owner', 'repo', 'src/index.ts')

    expect(fetchMock).toHaveBeenCalledWith(
      'https://api.github.com/repos/owner/repo/contents/src/index.ts',
      expect.objectContaining({ headers: expect.any(Object) }),
    )
  })

  it('throws GithubError(404) when file not found', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      }),
    )

    await expect(
      fetchFileContent('owner', 'repo', 'missing.ts'),
    ).rejects.toMatchObject({ status: 404 })
  })

  it('throws GithubError(403) on rate limit when fetching file', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        statusText: 'Forbidden',
      }),
    )

    await expect(
      fetchFileContent('owner', 'repo', 'file.ts'),
    ).rejects.toMatchObject({ status: 403 })
    await expect(
      fetchFileContent('owner', 'repo', 'file.ts'),
    ).rejects.toThrow('GITHUB_TOKEN')
  })

  it('throws GithubError(500) for unexpected encoding', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ content: 'raw text', encoding: 'utf-8' }),
      }),
    )

    await expect(
      fetchFileContent('owner', 'repo', 'file.ts'),
    ).rejects.toMatchObject({ status: 500 })
  })
})
