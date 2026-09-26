import type { SastFinding } from '@/types'

// ─── Rule interface ───────────────────────────────────────────────────────────

export interface SastRule {
  id: string
  name: string
  severity: SastFinding['severity']
  description: string
  recommendation: string
  /** Returns true when the line matches the rule */
  test: (line: string) => boolean
}

// ─── Built-in rules ───────────────────────────────────────────────────────────

export const RULES: SastRule[] = [
  {
    id: 'SAST-001',
    name: 'Hardcoded Secret or Token',
    severity: 'CRITICAL',
    description:
      'A hardcoded secret, API key or bearer token was found. Storing credentials in source code exposes them to anyone with repository access.',
    recommendation:
      'Remove the credential from the code. Use environment variables or a secrets manager (e.g. Vault, AWS Secrets Manager) instead.',
    test: (line) =>
      /(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|bearer)\s*[:=]\s*['"`][\w\-./+]{8,}/i.test(
        line
      ),
  },
  {
    id: 'SAST-002',
    name: 'Use of eval() or new Function()',
    severity: 'HIGH',
    description:
      'eval() or new Function() executes arbitrary code from a string, enabling code-injection and XSS attacks.',
    recommendation:
      'Avoid eval() and new Function(). Use safer alternatives such as JSON.parse() for data or static function references for callbacks.',
    test: (line) => /\beval\s*\(|new\s+Function\s*\(/.test(line),
  },
  {
    id: 'SAST-003',
    name: 'SQL Query Concatenation',
    severity: 'HIGH',
    description:
      'A SQL query is being built by concatenating user-supplied input, which can lead to SQL injection.',
    recommendation:
      'Use parameterised queries or a prepared-statement API (e.g. db.query("SELECT * FROM users WHERE id = ?", [id])) instead of string concatenation.',
    test: (line) =>
      // Concatenation with +: "SELECT ... " + var
      /(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b.+\+/.test(line) ||
      // Template literal with interpolation: `SELECT ... ${var}`
      /`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^`]*\$\{/i.test(line),
  },
  {
    id: 'SAST-004',
    name: 'Insecure HTTP URL in fetch/axios',
    severity: 'MEDIUM',
    description:
      'An HTTP (non-TLS) URL is passed to fetch or axios, transmitting data in cleartext.',
    recommendation:
      "Replace http:// with https:// to encrypt data in transit.",
    test: (line) =>
      /(?:fetch|axios\.(?:get|post|put|patch|delete|request))\s*\(\s*['"`]http:\/\//i.test(
        line
      ),
  },
  {
    id: 'SAST-005',
    name: 'TLS Verification Disabled (rejectUnauthorized: false)',
    severity: 'HIGH',
    description:
      'Setting rejectUnauthorized to false disables TLS certificate verification, making the connection vulnerable to man-in-the-middle attacks.',
    recommendation:
      'Remove rejectUnauthorized: false. If a self-signed certificate is required, add the CA certificate to the trust store instead.',
    test: (line) => /rejectUnauthorized\s*:\s*false/.test(line),
  },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

const MAX_SNIPPET_LENGTH = 200

function trimSnippet(line: string): string {
  const trimmed = line.trimEnd()
  return trimmed.length > MAX_SNIPPET_LENGTH
    ? trimmed.slice(0, MAX_SNIPPET_LENGTH) + '…'
    : trimmed
}

// ─── scanFile ─────────────────────────────────────────────────────────────────

export function scanFile(filePath: string, content: string): SastFinding[] {
  const findings: SastFinding[] = []
  const lines = content.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    for (const rule of RULES) {
      if (rule.test(line)) {
        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          filePath,
          line: i + 1,
          snippet: trimSnippet(line),
          description: rule.description,
          recommendation: rule.recommendation,
        })
      }
    }
  }

  return findings
}

// ─── scanRepo ────────────────────────────────────────────────────────────────

const IGNORED_PATH_PATTERNS = [/node_modules/, /\bdist\b/, /\.git\b/]
const MAX_CONTENT_BYTES = 500 * 1024 // 500 KB

export function scanRepo(
  files: { path: string; content: string }[]
): SastFinding[] {
  const findings: SastFinding[] = []

  for (const file of files) {
    // Skip ignored directories
    if (IGNORED_PATH_PATTERNS.some((re) => re.test(file.path))) continue

    // Skip files larger than 500 KB
    if (Buffer.byteLength(file.content, 'utf8') > MAX_CONTENT_BYTES) continue

    findings.push(...scanFile(file.path, file.content))
  }

  return findings
}
