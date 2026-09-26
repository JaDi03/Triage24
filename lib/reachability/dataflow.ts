/**
 * Lightweight, intra-file data-flow check for the arguments of a vulnerable call.
 * It answers "can attacker-controlled data reach this call?" well enough to separate
 * `logger.info("user: " + request.getParameter("u"))` from
 * `logger.info("version: {}", LoggerContext.class.getPackage().getImplementationVersion())`.
 *
 * Each argument is traced back through assignments and parameters in the same file:
 *   - "untrusted": it comes from an external input source (HTTP request, headers...)
 *   - "internal":  only literals, constants or values computed inside the application
 *   - "unknown":   the origin could not be established (for example a parameter whose
 *                  callers are in another file); never treated as safe
 */

export type FlowLabel = 'untrusted' | 'internal' | 'unknown'

export interface DataFlow {
  label: FlowLabel
  /** Human-readable trace, e.g. "user ← exchange.getRequestURI() (request URL)". */
  detail: string
}

interface Source {
  pattern: RegExp
  name: string
}

/** Expressions that read data from outside the application. */
const UNTRUSTED_SOURCES: Source[] = [
  { pattern: /\.getParameter(?:Values|Map|Names)?\s*\(/, name: 'HTTP request parameter' },
  { pattern: /\.getRequestHeaders\s*\(|\.getHeaders?\s*\(/, name: 'HTTP header' },
  { pattern: /\.getQueryString\s*\(|\.getRawQuery\s*\(|\.getQuery\s*\(/, name: 'URL query string' },
  { pattern: /\.getRequestURI\s*\(|\.getRequestURL\s*\(|\.getPathInfo\s*\(/, name: 'request URL' },
  { pattern: /\.getInputStream\s*\(|\.getReader\s*\(|\.getRequestBody\s*\(/, name: 'request body' },
  { pattern: /\.getCookies\s*\(/, name: 'cookies' },
  {
    pattern: /@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|QueryParam|PathParam|HeaderParam|FormParam)\b/,
    name: 'request parameter',
  },
  { pattern: /\bSystem\.in\b|\.readLine\s*\(/, name: 'console input' },
  {
    pattern: /\b(?:req|request)\s*\.\s*(?:query|body|params|param|headers|header|cookies|url|originalUrl|path|get|json|formData)\b/,
    name: 'HTTP request',
  },
  { pattern: /\b(?:ctx|context)\s*\.\s*(?:query|queryParam|pathParam|formParam|params|body|header|request)\b/, name: 'HTTP request' },
  { pattern: /\bevent\s*\.\s*(?:body|queryStringParameters|pathParameters|headers)\b/, name: 'serverless event' },
  { pattern: /\blocation\s*\.\s*(?:search|hash|href)\b|\bdocument\s*\.\s*(?:cookie|URL)\b|\bsearchParams\b/, name: 'browser URL' },
]

/** Parameter types and names that are themselves the incoming request. */
const REQUEST_PARAMETER =
  /\b(?:HttpServletRequest|ServletRequest|HttpExchange|ServerRequest|ServerHttpRequest|WebRequest|RoutingContext)\b/
const REQUEST_PARAMETER_NAMES = new Set(['req', 'request', 'event', 'ctx'])

const KEYWORDS = new Set([
  'new', 'this', 'super', 'null', 'true', 'false', 'class', 'return', 'instanceof', 'typeof', 'void',
  'undefined', 'await', 'async', 'function', 'var', 'let', 'const', 'final', 'static', 'in', 'of',
  'if', 'else', 'for', 'while', 'switch', 'case', 'catch', 'try', 'throw', 'yield', 'delete',
])
const CONTROL_FLOW = new Set(['if', 'for', 'while', 'switch', 'catch', 'synchronized', 'return', 'try'])
const MAX_DEPTH = 6
const MAX_ARGUMENT_LINES = 6

/**
 * Data-flow label for the arguments of a call on line `lineNumber` (1-based).
 * `callNames` are the names the call may use: the symbol itself and any local alias
 * (`import { template as render }`, `const tpl = require("lodash/template")`).
 */
export function analyzeCallArguments(content: string, lineNumber: number, callNames: string[]): DataFlow {
  const lines = content.split(/\r?\n/)
  // Assignments and parameters are searched in code only, so "tick={}" inside a log
  // message or "x = 1" inside a comment is never mistaken for an assignment.
  const context = { content: blankStringsAndComments(content) }
  for (const name of callNames) {
    const args = extractArguments(lines, lineNumber - 1, name)
    if (args !== null) return evaluate(args, context, 0, new Set())
  }
  return { label: 'unknown', detail: `${callNames[0]} is referenced but not called with arguments on this line` }
}

interface Context {
  content: string
}

function evaluate(expression: string, context: Context, depth: number, visited: Set<string>): DataFlow {
  const code = stripStrings(expression)

  const source = UNTRUSTED_SOURCES.find(({ pattern }) => pattern.test(code))
  if (source) return { label: 'untrusted', detail: `${summarize(code)} (${source.name})` }

  const refs = variableReferences(code)
  if (refs.length === 0) return { label: 'internal', detail: 'only literals, constants or library values' }

  const traced = refs.map((ref) => ({ ref, flow: trace(ref, context, depth + 1, visited) }))
  const untrusted = traced.find((t) => t.flow.label === 'untrusted')
  if (untrusted) return { label: 'untrusted', detail: `${untrusted.ref} ← ${untrusted.flow.detail}` }
  const unknown = traced.find((t) => t.flow.label === 'unknown')
  if (unknown) return { label: 'unknown', detail: `${unknown.ref}: ${unknown.flow.detail}` }
  return {
    label: 'internal',
    detail: `${traced.map((t) => t.ref).join(', ')} ${traced.length === 1 ? 'is' : 'are'} computed inside the application`,
  }
}

function trace(identifier: string, context: Context, depth: number, visited: Set<string>): DataFlow {
  // UPPER_CASE names are constants by convention.
  if (/^[A-Z][A-Z0-9_]*$/.test(identifier)) return { label: 'internal', detail: 'constant' }
  // Self-references (x = x + 1) add nothing; the other assignments decide.
  if (visited.has(identifier)) return { label: 'internal', detail: 'already traced' }
  if (depth > MAX_DEPTH) return { label: 'unknown', detail: 'data flow too deep to follow' }
  const nextVisited = new Set(visited).add(identifier)

  const assignments = findAssignments(identifier, context.content)
  if (assignments.length > 0) {
    const flows = assignments.map((rhs) => evaluate(rhs, context, depth, nextVisited))
    return (
      flows.find((f) => f.label === 'untrusted') ??
      flows.find((f) => f.label === 'unknown') ?? { label: 'internal', detail: flows[0].detail }
    )
  }

  const parameter = findParameter(identifier, context.content)
  if (parameter) {
    const annotated = UNTRUSTED_SOURCES.find(({ pattern }) => pattern.test(parameter.declaration))
    if (annotated) return { label: 'untrusted', detail: `parameter of ${parameter.method}() (${annotated.name})` }
    if (REQUEST_PARAMETER.test(parameter.declaration) || REQUEST_PARAMETER_NAMES.has(identifier)) {
      return { label: 'untrusted', detail: `the incoming request object in ${parameter.method}()` }
    }
    if (parameter.method === 'main' && identifier === 'args') {
      return { label: 'unknown', detail: 'command-line arguments' }
    }
    return { label: 'unknown', detail: `parameter of ${parameter.method}(); its callers are not traced` }
  }

  return { label: 'unknown', detail: 'origin not found in this file' }
}

/** Right-hand sides of every assignment to `identifier` in the file. */
function findAssignments(identifier: string, content: string): string[] {
  const id = escapeRegExp(identifier)
  const patterns = [
    // x = ..., String x = ..., const x = ..., this.x = ..., x += ... (not ==, <=, >=, !=)
    new RegExp(`(?:^|[^\\w$.]|this\\.)${id}\\s*[+\\-*/]?=(?![=>])\\s*([^;\\n]+)`, 'gm'),
    // const { a, x } = ...
    new RegExp(`\\{[^{}\\n]*\\b${id}\\b[^{}\\n]*\\}\\s*=(?!=)\\s*([^;\\n]+)`, 'g'),
    // for (String x : items), for (const x of items)
    new RegExp(`for\\s*\\(\\s*(?:final\\s+|const\\s+|let\\s+|var\\s+)?(?:[\\w<>\\[\\],.?]+\\s+)?${id}\\s*(?::|\\bof\\b|\\bin\\b)\\s*([^)]+)\\)`, 'g'),
  ]
  return patterns.flatMap((pattern) => [...content.matchAll(pattern)].map((match) => match[1]))
}

/** Finds a function or method declaring `identifier` as a parameter. */
function findParameter(identifier: string, content: string): { method: string; declaration: string } | undefined {
  const signatures = [
    // name(params) {   and   name(params) throws X {
    /([\w$]+)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*(?:throws\s+[\w.,\s]+)?\{/g,
    // (params) =>
    /()\(([^()]*)\)\s*=>/g,
    // param =>
    /()\b([\w$]+)\s*=>/g,
  ]
  for (const pattern of signatures) {
    for (const match of content.matchAll(pattern)) {
      const method = match[1] || 'an anonymous function'
      if (CONTROL_FLOW.has(method)) continue
      const declaration = splitTopLevel(match[2]).find((param) => lastIdentifier(param) === identifier)
      if (declaration !== undefined) return { method, declaration }
    }
  }
  return undefined
}

/** Text inside the parentheses of the call to `symbol`, possibly spanning a few lines. */
function extractArguments(lines: string[], index: number, symbol: string): string | null {
  const text = lines.slice(index, index + MAX_ARGUMENT_LINES).join('\n')
  // Only a call that starts on the matched line counts.
  const call = new RegExp(`(?:^|[^\\w$])${escapeRegExp(symbol)}\\s*\\(`).exec(text)
  if (!call || call.index > lines[index].length) return null

  let depth = 1
  let quote: string | null = null
  const start = call.index + call[0].length
  for (let i = start; i < text.length; i++) {
    const char = text[i]
    if (quote) {
      if (char === '\\') i++
      else if (char === quote) quote = null
      continue
    }
    if (char === '"' || char === "'" || char === '`') quote = char
    else if (char === '(') depth++
    else if (char === ')' && --depth === 0) return text.slice(start, i)
  }
  return null
}

/**
 * Replaces the contents of "..." and '...' literals with spaces and removes comments,
 * keeping line breaks. Template literals are kept because their ${...} parts are code.
 */
function blankStringsAndComments(content: string): string {
  let result = ''
  let i = 0
  while (i < content.length) {
    const char = content[i]
    const next = content[i + 1]
    if (char === '/' && next === '/') {
      while (i < content.length && content[i] !== '\n') i++
    } else if (char === '/' && next === '*') {
      const end = content.indexOf('*/', i + 2)
      const stop = end === -1 ? content.length : end + 2
      result += content.slice(i, stop).replace(/[^\n]/g, ' ')
      i = stop
    } else if (char === '"' || char === "'") {
      result += char
      i++
      while (i < content.length && content[i] !== char && content[i] !== '\n') {
        if (content[i] === '\\') {
          result += ' '
          i++
        }
        result += ' '
        i++
      }
      if (i < content.length && content[i] === char) {
        result += char
        i++
      }
    } else {
      result += char
      i++
    }
  }
  return result
}

/** Removes string literals but keeps the expressions interpolated in template literals. */
function stripStrings(code: string): string {
  return code
    .replace(/`(?:\\.|[^`\\])*`/g, (literal) =>
      [...literal.matchAll(/\$\{([^}]*)\}/g)].map((m) => ` ${m[1]} `).join(' ') || '""',
    )
    .replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, '""')
}

/** Root variable names used in an expression (not method names, members, types or keywords). */
function variableReferences(code: string): string[] {
  const refs = new Set<string>()
  for (const match of code.matchAll(/[A-Za-z_$][\w$]*/g)) {
    const name = match[0]
    const before = code.slice(0, match.index)
    const after = code.slice(match.index! + name.length)
    const isMember = /\.\s*$/.test(before) && !/\bthis\s*\.\s*$/.test(before)
    const isCall = /^\s*\(/.test(after)
    const isObjectKey = /^\s*:(?!:)/.test(after) && /[{,]\s*$/.test(before)
    if (isMember || isCall || isObjectKey || KEYWORDS.has(name)) continue
    // Capitalized names are types or constants (LoggerContext.class, Integer.MAX_VALUE).
    if (/^[A-Z]/.test(name) && !/^[A-Z][A-Z0-9_]*$/.test(name)) continue
    refs.add(name)
  }
  return [...refs]
}

function splitTopLevel(params: string): string[] {
  const parts: string[] = []
  let depth = 0
  let current = ''
  for (const char of params) {
    if ('<([{'.includes(char)) depth++
    if ('>)]}'.includes(char)) depth--
    if (char === ',' && depth === 0) {
      parts.push(current)
      current = ''
    } else {
      current += char
    }
  }
  if (current.trim()) parts.push(current)
  return parts
}

/** '@RequestParam("q") final String name' -> "name"; "name = 'x'" -> "name". */
function lastIdentifier(param: string): string | undefined {
  const withoutDefault = param.split('=')[0]
  const words = withoutDefault.replace(/@\w+(?:\([^)]*\))?/g, ' ').match(/[A-Za-z_$][\w$]*/g)
  return words?.[words.length - 1]
}

function summarize(code: string): string {
  const compact = code.replace(/\s+/g, ' ').trim()
  return compact.length > 80 ? `${compact.slice(0, 80)}…` : compact
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
