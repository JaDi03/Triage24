import type { Dependency } from '@/types'
import { analyzeCallArguments, type DataFlow } from './dataflow'

export interface SourceFile {
  path: string
  content: string
}

export type MatchKind = 'import' | 'usage'

export interface CodeMatch {
  file: string
  line: number
  kind: MatchKind
  /** The matched symbol, for usages. */
  symbol?: string
  /** The matched source line, trimmed. */
  code: string
  /** For usages: whether external input can reach the call's arguments. */
  dataFlow?: DataFlow
}

/** How a file refers to the dependency after importing it. */
interface FileImports {
  file: SourceFile
  lines: string[]
  importLines: Set<number>
  /** Local names bound to the whole module: `const _ = require("lodash")`, `import * as L`. */
  namespaces: Set<string>
  /** Local name -> imported name: `import { template as t }`, `require("lodash/template")`. */
  named: Map<string, string>
}

export interface ImportSearchResult {
  imports: CodeMatch[]
  files: FileImports[]
}

const JS_EXTENSIONS = /\.(?:[cm]?js|jsx|[cm]?ts|tsx)$/i
const JVM_EXTENSIONS = /\.(?:java|kt|kts|groovy|scala)$/i
const MAX_LINE_LENGTH = 240

/** Finds the files that import the dependency and the names they bind it to. */
export function findImports(files: SourceFile[], dependency: Dependency, importPrefixes: string[]): ImportSearchResult {
  return dependency.ecosystem === 'npm' ? findJsImports(files, dependency.name) : findJvmImports(files, importPrefixes)
}

/** Finds calls or references to the vulnerable symbols in files that import the dependency. */
export function findUsages(importResult: ImportSearchResult, dependency: Dependency, symbols: string[]): CodeMatch[] {
  if (symbols.length === 0) return []
  const matches: CodeMatch[] = []

  for (const info of importResult.files) {
    const patterns = symbols.flatMap((symbol) =>
      (dependency.ecosystem === 'npm' ? jsUsagePatterns(info, symbol) : jvmUsagePatterns(symbol)).map((pattern) => ({
        symbol,
        pattern,
      })),
    )

    info.lines.forEach((text, index) => {
      if (info.importLines.has(index + 1) || isComment(text)) return
      const hit = patterns.find(({ pattern }) => pattern.test(text))
      if (!hit) return
      const match = toMatch(info.file.path, info.lines, index + 1, 'usage', hit.symbol)
      const aliases = [...info.named].filter(([, imported]) => imported === hit.symbol).map(([local]) => local)
      // For a vulnerable class, using it at all is the risk; its arguments say nothing.
      match.dataFlow = /^[A-Z]/.test(hit.symbol)
        ? { label: 'unknown', detail: `the vulnerable class ${hit.symbol} is used` }
        : analyzeCallArguments(info.file.content, index + 1, [hit.symbol, ...aliases])
      matches.push(match)
    })
  }
  return matches
}

// ─── JavaScript / TypeScript ─────────────────────────────────────────────────

function findJsImports(files: SourceFile[], packageName: string): ImportSearchResult {
  const pkg = escapeRegExp(packageName)
  // Module specifier: the package itself or one of its subpaths ("lodash/template").
  const spec = `['"](${pkg}(?:/[^'"]*)?)['"]`
  const importPatterns = [
    // const x = require("pkg") | const { a, b: c } = require("pkg") | require("pkg")
    // The binding may not contain ";", "=" or quotes, so a match never spans earlier statements.
    new RegExp(`(?:(?:const|let|var)\\s+([^;=]{1,300}?)\\s*=\\s*)?require\\(\\s*${spec}\\s*\\)`, 'g'),
    // import x from "pkg" | import * as x from "pkg" | import { a as b } from "pkg" | import "pkg"
    new RegExp(`import\\s+(?:([^;'"]{1,500}?)\\s+from\\s+)?${spec}`, 'g'),
    // dynamic import("pkg")
    new RegExp(`import\\(\\s*${spec}\\s*\\)`, 'g'),
  ]

  const imports: CodeMatch[] = []
  const infos: FileImports[] = []

  for (const file of files) {
    if (!JS_EXTENSIONS.test(file.path)) continue
    const info = scanFile(file, (content, add) => {
      for (const pattern of importPatterns) {
        for (const match of content.matchAll(pattern)) {
          // Dynamic imports have no binding group; the specifier is the last group.
          const binding = match.length > 2 ? match[1] : undefined
          const specifier = match[match.length - 1]
          add(match.index!, match[0].length, binding, specifier.slice(packageName.length + 1))
        }
      }
    })
    if (info) {
      infos.push(info)
      for (const line of [...info.importLines].sort((a, b) => a - b)) {
        imports.push(toMatch(file.path, info.lines, line, 'import'))
      }
    }
  }
  return { imports, files: infos }
}

/** Records import lines and bindings; null when the file does not import the dependency. */
function scanFile(
  file: SourceFile,
  collect: (content: string, add: (index: number, length: number, binding: string | undefined, subpath: string) => void) => void,
): FileImports | null {
  const lines = file.content.split(/\r?\n/)
  const info: FileImports = { file, lines, importLines: new Set(), namespaces: new Set(), named: new Map() }

  collect(file.content, (index, length, binding, subpath) => {
    const start = lineNumberAt(file.content, index)
    const end = lineNumberAt(file.content, index + length)
    if (isComment(lines[start - 1] ?? '')) return
    for (let line = start; line <= end; line++) info.importLines.add(line)
    recordJsBinding(info, binding, subpath)
  })

  return info.importLines.size > 0 ? info : null
}

/** Interprets the text between the keyword and the specifier of an import or require. */
function recordJsBinding(info: FileImports, binding: string | undefined, subpath: string) {
  if (!binding) return
  const text = binding.replace(/\btype\s+/g, '').trim()

  // A subpath import binds its default export: require("lodash/template") -> template.
  const subpathSymbol = subpath.split('/').pop()

  const namedBlock = text.match(/\{([\s\S]*)\}/)
  if (namedBlock) {
    for (const part of namedBlock[1].split(',')) {
      const [imported, local] = part.split(/\s+as\s+|\s*:\s*/).map((s) => s.trim())
      if (imported && isIdentifier(imported)) info.named.set(local && isIdentifier(local) ? local : imported, imported)
    }
  }

  const namespace = text.match(/\*\s*as\s+([A-Za-z_$][\w$]*)/)?.[1]
  const defaultName = text.replace(/\{[\s\S]*\}/, '').replace(/\*\s*as\s+[\w$]+/, '').split(',')[0].trim()

  for (const local of [namespace, isIdentifier(defaultName) ? defaultName : undefined]) {
    if (!local) continue
    if (subpathSymbol) info.named.set(local, subpathSymbol)
    else info.namespaces.add(local)
  }
}

function jsUsagePatterns(info: FileImports, symbol: string): RegExp[] {
  const sym = escapeRegExp(symbol)
  const patterns: RegExp[] = []
  for (const ns of info.namespaces) {
    const n = escapeRegExp(ns)
    patterns.push(new RegExp(`(?:^|[^\\w$.])${n}\\s*(?:\\.\\s*${sym}\\b|\\[\\s*['"]${sym}['"]\\s*\\])`))
    // Chained lodash wrappers: _(value).template(...) or _.chain(value).template(...)
    patterns.push(new RegExp(`(?:^|[^\\w$.])${n}(?:\\.chain)?\\([^)]*\\)[\\s\\S]*\\.\\s*${sym}\\s*\\(`))
  }
  for (const [local, imported] of info.named) {
    if (imported === symbol) patterns.push(new RegExp(`(?:^|[^\\w$.])${escapeRegExp(local)}\\b`))
  }
  return patterns
}

// ─── Java / Kotlin / Groovy / Scala ──────────────────────────────────────────

function findJvmImports(files: SourceFile[], importPrefixes: string[]): ImportSearchResult {
  const imports: CodeMatch[] = []
  const infos: FileImports[] = []
  if (importPrefixes.length === 0) return { imports, files: infos }

  const prefixes = importPrefixes.map(escapeRegExp).join('|')
  const pattern = new RegExp(`^[ \\t]*import\\s+(?:static\\s+)?((?:${prefixes})(?:\\.[\\w*]+)*)\\s*;?`, 'gm')

  for (const file of files) {
    if (!JVM_EXTENSIONS.test(file.path)) continue
    const info = scanFile(file, (content, add) => {
      for (const match of content.matchAll(pattern)) add(match.index!, match[0].length, undefined, '')
    })
    if (info) {
      infos.push(info)
      for (const line of [...info.importLines].sort((a, b) => a - b)) {
        imports.push(toMatch(file.path, info.lines, line, 'import'))
      }
    }
  }
  return { imports, files: infos }
}

/** Class names match as words; method names match as calls (".info(" or "info("). */
function jvmUsagePatterns(symbol: string): RegExp[] {
  const sym = escapeRegExp(symbol)
  return /^[A-Z]/.test(symbol) ? [new RegExp(`\\b${sym}\\b`)] : [new RegExp(`(?:\\.|^|[^\\w$])${sym}\\s*\\(`)]
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function toMatch(file: string, lines: string[], line: number, kind: MatchKind, symbol?: string): CodeMatch {
  return { file, line, kind, ...(symbol ? { symbol } : {}), code: truncate(lines[line - 1].trim()) }
}

function lineNumberAt(content: string, index: number): number {
  let line = 1
  for (let i = 0; i < index && i < content.length; i++) if (content.charCodeAt(i) === 10) line++
  return line
}

function isComment(line: string): boolean {
  return /^\s*(?:\/\/|\/?\*)/.test(line)
}

function isIdentifier(value: string): boolean {
  return /^[A-Za-z_$][\w$]*$/.test(value)
}

function truncate(text: string): string {
  return text.length > MAX_LINE_LENGTH ? `${text.slice(0, MAX_LINE_LENGTH)}…` : text
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
