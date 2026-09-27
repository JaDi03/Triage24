import type { CVERecord, Dependency } from '@/types'

export interface SymbolHints {
  /** Function, method or class names whose use makes the vulnerability reachable. */
  symbols: string[]
  source: 'advisory' | 'curated' | 'none'
  /** For JVM packages: Java package prefixes that identify imports of this dependency. */
  importPrefixes: string[]
}

interface CuratedHint {
  symbols: string[]
  importPrefixes?: string[]
}

/**
 * Hand-written hints for well-known CVEs whose advisories do not name the vulnerable API
 * precisely. They are heuristics maintained by Triage24, not advisory data, and the UI
 * labels them as such.
 */
const CURATED_HINTS: Record<string, CuratedHint> = {
  // Log4Shell: any Log4j 2 logging call that includes attacker-controlled data. Code imports
  // log4j-api (org.apache.logging.log4j) while log4j-core provides the vulnerable lookups.
  'CVE-2021-44228': {
    symbols: ['info', 'error', 'warn', 'debug', 'trace', 'fatal', 'log', 'printf'],
    importPrefixes: ['org.apache.logging.log4j'],
  },
  // Incomplete fix of CVE-2021-44228 (context lookups in non-default pattern layouts).
  'CVE-2021-45046': {
    symbols: ['info', 'error', 'warn', 'debug', 'trace', 'fatal', 'log', 'printf'],
    importPrefixes: ['org.apache.logging.log4j'],
  },
  // Spring4Shell: request data binding in Spring MVC/WebFlux handlers. Its advisory names
  // mitigation APIs (disallowedFields, WebDataBinder), not what makes it reachable.
  'CVE-2022-22965': {
    symbols: ['RequestMapping', 'GetMapping', 'PostMapping', 'PutMapping', 'PatchMapping', 'DeleteMapping', 'ModelAttribute'],
    importPrefixes: ['org.springframework'],
  },
  // lodash
  'CVE-2021-23337': { symbols: ['template'] },
  'CVE-2020-28500': { symbols: ['toNumber', 'trim', 'trimEnd'] },
  'CVE-2025-13465': { symbols: ['unset', 'omit'] },
  'CVE-2020-8203': { symbols: ['zipObjectDeep'] },
  'CVE-2019-10744': { symbols: ['defaultsDeep'] },
  'CVE-2018-16487': { symbols: ['merge', 'mergeWith', 'defaultsDeep'] },
}

/** Words that look like identifiers in advisory text but are never the vulnerable API. */
const STOPWORDS = new Set([
  'a', 'an', 'the', 'this', 'that', 'function', 'functions', 'method', 'methods', 'class',
  'object', 'prototype', '__proto__', 'constructor', 'string', 'value', 'values', 'input',
  'version', 'versions', 'package', 'library', 'module', 'true', 'false', 'null', 'undefined',
  'options', 'option', 'data', 'user', 'users', 'code', 'attacker', 'jndi', 'ldap', 'http',
  'https', 'json', 'xml', 'regex', 'cve', 'npm', 'maven', 'java', 'javascript', 'node',
  // Adjectives and nouns that often precede "function"/"method" in prose.
  'vulnerable', 'affected', 'internal', 'following', 'same', 'any', 'public', 'private',
  'static', 'helper', 'utility', 'callback', 'custom', 'default', 'certain', 'several',
  'multiple', 'various', 'specific', 'given', 'its', 'their', 'which', 'each',
  // Package path segments and everyday JDK/JavaScript types found in advisory examples.
  'org', 'com', 'net', 'io', 'javax', 'lang', 'util', 'arraylist', 'hashmap', 'list', 'map',
  'set', 'integer', 'long', 'boolean', 'thread', 'system', 'runtime', 'exception', 'tostring',
  'getclass', 'forname', 'array', 'promise',
])

/** Placeholder names that advisories use in proof-of-concept examples. */
const EXAMPLE_NAME = /^(?:evil|exploit|gadget|attacker|malicious|payload|victim|poc|foo|bar|baz)/i

const IDENTIFIER = /^[A-Za-z_$][\w$]*$/

/**
 * Works out which functions or classes of a dependency the vulnerability lives in.
 * Curated hints win; otherwise names are extracted from the advisory text:
 * `backticked` identifiers (`_.template`, `JndiLookup.lookup()`) and phrases such as
 * "the template function" or "method verifyHostName".
 */
export function extractSymbols(cve: CVERecord, dependency: Dependency): SymbolHints {
  const importPrefixes = defaultImportPrefixes(dependency)

  for (const id of cve.aliases) {
    const curated = CURATED_HINTS[id.toUpperCase()]
    if (curated) {
      return { symbols: curated.symbols, source: 'curated', importPrefixes: curated.importPrefixes ?? importPrefixes }
    }
  }

  const packageWords = new Set(dependency.name.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean))
  const text = `${cve.description}\n${cve.details ?? ''}`
  const found = new Set<string>()

  for (const match of text.matchAll(/`([^`\n]{1,80})`/g)) {
    for (const name of identifiersFromCode(match[1])) found.add(name)
  }
  // "function zipObjectDeep": the next word is often prose ("function allows"), so only
  // code-looking names are accepted here.
  for (const match of text.matchAll(/\b(?:function|method|class)\s+([A-Za-z_$][\w$.]*(?:\(\))?)/g)) {
    if (!looksLikeCode(match[1])) continue
    for (const name of identifiersFromCode(match[1])) found.add(name)
  }
  // "the template function", "the merge() method"
  for (const match of text.matchAll(/\b([A-Za-z_$][\w$.]*(?:\(\))?)\s+(?:function|method)s?\b/g)) {
    for (const name of identifiersFromCode(match[1])) found.add(name)
  }

  const isPackageName = (name: string) =>
    [...packageWords].some((word) => word.length >= 4 && name.toLowerCase().startsWith(word))
  const symbols = [...found].filter(
    (name) => !STOPWORDS.has(name.toLowerCase()) && !EXAMPLE_NAME.test(name) && !isPackageName(name) && name.length > 2,
  )
  return { symbols: symbols.slice(0, 12), source: symbols.length > 0 ? 'advisory' : 'none', importPrefixes }
}

/** camelCase, PascalCase, snake_case, $names, dotted paths or a trailing "()". */
function looksLikeCode(word: string): boolean {
  return /[a-z][A-Z]|^[A-Z][a-z]+[A-Z]|[_$.]|\(\)$/.test(word)
}

/**
 * "_.template(str)" -> ["template"]; "JndiLookup.lookup()" -> ["JndiLookup", "lookup"];
 * "org.apache.logging.log4j.core.lookup.JndiLookup" -> ["JndiLookup"] (a package path is not an API).
 */
function identifiersFromCode(code: string): string[] {
  const cleaned = code.replace(/\(.*$/, '').trim()
  const parts = cleaned
    .split(/[.#:]/)
    .map((part) => part.trim())
    .filter((part) => IDENTIFIER.test(part) && part !== '_')
  if (parts.length < 3) return parts

  // Fully qualified names: keep the class and what follows it.
  const firstClass = parts.findIndex((part) => /^[A-Z]/.test(part))
  return firstClass === -1 ? parts.slice(-1) : parts.slice(firstClass)
}

/** For Maven, the groupId is usually also the Java package prefix. */
function defaultImportPrefixes(dependency: Dependency): string[] {
  if (dependency.ecosystem !== 'maven') return []
  const [groupId] = dependency.name.split(':')
  return [groupId]
}
