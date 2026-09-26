import { describe, it, expect } from 'vitest'
import { analyzeCallArguments } from '@/lib/reachability/dataflow'
import { findImports, findUsages } from '@/lib/reachability/search'
import { extractSymbols } from '@/lib/reachability/symbols'
import { analyzeReachability } from '@/lib/reachability'
import { depKey } from '@/lib/dep-key'
import type { CVERecord, Dependency } from '@/types'

function cve(overrides: Partial<CVERecord> = {}): CVERecord {
  return {
    cveId: 'CVE-2099-0001',
    osvIds: ['GHSA-test'],
    aliases: ['CVE-2099-0001', 'GHSA-test'],
    description: '',
    cvssScore: 7.5,
    severity: 'HIGH',
    publishedDate: '',
    malicious: false,
    ...overrides,
  }
}

const log4j: Dependency = { name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1', ecosystem: 'maven', direct: true }
const lodash: Dependency = { name: 'lodash', version: '4.17.20', ecosystem: 'npm', direct: true }

// ─── Data flow ───────────────────────────────────────────────────────────────

describe('analyzeCallArguments', () => {
  it('flags a request parameter that reaches the call through a variable', () => {
    const code = [
      'void handle(HttpServletRequest request) {',
      '  String name = request.getParameter("name");',
      '  logger.info("Hello " + name);',
      '}',
    ].join('\n')
    const flow = analyzeCallArguments(code, 3, ['info'])
    expect(flow.label).toBe('untrusted')
    expect(flow.detail).toContain('name')
  })

  it('treats literals and library metadata as internal', () => {
    const code = 'logger.info("version: {}", LoggerContext.class.getPackage().getImplementationVersion());'
    expect(analyzeCallArguments(code, 1, ['info']).label).toBe('internal')
  })

  it('does not mistake text inside a log message for an assignment', () => {
    const code = ['int count = 0;', 'logger.info("[tick={}] running", count);'].join('\n')
    expect(analyzeCallArguments(code, 2, ['info']).label).toBe('internal')
  })

  it('keeps a parameter whose callers are in another file as unknown, never safe', () => {
    const code = ['void audit(String message) {', '  logger.info(message);', '}'].join('\n')
    const flow = analyzeCallArguments(code, 2, ['info'])
    expect(flow.label).toBe('unknown')
  })

  it('recognizes Spring request annotations on parameters', () => {
    const code = ['public String greet(@RequestParam("q") String q) {', '  log.warn(q);', '  return q;', '}'].join('\n')
    expect(analyzeCallArguments(code, 2, ['warn']).label).toBe('untrusted')
  })

  it('recognizes Express request objects', () => {
    const code = ['app.get("/", (req, res) => {', '  const t = _.template(req.query.tpl);', '});'].join('\n')
    expect(analyzeCallArguments(code, 2, ['template']).label).toBe('untrusted')
  })
})

// ─── Import and usage search ─────────────────────────────────────────────────

describe('findImports and findUsages', () => {
  it('follows lodash namespace imports to the vulnerable call', () => {
    const files = [{ path: 'src/a.js', content: 'const _ = require("lodash")\nconst out = _.template(tpl)\n' }]
    const imports = findImports(files, lodash, [])
    const usages = findUsages(imports, lodash, ['template'])
    expect(imports.imports.map((m) => m.line)).toEqual([1])
    expect(usages.map((m) => m.line)).toEqual([2])
  })

  it('follows named and subpath imports', () => {
    const files = [
      { path: 'a.ts', content: 'import { template as render } from "lodash"\nrender(x)\n' },
      { path: 'b.js', content: 'const tpl = require("lodash/template")\ntpl(y)\n' },
    ]
    const usages = findUsages(findImports(files, lodash, []), lodash, ['template'])
    expect(usages.map((m) => `${m.file}:${m.line}`)).toEqual(['a.ts:2', 'b.js:2'])
  })

  it('ignores imports inside comments', () => {
    const files = [{ path: 'a.js', content: '// const _ = require("lodash")\n' }]
    expect(findImports(files, lodash, []).imports).toEqual([])
  })

  it('finds Java imports by package prefix', () => {
    const files = [{ path: 'App.java', content: 'import org.apache.logging.log4j.Logger;\nclass App {}\n' }]
    expect(findImports(files, log4j, ['org.apache.logging.log4j']).imports).toHaveLength(1)
  })
})

// ─── Vulnerable symbols ──────────────────────────────────────────────────────

describe('extractSymbols', () => {
  it('uses curated hints for Log4Shell', () => {
    const hints = extractSymbols(cve({ aliases: ['CVE-2021-44228'] }), log4j)
    expect(hints.source).toBe('curated')
    expect(hints.symbols).toContain('info')
    expect(hints.importPrefixes).toEqual(['org.apache.logging.log4j'])
  })

  it('extracts backticked names and "the X function" from advisory text', () => {
    const hints = extractSymbols(
      cve({ description: 'Prototype pollution in `_.zipObjectDeep`', details: 'The merge function allows overwriting.' }),
      lodash,
    )
    expect(hints.symbols).toEqual(expect.arrayContaining(['zipObjectDeep', 'merge']))
    expect(hints.symbols).not.toContain('allows')
  })

  it('does not take Java package segments or example names for the vulnerable API', () => {
    const hints = extractSymbols(
      cve({ details: 'Use `org.apache.commons.EvilGadget` with the class `org.example.Foo`.' }),
      { name: 'commons-foo:commons-foo', version: '1.0', ecosystem: 'maven' },
    )
    expect(hints.symbols).not.toContain('org')
    expect(hints.symbols).not.toContain('EvilGadget')
  })
})

// ─── Verdicts ────────────────────────────────────────────────────────────────

describe('analyzeReachability', () => {
  function verdictFor(files: { path: string; content: string }[], dep: Dependency, finding: CVERecord, kev = false) {
    const result = analyzeReachability(files, [dep], new Map([[depKey(dep), [finding]]]), new Set(kev ? finding.aliases : []))
    return result.get(depKey(dep))![0].reachability!
  }

  it('is uncertain when no source file imports the package', () => {
    expect(verdictFor([], lodash, cve({ aliases: ['CVE-2021-23337'] })).verdict).toBe('uncertain')
  })

  it('is not affected when the vulnerable functions are never used', () => {
    const files = [{ path: 'a.js', content: 'const _ = require("lodash")\n_.get(o, "a")\n' }]
    expect(verdictFor(files, lodash, cve({ aliases: ['CVE-2021-23337'] })).verdict).toBe('not_affected')
  })

  it('stays uncertain for an actively exploited issue whose names come from advisory prose', () => {
    const files = [{ path: 'a.js', content: 'const _ = require("lodash")\n_.get(o, "a")\n' }]
    const finding = cve({ details: 'Avoid the `sortedUniqBy` function.' })
    expect(verdictFor(files, lodash, finding, true).verdict).toBe('uncertain')
  })

  it('treats a malicious release as affected, with the manifest entry as evidence', () => {
    const debug: Dependency = { name: 'debug', version: '4.4.2', ecosystem: 'npm', manifestPath: 'package-lock.json' }
    const manifest = { path: 'package-lock.json', content: '{\n  "node_modules/debug": {\n    "version": "4.4.2"\n  }\n}' }
    const reachability = verdictFor([manifest], debug, cve({ malicious: true }))
    expect(reachability.verdict).toBe('affected')
    expect(reachability.evidence).toEqual([{ file: 'package-lock.json', line: 2, snippet: '"node_modules/debug": {' }])
  })
})
