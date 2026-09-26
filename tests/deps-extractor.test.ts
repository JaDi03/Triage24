import { describe, it, expect, vi } from 'vitest'
import {
  extractFromPackageLock,
  extractFromPomXml,
  extractDependencies,
} from '../lib/deps-extractor'

// ─── extractFromPackageLock ───────────────────────────────────────────────────

describe('extractFromPackageLock', () => {
  it('extracts direct + transitive deps from a v2 lockfile', () => {
    const lock = JSON.stringify({
      lockfileVersion: 2,
      packages: {
        '': { name: 'my-app', version: '1.0.0' },
        'node_modules/lodash': { version: '4.17.21' },
        'node_modules/react': { version: '18.2.0' },
        'node_modules/react/node_modules/scheduler': { version: '0.23.0' },
      },
    })

    const deps = extractFromPackageLock(lock)

    expect(deps).toHaveLength(3)
    expect(deps).toContainEqual({ name: 'lodash', version: '4.17.21', ecosystem: 'npm' })
    expect(deps).toContainEqual({ name: 'react', version: '18.2.0', ecosystem: 'npm' })
    expect(deps).toContainEqual({ name: 'scheduler', version: '0.23.0', ecosystem: 'npm' })
  })

  it('extracts deps from a v3 lockfile', () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'my-app', version: '0.1.0' },
        'node_modules/axios': { version: '1.6.0' },
      },
    })

    const deps = extractFromPackageLock(lock)

    expect(deps).toHaveLength(1)
    expect(deps[0]).toEqual({ name: 'axios', version: '1.6.0', ecosystem: 'npm' })
  })

  it('skips entries without a version', () => {
    const lock = JSON.stringify({
      lockfileVersion: 2,
      packages: {
        '': {},
        'node_modules/no-version-pkg': {},
        'node_modules/has-version': { version: '1.0.0' },
      },
    })

    const deps = extractFromPackageLock(lock)

    expect(deps).toHaveLength(1)
    expect(deps[0].name).toBe('has-version')
  })

  it('deduplicates same name@version appearing in multiple paths', () => {
    const lock = JSON.stringify({
      lockfileVersion: 2,
      packages: {
        '': {},
        'node_modules/foo': { version: '1.0.0' },
        'node_modules/bar/node_modules/foo': { version: '1.0.0' },
      },
    })

    const deps = extractFromPackageLock(lock)

    const foos = deps.filter((d) => d.name === 'foo')
    expect(foos).toHaveLength(1)
  })

  it('throws a descriptive error for lockfileVersion 1', () => {
    const lock = JSON.stringify({
      lockfileVersion: 1,
      dependencies: { lodash: { version: '4.17.21' } },
    })

    expect(() => extractFromPackageLock(lock)).toThrowError(/v1.*not supported/i)
  })

  it('throws a descriptive error when packages key is missing', () => {
    const lock = JSON.stringify({ lockfileVersion: 2 })

    expect(() => extractFromPackageLock(lock)).toThrowError(/v1.*not supported|packages/i)
  })

  it('strips UTF-8 BOM (0xFEFF) before parsing', () => {
    const lock = JSON.stringify({
      lockfileVersion: 2,
      packages: {
        '': {},
        'node_modules/bom-dep': { version: '2.0.0' },
      },
    })
    const withBom = '\uFEFF' + lock

    const deps = extractFromPackageLock(withBom)

    expect(deps).toHaveLength(1)
    expect(deps[0].name).toBe('bom-dep')
  })

  it('sets ecosystem to "npm" for all entries', () => {
    const lock = JSON.stringify({
      lockfileVersion: 2,
      packages: {
        '': {},
        'node_modules/pkg-a': { version: '0.1.0' },
        'node_modules/pkg-b': { version: '0.2.0' },
      },
    })

    const deps = extractFromPackageLock(lock)

    expect(deps.every((d) => d.ecosystem === 'npm')).toBe(true)
  })

  it('handles deeply nested scoped packages (@scope/name)', () => {
    const lock = JSON.stringify({
      lockfileVersion: 2,
      packages: {
        '': {},
        'node_modules/@babel/core': { version: '7.24.0' },
      },
    })

    const deps = extractFromPackageLock(lock)

    expect(deps).toHaveLength(1)
    expect(deps[0].name).toBe('@babel/core')
  })
})

// ─── extractFromPomXml ────────────────────────────────────────────────────────

describe('extractFromPomXml', () => {
  it('extracts a single dependency from a minimal pom.xml', () => {
    const pom = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.15.2</version>
    </dependency>
  </dependencies>
</project>`

    const deps = extractFromPomXml(pom)

    expect(deps).toHaveLength(1)
    expect(deps[0]).toEqual({
      name: 'com.fasterxml.jackson.core:jackson-databind',
      version: '2.15.2',
      ecosystem: 'maven',
    })
  })

  it('extracts multiple dependencies', () => {
    const pom = `<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.1.0</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
    </dependency>
  </dependencies>
</project>`

    const deps = extractFromPomXml(pom)

    expect(deps).toHaveLength(2)
    expect(deps.map((d) => d.name)).toContain('org.springframework:spring-core')
    expect(deps.map((d) => d.name)).toContain('junit:junit')
  })

  it('resolves ${property} placeholders from <properties>', () => {
    const pom = `<?xml version="1.0"?>
<project>
  <properties>
    <spring.version>6.1.0</spring.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-web</artifactId>
      <version>${'${spring.version}'}</version>
    </dependency>
  </dependencies>
</project>`

    const deps = extractFromPomXml(pom)

    expect(deps).toHaveLength(1)
    expect(deps[0].version).toBe('6.1.0')
  })

  it('does NOT coerce version "2.10" to float 2.1 (parseTagValue: false)', () => {
    const pom = `<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>tricky-version</artifactId>
      <version>2.10</version>
    </dependency>
  </dependencies>
</project>`

    const deps = extractFromPomXml(pom)

    expect(deps[0].version).toBe('2.10')
    // Must be a string "2.10", not the number 2.1
    expect(deps[0].version).not.toBe('2.1')
  })

  it('uses "unknown" when version is missing', () => {
    const pom = `<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>no-version</artifactId>
    </dependency>
  </dependencies>
</project>`

    const deps = extractFromPomXml(pom)

    expect(deps).toHaveLength(1)
    expect(deps[0].version).toBe('unknown')
  })

  it('returns [] when there are no dependencies', () => {
    const pom = `<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>empty-project</artifactId>
  <version>1.0.0</version>
</project>`

    expect(extractFromPomXml(pom)).toEqual([])
  })

  it('returns [] for completely empty/invalid input', () => {
    expect(extractFromPomXml('')).toEqual([])
  })

  it('sets ecosystem to "maven" for all entries', () => {
    const pom = `<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>a</groupId>
      <artifactId>b</artifactId>
      <version>1.0</version>
    </dependency>
  </dependencies>
</project>`

    const deps = extractFromPomXml(pom)

    expect(deps.every((d) => d.ecosystem === 'maven')).toBe(true)
  })

  it('skips dependency entries without groupId or artifactId', () => {
    const pom = `<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <version>1.0</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>real-dep</artifactId>
      <version>1.0</version>
    </dependency>
  </dependencies>
</project>`

    const deps = extractFromPomXml(pom)

    expect(deps).toHaveLength(1)
    expect(deps[0].name).toBe('com.example:real-dep')
  })
})

// ─── extractDependencies ──────────────────────────────────────────────────────

describe('extractDependencies', () => {
  it('uses package-lock.json when present in the tree', async () => {
    const lockContent = JSON.stringify({
      lockfileVersion: 2,
      packages: {
        '': {},
        'node_modules/express': { version: '4.18.2' },
      },
    })
    const fetchFile = vi.fn().mockResolvedValue(lockContent)
    const tree = [
      { path: 'package-lock.json', type: 'blob' },
      { path: 'package.json', type: 'blob' },
    ]

    const deps = await extractDependencies(tree, fetchFile)

    expect(fetchFile).toHaveBeenCalledWith('package-lock.json')
    expect(deps).toHaveLength(1)
    expect(deps[0].name).toBe('express')
  })

  it('finds package-lock.json in a sub-directory', async () => {
    const lockContent = JSON.stringify({
      lockfileVersion: 2,
      packages: {
        '': {},
        'node_modules/chalk': { version: '5.0.0' },
      },
    })
    const fetchFile = vi.fn().mockResolvedValue(lockContent)
    const tree = [{ path: 'frontend/package-lock.json', type: 'blob' }]

    const deps = await extractDependencies(tree, fetchFile)

    expect(fetchFile).toHaveBeenCalledWith('frontend/package-lock.json')
    expect(deps[0].name).toBe('chalk')
  })

  it('parses pom.xml when no package-lock.json exists', async () => {
    const pomContent = `<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0-jre</version>
    </dependency>
  </dependencies>
</project>`
    const fetchFile = vi.fn().mockResolvedValue(pomContent)
    const tree = [{ path: 'pom.xml', type: 'blob' }]

    const deps = await extractDependencies(tree, fetchFile)

    expect(fetchFile).toHaveBeenCalledWith('pom.xml')
    expect(deps).toHaveLength(1)
    expect(deps[0].name).toBe('com.google.guava:guava')
    expect(deps[0].ecosystem).toBe('maven')
  })

  it('merges npm + maven deps from the same repo', async () => {
    const lockContent = JSON.stringify({
      lockfileVersion: 2,
      packages: { '': {}, 'node_modules/lodash': { version: '4.17.21' } },
    })
    const pomContent = `<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.junit</groupId>
      <artifactId>junit</artifactId>
      <version>5.0.0</version>
    </dependency>
  </dependencies>
</project>`

    const fetchFile = vi.fn().mockImplementation((path: string) => {
      if (path.endsWith('package-lock.json')) return Promise.resolve(lockContent)
      if (path.endsWith('pom.xml')) return Promise.resolve(pomContent)
      return Promise.resolve('')
    })
    const tree = [
      { path: 'package-lock.json', type: 'blob' },
      { path: 'pom.xml', type: 'blob' },
    ]

    const deps = await extractDependencies(tree, fetchFile)

    expect(deps).toHaveLength(2)
    expect(deps.map((d) => d.ecosystem)).toContain('npm')
    expect(deps.map((d) => d.ecosystem)).toContain('maven')
  })

  it('deduplicates identical deps across multiple pom.xml files', async () => {
    const pomContent = `<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>common</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>`

    const fetchFile = vi.fn().mockResolvedValue(pomContent)
    const tree = [
      { path: 'module-a/pom.xml', type: 'blob' },
      { path: 'module-b/pom.xml', type: 'blob' },
    ]

    const deps = await extractDependencies(tree, fetchFile)

    expect(deps.filter((d) => d.name === 'org.example:common')).toHaveLength(1)
  })

  it('returns [] when the tree has no supported manifest files', async () => {
    const fetchFile = vi.fn()
    const tree = [
      { path: 'src/index.ts', type: 'blob' },
      { path: 'README.md', type: 'blob' },
    ]

    const deps = await extractDependencies(tree, fetchFile)

    expect(deps).toEqual([])
    expect(fetchFile).not.toHaveBeenCalled()
  })

  it('ignores tree entries with type "tree" (directories)', async () => {
    const fetchFile = vi.fn()
    const tree = [
      { path: 'node_modules', type: 'tree' },
      { path: 'src', type: 'tree' },
    ]

    const deps = await extractDependencies(tree, fetchFile)

    expect(deps).toEqual([])
    expect(fetchFile).not.toHaveBeenCalled()
  })
})

describe('development dependencies', () => {
  it('marks npm packages flagged "dev" in the lockfile', () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'app' },
        'node_modules/express': { version: '4.18.2' },
        'node_modules/jest': { version: '29.0.0', dev: true },
      },
    })
    const deps = extractFromPackageLock(lock)
    expect(deps.find((d) => d.name === 'express')?.dev).toBeUndefined()
    expect(deps.find((d) => d.name === 'jest')?.dev).toBe(true)
  })

  it('treats a release installed for both production and development as shipped', () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        'node_modules/a/node_modules/ms': { version: '2.1.3', dev: true },
        'node_modules/ms': { version: '2.1.3' },
      },
    })
    expect(extractFromPackageLock(lock)).toEqual([{ name: 'ms', version: '2.1.3', ecosystem: 'npm' }])
  })

  it('marks Maven test-scoped dependencies', () => {
    const pom = `<project><dependencies>
      <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
      <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.9</version></dependency>
    </dependencies></project>`
    const deps = extractFromPomXml(pom)
    expect(deps.find((d) => d.name === 'junit:junit')?.dev).toBe(true)
    expect(deps.find((d) => d.name === 'org.slf4j:slf4j-api')?.dev).toBeUndefined()
  })
})
