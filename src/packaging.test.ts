/**
 * Packaging invariants — the things that decide whether a CONSUMER can use this
 * package, which its own test suite otherwise never exercises.
 *
 * The consumers this exists for are Azure DevOps task builds: CommonJS, and on
 * TypeScript's classic `moduleResolution: "node"`, which predates and ignores
 * the `exports` map entirely. Node resolves a subpath like
 * `@4cloudguru/pipeline-task-core/gpg` at RUNTIME from `exports`, so the import
 * works — but `tsc` cannot find its types and the build fails with TS2307:
 *
 *   Cannot find module '@4cloudguru/pipeline-task-core/gpg' ... There are types
 *   at '.../dist/gpg/index.d.mts', but this result could not be resolved under
 *   your current 'moduleResolution' setting.
 *
 * `typesVersions` is the shim that makes those types resolvable anyway. It was
 * missing for `./gpg`, which blocked the azure-pipelines-packer migration that
 * the subpath was split out for in the first place. Adding a second subpath
 * later would reintroduce exactly that, silently, so this asserts the invariant
 * rather than the single fix.
 */
import { describe, expect, it } from 'vitest'

import pkg from '../package.json' with { type: 'json' }

type ExportEntry = { require?: { types?: string } } | string

const SUBPATHS = Object.entries(pkg.exports as Record<string, ExportEntry>)
  .filter(([key]) => key !== '.' && key !== './package.json')
  .map(([key, value]) => ({ key, bare: key.replace(/^\.\//, ''), value }))

const TYPES_VERSIONS = (
  pkg.typesVersions as Record<string, Record<string, string[]>> | undefined
)?.['*']

describe('packaging — subpath types resolve for classic moduleResolution', () => {
  it('declares at least one subpath, or this file is asserting nothing', () => {
    expect(SUBPATHS.length).toBeGreaterThan(0)
  })

  it.each(SUBPATHS)('$key has a typesVersions entry', ({ bare }) => {
    expect(TYPES_VERSIONS, 'typesVersions["*"] is missing entirely').toBeDefined()
    expect(TYPES_VERSIONS?.[bare], `no typesVersions entry for "${bare}"`).toBeDefined()
  })

  it.each(SUBPATHS)(
    '$key maps to the same declaration its require condition uses',
    ({ bare, value }) => {
      const declared = typeof value === 'string' ? undefined : value.require?.types
      // The CJS declaration, not the .d.mts — classic resolution has no notion of
      // conditions, so pointing it at the ESM types is the same failure again.
      expect(declared).toMatch(/\.d\.ts$/)
      expect(TYPES_VERSIONS?.[bare]).toEqual([declared])
    },
  )
})
