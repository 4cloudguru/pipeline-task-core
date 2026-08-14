#!/usr/bin/env node
/**
 * Consumer smoke test — build a throwaway project that consumes this package the
 * way the Azure DevOps task extensions actually do, and prove it compiles.
 *
 * WHY THIS EXISTS, and why the Build job's assertions were not enough. Those
 * check `./dist/index.cjs` and `./dist/gpg/index.cjs` by PATH. A consumer never
 * writes a path — it writes `@4cloudguru/pipeline-task-core/gpg` and lets the
 * `exports` map and `typesVersions` resolve it. Everything in that gap was
 * untested, and a real bug lived there: the `./gpg` subpath's types were
 * unresolvable under TypeScript's classic `moduleResolution: "node"`, which is
 * what every ADO task build uses. `tsc` failed with TS2307 while every check in
 * this repo stayed green, because nothing here compiles as a consumer.
 *
 * Fidelity is the whole point, so:
 *   - it installs the packed TARBALL, not a workspace link, so anything missing
 *     from `files` is missing here too;
 *   - the tsconfig mirrors azure-pipelines-packer's real one (commonjs, no
 *     explicit moduleResolution so classic `node` applies, skipLibCheck true) —
 *     making it stricter than the consumer would test something nobody runs.
 *
 * What it does NOT catch: semantic regressions. A parameter that quietly became
 * optional, or a result field that stopped being populated, compiles perfectly.
 * Those need the consumer's own tests; this only proves the package can be
 * imported and typed at all.
 */
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(fileURLToPath(new URL('.', import.meta.url)), '..')
const PKG = '@4cloudguru/pipeline-task-core'

const run = (cmd, args, opts = {}) =>
  execFileSync(cmd, args, { encoding: 'utf8', stdio: 'pipe', ...opts })

// npm is a .cmd on Windows, so it needs a shell; node does not, and running it
// through one re-splits an executable path containing spaces.
const npm = (args, opts = {}) => run('npm', args, { shell: process.platform === 'win32', ...opts })

const step = (message) => console.log(`  ${message}`)

// The consumer's tsconfig, copied from azure-pipelines-packer/tsconfig.json.
// `moduleResolution` is deliberately absent: `module: commonjs` makes TypeScript
// default to classic `node` resolution, which ignores `exports` entirely. That
// default IS the condition under test.
const CONSUMER_TSCONFIG = {
  compilerOptions: {
    target: 'ES2022',
    module: 'commonjs',
    skipLibCheck: true,
    strict: true,
    noImplicitReturns: true,
    noFallthroughCasesInSwitch: true,
    noEmit: true,
  },
  include: ['index.ts'],
}

// Touches both entry points and USES what it imports — an unused import can be
// elided before resolution and would prove nothing.
const CONSUMER_SOURCE = `
import { retryAsync, parseRetryAfterMs, redactUrl, VerificationFailure, assertEgressHostAllowed, resolveEnvProxy } from '${PKG}';
import { verifyDetached } from '${PKG}/gpg';
import type { VerifyDetachedResult } from '${PKG}/gpg';

export async function use(): Promise<string> {
    const capped: number | undefined = parseRetryAfterMs('120');
    const safe: string = redactUrl('https://example.com/a?token=secret');
    const failure: Error = new VerificationFailure('nope');
    const result: VerifyDetachedResult = await verifyDetached({
        message: new Uint8Array(),
        signature: new Uint8Array(),
        armoredPublicKeys: ['-----BEGIN PGP PUBLIC KEY BLOCK-----'],
    });
    // reasons is what an operator reads when a signature does not verify; if it
    // ever stops being part of the published types this stops compiling.
    const reasons: readonly string[] = result.reasons ?? [];
    await retryAsync(async () => undefined, { retries: 0 });
    assertEgressHostAllowed;
    // The destination is a required argument, and an injected environment is
    // how a consumer's own tests reach this; both are part of the published
    // signature, so a change to either stops compiling here.
    const proxy = resolveEnvProxy('https://example.com/v1', { https_proxy: 'http://proxy.internal:8080' });
    return [capped, safe, failure.name, result.verified, reasons.length, proxy?.proxyUrl ?? 'direct'].join(',');
}
`

let workdir
let failed = false
try {
  console.log('Consumer smoke test')

  step('building')
  npm(['run', 'build'], { cwd: ROOT })

  step('packing the tarball (respects "files", so an omitted dist file fails here)')
  workdir = mkdtempSync(join(tmpdir(), 'ptc-smoke-'))
  npm(['pack', '--pack-destination', workdir], { cwd: ROOT })
  const tarball = readdirSync(workdir).find((f) => f.endsWith('.tgz'))
  if (!tarball) throw new Error('npm pack produced no tarball')

  const consumer = join(workdir, 'consumer')
  mkdirSync(consumer)
  writeFileSync(
    join(consumer, 'package.json'),
    JSON.stringify({ name: 'consumer-smoke', version: '0.0.0', private: true }, null, 2),
  )
  writeFileSync(join(consumer, 'tsconfig.json'), JSON.stringify(CONSUMER_TSCONFIG, null, 2))
  writeFileSync(join(consumer, 'index.ts'), CONSUMER_SOURCE)

  step('installing the tarball as a real dependency')
  npm(['install', join(workdir, tarball), '--no-audit', '--no-fund', '--no-package-lock'], {
    cwd: consumer,
  })

  step(`type-checking against "${PKG}" and "${PKG}/gpg" with classic resolution`)
  run(process.execPath, [
    join(ROOT, 'node_modules', 'typescript', 'bin', 'tsc'),
    '--project',
    consumer,
  ])

  // A real install, resolved by package name through `exports` — not by dist
  // path. This also re-proves the openpgp split end-to-end: the root entry must
  // load with openpgp absent, which it is here (an optional peer nobody asked for).
  step('requiring the root entry point from the install, with openpgp absent')
  run(
    process.execPath,
    [
      '-e',
      `const c = require('${PKG}');
     if (typeof c.parseRetryAfterMs !== 'function') throw new Error('root entry did not export parseRetryAfterMs');
     if (typeof c.VerificationFailure !== 'function') throw new Error('root entry did not export VerificationFailure');`,
    ],
    { cwd: consumer },
  )

  // Types resolving is not the same as the subpath being reachable: with
  // `exports` present, Node treats it as the exclusive gate for subpaths, while
  // typesVersions would happily keep type-checking. Removing "./gpg" from
  // exports therefore breaks every consumer at runtime while tsc stays silent —
  // a mutation this test missed until it resolved the subpath too.
  //
  // require.resolve, not require: it exercises the same resolution algorithm
  // without executing the module, so this needs no openpgp and stays offline.
  step('resolving the gpg subpath through the exports map')
  run(
    process.execPath,
    [
      '-e',
      `try {
       require.resolve('${PKG}/gpg');
     } catch (error) {
       throw new Error('the ./gpg subpath is not reachable from a real install: ' + error.code + ' ' + error.message);
     }`,
    ],
    { cwd: consumer },
  )

  console.log('\nOK: the package installs, resolves and type-checks as an ADO task consumes it.')
} catch (error) {
  failed = true
  console.error('\nFAIL: a consumer could not use this package.\n')
  console.error(error.stdout?.toString() || '')
  console.error(error.stderr?.toString() || error.message)
} finally {
  if (workdir) rmSync(workdir, { recursive: true, force: true })
}

process.exit(failed ? 1 : 0)
