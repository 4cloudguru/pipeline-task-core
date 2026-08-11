import { defineConfig } from 'tsup'

// Dual CJS/ESM: ADO task hosts are CommonJS, so `require` must resolve to real
// CJS. `openpgp` is external so only the ./gpg entrypoint pays for it.
export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'gpg/index': 'src/gpg/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  splitting: false,
  target: 'node20',
  platform: 'node',
  external: ['openpgp'],
  outExtension({ format }) {
    return { js: format === 'cjs' ? '.cjs' : '.js' }
  },
})
