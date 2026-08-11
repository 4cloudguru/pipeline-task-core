# pipeline-task-core

`@4cloudguru/pipeline-task-core` — shared, versioned security primitives (HTTP client, retry, egress
allowlisting, URL secret redaction, proxy configuration) consumed by every Azure DevOps pipeline-task
extension in the estate:

- [azure-pipelines-terraform](https://github.com/sethbacon/azure-pipelines-terraform)
- [azure-pipelines-packer](https://github.com/sethbacon/azure-pipelines-packer)
- [azure-pipelines-release-docs](https://github.com/sethbacon/azure-pipelines-release-docs) *(planned)*

> **Status: scaffold.** The toolchain, CI and governance are in place, and one primitive
> (`parseRetryAfterMs`) is implemented to prove the build end to end. The remaining module inventory
> is Phase 0 work. The plan lives in
> [docs/initiatives/initiative-1-shared-task-core.md](docs/initiatives/initiative-1-shared-task-core.md)
> and covers both this package and the new extension that motivates it.

## Why this exists

The Terraform and Packer extensions each carry their own copy of the same HTTP/retry/egress
primitives — 33 files and 8 files respectively — kept in step by a provenance-comment convention
rather than by a compiler. That convention only checks the markers *exist*, not that their claims are
true, so status prose rots while CI stays green. This package replaces the convention with a
dependency.

## Constraints that shaped the build

These differ deliberately from `cloud-suite-ui`, which is a browser/React package:

| Constraint           | Value                         | Why                                                                                                               |
| -------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Module format        | dual CJS + ESM                | ADO tasks are CommonJS and use `import tl = require(...)`. CI asserts `require()` resolves.                       |
| Node floor           | 20                            | Every task declares a `Node20_1` fallback handler for agents without the Node 24 runner.                          |
| Runtime dependencies | none                          | `openpgp` is an *optional peer*, reachable only via the `./gpg` subpath.                                          |
| Registry             | public npmjs, with provenance | No consumer needs a token to install, and `--provenance` publishes a verifiable package → commit → workflow link. |

## Entrypoints

```ts
import { parseRetryAfterMs } from '@4cloudguru/pipeline-task-core'
import type { VerifyDetached } from '@4cloudguru/pipeline-task-core/gpg'
```

`./gpg` is separate so tasks that never verify release signatures do not vendor `openpgp` into their
`.vsix`. It deliberately ships **no signing key** — callers pass their own armoured key in and keep
their own key-freshness checks, because a trust root belongs in the repository that relies on it.

## Development

```bash
npm ci
npm run typecheck
npm test
npm run build
```

Commits follow Conventional Commits (enforced on PR titles); releases are cut by release-please.
