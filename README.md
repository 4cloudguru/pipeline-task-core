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

## Proxy support

`resolveProxy` reads the configuration an Azure DevOps agent hands out. `resolveEnvProxy` reads the
`HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` variables a GitHub self-hosted runner sets — in both
spellings, lowercase winning — which Node's `fetch` honours on its own for none of them. Neither
builds a dispatcher: `undici` stays a consumer dependency.

```ts
import { ProxyAgent } from 'undici'
import { createHttpClient, resolveEnvProxy } from '@4cloudguru/pipeline-task-core'

const client = createHttpClient({
  // Called for every attempt AND every redirect hop, with the URL about to be
  // issued — the answer depends on the destination, so a chain that redirects
  // off the origin has to be resolved again.
  fetchOptions: (url) => {
    const proxy = resolveEnvProxy(url)
    if (!proxy) return {}
    proxy.secrets.forEach((secret) => core.setSecret(secret)) // credentials in the URL are secrets
    return { dispatcher: new ProxyAgent(proxy.proxyUrl) } as RequestInit
  },
})
```

A proxy changes which socket carries the request, never which destination is permitted.
`assertEgressHostAllowed` still runs against the **destination** host — the initial one and every
redirect hop — and its subject is never the proxy: a CONNECT tunnel to an unauthorized host is still
unauthorized egress.

## The credential-bearing transport

`createHttpClient` is for downloading public artifacts over `fetch`. `httpsRequest` is the other
transport: raw `node:https`, for the requests that carry a bearer token, an API key or a basic
credential. That is why its refusal is phrased as *refusing to send credentials* over a non-https
URL rather than refusing to fetch one.

`createProxyTunnelAgent` is the raw-https counterpart of `resolveProxy`: `node:https` honours no
proxy setting unless handed an `agent`, so this builds one that opens an HTTP `CONNECT` tunnel and
upgrades it to TLS. `registerSecret` is **required**, not optional — the derived base64 `Basic`
credential is a byte sequence the caller never constructs and so could never think to mask.

```ts
import { createProxyTunnelAgent, httpsRequest, truncateBody } from '@4cloudguru/pipeline-task-core'

const { status, body } = await httpsRequest({
  method: 'POST',
  url: new URL(registryUrl), // parsed by the caller, which owns the "bad URL" message
  headers: { Authorization: `Bearer ${apiKey}` },
  body: Buffer.from(JSON.stringify(payload), 'utf8'),
  agent: createProxyTunnelAgent(tl.getHttpProxyConfiguration(), {
    tunnelTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS,
    registerSecret: (secret) => tl.setSecret(secret),
  }),
})
if (status >= 400) throw new Error(`Publish failed: ${truncateBody(body)}`)
```

### Why it is not `fetch`

Two independent reasons, and both still hold:

- **`undici` stays out.** This package has no runtime dependencies and is not growing one; consumers
  pin `undici` themselves, currently to 7.x because 8 breaks against the Node 24 bundles.
- **The consumers mock with `nock` and inject an `agent`.** `fetch` has no `agent` option at all, so
  a port would silently drop agent-proxy support — the tunnel above — and every test that drives a
  request through a real CONNECT proxy with it.

A status is returned, never thrown on: callers differ on what a non-2xx means, so the decision stays
with them. `truncateBody` is the bound that keeps a remote body from choosing how much of the job log
a failure occupies; `truncateForLog` is the stronger helper (it also strips the C0 characters that
forge a logging command) and is where a new caller should start.

## Development

```bash
npm ci
npm run typecheck
npm test
npm run build
```

Commits follow Conventional Commits (enforced on PR titles); releases are cut by release-please.
