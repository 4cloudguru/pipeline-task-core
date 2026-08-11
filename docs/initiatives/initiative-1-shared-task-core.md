# Initiative 1 — Shared task core + Release & Documentation extension

Status: **PLAN — nothing implemented**
Author: drafted 2026-08-11
Scope: two new repos (`pipeline-task-core`, `azure-pipelines-release-docs`) plus backports into
`azure-pipelines-terraform` and `azure-pipelines-packer`.

---

## 1. Why

Three facts drive this plan.

**The estate already shares security-critical code across repo boundaries, and the convention that
governs it cannot tell you the truth about drift.** `azure-pipelines-packer` carries nine modules
copied from `azure-pipelines-terraform`, governed by a provenance convention (`@shared-module`,
`@shared-module-policy`, `@shared-module-status`) enforced by `scripts/check-shared-modules.js`.
The *declared* state is:

| Status           | Modules                                                                                                                           |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| IN-SYNC (6)      | `artifact-discard`, `hashicorp-gpg-key`, `registry-allowlist`, `url-path-segment`, `url-secret-redaction`, `verification-failure` |
| **DIVERGED (3)** | `gpg-verifier`, `http-client`, `proxy-config`                                                                                     |

**Both `DIVERGED` headers are out of date** (verified against `origin/main` of both repos,
2026-08-11). `gpg-verifier.ts` states "Backport to azure-pipelines-terraform is pending" — it has
landed. `http-client.ts` lists three things Packer "has NOT yet taken" — `MAX_RESPONSE_BYTES`,
429/`Retry-After`, and the GitHub asset-redirect exception — and all three are present in Packer
today. The gate checks that the markers *exist*, not that their claims are *true*, so the status
prose rots silently while CI stays green. That is a structural limit of copy-with-provenance, and the
sharpest argument for a versioned dependency whose version number cannot lie.

That gate's own header already names the fix: *"Extracting a shared, versioned cross-extension
package remains the tracked long-term fix."*

**Neither copy is best-in-class — each is ahead in different places.** Terraform has decorrelated
jitter with an injectable entropy source, a wall-clock retry budget (`maxElapsedMs`), exported
`parseRetryAfterMs`, and CONNECT-tunnel proxying for credential-bearing `https.request`. Packer has
`inet_aton` radix IP parsing, embedded-IPv4 detection, bit-wise private-range classification and a
centralised `assertEgressHostAllowed()`. Copying either into a third extension would ship
known-weaker code.

**A third extension is coming.** It needs the same primitives. At N=3, with no canonical retry shape
to copy, continuing to duplicate compounds the problem.

**This invents nothing — the estate already shares libraries, in both languages.** An 18-repo survey
(2026-08-11) found four distinct sharing mechanisms already in use:

| Mechanism                | Example                                                 | Consumers                                                                                         |
| ------------------------ | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Go module                | `github.com/sethbacon/terraform-suite-identity` v0.27.0 | `terraform-registry-backend`, `terraform-state-manager-backend` (both pinned to the same version) |
| npm registry             | `@sethbacon/terraform-suite-ui` 0.8.1 (GitHub Packages) | `terraform-registry-frontend`, `terraform-state-manager-frontend`                                 |
| npm git-URL              | `terraform-drift-contract#v1.0.0`                       | `azure-pipelines-terraform`, `terraform-drift-report`                                             |
| copy + provenance header | the nine modules above                                  | `azure-pipelines-packer` ← `azure-pipelines-terraform`                                            |

The ADO task primitives are **the only shared family with no library mechanism at all** — the one
place still on copy-and-header. `pipeline-task-core` simply applies the `terraform-suite-ui` pattern
to it.

Two related observations from the same survey:

- **The npm mechanism should be standardised.** `terraform-drift-contract` is consumed as a git-URL
  pin, which bypasses `npm audit signatures`, provenance attestation and the hardened publish path
  that `terraform-suite-ui` goes through. Moving it to GitHub Packages is a small, separable
  improvement.
- **Cross-language parity is a real gap that no package can close.** Egress/SSRF classification is
  implemented independently in TypeScript (`registry-allowlist.ts`) and in Go
  (`terraform-suite-identity/identity/httpsafe`). A Node package cannot serve the Go services. The
  achievable fix is to **share the test corpus rather than the code**: publish the egress
  classification vectors (inet_aton spellings, IPv4-mapped / NAT64 / 6to4, RFC 6598, wildcard
  label-count cases) as language-neutral JSON fixtures, consumed by this package's vitest suite and
  by the Go modules' table tests. That buys parity of *behaviour* without a shared runtime.
- **The Go side has the same disease in a different organ** — see the parallel track below.

## 2. Objectives

1. One best-in-class implementation of the HTTP/retry/egress primitives, versioned and published.
2. A new extension for release-engineering and documentation-publishing tasks, consuming that
   package from day one.
3. Both existing extensions migrated onto it, retiring the copies.
4. No regression against the current hardening baseline — and adoption of the strongest patterns
   already present anywhere in the estate.

## 3. Proposed names

| Thing          | Proposal                                   | Notes                                                      |
| -------------- | ------------------------------------------ | ---------------------------------------------------------- |
| Shared repo    | `pipeline-task-core`                       | Neutral; serves all three extensions                       |
| Package        | `@sethbacon/pipeline-task-core`            | GitHub Packages, mirroring `@sethbacon/terraform-suite-ui` |
| Extension repo | `azure-pipelines-release-docs`             | Matches `azure-pipelines-{terraform,packer}`               |
| Extension id   | `pipeline-tasks-release-docs`              | Matches `pipeline-tasks-terraform`                         |
| Extension name | Pipeline Tasks for Release & Documentation |                                                            |

---

## 4. Prior art — closed issues this initiative reopens

Both extensions have already raised, and closed, the exact problems this initiative solves. None were
closed because the problem went away. They were closed because there was no mechanism to fix them
properly. That makes them evidence rather than noise, and it makes *reopening* the right move — each
one carries the original analysis, the reproduction detail and the audit labelling.

### The shared-module extraction

| Issue          | State                             | Substance                                                                                                        |
| -------------- | --------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| packer #46     | closed completed 2026-07-01       | "add HTTP-client timeouts **and extract the shared modules** copied from the terraform extension"                |
| packer #67     | closed completed 2026-07-02       | "add a CI parity gate for the modules copied from the terraform extension"                                       |
| terraform #300 | closed completed 2026-06-29       | "three byte-identical source files duplicated across installer tasks"                                            |
| terraform #760 | closed completed 2026-07-22       | duplication parity relies on a hand-maintained allowlist with no automatic detection of new duplicates           |
| terraform #681 | closed **not planned** 2026-07-23 | installer version-resolution/download orchestration copy-pasted across 3 tasks, *not* covered by the parity gate |
| terraform #407 | closed **not planned** 2026-07-07 | `truncate`/`truncateBody` reimplemented independently 4 times                                                    |

**packer #46 was closed on a partial fix.** Its title has two clauses and only the first shipped: the
timeouts landed, then #67 added a parity gate as a *substitute* for extraction. Its body is worth
quoting, because it predicted exactly what the 2026-08-11 verification went on to find:

> Six+ modules are maintained as byte-identical forked copies … with no shared package.
> Copy-paste-without-sharing guarantees drift, and it **has already happened**.

The two `not planned` items were declined for one shared reason: with no package to put the code in,
the only available fix was more copying. Phase 0 removes that constraint, so the grounds for
declining them no longer hold.

### The ServiceNow / Markdown2Html split

| Issue          | State                                           | Substance                                                                                                             |
| -------------- | ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| terraform #573 | closed completed 2026-07-16, labelled `wontfix` | "ServiceNow KB publishing remains a materially distinct, sizable threat surface bundled into a 'Terraform' extension" |
| terraform #798 | closed **not planned** 2026-07-23               | integration points coupled to bespoke, same-author companion projects rather than open protocols                      |

#573 is Phases 3 and 5 of this plan, written a month early — and it too was only half-fixed. Its body
records that the manifest-discoverability half was addressed (the description and tags now name
ServiceNow explicitly) while:

> the underlying architectural scope-creep — two materially unrelated feature domains shipped,
> versioned, and reviewed as a single artifact — remains

It also quantifies the surface: roughly a fifth of the task count plus four dedicated dependencies
(`markdown-it`, `highlight.js`, `js-yaml`, `cheerio`), carrying threat classes — stored XSS in KB
HTML, ServiceNow query injection, a bespoke proxy-tunnelling HTTP client — that anyone assessing
"should we trust this Terraform extension" currently has to review end to end.

### Protocol once coding starts

1. **Reopen, do not refile.** Reopen in the original repo. A new issue discards the evidence, the
   audit labels (`audit-2026-07`, `audit-2026-07-reaudit`) and the record of why it was closed.
2. **Comment on reopening** with a link to this plan, the phase that resolves it, and — for #46 and
   #573 — which clause of the original was left outstanding.
3. **Mind the cross-repo limit.** GitHub's `Closes #N` keyword only auto-closes within the same
   repository. A `pipeline-task-core` PR therefore *cannot* auto-close packer #46 or terraform #573;
   reference them as `sethbacon/azure-pipelines-packer#46` to create the link, then close them by
   hand from the PR that lands the change in that repo.
4. **Close each on the PR that actually removes the duplication**, not on the PR that publishes the
   package. #46, #300, #681 and #407 close during Phase 4 (backport), not Phase 0.
5. **Set the state reason to `completed` on close**, and drop the `wontfix` label from #573. Leave a
   closing comment naming the PR, so the audit trail shows the deferral was resolved rather than
   re-declined.

---

## 5. Tying into security-orchestration and the remediation ledger

Both new repos onboard into the existing audit/remediation apparatus **from the first commit**, not
after they ship. The framework already has a precedent for each of them, and — more importantly — it
has a blind spot that this initiative would otherwise walk straight into.

### What the apparatus is

Two repos, split by role:

| Repo                     | Role                                                                                                                                                                                                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `security-orchestration` | The blind audit engine — `engine/blind-audit-engine.js` (1,506 lines), one profile-driven script covering 8 targets. Recon → research → triage → 10 domain reviewers → adversarial verify panel → disposition → score vs baseline.                                        |
| `so-wt-ledger`           | The remediation half — `remediation/signatures/` (17 structural scanners), `remediation/replay/` (Python replay harness), `signatures/ledger.json` (17 closed-out entries), `signatures/registry.json` (signature → invocation), `replay/scope.json` (the repo registry). |

A **defect class** is a machine-checkable structural scanner, not a prose category. Each enumerates
*every* instance of its class across the estate, so a fix cannot land on the one site named in an
issue and miss five others.

### The blind spot — read this before extracting anything

`registry.json` declares which repo kinds each signature runs against. The complete set of kinds any
signature targets today is **`ado-extension`, `go-backend`, `gomod`**. There is **no `npm`**.

Of the 17 classes, **13 apply to `ado-extension`**:

| Class                       | Ledger | Lands in core?                                                                      |
| --------------------------- | ------ | ----------------------------------------------------------------------------------- |
| `egress-authorization`      | #161   | **yes** — and it is already a *regression* (closed 2026-07-25, reopened 2026-08-06) |
| `network-retry`             | #879   | **yes**                                                                             |
| `hardened-temp-writes`      | #881   | **yes**                                                                             |
| `premask-emission`          | #185   | **yes**                                                                             |
| `output-boundary`           | #101   | **yes**                                                                             |
| `capture-output-protection` | #869   | **yes**                                                                             |
| `artifact-trust`            | #65    | **yes** (the `./gpg` entrypoint)                                                    |
| `proxy-parity`              | #196   | **yes**                                                                             |
| `prototype-safe-lookup`     | #884   | **yes**                                                                             |
| `credential-input-type`     | #867   | no — `task.json` input types, extension-side                                        |
| `provider-auth-failclosed`  | #97    | no — extension-side                                                                 |
| `docs-claims`               | #205   | no — repo discipline                                                                |
| `enforced-disciplines`      | #192   | no — repo discipline                                                                |

Nine of those thirteen describe code this initiative **moves out of `ado-extension` scope and into an
`npm` module that no signature currently looks at.** Extract without acting and the replay goes green
because it stopped looking, not because anything was fixed. `suite-ui` already demonstrates the hole:
it is registered in `scope.json` as `kind: npm` and has zero applicable signatures.

**Therefore: adding `"npm"` to `appliesToKinds` for those nine classes is not follow-up work — it
ships in the same PR as the extraction.** Treat it as an exit criterion for Phase 4, and note that
`egress-authorization` has already regressed once, so it earns the most care.

### Registering the two repos

`replay/scope.json` is the registry. `suite-ui` is the exact structural precedent for the package —
same kind, same shape:

```json
{ "name": "suite-ui", "dir": "terraform-suite-ui", "gh": "sethbacon/terraform-suite-ui",
  "kind": "npm", "manifest": "package.json",
  "modulePath": "@sethbacon/terraform-suite-ui",
  "consumers": ["registry-frontend", "tsm-frontend"] }
```

- **`pipeline-task-core`** → `sharedModules[]`, `kind: "npm"`, `modulePath: "@sethbacon/pipeline-task-core"`,
  `consumers: ["terraform-ext", "packer-ext", "release-docs-ext"]`.
- **`azure-pipelines-release-docs`** → `suite[]`, `kind: "ado-extension"`, `consumes: ["pipeline-task-core"]`.
- The two existing extensions gain `consumes: ["pipeline-task-core"]` at Phase 4.

That last change also retires a comment in `scope.json` that currently states the problem this
initiative exists to solve:

> The two `ado-extension` repos are SIBLING Azure DevOps extensions that copy modules between each
> other … They consume no versioned shared module, so they carry no `consumes` entry and no
> `sharedModules` record: the parity is copy-paste, which is exactly why every signature has to run
> in BOTH.

Separately, each repo needs an engine profile in `PROFILES` (`blind-audit-engine.js`) plus a baseline
file. Model the package on `suite-ui` (`kind: 'lib'`) and the extension on `packer-ext`. Note the
engine's `repoPath`/`baselineFile` values are **Linux paths** (`/home/sethbacon/Repos/terraform/…`) —
it runs under WSL, not the Windows checkout.

### What "TDD with security in mind" means here

The ledger already encodes the discipline; the new repos adopt it rather than inventing one. Three
fields carry it, and the division of labour between them is the point — quoting entry #879:

> It claims nothing about retry CORRECTNESS (budget, backoff, jitter, partial-file safety, which
> errors are classified retryable) — all of that is the class test's job.

1. **`scope`** — an explicit statement of what a green entry does *and does not* claim. Written first,
   it is the contract the tests are held to.
2. **`classTest`** — the named test proving *behaviour*. The established shape is two tables: **Table A**
   drives the behaviour (transient failure then success; an egress rejection that must *not* be
   retried; a retry that must not resume into a prior attempt's partial bytes), **Table B** hand-verdicts
   every site in the repo. The signature proves site coverage; the class test proves conduct.
3. **`mutationBySite`** — red/green proof the test actually detects the defect. From #161: deleting the
   RFC 6598 CIDR "turned exactly 3 rows red … and restoring it returned 68 passing." A test that
   passes against the buggy code is worthless, and the ledger refuses to take it on trust.

`blindVerify` is recorded honestly as `NOT RUN` where it was not run. Keep that habit.

**Concretely, for every module in Phase 0.2:** write the class test before the implementation, in the
two-table shape; record a mutation that reddens it; write the `scope` paragraph stating the limits of
the claim. `pipeline-task-core` then becomes the *fix location* the remediation runbook already
mandates:

> if the defect is expressible in the shared module, it is fixed in the shared module. A consumer-side
> guard is a mitigation, not the fix. The module fix is **inert until every consumer bumps**.

That last clause is why `consumers[]` in `scope.json` matters: it drives the pin check
(`replay/replaylib/pins.py`) that keeps a batch open until every consumer is bumped or explicitly
deferred. The package inherits exactly the discipline `suite-identity` and `suite-ui` already carry.

For `azure-pipelines-release-docs` the implication is blunter: **all 13 `ado-extension` classes apply
to it on day one.** They are a pre-existing, machine-checkable specification — satisfy them before the
first release rather than discovering them in the first audit. Adopt Packer's in-repo halves of those
gates too (`check-egress-authorization.js`, `check-artifact-trust.js`, `check-proxy-parity.js`,
`check-docs-claims.js`, `check-enforced-disciplines.js`).

---

## Phase 0 — `@sethbacon/pipeline-task-core`

Blocks everything else.

### 0.1 Hard constraints (differ from `terraform-suite-ui`)

`terraform-suite-ui` is a browser/React package: ESM-only, `engines: node >=22 <25`. **Do not copy
those two choices.** This package is consumed by ADO task hosts:

- **Must ship CommonJS** (dual CJS/ESM via tsup is fine). ADO tasks compile to CJS and use
  `import tl = require('azure-pipelines-task-lib/task')`.
- **Node floor is 20, not 22.** Every task declares a `Node20_1` fallback handler alongside `Node24`
  for agents without the Node 24 runner. A Node 22 floor would silently break that fallback.
- **Zero runtime dependencies** if achievable. `undici` is the only likely exception (proxy
  `ProxyAgent`); prefer a peer/optional dependency so tasks control the version.
- Must work when vendored into a `.vsix` via `npm ci --omit=dev`.

### 0.2 Module inventory (merged best-of-both)

| Module                                     | Take from Terraform                                                                                                                                                                                                                                          | Take from Packer                                                                                                                                                                                                                                                                                                                         |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `retry`                                    | `retryAsync()` with decorrelated jitter, `maxElapsedMs` wall-clock budget, `retryResult`/`retryError` predicates, `RetryOutcome` union, `parseRetryAfterMs(value, capMs)` capped at 30 s                                                                     | —                                                                                                                                                                                                                                                                                                                                        |
| `http-client` (fetch)                      | `MAX_REDIRECTS = 5`, manual redirect loop, per-hop scheme + host re-validation, `MAX_RESPONSE_BYTES = 10 MB`, `AbortController` timeouts, `HttpError(message, retryable, retryAfterMs?)`, `isRetryableHttpStatus()`, GitHub release-asset redirect predicate | —                                                                                                                                                                                                                                                                                                                                        |
| `https-client` + `ProxyTunnelAgent`        | CONNECT tunnelling for credential-bearing `https.request`, separate tunnel timeout bounding CONNECT + TLS, base64 credential masking                                                                                                                         | —                                                                                                                                                                                                                                                                                                                                        |
| `egress` (registry-allowlist)              | —                                                                                                                                                                                                                                                            | `assertEgressHostAllowed()` as the single decision point, `parseIpv4()` with inet_aton radix forms, `parseIpv6()` with embedded-IPv4 (mapped / compatible / NAT64 / 6to4), bit-wise `PRIVATE_IPV4_RANGES` incl. RFC 6598 `100.64.0.0/10`, `bareHost()`, `assertValidAllowlistEntry()`, RFC 6125 wildcard semantics, `EgressHostMessages` |
| `url-secret-redaction`                     | Already byte-identical in both                                                                                                                                                                                                                               |                                                                                                                                                                                                                                                                                                                                          |
| `url-path-segment`                         | Already byte-identical in both                                                                                                                                                                                                                               |                                                                                                                                                                                                                                                                                                                                          |
| `proxy-config`                             | Raw **and** percent-encoded proxy password `setSecret()` registration                                                                                                                                                                                        |                                                                                                                                                                                                                                                                                                                                          |
| `verification-failure`, `artifact-discard` | Installer trust-chain markers; used by two of three extensions today                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                                          |

`gpg-verifier` belongs in core behind a **separate subpath entrypoint** (`@sethbacon/pipeline-task-core/gpg`)
with `openpgp` as an optional peer — it is copied three times today. `hashicorp-gpg-key` stays in the
consuming repos. See decision 4.

### 0.3 Three design conflicts needing a decision

1. **Redirect strictness.** Terraform permits `github.com` → `*.githubusercontent.com`; Packer is
   strict same-host. *Recommendation:* default strict, export a `githubAssetRedirects` predicate
   callers opt into. Secure-by-default, no capability lost.
2. **Wildcard semantics.** Terraform's suffix match silently widens `*.s3.amazonaws.com` to
   `a.bucket.s3.amazonaws.com`; Packer enforces RFC 6125 single-label. *Recommendation:* adopt
   Packer's. This is a behaviour change for Terraform allowlists — call it out in release notes and
   audit existing allowlist values before cutover.
3. **Backoff.** Decorrelated jitter (Terraform) vs plain exponential (Packer). *Recommendation:*
   jitter by default with an injectable entropy source so tests stay deterministic.

### 0.4 Security posture for this repo

Baseline is `terraform-suite-ui`'s `publish.yml`, which is the strongest pipeline in the estate.
Non-negotiables:

- **Split unprivileged build / privileged publish.** The build job runs `npm ci` (the untrusted
  dependency lifecycle) holding *no* registry, OIDC or attestation permissions; the publish job holds
  those permissions and installs nothing. A poisoned transitive dependency cannot reach the token or
  forge an attestation.
- **`step-security/harden-runner`** — `egress-policy: audit` on build, **`block` with an explicit
  endpoint allowlist** on publish.
- `persist-credentials: false` on checkout; `package-manager-cache: false` on privileged jobs.
- Tag must equal `package.json` version; tagged commit must be reachable from `main`.
- `npm ci --ignore-scripts`; `.npmrc` with `ignore-scripts=true`.
- `npm audit --audit-level=moderate` **and** `npm audit signatures`, re-run at publish time.
- **Tarball content allowlist** (exactly the expected files, no more, no fewer) and a **byte-for-byte
  diff of the packed tarball against the built `dist/`**.
- Pack once; bind `attest-build-provenance` and `attest-sbom` to that exact tarball.
- CycloneDX SBOM via `anchore/sbom-action`.
- `release` GitHub Environment with a required reviewer and a deployment branch/tag policy.
- All Actions pinned to full commit SHAs. CodeQL `security-extended`. release-please + commitlint.
- Publish-time values flow via `env:`, never template-expanded into script bodies (zizmor
  template-injection).

### 0.5 Testing bar

Every module ships as a **ledger class test** in the two-table shape (§5): Table A drives behaviour,
Table B hand-verdicts every call site, and a recorded mutation proves the test reddens when the guard
is removed. Write the `scope` paragraph — what a green result does *and does not* claim — before the
implementation.

Vitest with coverage thresholds at least matching the extensions' security tier (80 % lines / 50 %
functions / 50 % branches). Required cases: inet_aton spellings resolving to loopback; IPv4-mapped
and NAT64 IPv6; redirect chains that change host mid-chain; redirect count exceeding the cap;
response bodies exceeding the byte cap; `Retry-After` above and below the cap; wall-clock budget
expiry mid-retry; proxy password masking in both raw and percent-encoded forms.

These overlap the existing class tests by design — `Tests/EgressAuthorizationL0.ts` and
`Tests/NetworkRetryClassL0.ts` are the reference behaviour, and porting them is how the package
inherits ledger entries #161 and #879 rather than restating them.

### 0.6 Exit criteria

`0.1.0` published to GitHub Packages, signed, SBOM-attested, installable by a scratch task project on
both Node 20 and Node 24.

Plus, from §5 — the package is registered in `replay/scope.json` under `sharedModules[]` with its
`consumers[]` list, it has an engine profile and a seeded baseline, and every module carries a class
test with a recorded mutation.

---

## Phase 1 — Extension repo skeleton

Fork the structure from **`azure-pipelines-packer`**, not Terraform — it is the newer and more
hardened of the two (`check-artifact-trust`, `check-egress-authorization`, `check-enforced-disciplines`,
`check-proxy-parity`, `check-docs-claims`, `publish-marketplace.js` with the token on stdin plus
bounded retry, and a `signature-replay.yml` workflow).

Carry over unchanged: `.npmrc` `ignore-scripts=true`; SHA-pinned Actions; CodeQL `security-extended`;
zizmor with an explicit ignore list only; `dependency-review-action` blocking ≥ moderate; `npm audit`
on prod *and* dev; weekly OSV scan with issue dedup; Dependabot per task and root; per-file coverage
floors; conventional PR title gate; CODEOWNERS; `Node24` + `Node20_1` handlers; mandatory `task.json`
Minor bump, triple-enforced; cosign keyless signing of the `.vsix` with verification before publish
*and* before release attachment; marketplace environment protection verified fail-closed at release
time and by a weekly canary; draft release undrafted only after a successful publish.

Add on top, from `terraform-suite-ui`: the unprivileged-build / privileged-publish job split and
`harden-runner` egress policies. Both extension repos should adopt this too — see Phase 4.

Consuming a GitHub Packages package needs an `.npmrc` registry entry plus a token: `GITHUB_TOKEN` in
Actions, a PAT for local development. Document it in CONTRIBUTING; it is the most likely onboarding
snag.

**Exit criteria:** a dev-config `.vsix` builds, signs, verifies and installs privately, containing one
trivial task that calls into `@sethbacon/pipeline-task-core`. No public publish yet.

## Phase 2 — Changelog / release task

Behaviour mirrors release-please: parse conventional commits since the last `v*` tag → compute the
bump → **prepend** to `CHANGELOG.md` → stamp version files → open or update a release PR → tag and
release on merge. Model the config on the existing `.release-please-config.json`
(`changelog-sections`, `extra-files` with a JSON path, `draft`).

Empirically established constraints (lab build 366923):

- Splice **after** the Keep a Changelog preamble; a naive prepend lands above the `# Changelog` title.
- Strip `^Merged PR \d+: ` before conventional parsing or every ADO merge commit is silently dropped.
- Skip `chore` / `ci` / `build` / `test` and non-conventional commits.
- `feat!:` takes 0.3.7 → 1.0.0. Decide whether to cap 0.x majors; make it an input.

Threat model specific to this task:

| Threat                                                                | Control                                                                                                                                                                                                                                               |
| --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Command injection via commit message, branch or tag into `git`        | argv arrays only, never shell interpolation                                                                                                                                                                                                           |
| Privileged push to a protected branch                                 | `dryRun` input modelled on `PublishKbArticle`'s `dry-run.ts`; document the branch-policy bypass requirement rather than silently needing it                                                                                                           |
| Token handling                                                        | `setSecret()` on raw **and** derived/base64 forms, per the existing `auth.ts` pattern                                                                                                                                                                 |
| Unbounded `git log`                                                   | Bounded commit count plus the core package's wall-clock budget                                                                                                                                                                                        |
| ADO REST calls for PR create/update                                   | Core `https-client`: HTTPS-only, response cap, socket timeout                                                                                                                                                                                         |
| **Commit message → `CHANGELOG.md` → `Markdown2Html` → ServiceNow KB** | A hostile commit message becomes HTML in a published KB article once all three tasks share an extension. The fail-closed gates in `html-validate.ts` / `uri-scheme-guard.ts` catch it at publish, but escape at write time too, with an explicit test |

Security-tier coverage floors apply.

## Phase 3 — Migrate `Markdown2Html` + `PublishKbArticle`

Resolves the outstanding half of terraform #573 (see §4). These move **together**:
`uri-scheme-guard.ts` is a byte-identical family shared only between them, so it travels intact.

Parallel-run, not flag-day — two co-installed extensions cannot both contribute the same task name or
GUID. New GUIDs, new names, then cut over. Every consumer reference lives in two files
(`build-template.yml` and `release-template.yml` in `terraform-pipeline-templates`), so the cutover is
one PR.

Per task: copy with new GUID and name → register in the manifest, Dependabot, SBOM list, CI matrix →
publish → cut the templates over → mark the originals deprecated.

## Phase 4 — Backport core into the existing extensions

This is where packer #46, terraform #300, #681 and #407 are closed (see §4) — on the PRs that remove
the duplication, not on the one that publishes the package.

**Blocking exit criterion (§5):** the same PR that moves a primitive into core must add `"npm"` to
that class's `appliesToKinds` in `signatures/registry.json`, and add `consumes: ["pipeline-task-core"]`
to the repo's `scope.json` entry. Nine classes are affected. Skip this and the signature replay goes
green because it stopped looking — `egress-authorization` (#161) has already regressed once.

Order: **Packer first** (fewer copies, and it holds the three diverged modules), then Terraform (where
the seven-task `retry.ts` family collapses into a dependency).

Per repo: add the dependency → replace the copied modules → delete the entries from
`check-shared-modules.js` → keep the provenance headers only on anything still copied. When a repo's
registry empties, that gate can retire.

Independent of this plan, two housekeeping items fall out of the 2026-08-11 verification:

1. **Refresh the stale `@shared-module-status` prose** on Packer's `gpg-verifier.ts` and
   `http-client.ts` — both describe a divergence that no longer exists.
2. **Packer's retry is the one substantive remaining delta.** It open-codes `withRetry` inside
   `http-client.ts` using plain `Math.pow(2, attempt - 1)` with no jitter, no `maxElapsedMs` budget
   and no `parseRetryAfterMs`; there is no standalone retry module on `origin/main`. Terraform's
   `retry.ts` has all four. This is the gap the package closes, so it needs no separate backport.

Consider also strengthening the gate itself so `@shared-module-status: IN-SYNC` is *verified* (e.g. a
checked-in digest of the upstream body) rather than asserted — worthwhile only if the package
extraction is deferred.

## Phase 5 — Retire the originals

Remove the two tasks from the Terraform extension in a major release after a soak period.
`check-task-list.js` fails loudly if any of the four hand-maintained surfaces are missed. Close
terraform #573 here and drop its `wontfix` label.

---

## Parallel track — Go shared-module hygiene

Independent of the TypeScript work above, and separately schedulable. Findings verified 2026-08-11.

### The naming decision

Names stay **functional**, not language-based. `terraform-suite-go` / `terraform-suite-typescript`
were considered and rejected: the language is already stated by `go.mod` / `package.json`, a
language-named repo has no principled exclusion rule and becomes a junk drawer, and it breaks
immediately once a language has two shared libraries (which TypeScript is about to, with
`terraform-suite-ui` and `pipeline-task-core`). Renaming is also expensive on the Go side
specifically: the module path `github.com/sethbacon/terraform-suite-identity` is pinned at `v0.27.0`
by two consumers, and Go requires the module path to track the repo path, so a rename is a breaking
module-path change that persists in the module proxy and checksum DB.

**Do not rename `terraform-suite-identity` to `-core`.** By file count it is ~80 % identity
(`store` 34, `models` 9, `auth`+`oidc`+`oauthstate` 22, `identity` 11, `crypto` 3, `suite` 7).
Renaming the whole module to accommodate a 2-file package makes the name *less* accurate and forces
a module-path break on both consumers.

### Finding 1 — a duplicate `httpsafe`, in the same binary (fix first, cheap)

`terraform-registry-backend` carries **both**:

- 7 files importing the shared `github.com/sethbacon/terraform-suite-identity/identity/httpsafe`
  (`api/router.go`, `api/suite.go`, `api/admin/notification_channels.go`, `auth/oidc/provider.go`, tests)
- a **377-line local fork** at `backend/internal/httpsafe/` (plus 542 lines of tests), imported by
  `internal/scm/httpclient.go`

Two packages named `httpsafe`, exporting the same `Guard` type and `NewGuard`/`NewClient` names, with
**diverged APIs**, linked into one binary. A reviewer reading `httpsafe.NewGuard(allowlist)` cannot
tell which implementation is in play without checking the import block.

| API                | Shared (372 lines) | Local fork (377 lines)      |
| ------------------ | ------------------ | --------------------------- |
| `ValidateURL`      | `(ctx, rawURL)`    | `(rawURL)` — **no context** |
| `ValidateHostPort` | absent             | `(ctx, addr)`               |
| `NewClientWithTLS` | present            | absent                      |

`terraform-state-manager-backend` is the model to copy: it imports the shared package directly in
both `internal/egress/egress.go` (strict default) and `internal/statesource/egress.go` (RFC 1918 /
ULA permitted by default).

**Action:** port `ValidateHostPort` into the shared package (with its seven existing tests — it is
load-bearing, see decision 6), adopt the shared `ValidateURL(ctx, …)` signature at the fork's call
sites, delete `backend/internal/httpsafe/`, repoint `internal/scm` at the shared package. The two
implementations have been diffed and agree on classification (decision 7). No module surgery
required — the dependency is already in `go.mod`.

### Finding 2 — unbundle `httpsafe` and `mailer` (later, one churn event)

Cohesion argues both out of an identity module; the import graph says only one is free today.

| Package              | Internal identity imports                                                         | Verdict                                                                                                                                                                   |
| -------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mailer` (4 files)   | **none** — stdlib only, and nothing else in the module imports it except `notify` | **Cleanly separable now**                                                                                                                                                 |
| `httpsafe` (2 files) | none                                                                              | **Separable**; nothing identity-specific — it serves SCM, mirrors, webhooks, OSV, policy bundles, IdP metadata                                                            |
| `notify` (13 files)  | `crypto`, `httpsafe`, `store`, `models`, **`internal/safeloop`**                  | **Not separable.** The `internal/` import is a hard blocker: external modules cannot import it. Splitting would need `safeloop` promoted to public API or a deep refactor |

`notify` is also arguably in scope for an identity module anyway — its main job is the API-key expiry
notifier, which is an identity concern. So the genuine drift is just `mailer` (generic SMTP) and
`httpsafe` (generic egress safety), not the 17 files a file-count read suggested.

**Action, when convenient:** split `httpsafe` and `mailer` into their own functionally-named modules
(`terraform-suite-httpsafe`, `terraform-suite-mailer`), as a **single unbundling event** so consumers
absorb one round of module-path churn rather than three. The benefit beyond cohesion is dependency
hygiene: a service that wants SSRF safety currently inherits `identity/store` (34 files, DB drivers)
into its `go.sum`. Keep `notify` where it is.

### Finding 3 — retry does not consolidate

Deliberately leaving these separate. `terraform-registry-backend`'s `webhook_retry_job.go` is a
background job state machine with **minute-scale** backoff (`2^n` minutes, persisted `retry_count` /
`next_retry_at`), while `terraform-state-manager-backend`'s `pipelines/retry.go` is request-path
resilience with **millisecond-scale** backoff (300 ms × `2^(n-1)`, idempotent methods only). Same
word, different problems. Neither belongs in a shared HTTP module.

Worth noting for the TypeScript side: both Go retries lack jitter, and the state-manager one treats
429 as a generic transport error. If the JSON test-vector idea lands, retry semantics are a candidate
for the same treatment.

---

## Risks

- **RFC 6125 wildcard change is a behaviour change.** Existing Terraform allowlists relying on the
  loose suffix match will start rejecting hosts. Audit values before cutover; consider a one-release
  warning mode.
- **A shared package is a new supply-chain surface.** Mitigated by the Phase 0.4 controls, but it is a
  real addition — the package becomes a dependency of everything.
- **GitHub Packages auth friction** for local development and for `.vsix` packaging.
- **Bus factor.** Four repos, one maintainer. Argues for keeping the core package small and stable.
- **Node 20 floor** constrains language/runtime features for the life of the fallback handler.

## Decisions

Resolved 2026-08-11. Each was decided against evidence in the estate rather than preference.

### 1. The new extension is public, and it needs its own `marketplace` environment

Public, following the existing pattern exactly: base `azure-devops-extension.json` stays
`"public": false` as the dev-safe default (both current extensions do this), and
`configs/release.json` overrides to `"public": true` + `galleryFlags: ["Public"]`. A dev or test
package then cannot accidentally ship a public listing.

The environment half of the question has a factual answer: **GitHub Environments are
repository-scoped, so the existing one cannot be reused.** `azure-pipelines-release-docs` must define
its own `marketplace` environment with its own required reviewer and deployment branch/tag policy,
its own `verify-marketplace-environment-protection` job in `weekly-security.yml`, and its own
fail-closed guard step in `release.yml`. The Entra federated credential is also repo-scoped (the
subject embeds the repo), so a new federated credential is required even though the publisher
(`sethbacon`) is shared.

### 2. Do not add `vso.code_write`. The changelog task uses `System.AccessToken`

Both existing extensions declare exactly `scopes: ["vso.build"]`. Raising that to `vso.code_write`
would re-prompt every installing organisation for consent and would grant repo write to the whole
extension for the benefit of one task.

It is also unnecessary. Extension scopes govern accesses made with the *extension's* identity (the
Terraform tab uses `vso.build` that way). A build task authenticates with the *job's* identity —
`tasks.getEndpointAuthorizationParameter('SystemVssConnection', 'AccessToken', false)`, which this
repo already does in `azure-terraform-command-handler.ts` and `id-token-generator.ts`. What actually
gates it is the Build Service account's repo permissions.

So: keep the manifest minimal, read `System.AccessToken` via `SystemVssConnection`, and document that
the pipeline author must grant the Build Service **Contribute** and **Contribute to pull requests**
on the target repo. That puts the privilege decision per-repo, with the person who owns that repo.
Offer an explicit token input only as an override for cross-repo or cross-org publishing.

### 3. Prefix the migrated pair — the collision resolves itself

Of the eleven tasks in the Terraform extension, `Markdown2Html` and `PublishKbArticle` are the **only
two without the `Pipeline` prefix**; the other nine all carry it (`PipelineTerraformTask`,
`PipelinePolicyAgentInstaller`, …). The convention is a bare `Pipeline` prefix, not
`PipelineTerraform`.

That pre-existing inconsistency is convenient: the new extension can adopt **`PipelineMarkdown2Html`**
and **`PipelinePublishKbArticle`**, which brings them into line with the convention *and* cannot
collide with the unprefixed originals during the parallel run. No invented disambiguating names are
needed. New GUIDs regardless — a task id must never be reused across extensions.

### 4. `gpg-verifier` goes in core behind a subpath; the key does not

`gpg-verifier.ts` is copied into **three** installer tasks across both repos (TerraformInstaller,
PolicyAgentInstaller, PackerInstaller), so it is squarely in scope — the plan previously
under-rated it. But `openpgp` is declared in exactly those three `package.json` files and is a heavy
dependency the release-docs tasks would otherwise vendor into their `.vsix` for nothing.

Ship it as a **subpath entrypoint** — `@sethbacon/pipeline-task-core/gpg` — with `openpgp` as an
optional `peerDependency`. Subpath `exports` work under CJS, so the Node 20 floor is unaffected.

`hashicorp-gpg-key.ts` **stays in the consuming repos**, and core's verifier takes the armoured key as
a parameter. A signing key is a trust root, and a trust root should be explicit and auditable in the
repo that relies on it — vendoring it transitively through an npm package means a compromise of that
package silently replaces it. Keeping it local also means Packer's weekly GPG key-freshness check
keeps working unchanged, and a key rotation does not require a core release plus three consumer bumps.

### 5. Side-by-side is already proven in production — no experiment needed

This was answered before it was asked. `docs/migration-from-ms-devlabs.md` documents the Terraform
extension running side-by-side with Microsoft DevLabs' today, using three mechanisms: distinct task
GUIDs, the `Pipeline` task-name prefix ("so they're easy to tell apart in YAML and the classic
editor"), and `PTT`-prefixed service connection type IDs "so both extensions can coexist without ID
collisions".

Apply the same three to the parallel run. Decision 3 already satisfies the name half; the migrated
pair contributes no service connection types, so only GUIDs and names matter here.

### 6. Port `ValidateHostPort` up — deletion is not an option

It has one production call site: `backend/internal/api/setup/handlers.go:359`, inside
`probeEgressAllowed`, which validates an operator-supplied connectivity-probe target that may be
either a URL *or* a bare `host:port`. The rationale is recorded against issue #749:

> `ValidateHostPort` exists for transports this package does not supply: an LDAP TCP dial, a cloud
> SDK's own HTTP client. Those never reach `DialContext`, so without this they bypassed the egress
> policy entirely.

`ValidateURL` cannot substitute — for a bare `host:port` there is no URL to parse. So Finding 1 is a
small port, not a straight deletion: move `ValidateHostPort` into the shared package (with its seven
existing tests), then delete the fork.

### 7. The two implementations agree — consolidation is safe

Diffed directly. 91 differing lines, but **every** non-comment, non-blank difference is one of the
three already-known API deltas: the `ValidateURL` context parameter, `NewClientWithTLS` +
`crypto/tls`, and `ValidateHostPort`. There is **zero** divergence in the classification core —
`checkIP`, `ipAllowlisted`, `resolve` and `DialContext` are identical. No hidden behavioural drift is
lurking in the fork.

One detail worth capturing: the fork's `ValidateURL` hard-codes
`context.WithTimeout(context.Background(), …)`, so it ignores caller cancellation, and its
`CheckRedirect` cannot propagate request context. The shared signature threads `req.Context()`
through. Adopting it is a strict improvement, not merely a signature change.

---

## Still genuinely open

Nothing blocking. Two items deferred by choice:

- Whether `terraform-suite-httpsafe` and `terraform-suite-mailer` (Finding 2) split before or after
  the Phase 0 package ships. They are independent tracks; sequencing is a capacity question.
- Whether the language-neutral egress test vectors live in `pipeline-task-core` or their own repo.
  Defer until there is a second consumer actually consuming them.
