# Security Policy

## Reporting a vulnerability

Report privately via [GitHub Security Advisories](https://github.com/4cloudguru/pipeline-task-core/security/advisories/new).
Please do not open a public issue for a suspected vulnerability.

Include the affected version, a description of the impact, and reproduction steps.
You will get an acknowledgement within 7 days.

## Supported versions

Until `1.0.0`, only the latest published minor receives fixes.

## Scope

This package provides security-relevant primitives — SSRF/egress classification,
redirect handling, secret redaction and signature verification contracts. Bugs in
those are treated as security issues, not ordinary defects.

Out of scope: vulnerabilities in consuming extensions that arise from misuse of
this package's API. Report those against the consuming repository.

## Trust roots

This package does **not** bundle any signing key. Callers supply their own
armoured public keys to the `./gpg` entrypoint and retain responsibility for key
rotation and freshness checking. A report that this package embeds a stale key is
therefore always a bug — it should embed none.

## Shared CI workflows

Part of this repository's CI is **defined in another repository** — [`4cloudguru/shared-workflows`](https://github.com/4cloudguru/shared-workflows) — and called from `.github/workflows/`. That is a real supply-chain relationship, and it is recorded here so an audit of this repository does not stop at this repository's own tree.

**What runs, and where it is pinned.** Each caller in `.github/workflows/` names the shared workflow on its `uses:` line, pinned to a full 40-hex commit SHA with a trailing comment naming the release that SHA is. The tag is a label; the SHA is what runs. An unlabelled SHA is rejected by the workflow-hardening gate, because a bare 40-hex ref cannot be reviewed or updated deliberately.

**Why the pins have to agree across repositories.** A shared definition drifts differently from a duplicated file: every repository looks like it is using "the shared one" while sitting on different commits, which is *harder* to see than divergent files, not easier. A signature in `security-orchestration` (`shared-workflow-pin-parity`) reports **disagreement** between callers of the same shared workflow — it reports disagreement rather than staleness, because a repository deliberately held back is a decision while N repositories disagreeing without anyone deciding is drift.

**What the shared repository is itself protected by.** Its `main` requires its own zizmor and actionlint checks with `enforce_admins` enabled, restricts which third-party actions may run to an explicit allowlist, issues a read-only default `GITHUB_TOKEN`, and runs the workflow-hardening gate against itself.

**What this repository still controls.** Triggers, concurrency, and the secrets it passes. Secrets are passed **by name** — never `secrets: inherit`, which would forward every secret in this repository to a workflow owned by someone else. Any `vars.*` a shared workflow reads resolve against **this** repository, so credentials and their installation scope do not move.
