# Security Policy

## Reporting a vulnerability

Report privately via [GitHub Security Advisories](https://github.com/sethbacon/pipeline-task-core/security/advisories/new).
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
