/**
 * `@sethbacon/pipeline-task-core`
 *
 * Shared HTTP, retry, egress and redaction primitives for the Azure Pipelines
 * task extensions. The module inventory and the design decisions behind it are
 * in `docs/initiatives/initiative-1-shared-task-core.md`.
 *
 * GPG verification lives behind the `./gpg` subpath so that consumers which do
 * not verify HashiCorp release signatures never pull in `openpgp`.
 */

export { RETRY_AFTER_CAP_MS, parseRetryAfterMs } from './retry/retry-after'
export { retryAsync } from './retry/retry'
export type { RetryController, RetryOutcome } from './retry/retry'
