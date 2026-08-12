/**
 * `@4cloudguru/pipeline-task-core`
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
export {
  assertEgressHostAllowed,
  bareHost,
  isHostAllowed,
  isIpLiteral,
  isPrivateIpv4Address,
  isPrivateOrLinkLocalHost,
  looseSuffixOnlyMatch,
  parseAllowedHosts,
  parseIpv4,
  parseIpv6,
  resolvesToPrivateOrLinkLocalAddress,
} from './egress/egress'
export type { EgressHostMessages } from './egress/egress'
export {
  DOWNLOAD_TIMEOUT_MS,
  HttpError,
  MAX_REDIRECTS,
  MAX_RESPONSE_BYTES,
  METADATA_TIMEOUT_MS,
  anyRedirectPolicy,
  createHttpClient,
  githubAssetRedirects,
  isRetryableHttpStatus,
  retryAfterMsFromResponse,
  sameHostOnly,
} from './http/http'
export type {
  AuthorizeHost,
  HttpClient,
  HttpClientOptions,
  HttpMessages,
  RedirectPolicy,
} from './http/http'
export {
  extractUrlTokenSecrets,
  extractUrlUserInfoSecrets,
  redactUrl,
  redactUrlUserInfo,
  scrubSecretsFromMessage,
  stripControlCharacters,
} from './url/redaction'
export { validateUrlPathSegment } from './url/path-segment'
