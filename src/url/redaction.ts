/**
 * Redaction for URLs that carry credentials.
 *
 * Two distinct leaks, with different shapes:
 *
 * 1. A registry-issued pre-signed download URL (Azure blob SAS, AWS S3
 *    presigned, GCS signed) carries a live short-TTL storage credential in its
 *    QUERY STRING. `azure-pipelines-tool-lib` logs the URL at INFO and only
 *    auto-redacts Azure's `sig=`, so the AWS and GCS equivalents print in the
 *    clear on an ordinary run.
 *
 * 2. An operator-supplied registry/mirror URL can carry basic-auth USERINFO
 *    (`https://user:password@host/...`, routine for internal artifact proxies).
 *    Unlike (1) this value is echoed into pipeline variables and messages on
 *    every run.
 *
 * Ported from the `url-secret-redaction.ts` copies in azure-pipelines-terraform
 * (four, byte-identical) and azure-pipelines-packer (one, in sync).
 */

/**
 * Removes C0 and DEL control characters.
 *
 * A CR or LF inside a value that reaches `##vso[task.setvariable variable=x]VALUE`
 * forges a second logging command on the following line. `new URL()` does not
 * catch this: the WHATWG parser silently STRIPS tab/CR/LF while parsing, so
 * `https://ex\nample.com` validates cleanly while the raw string the caller
 * keeps passing around still carries the newline.
 */
export function stripControlCharacters(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001F\u007F]/g, '')
}

/**
 * Characters of a remote response echoed into a failure message by default.
 * Enough to identify a registry's error payload, far short of letting a peer
 * choose the size of the consumer's log.
 */
export const LOG_EXCERPT_CHARS = 512

/**
 * Makes a remote-controlled string safe to interpolate into an error message,
 * a job log line or a CI annotation.
 *
 * Two independent problems, both present wherever a response body was pasted
 * straight into a thrown `Error`:
 *
 * 1. UNBOUNDED LENGTH. The body is chosen by whatever host the operator's URL
 *    names, so without a cap the peer decides how much of the consumer's log
 *    and annotation surface it occupies — enough volume buries the real error.
 * 2. CONTROL CHARACTERS. GitHub's `core.setFailed` percent-encodes only `%`,
 *    CR and LF, and Azure Pipelines' logging commands are line-oriented too, so
 *    every other C0 character survives into the rendered annotation.
 *
 * Stripping runs BEFORE truncating so the retained count is of characters that
 * will actually be displayed, and so a control character cannot ride in on the
 * boundary. The elision marker states how much was dropped, so a reader can
 * tell a short body from a truncated one.
 */
export function truncateForLog(value: string, maxChars: number = LOG_EXCERPT_CHARS): string {
  const safeValue = stripControlCharacters(value)
  if (safeValue.length <= maxChars) return safeValue
  return `${safeValue.slice(0, maxChars)}… (${safeValue.length - maxChars} more characters truncated)`
}

/**
 * Bounds a remote response body before it is interpolated into a thrown error
 * or a log line, so a large — or credential-reflecting — body cannot be dumped
 * wholesale. The credential itself is registered with the host's masker as
 * well; this is defence in depth against verbose error bodies.
 *
 * Callers that scrub known request secrets out of a body do so BEFORE calling
 * this, so a secret straddling the truncation boundary is still scrubbed whole.
 *
 * WHY THIS IS NOT `truncateForLog`. They are close but not the same function,
 * and the difference is visible to an operator: this one caps at 500 rather than
 * 512, marks the elision as `… (truncated)` rather than naming the dropped
 * count, and does NOT strip control characters. It was hand-copied verbatim into
 * four transports in azure-pipelines-terraform and byte-compared across all
 * four, so its output is the failure text those tasks emit today. Converging the
 * two would change that text and the bound each promises, which is a behaviour
 * change and belongs in its own commit — not smuggled into the extraction that
 * gave them a single owner. `truncateForLog` is the stronger of the two (it
 * neutralizes the C0 characters that forge a second logging command) and is
 * where a new caller should start.
 */
export function truncateBody(body: string, max = 500): string {
  if (!body) {
    return ''
  }
  return body.length > max ? `${body.slice(0, max)}… (truncated)` : body
}

function isSensitiveQueryParam(name: string): boolean {
  const lower = name.toLowerCase()
  return (
    lower === 'sig' ||
    lower.includes('signature') ||
    lower.includes('credential') ||
    lower.includes('token')
  )
}

/**
 * Extracts the values of every sensitive query-string parameter.
 *
 * Values come back in the raw percent-encoded form they appear in, so they
 * match the exact substring a logger prints, plus the decoded form when it
 * differs, so a consumer that logs the decoded value is masked too.
 */
export function extractUrlTokenSecrets(url: string): string[] {
  const queryStart = url.indexOf('?')
  if (queryStart === -1) return []
  const query = url.slice(queryStart + 1).split('#')[0] ?? ''
  const secrets: string[] = []
  for (const pair of query.split('&')) {
    const eq = pair.indexOf('=')
    if (eq === -1) continue
    const name = pair.slice(0, eq)
    const rawValue = pair.slice(eq + 1)
    if (!rawValue || !isSensitiveQueryParam(name)) continue
    secrets.push(rawValue)
    let decoded: string
    try {
      decoded = decodeURIComponent(rawValue)
    } catch {
      decoded = rawValue
    }
    if (decoded !== rawValue) secrets.push(decoded)
  }
  return secrets
}

/**
 * Strips the ENTIRE query string for safe logging. Dropping the whole query
 * rather than redacting known parameter names means an unforeseen token
 * parameter cannot leak through this path.
 */
export function redactUrl(url: string): string {
  try {
    const parsed = new URL(url)
    return parsed.origin + parsed.pathname + (parsed.search ? '?<redacted>' : '')
  } catch {
    // Unparseable input reaches the log as-is, so it is neutralized here. The
    // success path above needs no such step: the parser strips tab/CR/LF and
    // percent-encodes the remaining controls in `pathname`.
    return stripControlCharacters(url.split('?')[0] ?? url)
  }
}

/**
 * Scrubs a raw URL and its extracted secrets out of a message.
 *
 * Scrubbing the individual token values as well as the URL guards against a
 * downstream library embedding a differently-transformed copy — tool-lib's own
 * partial `sig=` redaction produces exactly that.
 */
export function scrubSecretsFromMessage(
  message: string,
  url: string,
  secrets: readonly string[],
): string {
  let safeMessage = message.split(url).join(redactUrl(url))
  for (const secret of secrets) {
    // Splitting on an empty needle explodes the message into single characters
    // and rejoins it with the replacement.
    if (!secret) continue
    safeMessage = safeMessage.split(secret).join('<redacted>')
  }
  return safeMessage
}

/**
 * Reads the raw `user:password` substring from a URL, or null when there is
 * none. Operates on the raw string rather than a parsed URL, so the exact bytes
 * a logger would print are what gets masked. The authority ends at the first
 * `/`, `?` or `#`; the userinfo/host split uses the LAST `@` within it, which
 * matches the WHATWG parser and covers an `@` inside the password.
 */
function rawUserInfo(url: string): string | null {
  const schemeEnd = url.indexOf('://')
  if (schemeEnd === -1) return null
  const authorityStart = schemeEnd + 3
  const rest = url.slice(authorityStart)
  const authorityEnd = rest.search(/[/?#]/)
  const authority = authorityEnd === -1 ? rest : rest.slice(0, authorityEnd)
  const at = authority.lastIndexOf('@')
  if (at === -1) return null
  return authority.slice(0, at)
}

/**
 * Extracts the credential material embedded in a URL's userinfo, for
 * registration with the agent's secret masker.
 *
 * Returns the whole `user:password` pair plus, when a password is present, the
 * password alone — each in raw and percent-decoded form. The username is not
 * masked on its own, so a common value like `admin` does not get redacted out
 * of unrelated log lines; a lone userinfo with no `:` is treated as a token and
 * masked whole.
 */
export function extractUrlUserInfoSecrets(url: string): string[] {
  const userInfo = rawUserInfo(url)
  if (!userInfo) return []
  const secrets: string[] = []
  const pushWithDecoded = (raw: string): void => {
    if (!raw) return
    secrets.push(raw)
    let decoded: string
    try {
      decoded = decodeURIComponent(raw)
    } catch {
      decoded = raw
    }
    if (decoded !== raw && decoded) secrets.push(decoded)
  }
  pushWithDecoded(userInfo)
  const colon = userInfo.indexOf(':')
  if (colon !== -1) pushWithDecoded(userInfo.slice(colon + 1))
  return secrets
}

/**
 * Strips the userinfo so a URL can be echoed into a pipeline variable or a
 * message. Unlike `redactUrl` this keeps scheme, host, port, path and query: an
 * operator-supplied registry URL carries its credential only in the userinfo,
 * and keeping the rest lets the operator still see which registry was used.
 */
export function redactUrlUserInfo(url: string): string {
  // Before anything else, so the index arithmetic below lines up with the value
  // actually returned.
  const safeUrl = stripControlCharacters(url)
  const userInfo = rawUserInfo(safeUrl)
  if (userInfo === null) return safeUrl
  const authorityStart = safeUrl.indexOf('://') + 3
  return safeUrl.slice(0, authorityStart) + safeUrl.slice(authorityStart + userInfo.length + 1)
}
