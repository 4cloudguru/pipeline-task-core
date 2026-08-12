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
