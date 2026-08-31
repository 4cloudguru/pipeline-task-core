/**
 * HTTPS-pinned fetch primitives: manual redirect following with per-hop
 * re-authorization, bounded in-memory bodies, retry classification, and a
 * streaming download that re-checks the host at every hop.
 *
 * Ported from the `http-client.ts` family in azure-pipelines-terraform (three
 * byte-identical installer copies) and azure-pipelines-packer (one copy that
 * has DIVERGED). Neither side was a superset: terraform's carries the response
 * cap, 429/Retry-After handling and the GitHub asset-redirect exception;
 * packer's carries the retry-safe download attempt. This takes the union.
 *
 * Nothing here imports `azure-pipelines-task-lib` or `undici`. Proxy dispatch,
 * secret masking, debug logging and localized message text are all injected by
 * the task, which is what lets one implementation serve both extensions and
 * keeps this package free of runtime dependencies.
 */
import { createWriteStream, promises as fsPromises } from 'node:fs'
import { Readable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { retryAsync } from '../retry/retry'
import { parseRetryAfterMs } from '../retry/retry-after'
import { truncateForLog } from '../url/redaction'

/** Quick metadata lookups: checkpoint/registry version endpoints, checksums, signatures. */
export const METADATA_TIMEOUT_MS = 60_000

/** Binary/archive downloads, which need a far larger ceiling than metadata. */
export const DOWNLOAD_TIMEOUT_MS = 600_000

/** Redirect hops followed before a chain is refused as a loop. */
export const MAX_REDIRECTS = 5

/**
 * Ceiling on a response buffered in memory. Node's `fetch()` imposes no limit
 * of its own — `.json()`/`.text()`/`.arrayBuffer()` buffer until stream end or
 * process OOM — so an endpoint reachable through an operator-supplied registry
 * or mirror URL could otherwise exhaust the agent. Streaming downloads go
 * through `downloadToFile` and are not subject to this.
 */
export const MAX_RESPONSE_BYTES = 10 * 1024 * 1024

/**
 * A failure carrying whether it is worth repeating. `retryAfterMs` holds the
 * capped delay a 429 asked for; when undefined the caller falls back to
 * jittered backoff.
 */
export class HttpError extends Error {
  readonly retryable: boolean
  readonly retryAfterMs: number | undefined

  constructor(message: string, retryable: boolean, retryAfterMs?: number) {
    super(message)
    this.name = 'HttpError'
    this.retryable = retryable
    this.retryAfterMs = retryAfterMs
  }
}

/**
 * Whether a status is worth repeating: a server-side 5xx, or 429. The
 * unauthenticated GitHub release API, the checkpoint API and registry
 * endpoints all rate-limit with 429, so treating it as fatal fails installs
 * that would have succeeded a second later.
 */
export function isRetryableHttpStatus(status: number): boolean {
  return status >= 500 || status === 429
}

/** The capped Retry-After delay from a 429; undefined for any other status or an absent/invalid header. */
export function retryAfterMsFromResponse(response: Response): number | undefined {
  return response.status === 429
    ? parseRetryAfterMs(response.headers.get('retry-after'))
    : undefined
}

/** Decides whether a redirect hop may be followed. Receives the ORIGINAL host, not the previous hop's. */
export type RedirectPolicy = (originHost: string, next: URL) => boolean | Promise<boolean>

/** The default: a redirect may not leave the host the request started on. */
export const sameHostOnly: RedirectPolicy = (originHost, next) => next.host === originHost

/**
 * Opt-in exception for GitHub release assets, which 302 from github.com onto
 * GitHub's own asset CDN (`objects.` / `release-assets.githubusercontent.com`).
 * Callers that fetch verification material from GitHub releases — OpenTofu's
 * SHA256SUMS, OPA's .sha256, terraform-docs' .sha256sum — fail closed under
 * `sameHostOnly` alone and need this; callers that pull only from
 * releases.hashicorp.com must not enable it.
 *
 * The redirect must have been issued by the TLS-authenticated github.com
 * origin, must stay https, and must land on one of GitHub's own named asset
 * CDN hosts. An explicit set, not a `.githubusercontent.com` suffix test:
 * that suffix also matches raw.githubusercontent.com and
 * gist.githubusercontent.com, both of which serve attacker-authored file
 * content from any public repo or gist, not GitHub-issued release assets.
 */
const GITHUB_ASSET_CDN_HOSTS = new Set(['objects.githubusercontent.com', 'release-assets.githubusercontent.com'])

export const githubAssetRedirects: RedirectPolicy = (originHost, next) =>
  (originHost === 'github.com' || originHost === 'www.github.com') &&
  next.protocol === 'https:' &&
  GITHUB_ASSET_CDN_HOSTS.has(next.host)

/** Permits a hop that ANY of `policies` accepts. With none supplied, every hop is refused. */
export function anyRedirectPolicy(...policies: readonly RedirectPolicy[]): RedirectPolicy {
  return async (originHost, next) => {
    for (const policy of policies) {
      if (await policy(originHost, next)) return true
    }
    return false
  }
}

/** Message text the task supplies, so rejections can be localized and name the operator's own inputs. */
export interface HttpMessages {
  /** A non-https URL was supplied or redirected to. */
  insecureUrl: (url: string) => string
  /** A request completed with a non-success status. */
  requestFailed: (url: string, status: number) => string
}

const DEFAULT_MESSAGES: HttpMessages = {
  insecureUrl: (url) => `Refusing to fetch ${url}: only https:// URLs are permitted.`,
  requestFailed: (url, status) => `Request to ${url} failed with HTTP ${status}.`,
}

export interface HttpClientOptions {
  /**
   * Per-request `fetch` init, re-evaluated for every attempt AND every redirect
   * hop. This is where a task supplies an undici `ProxyAgent` dispatcher;
   * re-evaluating means a proxy change between retries is picked up.
   *
   * It receives the URL of the hop about to be issued, because a proxy decision
   * belongs to the destination: `NO_PROXY` is matched against it and its scheme
   * picks the variable (see `resolveEnvProxy`), so a chain that redirects off
   * the origin has to be resolved again. Supplying a dispatcher does not move
   * the egress decision — `authorizeHost` still runs against the destination on
   * every hop, and a tunnel to a refused host is still refused.
   */
  fetchOptions?: (url: string) => RequestInit | Promise<RequestInit>
  /** `fetch` implementation, injectable so tests need no network. Defaults to the global. */
  fetchImpl?: typeof fetch
  /** Receives retry diagnostics. Wire to the task's debug channel. */
  debug?: (message: string) => void
  /** Overrides for individual message strings; anything omitted keeps the default text. */
  messages?: Partial<HttpMessages>
  /** Redirect rule applied to every hop. Defaults to `sameHostOnly`. */
  redirectPolicy?: RedirectPolicy
  /** Total attempts, including the first. Default 3. */
  attempts?: number
  /** Backoff base in ms. Default 200. */
  baseDelayMs?: number
  /** Ceiling on a buffered response body. Default `MAX_RESPONSE_BYTES`. */
  maxResponseBytes?: number
}

/** Authorizes a host before it is contacted. THROWS to refuse, so the message can name the host and the allowlist. */
export type AuthorizeHost = (host: string) => void | Promise<void>

/** A completed exchange whose status the caller interprets itself. See {@link HttpClient.fetchStatusText}. */
export interface HttpStatusText {
  status: number
  body: string
}

export interface HttpClient {
  /**
   * Fetches an https URL under a wall-clock timeout covering the connection,
   * every redirect hop, the response headers AND `consume`.
   *
   * The bound is an abort signal, not pre-emption: it reaches the connection
   * and the response body stream, which real `fetch` wires to the signal, so a
   * stalled body IS bounded. Consume work that is not wired to it — a
   * `pipeline()` onto a stalled network share — is not, and runs past the
   * deadline.
   *
   * Redirects are followed manually rather than via `redirect: 'follow'`,
   * because each hop's Location has to be re-checked before it is followed.
   */
  fetchWithTimeout: <T>(
    url: string,
    timeoutMs: number,
    consume: (response: Response) => Promise<T>,
    redirectPolicy?: RedirectPolicy,
  ) => Promise<T>
  /**
   * Returns the status AND the bounded body, without throwing on a non-2xx.
   *
   * Exists because a caller that needs the status alongside the body used to
   * have no bounded way to get it: `fetchText` and friends throw on non-2xx and
   * hand back only the text, so such a caller reached for `fetchWithTimeout`
   * with its own `async (r) => ({ status: r.status, body: await r.text() })`.
   * That `consume` never touches `readBounded`, so `maxResponseBytes` silently
   * does not apply to it and a hostile or wedged endpoint can buffer until the
   * agent OOMs. Both GitHub Actions in this family had written exactly that.
   *
   * Retries still cover transport failures and timeouts; an HTTP status is a
   * result here, not an error, so it is returned rather than repeated.
   */
  fetchStatusText: (url: string, timeoutMs?: number) => Promise<HttpStatusText>
  fetchJson: <T>(url: string, timeoutMs?: number) => Promise<T>
  fetchText: (url: string, timeoutMs?: number) => Promise<string>
  /** Null on 404, so callers can tell "not published" from a failure without matching error text. */
  fetchTextAllow404: (url: string, timeoutMs?: number) => Promise<string | null>
  fetchBuffer: (url: string, timeoutMs?: number) => Promise<Uint8Array>
  /** Null on 404, so callers can tell "not published" from a failure without matching error text. */
  fetchBufferAllow404: (url: string, timeoutMs?: number) => Promise<Uint8Array | null>
  /**
   * Streams a download to disk, authorizing the initial host and every
   * redirect hop against the same `authorizeHost` decision. Streaming keeps a
   * large archive off the heap, and per-hop authorization closes the gap where
   * an allowlisted download URL itself redirects somewhere arbitrary.
   */
  downloadToFile: (
    url: string,
    destPath: string,
    timeoutMs: number,
    authorizeHost: AuthorizeHost,
  ) => Promise<void>
}

export function createHttpClient(options: HttpClientOptions = {}): HttpClient {
  const doFetch: typeof fetch = options.fetchImpl ?? ((...args) => fetch(...args))
  const getFetchOptions = options.fetchOptions ?? ((_url: string): RequestInit => ({}))
  const messages: HttpMessages = { ...DEFAULT_MESSAGES, ...options.messages }
  const defaultRedirectPolicy = options.redirectPolicy ?? sameHostOnly
  const attempts = options.attempts ?? 3
  const baseDelayMs = options.baseDelayMs ?? 200
  const maxResponseBytes = options.maxResponseBytes ?? MAX_RESPONSE_BYTES

  async function fetchWithTimeout<T>(
    url: string,
    timeoutMs: number,
    consume: (response: Response) => Promise<T>,
    redirectPolicy: RedirectPolicy = defaultRedirectPolicy,
  ): Promise<T> {
    if (!url.startsWith('https://')) {
      throw new HttpError(messages.insecureUrl(url), false)
    }
    const originHost = new URL(url).host

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    try {
      let currentUrl = url
      for (let redirects = 0; ; redirects++) {
        const init = await getFetchOptions(currentUrl)
        const response = await doFetch(currentUrl, {
          ...init,
          signal: controller.signal,
          redirect: 'manual',
        })
        const location =
          response.status >= 300 && response.status < 400 ? response.headers.get('location') : null
        if (location === null) {
          return await consume(response)
        }
        if (redirects >= MAX_REDIRECTS) {
          throw new HttpError(`Too many redirects fetching ${url} (limit ${MAX_REDIRECTS}).`, false)
        }
        // A Location header is remote-controlled, so both messages below echo a
        // string the peer chose. The WHATWG parser has already neutralized the
        // control characters (it strips tab/CR/LF and percent-encodes the rest),
        // but not the LENGTH — a hostname or path bounded only by the header
        // limit would otherwise decide how much of the consumer's log the
        // failure occupies. Same excerpt-safety helper as every other remote
        // string this module interpolates.
        const next = new URL(location, currentUrl)
        if (next.protocol !== 'https:') {
          throw new HttpError(messages.insecureUrl(truncateForLog(next.toString())), false)
        }
        if (!(await redirectPolicy(originHost, next))) {
          throw new HttpError(
            `Refusing to follow an off-host redirect (${originHost} -> ${truncateForLog(next.host)}) while fetching ${url}.`,
            false,
          )
        }
        currentUrl = next.toString()
      }
    } catch (error) {
      if (controller.signal.aborted) {
        throw new HttpError(`Request to ${url} timed out after ${timeoutMs}ms.`, true)
      }
      throw error
    } finally {
      clearTimeout(timer)
    }
  }

  /**
   * Repeats transient failures — transport errors, timeouts, 5xx, 429 — with
   * jittered backoff, honouring a capped Retry-After when the server sent one.
   * A non-HttpError is a transport/DNS/TLS failure and counts as transient; an
   * HttpError is repeated only when it says so.
   */
  function withRetry<T>(call: () => Promise<T>): Promise<T> {
    return retryAsync(call, {
      retries: attempts - 1,
      baseDelayMs,
      retryError: (error) => (error instanceof HttpError ? error.retryable : true),
      delayMs: (_attempt, backoffMs, outcome) =>
        outcome.kind === 'error' &&
        outcome.error instanceof HttpError &&
        outcome.error.retryAfterMs !== undefined
          ? outcome.error.retryAfterMs
          : backoffMs,
      onRetry: (attempt, _delayMs, outcome) => {
        const error = outcome.kind === 'error' ? outcome.error : undefined
        options.debug?.(
          `Fetch attempt ${attempt + 1} failed (${error instanceof Error ? error.message : String(error)}); retrying...`,
        )
      },
    })
  }

  /** Reads a body into memory under a hard byte count, cancelling the stream rather than buffering past it. */
  async function readBounded(response: Response, url: string): Promise<Uint8Array> {
    if (!response.body) {
      return new Uint8Array(await response.arrayBuffer())
    }
    const reader = response.body.getReader()
    const chunks: Uint8Array[] = []
    let total = 0
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (value === undefined) continue
      total += value.byteLength
      if (total > maxResponseBytes) {
        await reader.cancel(`Response exceeded ${maxResponseBytes} bytes.`).catch(() => undefined)
        throw new HttpError(`Response from ${url} exceeded ${maxResponseBytes} bytes.`, false)
      }
      chunks.push(value)
    }
    const out = new Uint8Array(total)
    let offset = 0
    for (const chunk of chunks) {
      out.set(chunk, offset)
      offset += chunk.byteLength
    }
    return out
  }

  function failFor(url: string, response: Response): HttpError {
    return new HttpError(
      messages.requestFailed(url, response.status),
      isRetryableHttpStatus(response.status),
      retryAfterMsFromResponse(response),
    )
  }

  function fetchJson<T>(url: string, timeoutMs: number = METADATA_TIMEOUT_MS): Promise<T> {
    return withRetry(() =>
      fetchWithTimeout(url, timeoutMs, async (response) => {
        if (!response.ok) throw failFor(url, response)
        const text = Buffer.from(await readBounded(response, url)).toString('utf8')
        try {
          return JSON.parse(text) as T
        } catch {
          // A 2xx that is not JSON — a captive portal, a WAF, an internal
          // registry answering with an HTML error page — is deterministic, not
          // transient. A bare SyntaxError would default to retryable and burn
          // the whole budget on it.
          //
          // `truncateForLog`, not `.slice()`: the peer chose these bytes, and a
          // length bound leaves every C0 control in them intact on the way to
          // `core.setFailed`/`tl.setResult`. It also states how much it dropped,
          // which is what the old "first N bytes" prose was there to convey.
          throw new HttpError(
            `Response from ${url} was not valid JSON: ${truncateForLog(text)}`,
            false,
          )
        }
      }),
    )
  }

  function fetchStatusText(
    url: string,
    timeoutMs: number = METADATA_TIMEOUT_MS,
  ): Promise<HttpStatusText> {
    return withRetry(() =>
      fetchWithTimeout(url, timeoutMs, async (response) => ({
        status: response.status,
        body: Buffer.from(await readBounded(response, url)).toString('utf8'),
      })),
    )
  }

  function fetchText(url: string, timeoutMs: number = METADATA_TIMEOUT_MS): Promise<string> {
    return withRetry(() =>
      fetchWithTimeout(url, timeoutMs, async (response) => {
        if (!response.ok) throw failFor(url, response)
        return Buffer.from(await readBounded(response, url)).toString('utf8')
      }),
    )
  }

  function fetchTextAllow404(
    url: string,
    timeoutMs: number = METADATA_TIMEOUT_MS,
  ): Promise<string | null> {
    return withRetry(() =>
      fetchWithTimeout(url, timeoutMs, async (response) => {
        if (response.status === 404) return null
        if (!response.ok) throw failFor(url, response)
        return Buffer.from(await readBounded(response, url)).toString('utf8')
      }),
    )
  }

  function fetchBuffer(url: string, timeoutMs: number = DOWNLOAD_TIMEOUT_MS): Promise<Uint8Array> {
    return withRetry(() =>
      fetchWithTimeout(url, timeoutMs, async (response) => {
        if (!response.ok) throw failFor(url, response)
        return readBounded(response, url)
      }),
    )
  }

  function fetchBufferAllow404(
    url: string,
    timeoutMs: number = DOWNLOAD_TIMEOUT_MS,
  ): Promise<Uint8Array | null> {
    return withRetry(() =>
      fetchWithTimeout(url, timeoutMs, async (response) => {
        if (response.status === 404) return null
        if (!response.ok) throw failFor(url, response)
        return readBounded(response, url)
      }),
    )
  }

  /**
   * One download attempt, safe to repeat: it clears whatever a prior attempt
   * left at `destPath` before opening its own stream, and re-runs
   * `authorizeHost` from scratch for the initial host and every hop, so a
   * retry can neither resume into a truncated file nor inherit a stale
   * authorization.
   *
   * An `authorizeHost` refusal is re-thrown NON-retryable. Without that it
   * would be classified as transport failure and repeated — handing a host
   * that resolves differently per lookup several chances inside one run to
   * flip from refused to allowed.
   */
  async function attemptDownload(
    url: string,
    destPath: string,
    timeoutMs: number,
    authorizeHost: AuthorizeHost,
  ): Promise<void> {
    const assertAllowed = async (host: string): Promise<void> => {
      try {
        await authorizeHost(host)
      } catch (error) {
        throw new HttpError(error instanceof Error ? error.message : String(error), false)
      }
    }

    await fsPromises.unlink(destPath).catch(() => undefined)
    await assertAllowed(new URL(url).hostname)

    try {
      await fetchWithTimeout(
        url,
        timeoutMs,
        async (response) => {
          if (!response.ok) throw failFor(url, response)
          if (!response.body) {
            throw new HttpError(`Download from ${url} returned an empty response body.`, false)
          }
          await pipeline(
            Readable.fromWeb(response.body as Parameters<typeof Readable.fromWeb>[0]),
            createWriteStream(destPath),
          )
        },
        // A download's hop rule IS the allowlist, replacing the client's
        // redirect policy: a registry download URL legitimately redirects to a
        // CDN, which sameHostOnly would refuse, and the allowlist is the
        // stronger and more specific gate. next.host, not next.hostname, so an
        // explicit port travels with the host and an allowlist entry without
        // one cannot silently match a redirect to a different port.
        async (_originHost, next) => {
          await assertAllowed(next.host)
          return true
        },
      )
    } catch (error) {
      // A stream failure partway through (disk full, permissions) leaves a
      // truncated file; remove it so no caller mistakes it for a complete,
      // verifiable download.
      await fsPromises.unlink(destPath).catch(() => undefined)
      throw error
    }
  }

  return {
    fetchWithTimeout,
    fetchStatusText,
    fetchJson,
    fetchText,
    fetchTextAllow404,
    fetchBuffer,
    fetchBufferAllow404,
    downloadToFile: (url, destPath, timeoutMs, authorizeHost) =>
      withRetry(() => attemptDownload(url, destPath, timeoutMs, authorizeHost)),
  }
}
