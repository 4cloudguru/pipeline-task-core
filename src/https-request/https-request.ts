/**
 * The credential-bearing raw-`https.request` transport.
 *
 * A SECOND transport, deliberately not merged into `createHttpClient`. The two
 * sit on different primitives and different trust models: the `http` module's
 * client downloads public release artifacts over `fetch` + `AbortController` and
 * sends no credential, while everything here attaches a bearer token, an API key
 * or a basic credential to every request. That is why the https:// guard below
 * is phrased as a refusal to send CREDENTIALS rather than a refusal to fetch.
 *
 * WHY RAW `https.request` AND NOT `fetch`/`undici`. Two independent reasons,
 * both load-bearing:
 *
 *  1. The consumers' tests intercept HTTP with `nock`, which patches `http` and
 *     `https` and does not see `undici`. Moving this onto `fetch` would silently
 *     delete the interception those suites exist to provide — the tests would
 *     still be there, still green, and no longer testing a transport.
 *  2. This package has no `undici` dependency and is not going to grow one; its
 *     consumers pin `undici` themselves, currently to 7.x because 8 breaks
 *     against the Node 24 bundles.
 *
 * So the shape is not incidental. `src/https-request/https-request.test.ts`
 * asserts the interception directly, which is what makes a future "modernise the
 * transport" change fail a test rather than quietly land.
 *
 * Ported from the byte-identical `https-client.ts` pair in
 * azure-pipelines-terraform and the hand-tracked parallel inside
 * PublishKbArticle's `servicenow-http.ts`. The https:// guard was the one piece
 * of that family which no parity gate covered at all — the repo's own gate
 * called it out as "a hand-tracked parallel" — so it is the piece that most
 * needed a single owner.
 */
import type { IncomingHttpHeaders } from 'node:http'
import * as https from 'node:https'
import { MAX_RESPONSE_BYTES } from '../http/http'

/**
 * Per-request socket timeout. An INACTIVITY timer: it is what stops a hung
 * connection from running to the CI job's own timeout, which is the only other
 * bound a stalled request has.
 */
export const DEFAULT_REQUEST_TIMEOUT_MS = 100_000

export interface HttpsResponse {
  status: number
  body: string
  /** Raw response headers, so a caller can read e.g. `Retry-After` itself. */
  headers: IncomingHttpHeaders
}

export interface HttpsRequestOptions {
  method: string
  /**
   * Already parsed, deliberately. Every caller has its own message for an
   * unparseable operator-supplied URL ("Invalid ServiceNow URL: ...") and its
   * own query-parameter handling, and both are decisions this module has no
   * business making. Taking a `URL` means the parse cannot fail in here.
   */
  url: URL
  headers?: Record<string, string> | undefined
  /**
   * Already encoded, because the encoding is the caller's (JSON, form, raw
   * binary). `Content-Length` is set from it, and an EMPTY buffer is still a
   * body: it sends `Content-Length: 0`, where `undefined` sends no body and no
   * length header at all.
   */
  body?: Buffer | undefined
  timeoutMs?: number | undefined
  /**
   * Passed through only when explicitly supplied. Node's TLS layer treats an
   * absent key differently from a present `undefined` one — absent falls back
   * to `NODE_TLS_REJECT_UNAUTHORIZED` — so a caller that never mentions TLS
   * verification must not have a value invented for it here.
   */
  rejectUnauthorized?: boolean | undefined
  /**
   * The agent that carries the request, which is how a proxy is honoured:
   * `node:https` ignores `HTTPS_PROXY` and every agent setting unless handed
   * one. See `createProxyTunnelAgent`.
   */
  agent?: https.Agent | undefined
  /** Ceiling on the response buffered in memory. Default `MAX_RESPONSE_BYTES`. */
  maxResponseBytes?: number | undefined
}

/**
 * Issues one request and resolves with the status, the bounded body and the
 * response headers. A non-2xx is a RESULT, not an error: callers differ on what
 * to do with one (the registry publish inspects it, the ServiceNow client
 * rejects on it), so the decision stays with them.
 *
 * Rejects on a non-https URL, a transport failure, the socket timeout, or the
 * response exceeding `maxResponseBytes`.
 *
 * The byte cap is not redundant with the timeout. The timeout catches a
 * connection that goes idle; it never fires on an endpoint that streams
 * continuously, which is exactly how an agent's memory gets exhausted.
 */
export function httpsRequest(options: HttpsRequestOptions): Promise<HttpsResponse> {
  const { url, body } = options
  const timeoutMs = options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS
  const maxResponseBytes = options.maxResponseBytes ?? MAX_RESPONSE_BYTES

  return new Promise<HttpsResponse>((resolve, reject) => {
    // Never send a credential-bearing request over a non-HTTPS connection.
    if (url.protocol !== 'https:') {
      reject(
        new Error(
          `Refusing to send credentials over a non-HTTPS URL (scheme '${url.protocol}//' on host '${url.host}'). Use an https:// URL.`,
        ),
      )
      return
    }

    const headers: Record<string, string> = { ...(options.headers ?? {}) }
    if (body !== undefined) {
      headers['Content-Length'] = String(body.length)
    }

    const requestOptions: https.RequestOptions = {
      method: options.method,
      hostname: url.hostname,
      port: url.port || 443,
      path: `${url.pathname}${url.search}`,
      headers,
      agent: options.agent,
    }
    if (options.rejectUnauthorized !== undefined) {
      requestOptions.rejectUnauthorized = options.rejectUnauthorized
    }

    const req = https.request(requestOptions, (res) => {
      const chunks: Buffer[] = []
      let total = 0
      let overflowed = false
      res.on('data', (chunk: Buffer) => {
        total += chunk.length
        if (total > maxResponseBytes) {
          overflowed = true
          req.destroy(new Error(`Response from ${url.host} exceeded ${maxResponseBytes} bytes.`))
          return
        }
        chunks.push(chunk)
      })
      res.on('end', () => {
        // The destroy above rejects through the 'error' handler; resolving here
        // as well would settle the promise with the truncated body it refused.
        if (overflowed) {
          return
        }
        resolve({
          status: res.statusCode ?? 0,
          body: Buffer.concat(chunks).toString('utf8'),
          headers: res.headers,
        })
      })
    })
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Request to ${url.host} timed out after ${timeoutMs}ms.`))
    })
    req.on('error', reject)
    if (body !== undefined) {
      req.write(body)
    }
    req.end()
  })
}
