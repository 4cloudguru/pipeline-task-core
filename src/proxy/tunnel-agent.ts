/**
 * A CONNECT-tunnelling `https.Agent` for the raw-`https.request` transports.
 *
 * The counterpart of what {@link resolveProxy} does for `fetch`. There, the
 * consumer hands the resolved URL to an undici `ProxyAgent`; a raw
 * `https.request` has no dispatcher to hand anything to, so the proxy has to be
 * an `https.Agent` that opens an HTTP `CONNECT` tunnel and upgrades the
 * tunnelled socket to TLS itself. That agent is built here, from Node built-ins
 * only — `undici` stays a consumer dependency exactly as it is for `resolveProxy`.
 *
 * Ported from the three hand-copies in azure-pipelines-terraform
 * (TerraformModulePublish's and TerraformDriftReport's `https-client.ts`, and
 * PublishKbArticle's `servicenow-http.ts`), where the class body was held
 * byte-identical by a repo-local parity gate. That gate could only ever see
 * files in its own repository, and PublishKbArticle is moving to a repository of
 * its own; sharing the class as a dependency is what survives the move.
 *
 * WHAT THIS DOES NOT DECIDE. Same as `resolveProxy`: a tunnel changes which
 * socket carries the request, never which destination is permitted. A CONNECT
 * tunnel to a refused host is still refused egress, and `assertEgressHostAllowed`
 * still has to run against the destination.
 */
import * as http from 'node:http'
import * as https from 'node:https'
import * as net from 'node:net'
import type { Duplex } from 'node:stream'
import * as tls from 'node:tls'
import { extractUrlUserInfoSecrets } from '../url/redaction'
import type { AgentProxyConfiguration } from './proxy'

export interface ProxyTunnelAgentOptions {
  /**
   * Bounds the CONNECT round-trip AND the inner TLS handshake, which both run
   * before the outer request's own socket timeout can arm.
   */
  tunnelTimeoutMs: number
  /**
   * Registers a credential literal with the host's log masker
   * (`tasks.setSecret` on an Azure DevOps agent, `core.setSecret` on a GitHub
   * runner).
   *
   * REQUIRED, not optional, and that is the point: the derived `Basic`
   * credential this module builds is a byte sequence the caller never sees, so
   * a caller that forgot to mask it could not be blamed for the leak. Making it
   * a required parameter turns "the proxy password was not masked" from a
   * review question into a compile error.
   */
  registerSecret: (secret: string) => void
}

/**
 * Tunnels every connection through an HTTP(S) proxy via a CONNECT request, then
 * upgrades the tunnelled socket to TLS, instead of connecting to the target
 * host directly.
 */
class ProxyTunnelAgent extends https.Agent {
  constructor(
    private readonly proxyHostname: string,
    private readonly proxyPort: number,
    private readonly proxyAuthHeader: string | undefined,
    private readonly tunnelTimeoutMs: number,
  ) {
    super()
  }

  override createConnection(
    options: https.RequestOptions,
    callback?: (err: Error | null, stream: Duplex) => void,
  ): Duplex | null | undefined {
    const targetHost = String(options.hostname ?? options.host ?? '')
    const targetPort = options.port ? Number(options.port) : 443
    const target = `${targetHost}:${targetPort}`
    let settled = false
    let tlsSocket: tls.TLSSocket | undefined
    // Boxed so settle() (defined before the timer is armed) can clear it.
    const deadline: { timer?: ReturnType<typeof setTimeout> } = {}
    const connectReq = http.request({
      host: this.proxyHostname,
      port: this.proxyPort,
      method: 'CONNECT',
      path: target,
      headers: {
        Host: target,
        ...(this.proxyAuthHeader ? { 'Proxy-Authorization': this.proxyAuthHeader } : {}),
      },
    })
    // Settle this connection attempt exactly once, then stop the deadline timer.
    // On failure, actively tear down the pending CONNECT request and any
    // half-open TLS socket so a wedged proxy leaves nothing dangling.
    const settle = (err: Error | null, stream?: tls.TLSSocket): void => {
      if (settled) {
        return
      }
      settled = true
      if (deadline.timer) {
        clearTimeout(deadline.timer)
      }
      if (err) {
        connectReq.destroy()
        tlsSocket?.destroy()
      }
      callback?.(err, (stream ?? undefined) as unknown as Duplex)
    }
    // Bound the whole CONNECT round-trip AND the inner TLS handshake below with
    // the caller's configured timeout. The outer request's req.setTimeout() only
    // arms once this createConnection callback fires (invoking that callback is
    // what emits the request's 'socket' event), so a proxy that accepts the TCP
    // connection but never answers the CONNECT -- a wedged/overloaded corporate
    // proxy -- would otherwise hang past timeoutMs until the job timeout. This
    // timer is that phase's only deadline; it is cleared the instant the tunnel
    // is established (or fails), after which req.setTimeout() takes over.
    deadline.timer = setTimeout(
      () =>
        settle(
          new Error(
            `Proxy CONNECT tunnel to ${target} via ${this.proxyHostname}:${this.proxyPort} timed out after ${this.tunnelTimeoutMs}ms.`,
          ),
        ),
      this.tunnelTimeoutMs,
    )
    connectReq.on('connect', (res, socket) => {
      if (res.statusCode !== 200) {
        socket.destroy()
        settle(new Error(`Proxy CONNECT to ${target} failed with status ${res.statusCode}.`))
        return
      }
      try {
        // Node's TLS SNI extension (servername) may not carry an IP-address
        // literal (RFC 6066) -- Node throws synchronously if asked to. Node's
        // own default (non-proxied) connection path silently omits servername
        // in that case; mirror that here rather than sending SNI only when the
        // target host is a literal IP.
        const sniName = options.servername || targetHost
        const tlsOptions: tls.ConnectionOptions = {
          socket,
          servername: net.isIP(sniName) ? undefined : sniName,
        }
        // Only set rejectUnauthorized when the caller passed an explicit value.
        // Node's own TLS layer treats an explicitly-present `undefined` key
        // differently from an absent one: an absent key falls back to the
        // NODE_TLS_REJECT_UNAUTHORIZED env var (matching the non-proxied
        // https.request default path), while an explicit `undefined` does not.
        if (options.rejectUnauthorized !== undefined) {
          tlsOptions.rejectUnauthorized = options.rejectUnauthorized
        }
        tlsSocket = tls.connect(tlsOptions)
        tlsSocket.once('secureConnect', () => settle(null, tlsSocket))
        tlsSocket.once('error', (err) => settle(err))
      } catch (err) {
        socket.destroy()
        settle(err instanceof Error ? err : new Error(String(err)))
      }
    })
    connectReq.on('error', (err) => settle(err))
    connectReq.end()
    return undefined
  }
}

/**
 * Returns an agent that tunnels through the configured proxy, or `undefined`
 * when none is configured — so a caller can pass the result straight to
 * `https.request({ agent })` and fall back to a direct connection unchanged.
 *
 * Every credential literal that could reach a log is handed to
 * `options.registerSecret` BEFORE the agent is returned, and therefore before
 * any request is issued through it. Three spellings, because a masker matches
 * registered literals and never derivations of them:
 *
 *  - a credential already embedded in `proxyUrl`'s userinfo, in raw and
 *    percent-decoded form (via `extractUrlUserInfoSecrets`);
 *  - the separately-supplied `proxyPassword`;
 *  - the base64 `user:password` the `Proxy-Authorization` header actually
 *    carries, which is a different byte sequence from the password itself.
 *
 * The header is derived ONLY from an explicit `proxyUsername`, never from
 * userinfo inside `proxyUrl`. That is the behaviour of every call site this was
 * taken from, and widening it would start sending a `Proxy-Authorization` on
 * configurations that have never sent one. Masking the userinfo regardless is
 * safe in the other direction: it can only ever remove a value from a log.
 *
 * @throws if `proxyUrl` is set but unparseable — never silently going direct,
 *   which is the failure that puts a credential outside the egress chokepoint.
 */
export function createProxyTunnelAgent(
  config: AgentProxyConfiguration | null | undefined,
  options: ProxyTunnelAgentOptions,
): https.Agent | undefined {
  if (!config?.proxyUrl) {
    return undefined
  }

  let proxyUrl: URL
  try {
    proxyUrl = new URL(config.proxyUrl)
  } catch (error) {
    throw new Error(
      `Invalid proxy URL configured on the agent: ${error instanceof Error ? error.message : String(error)}`,
    )
  }

  for (const secret of extractUrlUserInfoSecrets(config.proxyUrl)) {
    options.registerSecret(secret)
  }

  let proxyAuthHeader: string | undefined
  if (config.proxyUsername) {
    if (config.proxyPassword) {
      options.registerSecret(config.proxyPassword)
    }
    const proxyCredentials = Buffer.from(
      `${config.proxyUsername}:${config.proxyPassword ?? ''}`,
    ).toString('base64')
    options.registerSecret(proxyCredentials)
    proxyAuthHeader = `Basic ${proxyCredentials}`
  }

  const proxyPort = Number(proxyUrl.port || (proxyUrl.protocol === 'https:' ? 443 : 80))
  return new ProxyTunnelAgent(
    proxyUrl.hostname,
    proxyPort,
    proxyAuthHeader,
    options.tunnelTimeoutMs,
  )
}
