/**
 * Resolves a proxy configuration into a dispatcher-ready URL plus the exact byte
 * sequences that must be registered with the log masker.
 *
 * Two sources, because the two hosts configure a proxy differently:
 *
 *  - {@link resolveProxy} takes the object an Azure DevOps agent hands out
 *    (`tasks.getHttpProxyConfiguration()`). Ported from the `proxy-config.ts`
 *    copies in azure-pipelines-terraform and azure-pipelines-packer (executable
 *    bodies byte-identical), and from the equivalent `buildFetchOptions()`
 *    inside the installer HTTP clients.
 *  - {@link resolveEnvProxy} reads the environment variables a GitHub
 *    self-hosted runner sets. Node's `fetch` honours none of them on its own —
 *    only a client that opts in does — so without this an action behind a
 *    mandatory egress proxy either fails at the firewall or, where direct
 *    egress happens to be permitted, sends its one credential-bearing request
 *    outside the proxy's allowlist, inspection and audit trail.
 *
 * Both deliberately stop short of building a dispatcher: `undici` is a
 * task-side dependency, and keeping it there is what lets this package stay
 * dependency free. The caller does `new ProxyAgent(resolved.proxyUrl)`.
 */
import { extractUrlUserInfoSecrets } from '../url/redaction'

/** The shape `tasks.getHttpProxyConfiguration()` returns. */
export interface AgentProxyConfiguration {
  proxyUrl: string
  proxyUsername?: string | undefined
  proxyPassword?: string | undefined
}

export interface ResolvedProxy {
  /** Credentials embedded, ready for a dispatcher. */
  proxyUrl: string
  /**
   * Every representation of the credential that could reach a log. Register
   * ALL of them: the agent's masker matches registered literals, not
   * derivations of them.
   */
  secrets: string[]
}

/**
 * Returns null when no proxy is configured, so a caller can spread an empty
 * options object unconditionally.
 *
 * @throws if `proxyUrl` is set but unparseable.
 */
export function resolveProxy(
  config: AgentProxyConfiguration | null | undefined,
): ResolvedProxy | null {
  if (!config?.proxyUrl) return null

  // Credentials can arrive already embedded in Agent.ProxyUrl instead of in
  // the separate username/password variables. The sources only mask when
  // proxyUsername is set, so that spelling went unmasked entirely.
  const secrets = extractUrlUserInfoSecrets(config.proxyUrl)

  if (!config.proxyUsername) {
    return { proxyUrl: config.proxyUrl, secrets: dedupe(secrets) }
  }

  let url: URL
  try {
    url = new URL(config.proxyUrl)
  } catch (error) {
    throw new Error(
      `Invalid proxy URL configured on the agent: ${error instanceof Error ? error.message : String(error)}`,
    )
  }

  if (config.proxyPassword) secrets.push(config.proxyPassword)

  url.username = config.proxyUsername
  url.password = config.proxyPassword ?? ''

  // The setter stored the PERCENT-ENCODED password ('p@ss' -> 'p%40ss'), and
  // that is the form url.toString() embeds and a dispatcher error would echo.
  // It is a different literal from the raw password above.
  if (url.password && url.password !== config.proxyPassword) {
    secrets.push(url.password)
  }

  return { proxyUrl: url.toString(), secrets: dedupe(secrets) }
}

function dedupe(values: readonly string[]): string[] {
  return [...new Set(values)]
}

/** The variables a runner exposes. `process.env` satisfies it. */
export type ProxyEnvironment = Readonly<Record<string, string | undefined>>

/**
 * Resolves the proxy that applies TO A GIVEN DESTINATION from the environment,
 * or null when the destination must be reached directly.
 *
 * The destination is a required argument rather than a convenience, because
 * every part of the decision is a property of it: the scheme picks the
 * variable, and `NO_PROXY` is matched against it. There is deliberately no way
 * to ask this module "what is the proxy" without saying what for.
 *
 * WHAT THIS DOES NOT DECIDE. A proxy changes which socket carries the request,
 * never which destination is permitted. `assertEgressHostAllowed` still has to
 * run against the destination host — the initial one and every redirect hop —
 * and its subject is never the proxy: a CONNECT tunnel to a refused host is
 * still refused egress. Resolving a proxy here is not authorization and must
 * not be treated as any part of it.
 *
 * One caveat worth stating rather than discovering: the default-deny arm of
 * `assertEgressHostAllowed` resolves DNS on the agent, while a proxied
 * connection is resolved at the proxy, so the two can disagree about what a
 * name points at. The allowlist arm — what an operator behind a proxy
 * configures — is a decision about the NAME and is unaffected.
 *
 * @param destinationUrl the absolute URL about to be fetched, re-supplied on
 *   every redirect hop, since the host it names is what the answer depends on.
 * @throws if `destinationUrl` is unparseable, or if the applicable proxy
 *   variable is set to something unusable — never silently going direct, which
 *   is the failure that puts a credential outside the chokepoint. The message
 *   names the VARIABLE and never echoes its value, which can carry a password.
 */
export function resolveEnvProxy(
  destinationUrl: string,
  env: ProxyEnvironment = process.env,
): ResolvedProxy | null {
  let destination: URL
  try {
    destination = new URL(destinationUrl)
  } catch {
    // The URL itself is not echoed: an operator-supplied registry URL routinely
    // carries basic-auth userinfo, and the caller already knows what it passed.
    throw new Error('resolveEnvProxy requires an absolute destination URL.')
  }

  const scheme = SCHEMES[destination.protocol]
  if (!scheme) return null
  if (noProxyMatches(destination, readEnv(env, 'no_proxy', 'NO_PROXY')?.value)) return null

  const configured = readEnv(env, scheme.lower, scheme.upper)
  if (!configured) return null

  let proxy: URL
  try {
    proxy = new URL(configured.value)
  } catch {
    throw new Error(`The ${configured.name} environment variable is not a valid URL.`)
  }
  if (proxy.protocol !== 'http:' && proxy.protocol !== 'https:') {
    throw new Error(
      `The ${configured.name} environment variable must name an http:// or https:// proxy.`,
    )
  }

  // The raw configured string, not `proxy.toString()`: the exact bytes the
  // operator set are what the dispatcher should use and what an error would
  // echo, which is also what the extracted secrets are the literals of.
  return {
    proxyUrl: configured.value,
    secrets: dedupe(extractUrlUserInfoSecrets(configured.value)),
  }
}

/**
 * Which variable pair answers for a destination scheme. `https_proxy` covers an
 * https destination even though the hop to the proxy is usually plaintext — the
 * variable names the destination's scheme, not the proxy's.
 */
const SCHEMES: Readonly<Record<string, { lower: string; upper: string } | undefined>> = {
  'https:': { lower: 'https_proxy', upper: 'HTTPS_PROXY' },
  'http:': { lower: 'http_proxy', upper: 'HTTP_PROXY' },
}

/**
 * The first of the two spellings that is set to something other than blank,
 * lowercase first — the de-facto precedence (curl, requests), and the one an
 * operator debugging a runner expects.
 */
function readEnv(
  env: ProxyEnvironment,
  lower: string,
  upper: string,
): { name: string; value: string } | null {
  for (const name of [lower, upper]) {
    const value = env[name]?.trim()
    if (value) return { name, value }
  }
  return null
}

/**
 * Whether `NO_PROXY` exempts this destination, following the conventions curl
 * and Go's `httpproxy` share:
 *
 *  - `*` alone exempts everything;
 *  - a bare name matches itself and its subdomains (`example.com` covers
 *    `api.example.com`) — but only on a LABEL boundary, so `notexample.com` and
 *    `example.com.evil.test` do not match;
 *  - a leading `.` matches subdomains only, and `*.` is accepted as the
 *    spelling several tools use for the same thing;
 *  - an entry may pin a port, matched against the destination's explicit port
 *    or its scheme default.
 *
 * The label boundary is the load-bearing part. A match here means LEAVING the
 * proxy, so an over-broad rule is the one direction that silently costs an
 * operator the egress chokepoint they configured.
 */
function noProxyMatches(destination: URL, noProxy: string | undefined): boolean {
  if (!noProxy) return false
  const host = normalizeHost(destination.hostname)
  const port = destination.port || (destination.protocol === 'https:' ? '443' : '80')

  return noProxy.split(',').some((rawEntry) => {
    const entry = rawEntry.trim().toLowerCase()
    if (!entry) return false
    if (entry === '*') return true

    const [entryHost, entryPort] = splitHostPort(entry)
    if (entryPort !== undefined && entryPort !== port) return false

    const pattern = normalizeHost(entryHost.startsWith('*.') ? entryHost.slice(1) : entryHost)
    if (pattern.startsWith('.')) return host.endsWith(pattern)
    return host === pattern || host.endsWith(`.${pattern}`)
  })
}

/**
 * Splits an entry's optional `:port`. A bracketed IPv6 literal keeps its own
 * colons, and an unbracketed one — two colons or more — is never read as a
 * `host:port`.
 */
function splitHostPort(entry: string): [host: string, port: string | undefined] {
  if (entry.startsWith('[')) {
    const close = entry.indexOf(']')
    if (close === -1) return [entry, undefined]
    const rest = entry.slice(close + 1)
    const port = rest.startsWith(':') && /^\d+$/.test(rest.slice(1)) ? rest.slice(1) : undefined
    return [entry.slice(1, close), port]
  }
  const colon = entry.indexOf(':')
  if (colon === -1 || colon !== entry.lastIndexOf(':')) return [entry, undefined]
  const port = entry.slice(colon + 1)
  return /^\d+$/.test(port) ? [entry.slice(0, colon), port] : [entry, undefined]
}

/** Lowercased, unbracketed, and without the trailing FQDN dot, so both sides compare alike. */
function normalizeHost(host: string): string {
  const bare = host.toLowerCase().replace(/^\[|\]$/g, '')
  return bare.endsWith('.') && bare.length > 1 ? bare.slice(0, -1) : bare
}
