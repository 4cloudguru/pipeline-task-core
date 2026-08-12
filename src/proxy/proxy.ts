/**
 * Resolves the agent's proxy configuration into a dispatcher-ready URL plus the
 * exact byte sequences that must be registered with the log masker.
 *
 * Ported from the `proxy-config.ts` copies in azure-pipelines-terraform and
 * azure-pipelines-packer (executable bodies byte-identical), and from the
 * equivalent `buildFetchOptions()` inside the installer HTTP clients.
 *
 * Deliberately stops short of building a dispatcher: `undici` is a task-side
 * dependency, and keeping it there is what lets this package stay dependency
 * free. The caller does `new ProxyAgent(resolved.proxyUrl)`.
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
