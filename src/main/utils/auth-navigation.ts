export function isTrustedAuthNavigation(
  currentOrigin: string,
  targetOrigin: string,
  connection?: { url: string; authOrigins?: string[] }
): boolean {
  if (!connection || !Array.isArray(connection.authOrigins)) return false

  const trustedOrigins = new Set<string>()
  try {
    trustedOrigins.add(new URL(connection.url).origin)
  } catch {
    return false
  }

  for (const origin of connection.authOrigins) {
    if (typeof origin !== 'string') continue
    try {
      const parsed = new URL(origin)
      if (
        parsed.protocol === 'https:' &&
        !parsed.username &&
        !parsed.password &&
        parsed.pathname === '/' &&
        !parsed.search &&
        !parsed.hash
      ) {
        trustedOrigins.add(parsed.origin)
      }
    } catch {
      // Ignore invalid entries rather than widening the navigation policy.
    }
  }

  return trustedOrigins.has(currentOrigin) && trustedOrigins.has(targetOrigin)
}
