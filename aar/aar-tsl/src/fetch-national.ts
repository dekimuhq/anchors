/**
 * Fetch a single national TSL XML.
 */

const FETCH_TIMEOUT_MS = 15_000;

/**
 * Fetch a national TSL XML by URL.
 * Returns raw XML string. Throws on HTTP failure or timeout.
 */
export async function fetchNational(url: string): Promise<string> {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) {
    throw new Error(`fetchNational: HTTP ${res.status} from ${url}`);
  }
  return res.text();
}
