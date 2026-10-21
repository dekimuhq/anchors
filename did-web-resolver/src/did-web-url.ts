import { DidWebResolveError } from "./errors.ts";

const PREFIX = "did:web:";

/**
 * Map a `did:web:` identifier to its `/.well-known/dekimu-keys.json` URL
 * per W3C did:web v1.0. Path segments are colon-separated in the DID
 * and slash-separated in the URL; each segment is percent-decoded.
 *
 * Examples:
 *   did:web:example.com                → https://example.com/.well-known/dekimu-keys.json
 *   did:web:example.com:user:alice     → https://example.com/user/alice/.well-known/dekimu-keys.json
 *   did:web:example.com:org%3A42       → https://example.com/org:42/.well-known/dekimu-keys.json
 */
export function didWebToUrl(iss: string): URL {
  if (!iss.startsWith(PREFIX)) {
    throw new DidWebResolveError(
      "unsupported_did_method",
      `iss must start with "${PREFIX}" (got: ${iss.slice(0, 32)})`,
    );
  }
  const rest = iss.slice(PREFIX.length);
  if (rest.length === 0) {
    throw new DidWebResolveError("invalid_did", "did:web: missing domain");
  }
  const segments = rest.split(":").map(decodeURIComponent);
  const [domain, ...pathParts] = segments;
  if (!domain) {
    throw new DidWebResolveError("invalid_did", "did:web: missing domain");
  }
  const path = pathParts.length > 0 ? `/${pathParts.join("/")}` : "";
  return new URL(`https://${domain}${path}/.well-known/dekimu-keys.json`);
}
