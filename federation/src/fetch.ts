/**
 * Fetch + structurally-validate a remote `ar.issuer_manifest.v1` document.
 *
 * - Injectable `fetcher` for tests; defaults to `globalThis.fetch`.
 * - 1 MB response cap.
 * - 5 s default timeout via `AbortController`.
 * - Throws `ManifestFetchError` (transport) or `ManifestSchemaError` (structural).
 */

import { parseIssuerManifest } from "./schema.ts";
import type { IssuerManifestV1 } from "./types.ts";

export interface FetchIssuerManifestOptions {
  /** Full URL to the manifest (typically `https://<domain>/.well-known/dekimu-issuer.json`). */
  url: string;
  /** Injectable HTTP fetcher. Defaults to `globalThis.fetch`. */
  fetcher?: (url: string, init?: { signal?: AbortSignal }) => Promise<Response>;
  /** Timeout in milliseconds. Default: 5000. */
  timeoutMs?: number;
}

export type ManifestFetchCode =
  | "non_200"
  | "network"
  | "timeout"
  | "malformed_json"
  | "oversized_response";

export class ManifestFetchError extends Error {
  code: ManifestFetchCode;
  constructor(
    code: ManifestFetchCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "ManifestFetchError";
    this.code = code;
  }
}

export class ManifestSchemaError extends Error {
  reason: string;
  constructor(reason: string) {
    super(reason);
    this.name = "ManifestSchemaError";
    this.reason = reason;
  }
}

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_BYTES = 1_000_000;

export async function fetchIssuerManifest(
  opts: FetchIssuerManifestOptions,
): Promise<IssuerManifestV1> {
  if (typeof opts.url !== "string" || opts.url.length === 0) {
    throw new ManifestFetchError("network", "url required");
  }
  const fetcher = opts.fetcher ?? (globalThis.fetch as FetchIssuerManifestOptions["fetcher"]);
  if (!fetcher) {
    throw new ManifestFetchError("network", "no fetcher available (globalThis.fetch undefined and no fetcher injected)");
  }
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);

  let res: Response;
  try {
    res = await fetcher(opts.url, { signal: ac.signal });
  } catch (err) {
    clearTimeout(timer);
    if (ac.signal.aborted) {
      throw new ManifestFetchError("timeout", `fetch ${opts.url}: timeout after ${timeoutMs}ms`);
    }
    throw new ManifestFetchError("network", `fetch ${opts.url}: ${stringifyErr(err)}`, { cause: err });
  }
  clearTimeout(timer);

  if (res.status !== 200) {
    throw new ManifestFetchError("non_200", `fetch ${opts.url}: status ${res.status}`);
  }

  let text: string;
  try {
    text = await res.text();
  } catch (err) {
    throw new ManifestFetchError("network", `read body: ${stringifyErr(err)}`, { cause: err });
  }

  if (text.length > MAX_BYTES) {
    throw new ManifestFetchError(
      "oversized_response",
      `fetch ${opts.url}: response ${text.length} bytes exceeds ${MAX_BYTES} cap`,
    );
  }

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new ManifestFetchError("malformed_json", `parse JSON: ${stringifyErr(err)}`, { cause: err });
  }

  const parsed = parseIssuerManifest(raw);
  if (!parsed.ok) {
    throw new ManifestSchemaError(parsed.reason);
  }
  return parsed.doc;
}

/**
 * Build the well-known URL for an issuer manifest from a `did:web` DID.
 *
 * `did:web:example.com` → `https://example.com/.well-known/dekimu-issuer.json`
 * `did:web:example.com:path:sub` → `https://example.com/path/sub/.well-known/dekimu-issuer.json`
 */
export function manifestUrlFromDid(did: string): string {
  if (!did.startsWith("did:web:")) {
    throw new Error(`expected did:web DID, got ${did}`);
  }
  const parts = did.slice("did:web:".length).split(":");
  const domain = decodeURIComponent(parts[0]!);
  const path = parts.slice(1).map(decodeURIComponent).join("/");
  const base = path ? `https://${domain}/${path}` : `https://${domain}`;
  return `${base}/.well-known/dekimu-issuer.json`;
}

function stringifyErr(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
