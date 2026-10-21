/**
 * Fetch + structurally-validate a remote `ar.trusted_issuers.v1` document.
 *
 * - Injectable `fetcher` for tests; defaults to `globalThis.fetch`.
 * - 1 MB response cap (rejects oversize before parsing — defends against
 *   malicious resolver responses).
 * - 5 s default timeout via `AbortController`.
 * - Throws `TrustedIssuersFetchError` (transport / network / timeout / oversize)
 *   or `TrustedIssuersSchemaError` (structural). Both have discriminated codes.
 */

import { parseTrustedIssuerList } from "./schema.ts";
import type { TrustedIssuerListV1 } from "./types.ts";

export interface FetchTrustedIssuersOptions {
  url: string;
  fetcher?: (url: string, init?: { signal?: AbortSignal }) => Promise<Response>;
  timeoutMs?: number;
}

export type TrustedIssuersFetchCode =
  | "non_200"
  | "network"
  | "timeout"
  | "malformed_json"
  | "oversized_response";

export class TrustedIssuersFetchError extends Error {
  code: TrustedIssuersFetchCode;
  constructor(
    code: TrustedIssuersFetchCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "TrustedIssuersFetchError";
    this.code = code;
  }
}

export class TrustedIssuersSchemaError extends Error {
  reason: string;
  constructor(reason: string) {
    super(reason);
    this.name = "TrustedIssuersSchemaError";
    this.reason = reason;
  }
}

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_BYTES = 1_000_000; // 1 MB hard cap.

export async function fetchTrustedIssuers(
  opts: FetchTrustedIssuersOptions,
): Promise<TrustedIssuerListV1> {
  if (typeof opts.url !== "string" || opts.url.length === 0) {
    throw new TrustedIssuersFetchError("network", "url required");
  }
  const fetcher = opts.fetcher ?? (globalThis.fetch as FetchTrustedIssuersOptions["fetcher"]);
  if (!fetcher) {
    throw new TrustedIssuersFetchError("network", "no fetcher available (globalThis.fetch undefined and no fetcher injected)");
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
      throw new TrustedIssuersFetchError("timeout", `fetch ${opts.url}: timeout after ${timeoutMs}ms`);
    }
    throw new TrustedIssuersFetchError("network", `fetch ${opts.url}: ${stringifyErr(err)}`, { cause: err });
  }
  clearTimeout(timer);

  if (res.status !== 200) {
    throw new TrustedIssuersFetchError("non_200", `fetch ${opts.url}: status ${res.status}`);
  }

  let text: string;
  try {
    text = await res.text();
  } catch (err) {
    throw new TrustedIssuersFetchError("network", `read body: ${stringifyErr(err)}`, { cause: err });
  }

  // Byte-count cap. `text.length` is UTF-16 units; a UTF-8 byte count would
  // be more precise, but cap is conservative either way — any input above
  // MAX_BYTES UTF-16 code units is above MAX_BYTES UTF-8 bytes too (for
  // ASCII-heavy JSON).
  if (text.length > MAX_BYTES) {
    throw new TrustedIssuersFetchError(
      "oversized_response",
      `fetch ${opts.url}: response ${text.length} bytes exceeds ${MAX_BYTES} cap`,
    );
  }

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new TrustedIssuersFetchError("malformed_json", `parse JSON: ${stringifyErr(err)}`, { cause: err });
  }

  const parsed = parseTrustedIssuerList(raw);
  if (!parsed.ok) {
    throw new TrustedIssuersSchemaError(parsed.reason);
  }
  return parsed.doc;
}

function stringifyErr(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
