import { didWebToUrl } from "./did-web-url.ts";
import { parseKeyDoc, type KeyEntryV1 } from "./key-doc.ts";
import { DidWebResolveError } from "./errors.ts";
import type { KeyCache } from "./cache.ts";

export interface ResolveDidWebKeyOptions {
  iss: string;
  iss_key: string;
  fetcher?: typeof fetch;
  cache?: KeyCache;
  now?: () => Date;
}

/**
 * Fetch the issuer's `/.well-known/dekimu-keys.json`, locate the entry whose
 * `iss_key` matches, validate its rotation window, and return the served
 * public-key bytes (ed25519: SPKI DER, 44 B; ml-dsa-65: the raw 1952-byte key —
 * no SPKI framing). The `iss_key`↔served-key fingerprint binding is enforced
 * per-algorithm before returning (`checkKeyFingerprint`).
 *
 * Pure: no globals, no infra. `fetcher` is injectable for tests; defaults
 * to the global `fetch`. `cache` is injectable; when present, the key bytes
 * are stored keyed by `${iss}#${iss_key}` (base64 in cache, decoded
 * on read so the API still returns Uint8Array).
 *
 * Throws `DidWebResolveError` with a discriminated `code` on every failure path.
 */
export async function resolveDidWebKey(opts: ResolveDidWebKeyOptions): Promise<Uint8Array> {
  const fetcher = opts.fetcher ?? fetch;
  const now = opts.now ?? (() => new Date());
  const cacheKey = `${opts.iss}#${opts.iss_key}`;

  if (opts.cache) {
    const cached = opts.cache.get(cacheKey);
    if (cached !== undefined) return base64Decode(cached, "cache");
    const negCached = opts.cache.getNegative?.(cacheKey);
    if (negCached !== undefined) {
      throw new DidWebResolveError(
        "negative_cached",
        `negative-cached failure for ${cacheKey}: ${negCached}`,
      );
    }
  }

  const url = didWebToUrl(opts.iss); // throws on invalid did:web

  let res: Response;
  try {
    res = await fetcher(url);
  } catch (err) {
    throw new DidWebResolveError("fetch_failed", `fetch ${url.href}: ${stringifyErr(err)}`, { cause: err });
  }
  if (res.status !== 200) {
    opts.cache?.setNegative?.(cacheKey, `non_200:${res.status}`);
    throw new DidWebResolveError("non_200", `fetch ${url.href}: status ${res.status}`);
  }

  let text: string;
  try {
    text = await res.text();
  } catch (err) {
    throw new DidWebResolveError("fetch_failed", `read body: ${stringifyErr(err)}`, { cause: err });
  }

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new DidWebResolveError("json_parse", `parse JSON: ${stringifyErr(err)}`, { cause: err });
  }

  const doc = parseKeyDoc(raw);
  const entry = doc.keys.find((k) => k.iss_key === opts.iss_key);
  if (!entry) {
    opts.cache?.setNegative?.(cacheKey, "no_matching_key");
    throw new DidWebResolveError(
      "no_matching_key",
      `iss_key ${opts.iss_key} not found in key doc for ${opts.iss}`,
    );
  }

  checkWindow(entry, now());

  const der = base64Decode(entry.public_key_der_base64, "key");
  // Bind the requested `iss_key` fingerprint to the served key bytes. If the
  // issuer's domain is compromised and the doc swaps in an attacker key under
  // the legit `iss_key`, the fingerprint no longer matches and we hard-fail
  // BEFORE caching — a forged key is never cached. Not negative-cached: a
  // mismatch is a security event we re-verify on every call, like a window
  // violation, rather than mask behind a TTL.
  checkKeyFingerprint(opts.iss_key, der);
  if (opts.cache) opts.cache.set(cacheKey, entry.public_key_der_base64);
  return der;
}

const ED25519_PREFIX = "ed25519:";
const ED25519_SPKI_LEN = 44; // 12-byte SPKI prefix + 32-byte raw public key
const ED25519_RAW_LEN = 32;
const ML_DSA_65_PREFIX = "ml-dsa-65:";
// MLDSA65_PUBKEY_BYTES from @dekimuhq/anchors-envelope — inlined to keep this
// package zero-dependency. ML-DSA-65 (FIPS 204) has no SPKI DER framing in
// node:crypto, so the served key IS the raw public key.
const ML_DSA_65_PUBKEY_LEN = 1952;

function fingerprintMismatch(iss_key: string): DidWebResolveError {
  return new DidWebResolveError(
    "iss_key_fingerprint_mismatch",
    `iss_key fingerprint does not match the served public key for ${iss_key}`,
  );
}

/**
 * Assert that an `<alg>:<base64url>` `iss_key` fingerprint matches the served
 * public-key bytes. Two registered schemes (v1.3 rollout R2):
 *
 *   - `ed25519:` — fingerprint is the base64url of the 32-byte raw key; the
 *     served bytes are SPKI DER (44 B), so bind the trailing 32 raw bytes.
 *   - `ml-dsa-65:` — fingerprint is the base64url of the 1952-byte raw key; the
 *     served bytes ARE that raw key (no SPKI framing), so bind the whole thing.
 *
 * The derivation matches `keyObjectFromSeed`/`encodeMlDsaIssKey` in
 * `@dekimuhq/anchors-envelope`. An unregistered prefix passes through unchecked
 * so a future sig-alg doesn't trip this guard — such a key has no verifier
 * downstream and fails at signature verification.
 */
function checkKeyFingerprint(iss_key: string, key: Uint8Array): void {
  if (iss_key.startsWith(ED25519_PREFIX)) {
    const claimed = Uint8Array.from(
      Buffer.from(iss_key.slice(ED25519_PREFIX.length), "base64url"),
    );
    const raw = key.subarray(key.length - ED25519_RAW_LEN);
    if (key.length !== ED25519_SPKI_LEN || claimed.length !== ED25519_RAW_LEN || !bytesEqual(claimed, raw)) {
      throw fingerprintMismatch(iss_key);
    }
    return;
  }
  if (iss_key.startsWith(ML_DSA_65_PREFIX)) {
    const claimed = Uint8Array.from(
      Buffer.from(iss_key.slice(ML_DSA_65_PREFIX.length), "base64url"),
    );
    if (
      key.length !== ML_DSA_65_PUBKEY_LEN ||
      claimed.length !== ML_DSA_65_PUBKEY_LEN ||
      !bytesEqual(claimed, key)
    ) {
      throw fingerprintMismatch(iss_key);
    }
    return;
  }
  // Unregistered prefix — pass through unchecked (forward-compat).
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function checkWindow(entry: KeyEntryV1, now: Date): void {
  const from = new Date(entry.valid_from);
  if (Number.isNaN(from.getTime())) {
    throw new DidWebResolveError("key_doc_invalid", `valid_from not parseable: ${entry.valid_from}`);
  }
  if (now < from) {
    throw new DidWebResolveError(
      "key_not_yet_valid",
      `key ${entry.iss_key} not yet valid (valid_from=${entry.valid_from}, now=${now.toISOString()})`,
    );
  }
  if (entry.valid_until !== null) {
    const until = new Date(entry.valid_until);
    if (Number.isNaN(until.getTime())) {
      throw new DidWebResolveError("key_doc_invalid", `valid_until not parseable: ${entry.valid_until}`);
    }
    if (now >= until) {
      throw new DidWebResolveError(
        "key_no_longer_valid",
        `key ${entry.iss_key} no longer valid (valid_until=${entry.valid_until}, now=${now.toISOString()})`,
      );
    }
  }
}

function base64Decode(b64: string, label: "key" | "cache"): Uint8Array {
  if (label === "key" && !/^[A-Za-z0-9+/=_-]*$/.test(b64)) {
    throw new DidWebResolveError("invalid_public_key_encoding", `non-base64 chars in public key`);
  }
  return Uint8Array.from(Buffer.from(b64, "base64"));
}

function stringifyErr(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
