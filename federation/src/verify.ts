/**
 * Verify an `ar.issuer_manifest.v1` document end-to-end.
 *
 * Algorithm (cross-issuer interop plan §3):
 *   1. Defensive structural re-check (caller may have bypassed `fetchIssuerManifest`).
 *   2. Validity window: `now` vs `valid_until` (advisory — stale manifest
 *      triggers a warning, not a hard fail).
 *   3. Self-consistency: `iss` is a `did:web` DID.
 *   4. Resolve the issuer's signing key via `resolveDidWebKey` using the
 *      `iss` and the fingerprint extracted from their key doc.
 *   5. Verify Ed25519 signature over JCS-canonical doc-with-sig-null.
 */

import {
  resolveDidWebKey,
  type KeyCache,
} from "@dekimuhq/did-web-resolver";
import { verifyCanonical, base64UrlDecode } from "@dekimuhq/anchors-envelope";
import { parseIssuerManifest } from "./schema.ts";
import type { IssuerManifestV1 } from "./types.ts";

export interface VerifyIssuerManifestOptions {
  /** The manifest document to verify. */
  doc: IssuerManifestV1;
  /**
   * Injectable HTTP fetcher for did:web key resolution.
   * Defaults to `globalThis.fetch`.
   */
  fetcher?: typeof fetch;
  /** Key cache for did:web resolver (avoids re-fetching key docs). */
  cache?: KeyCache;
  /** Clock override. Default: `() => new Date()`. */
  now?: () => Date;
  /**
   * The expected `iss_key` fingerprint (e.g. `ed25519:<base64url>`).
   * When supplied, resolves this specific key from the issuer's key doc.
   * When omitted, the verifier tries every key in the doc until one
   * validates the signature (first-match strategy).
   */
  iss_key?: string;
}

export type VerifyManifestOutcome =
  | "valid"
  | "valid_stale";

export type VerifyManifestOutcomeError =
  | "schema_invalid"
  | "signature_invalid"
  | "key_resolution_failed"
  | "iss_consistency_failed";

export type VerifyIssuerManifestResult =
  | { ok: true; doc: IssuerManifestV1; outcome: VerifyManifestOutcome; warnings: string[] }
  | { ok: false; outcome: VerifyManifestOutcomeError; reason: string };

const RAW_ED25519_PUB_BYTES = 32;

export async function verifyIssuerManifest(
  opts: VerifyIssuerManifestOptions,
): Promise<VerifyIssuerManifestResult> {
  // Step 1 — Defensive structural re-check.
  const parsed = parseIssuerManifest(opts.doc);
  if (!parsed.ok) {
    return { ok: false, outcome: "schema_invalid", reason: parsed.reason };
  }
  const doc = parsed.doc;

  // Step 2 — iss self-consistency: iss must be did:web.
  if (!doc.iss.startsWith("did:web:")) {
    return {
      ok: false,
      outcome: "iss_consistency_failed",
      reason: `iss must start with did:web:, got ${doc.iss}`,
    };
  }

  // Step 3 — Validity window (advisory — stale manifest → warning, not hard fail).
  const warnings: string[] = [];
  const now = (opts.now ?? (() => new Date()))();
  const validUntilMs = Date.parse(doc.valid_until);
  const nowMs = now.getTime();
  const isStale = nowMs > validUntilMs;
  if (isStale) {
    warnings.push(
      `issuer_manifest_stale: now=${now.toISOString()} > valid_until=${doc.valid_until}`,
    );
  }

  // Step 4 — Resolve the issuer's signing key via did:web.
  // If caller provides iss_key, use it directly. Otherwise try to resolve
  // using key_doc_uri as a hint and match against the signature.
  let spki: Uint8Array;

  if (opts.iss_key) {
    // Direct key resolution.
    try {
      const resolveOpts: Parameters<typeof resolveDidWebKey>[0] = {
        iss: doc.iss,
        iss_key: opts.iss_key,
      };
      if (opts.fetcher) resolveOpts.fetcher = opts.fetcher;
      if (opts.cache) resolveOpts.cache = opts.cache;
      if (opts.now) resolveOpts.now = opts.now;
      spki = await resolveDidWebKey(resolveOpts);
    } catch (err) {
      return {
        ok: false,
        outcome: "key_resolution_failed",
        reason: `resolveDidWebKey failed for ${doc.iss}#${opts.iss_key}: ${stringifyErr(err)}`,
      };
    }
  } else {
    // No iss_key hint — fetch the key doc and try each key.
    const resolved = await resolveFirstMatchingKey(doc, opts);
    if (!resolved.ok) {
      return {
        ok: false,
        outcome: resolved.outcome,
        reason: resolved.reason,
      };
    }
    spki = resolved.spki;
  }

  // Step 5 — Verify Ed25519 signature over JCS-canonical doc-with-sig-null.
  if (!spki || spki.length < RAW_ED25519_PUB_BYTES) {
    return {
      ok: false,
      outcome: "signature_invalid",
      reason: `resolved SPKI too short (${spki?.length ?? 0} bytes, need ≥${RAW_ED25519_PUB_BYTES})`,
    };
  }

  const rawPub =
    spki.length === RAW_ED25519_PUB_BYTES
      ? spki
      : spki.subarray(spki.length - RAW_ED25519_PUB_BYTES);

  let sigBytes: Uint8Array;
  try {
    sigBytes = base64UrlDecode(doc.sig);
  } catch (err) {
    return {
      ok: false,
      outcome: "signature_invalid",
      reason: `sig not base64url: ${stringifyErr(err)}`,
    };
  }

  const docWithSigNull = { ...doc, sig: null };
  const valid = verifyCanonical(docWithSigNull, sigBytes, rawPub);
  if (!valid) {
    return {
      ok: false,
      outcome: "signature_invalid",
      reason: "ed25519 verify failed over JCS-canonical doc-with-sig-null",
    };
  }

  return {
    ok: true,
    doc,
    outcome: isStale ? "valid_stale" : "valid",
    warnings,
  };
}

/**
 * When no `iss_key` hint is provided, fetch the issuer's key doc and try
 * each key entry until one validates the manifest signature.
 */
async function resolveFirstMatchingKey(
  doc: IssuerManifestV1,
  opts: VerifyIssuerManifestOptions,
): Promise<
  | { ok: true; spki: Uint8Array }
  | { ok: false; outcome: VerifyManifestOutcomeError; reason: string }
> {
  // Import parseKeyDoc to read the key doc directly.
  const { parseKeyDoc, didWebToUrl } = await import("@dekimuhq/did-web-resolver");

  const keyDocUrl = doc.key_doc_uri;
  const fetcher = opts.fetcher ?? (globalThis.fetch as typeof fetch);

  let res: Response;
  try {
    res = await fetcher(keyDocUrl);
  } catch (err) {
    return {
      ok: false,
      outcome: "key_resolution_failed",
      reason: `fetch key doc ${keyDocUrl}: ${stringifyErr(err)}`,
    };
  }

  if (res.status !== 200) {
    return {
      ok: false,
      outcome: "key_resolution_failed",
      reason: `fetch key doc ${keyDocUrl}: status ${res.status}`,
    };
  }

  let raw: unknown;
  try {
    raw = await res.json();
  } catch (err) {
    return {
      ok: false,
      outcome: "key_resolution_failed",
      reason: `parse key doc JSON: ${stringifyErr(err)}`,
    };
  }

  let keyDoc;
  try {
    keyDoc = parseKeyDoc(raw);
  } catch (err) {
    return {
      ok: false,
      outcome: "key_resolution_failed",
      reason: `invalid key doc: ${stringifyErr(err)}`,
    };
  }

  // Verify iss consistency: the key doc URL must match the iss DID.
  const expectedBase = didWebToUrl(doc.iss).origin;
  const actualBase = new URL(keyDocUrl).origin;
  if (expectedBase !== actualBase) {
    return {
      ok: false,
      outcome: "iss_consistency_failed",
      reason: `key_doc_uri origin (${actualBase}) does not match iss DID origin (${expectedBase})`,
    };
  }

  // Try each key entry — find one whose signature verifies.
  const sigBytes = base64UrlDecode(doc.sig);
  const docWithSigNull = { ...doc, sig: null };

  for (const entry of keyDoc.keys) {
    // Key doc uses standard base64 (not base64url).
    let pubBytes: Uint8Array;
    try {
      pubBytes = Uint8Array.from(Buffer.from(entry.public_key_der_base64, "base64"));
    } catch {
      continue;
    }
    if (pubBytes.length < RAW_ED25519_PUB_BYTES) continue;
    const rawPub =
      pubBytes.length === RAW_ED25519_PUB_BYTES
        ? pubBytes
        : pubBytes.subarray(pubBytes.length - RAW_ED25519_PUB_BYTES);

    const ok = verifyCanonical(docWithSigNull, sigBytes, rawPub);
    if (ok) {
      return { ok: true, spki: pubBytes };
    }
  }

  return {
    ok: false,
    outcome: "signature_invalid",
    reason: `no key in key doc at ${keyDocUrl} verified the manifest signature (tried ${keyDoc.keys.length} keys)`,
  };
}

function stringifyErr(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
