/**
 * Verify an `ar.trusted_issuers.v1` document end-to-end.
 *
 * Algorithm (Phase B master plan §2.1 + Phase B1 plan):
 *   1. Defensive structural re-check (caller may have bypassed `fetchTrustedIssuers`).
 *   2. Validity window: `now` ∈ [issued_at, valid_until].
 *   3. Resolve publisher SPKI — bootstrap wins when its `publisher_key`
 *      matches the doc; otherwise resolver fallback; otherwise classify the
 *      failure (`publisher_key_mismatch` | `bootstrap_required_but_absent` |
 *      `resolver_failed`).
 *   4. Verify Ed25519 signature over JCS-canonical doc-with-sig-null.
 */

import {
  verifyCanonical,
  verifyMlDsaCanonical,
  base64UrlDecode,
  MLDSA65_PUBKEY_BYTES,
} from "@dekimuhq/anchors-envelope";
import { parseTrustedIssuerList } from "./schema.ts";
import type { TrustedIssuerListV1 } from "./types.ts";

export interface VerifyTrustedIssuersListOptions {
  doc: TrustedIssuerListV1;
  resolver?: (iss: string, iss_key: string) => Promise<Uint8Array>;
  bootstrap?: { publisher_key: string; spki_der: Uint8Array };
  now?: () => Date;
}

export type VerifyOutcomeError =
  | "schema_invalid"
  | "signature_invalid"
  | "publisher_key_mismatch"
  | "unsupported_publisher_key_alg"
  | "window_invalid"
  | "resolver_failed"
  | "bootstrap_required_but_absent";

/**
 * Signature algorithms this verifier can evaluate offline. The schema
 * (`PUBLISHER_KEY_RE`) accepts the *format* of any registered `SIG_ALGS` key so
 * a list published under a future algorithm parses cleanly; this set is the
 * subset whose list signature Step 4 can actually verify. `ed25519`
 * (`verifyCanonical`) and `ml-dsa-65` (FIPS 204, `verifyMlDsaCanonical`, Node
 * ≥24.6) are registered (rollout R2). A `publisher_key` whose algorithm prefix
 * is outside this set fails closed with `unsupported_publisher_key_alg` — never
 * silently mis-verified under the wrong scheme. Step 4 dispatches on the prefix,
 * so adding a scheme here REQUIRES adding its verify branch below.
 */
const SUPPORTED_LIST_SIG_ALGS: ReadonlySet<string> = new Set(["ed25519", "ml-dsa-65"]);

export type VerifyTrustedIssuersListResult =
  | { ok: true; doc: TrustedIssuerListV1; spki: Uint8Array; outcome: "valid" }
  | { ok: false; outcome: VerifyOutcomeError; reason: string };

const RAW_ED25519_PUB_BYTES = 32;

export async function verifyTrustedIssuersList(
  opts: VerifyTrustedIssuersListOptions,
): Promise<VerifyTrustedIssuersListResult> {
  // Step 1 — Defensive structural re-check.
  const parsed = parseTrustedIssuerList(opts.doc);
  if (!parsed.ok) {
    return { ok: false, outcome: "schema_invalid", reason: parsed.reason };
  }
  const doc = parsed.doc;

  // Step 1.5 — Publisher-key algorithm capability gate (v1.3 §L6).
  // `publisher_key` is `<alg>:<base64url>`; the schema guarantees a registered
  // `SIG_ALGS` prefix, and Step 4 dispatches over SUPPORTED_LIST_SIG_ALGS
  // (ed25519 + ml-dsa-65). Those two sets currently coincide, so this gate is
  // unreachable for a schema-valid doc today — it is retained as forward-safety:
  // if a future `sig_alg` is registered (widening the schema) before Step 4
  // grows a verify branch for it, this fails closed (distinct outcome,
  // unsupported ≠ invalid signature) rather than resolving-and-mis-verifying it
  // under the wrong scheme.
  const keyAlg = doc.publisher_key.slice(0, doc.publisher_key.indexOf(":"));
  if (!SUPPORTED_LIST_SIG_ALGS.has(keyAlg)) {
    return {
      ok: false,
      outcome: "unsupported_publisher_key_alg",
      reason: `publisher_key algorithm "${keyAlg}" is not yet verifiable here (supported: ${[...SUPPORTED_LIST_SIG_ALGS].join(", ")})`,
    };
  }

  // Step 2 — Window check.
  const now = (opts.now ?? (() => new Date()))();
  const issuedAtMs = Date.parse(doc.issued_at);
  const validUntilMs = Date.parse(doc.valid_until);
  const nowMs = now.getTime();
  if (nowMs < issuedAtMs) {
    return {
      ok: false,
      outcome: "window_invalid",
      reason: `now=${now.toISOString()} < issued_at=${doc.issued_at}`,
    };
  }
  if (nowMs > validUntilMs) {
    return {
      ok: false,
      outcome: "window_invalid",
      reason: `now=${now.toISOString()} > valid_until=${doc.valid_until}`,
    };
  }

  // Step 3 — Resolve publisher SPKI.
  let spki: Uint8Array;
  if (opts.bootstrap && opts.bootstrap.publisher_key === doc.publisher_key) {
    spki = opts.bootstrap.spki_der;
  } else if (opts.bootstrap && opts.bootstrap.publisher_key !== doc.publisher_key) {
    if (!opts.resolver) {
      return {
        ok: false,
        outcome: "publisher_key_mismatch",
        reason: `bootstrap publisher_key=${opts.bootstrap.publisher_key} does not match doc publisher_key=${doc.publisher_key} and no resolver supplied`,
      };
    }
    try {
      spki = await opts.resolver(doc.publisher, doc.publisher_key);
    } catch (err) {
      return {
        ok: false,
        outcome: "publisher_key_mismatch",
        reason: `bootstrap publisher_key=${opts.bootstrap.publisher_key} does not match doc publisher_key=${doc.publisher_key}; resolver fallback failed: ${stringifyErr(err)}`,
      };
    }
  } else if (opts.resolver) {
    try {
      spki = await opts.resolver(doc.publisher, doc.publisher_key);
    } catch (err) {
      return {
        ok: false,
        outcome: "resolver_failed",
        reason: `resolver threw: ${stringifyErr(err)}`,
      };
    }
  } else {
    return {
      ok: false,
      outcome: "bootstrap_required_but_absent",
      reason: "no bootstrap pin and no resolver supplied",
    };
  }

  // Decode the list signature once (shared across algorithms).
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

  // Step 4 — Verify the list signature over JCS-canonical doc-with-sig-null,
  // dispatching on the publisher-key algorithm (already gated to
  // SUPPORTED_LIST_SIG_ALGS at Step 1.5). Each scheme consumes its own raw-key
  // encoding — so a key resolved for one algorithm can never be verified under
  // another (the §L6 capability gate + this dispatch are the two halves).
  let valid: boolean;
  if (keyAlg === "ml-dsa-65") {
    // ML-DSA-65 public keys have no SPKI DER framing in node:crypto — the
    // resolved bytes ARE the 1952-byte raw key. A wrong length is a malformed
    // key, not a wrong signature.
    if (spki.length !== MLDSA65_PUBKEY_BYTES) {
      return {
        ok: false,
        outcome: "signature_invalid",
        reason: `resolved ml-dsa-65 key is ${spki.length} bytes, need ${MLDSA65_PUBKEY_BYTES}`,
      };
    }
    valid = verifyMlDsaCanonical(docWithSigNull, sigBytes, spki);
  } else {
    // ed25519: resolver returns SPKI DER (44 B) or the raw 32-byte key; take the
    // trailing 32 raw bytes for verifyCanonical.
    if (spki.length < RAW_ED25519_PUB_BYTES) {
      return {
        ok: false,
        outcome: "signature_invalid",
        reason: `resolved SPKI too short (${spki.length} bytes, need ≥${RAW_ED25519_PUB_BYTES})`,
      };
    }
    const rawPub =
      spki.length === RAW_ED25519_PUB_BYTES
        ? spki
        : spki.subarray(spki.length - RAW_ED25519_PUB_BYTES);
    valid = verifyCanonical(docWithSigNull, sigBytes, rawPub);
  }

  if (!valid) {
    return {
      ok: false,
      outcome: "signature_invalid",
      reason: `${keyAlg} verify failed over JCS-canonical doc-with-sig-null`,
    };
  }

  return { ok: true, doc, spki, outcome: "valid" };
}

function stringifyErr(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
