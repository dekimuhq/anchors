/**
 * computeTsaImprint — shared helper for TSA imprint computation.
 *
 * Phase B Task 13. Extracted from attachTsaBlock so that both the issuer-kit
 * (mint side) and the verifier (verify side) compute the imprint identically.
 *
 * Imprint = SHA-256 of `canonicalize(envelope)`, where `canonicalize` zeros
 * the 4 SIGNED_OUT_FIELDS (`anchor`, `sig`, `countersig`, `tsa`) per
 * `preSigCanonical`. The imprint thus excludes `sig` — only `credentialStatus`
 * and the rest of the envelope contents are committed. This is the same byte
 * sequence Ed25519 signs over, which means the TSA timestamp binds to the
 * exact signing input — not the signature itself.
 */

import { createHash } from "node:crypto";
import { canonicalizeEnvelope } from "../envelope.ts";
import type { Envelope } from "../envelope-types.ts";

/**
 * Compute the SHA-256 imprint over an envelope for TSA signing/verification.
 *
 * Imprint = SHA-256 of `canonicalize(envelope)`. The `canonicalize` function
 * routes through `preSigCanonical` which zeros all 4 SIGNED_OUT_FIELDS
 * (`anchor`, `sig`, `countersig`, `tsa`). `credentialStatus` is signed-in
 * and therefore included in the imprint.
 *
 * Pre-zeroing here (anchor/countersig/tsa) is defensive: `canonicalize` would
 * zero them anyway, but pre-zeroing makes the intent explicit at the call site
 * and protects against a future refactor that splits canonicalize from the
 * signed-out logic.
 *
 * Producer and consumer of a TSA block MUST compute the imprint identically —
 * that's why this helper is shared.
 */
export function computeTsaImprint(envelope: Envelope): Uint8Array {
  const zeroed: Record<string, unknown> = {
    ...(envelope as unknown as Record<string, unknown>),
    anchor: null,
    countersig: null,
    tsa: null,
  };
  const canonical = canonicalizeEnvelope(zeroed as unknown as Envelope);
  return new Uint8Array(createHash("sha256").update(canonical).digest());
}
