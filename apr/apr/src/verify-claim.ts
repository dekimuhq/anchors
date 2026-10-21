/**
 * Pure claim-signature verification. No I/O, no anchor logic.
 * Mirrors `apr-spec/v1.md` §5.
 */

import { canonicalize } from "./canonicalize.ts";
import { base64UrlDecode } from "./base64url.ts";
import { ed25519Verify } from "./ed25519.ts";
import type {
  APRClaim,
  ClaimKeyResolver,
  VerifyReason,
} from "./types.ts";

interface ClaimCheckOk {
  ok: true;
  claim: APRClaim;
}
interface ClaimCheckFail {
  ok: false;
  reason: VerifyReason;
}
export type ClaimCheckResult = ClaimCheckOk | ClaimCheckFail;

const KNOWN_CLAIM_KEYS: ReadonlySet<string> = new Set([
  "v",
  "id",
  "kind",
  "issuer",
  "subject",
  "iat",
  "kid",
  "body",
  "sig",
  "holder",
  "audience",
  "exp",
  "parent",
]);

function isClaimShape(value: unknown): value is APRClaim {
  if (!value || typeof value !== "object") return false;
  const c = value as Record<string, unknown>;
  if (c.v !== 1) return false;
  if (typeof c.id !== "string") return false;
  if (c.kind !== "ar.provenance.v1") return false;
  if (typeof c.issuer !== "string") return false;
  if (typeof c.subject !== "string") return false;
  if (typeof c.iat !== "number" || !Number.isInteger(c.iat) || c.iat < 0) {
    return false;
  }
  if (typeof c.kid !== "string") return false;
  if (typeof c.sig !== "string") return false;
  if (!c.body || typeof c.body !== "object") return false;
  for (const key of Object.keys(c)) {
    if (!KNOWN_CLAIM_KEYS.has(key)) return false;
  }
  return true;
}

export function verifyClaim(
  rawClaim: unknown,
  resolver: ClaimKeyResolver,
  now: number,
): ClaimCheckResult {
  if (!isClaimShape(rawClaim)) {
    return { ok: false, reason: "schema_invalid" };
  }
  const claim = rawClaim;

  const verifyingKey = resolver(claim.kid);
  if (!verifyingKey) {
    return { ok: false, reason: "unknown_kid" };
  }
  if (verifyingKey.issuer !== claim.issuer) {
    return { ok: false, reason: "issuer_kid_mismatch" };
  }
  if (verifyingKey.publicKey.length !== 32) {
    return { ok: false, reason: "schema_invalid" };
  }
  if (
    verifyingKey.notBefore !== undefined &&
    now < verifyingKey.notBefore
  ) {
    return { ok: false, reason: "kid_not_yet_valid" };
  }
  if (
    verifyingKey.notAfter !== undefined &&
    now > verifyingKey.notAfter
  ) {
    return { ok: false, reason: "kid_no_longer_valid" };
  }
  if (claim.exp !== undefined && now > claim.exp) {
    return { ok: false, reason: "expired" };
  }

  const { sig, ...unsigned } = claim;
  let sigBytes: Uint8Array;
  try {
    sigBytes = base64UrlDecode(sig);
  } catch {
    return { ok: false, reason: "signature_invalid" };
  }
  if (sigBytes.length !== 64) {
    return { ok: false, reason: "signature_invalid" };
  }
  let canonicalBytes: Uint8Array;
  try {
    canonicalBytes = new TextEncoder().encode(canonicalize(unsigned));
  } catch {
    return { ok: false, reason: "schema_invalid" };
  }
  const ok = ed25519Verify(verifyingKey.publicKey, canonicalBytes, sigBytes);
  if (!ok) return { ok: false, reason: "signature_invalid" };
  return { ok: true, claim };
}
