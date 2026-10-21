/**
 * `ar.continuity.v1` — family-shared issuer key-rotation attestation.
 *
 * Standalone attestation (NOT a v=2 envelope). Issued when an issuer rotates
 * its Ed25519 key. Bridges the old key to the new key over a sealed mapping
 * so downstream verifiers can resolve historic receipts after a rotation.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
 *
 * Wire format compliant (`ar.<noun>.v<N>`). The `family` field discriminates
 * the issuer's family so rotation tooling can stay family-agnostic at the
 * schema level. Each member's issuer-kit re-exports these helpers and pins
 * its `family` slug at issue time.
 */

import {
  verify as nodeVerify,
  sign as nodeSign,
  createPublicKey,
  type KeyObject,
} from "node:crypto";
import { canonicalize } from "./canonicalize.ts";
import { base64UrlDecode, base64UrlEncode } from "./base64url.ts";

/**
 * Family slug — discriminates which member's issuer minted the attestation.
 * Closed union matches the 14 continuity-participating families (the 7 later
 * members — AActR/AQR/AGR/AGrR/AgTR/APIIR/ACBR — opt out via
 * `continuity: false` in their `family.ts`).
 * Additions require a wire-format additive bump (new families MUST be appended;
 * removal is breaking).
 */
export type FamilySlug =
  | "apr"
  | "acr"
  | "arr"
  | "alr"
  | "atr"
  | "apur"
  | "aer"
  | "aar"
  | "adr"
  | "anr"
  | "asr"
  | "abr"
  | "air"
  | "atokr";

export type ContinuitySealedMappingAlg =
  | "raw"
  | "sealedbox.x25519"
  | "aead.x25519";

export interface ContinuityAttestation {
  kind: "ar.continuity.v1";
  family: FamilySlug;
  iss: string;
  iss_key: string;
  epoch_from: string;
  epoch_to: string;
  sealedMapping: string;
  sealedMapping_alg: ContinuitySealedMappingAlg;
  issued_at: string;
  sig: string | null;
}

export interface IssueContinuityInput {
  family: FamilySlug;
  iss: string;
  iss_key: string;
  privateKey: KeyObject;
  epoch_from: string;
  epoch_to: string;
  sealedMapping: string;
  sealedMapping_alg: ContinuitySealedMappingAlg;
  issued_at: string;
}

export interface VerifyContinuityResult {
  valid: boolean;
  errors: string[];
}

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function signCanonical(payload: unknown, privateKey: KeyObject): string {
  const msg = new TextEncoder().encode(canonicalize(payload));
  const sig = nodeSign(null, msg, privateKey);
  return `ed25519:${base64UrlEncode(new Uint8Array(sig))}`;
}

export function issueContinuityAttestation(
  input: IssueContinuityInput,
): ContinuityAttestation {
  const att: ContinuityAttestation = {
    kind: "ar.continuity.v1",
    family: input.family,
    iss: input.iss,
    iss_key: input.iss_key,
    epoch_from: input.epoch_from,
    epoch_to: input.epoch_to,
    sealedMapping: input.sealedMapping,
    sealedMapping_alg: input.sealedMapping_alg,
    issued_at: input.issued_at,
    sig: null,
  };
  att.sig = signCanonical(att, input.privateKey);
  return att;
}

export function verifyContinuityAttestation(
  att: ContinuityAttestation,
): VerifyContinuityResult {
  const errors: string[] = [];
  if (att.kind !== "ar.continuity.v1") {
    return { valid: false, errors: ["kind.invalid"] };
  }
  if (!att.sig) {
    return { valid: false, errors: ["sig.missing"] };
  }
  try {
    const raw = base64UrlDecode(att.iss_key.replace(/^ed25519:/, ""));
    const pub = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]),
      format: "der",
      type: "spki",
    });
    const sigRaw = base64UrlDecode(att.sig.replace(/^ed25519:/, ""));
    const unsigned: ContinuityAttestation = { ...att, sig: null };
    const msg = new TextEncoder().encode(canonicalize(unsigned));
    if (!nodeVerify(null, msg, pub, Buffer.from(sigRaw))) {
      errors.push("sig.invalid");
    }
  } catch {
    errors.push("sig.import_error");
  }
  return { valid: errors.length === 0, errors };
}
