/**
 * `ar.field_commit.v1` — issuer-signed binding of a receipt to its field_root.
 *
 * Standalone attestation (NOT a v=2 envelope, no claim_type). Phase 2 Tier A:
 * the envelope signs the full body, so `field_root` is not standalone-verifiable
 * from a redacted receipt. This attestation signs ONLY {id, field_root, iss_key}
 * so a selective-disclosure verifier can confirm field_root is issuer-authentic
 * WITHOUT the body.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
 */
import {
  verify as nodeVerify,
  sign as nodeSign,
  createPublicKey,
  type KeyObject,
} from "node:crypto";
import { canonicalize } from "./canonicalize.ts";
import { base64UrlDecode, base64UrlEncode } from "./base64url.ts";
import type { FamilySlug } from "./continuity.ts";

export interface FieldCommitAttestation {
  kind: "ar.field_commit.v1";
  family: FamilySlug;
  /** Envelope id of the committed receipt. */
  id: string;
  /** Merkle root over the receipt's per-field commitments, `sha256:<hex64>`. */
  field_root: string;
  /** Number of leaves in the per-field Merkle tree — binds tree size so a presentation can't inflate it. */
  leaf_count: number;
  /** Issuer Ed25519 public key, `ed25519:<b64u>`. */
  iss_key: string;
  issued_at: string;
  sig: string | null;
}

export interface IssueFieldCommitInput {
  family: FamilySlug;
  id: string;
  field_root: string;
  /** Number of leaves in the per-field Merkle tree — binds tree size so a presentation can't inflate it. */
  leaf_count: number;
  iss_key: string;
  issued_at: string;
}

export interface VerifyFieldCommitResult {
  valid: boolean;
  errors: string[];
}

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

export function issueFieldCommit(
  input: IssueFieldCommitInput,
  privateKey: KeyObject,
): FieldCommitAttestation {
  const att: FieldCommitAttestation = {
    kind: "ar.field_commit.v1",
    family: input.family,
    id: input.id,
    field_root: input.field_root,
    leaf_count: input.leaf_count,
    iss_key: input.iss_key,
    issued_at: input.issued_at,
    sig: null,
  };
  const msg = new TextEncoder().encode(canonicalize(att));
  att.sig = `ed25519:${base64UrlEncode(new Uint8Array(nodeSign(null, msg, privateKey)))}`;
  return att;
}

export function verifyFieldCommit(att: FieldCommitAttestation): VerifyFieldCommitResult {
  const errors: string[] = [];
  if (att.kind !== "ar.field_commit.v1") return { valid: false, errors: ["kind.invalid"] };
  if (!att.sig) return { valid: false, errors: ["sig.missing"] };
  try {
    const raw = base64UrlDecode(att.iss_key.replace(/^ed25519:/, ""));
    const pub = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]),
      format: "der",
      type: "spki",
    });
    const sigRaw = base64UrlDecode(att.sig.replace(/^ed25519:/, ""));
    const unsigned: FieldCommitAttestation = { ...att, sig: null };
    const msg = new TextEncoder().encode(canonicalize(unsigned));
    if (!nodeVerify(null, msg, pub, Buffer.from(sigRaw))) errors.push("sig.invalid");
  } catch {
    errors.push("sig.import_error");
  }
  return { valid: errors.length === 0, errors };
}
