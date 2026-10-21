import type { FieldCommitAttestation } from "@dekimuhq/anchors-envelope";

/** One declared disclosable leaf. `array:true` ⇒ path is an array; each element
 *  becomes a leaf at /path/0, /path/1, … in index order. */
export interface LeafSpec {
  path: string;        // JSON pointer into the receipt body
  array?: boolean;
}

/** A family's declaration of which body paths are independently revealable.
 *  Order defines leaf layout; it is part of the commitment. */
export interface DisclosureSchema {
  claim_type: string;
  leaves: LeafSpec[];
}

/** Resolves a per-leaf salt (base64url) for a concrete resolved path. */
export interface SaltSource {
  saltFor(resolvedPath: string): string;
}

/** One revealed field inside a presentation. */
export interface RevealedField {
  path: string;            // resolved JSON pointer, e.g. "/purposes/0"
  value: unknown;          // canonicalised at commit/verify
  salt: string;            // base64url
  merkle_path: string[];   // RFC-6962 inclusion path → field_root
  leaf_index: number;
}

/** Holder-produced selective-disclosure presentation. Not holder-signed (Tier A). */
export interface DisclosurePresentation {
  kind: "ar.disclosure.v1";
  receipt_ref: string;             // === field_commit.id
  field_commit: FieldCommitAttestation;
  field_root: string;              // === field_commit.field_root
  leaf_count: number;
  revealed: RevealedField[];
  incl?: unknown;                  // optional Phase-1 transparency inclusion proof (opaque here)
}

export type VerifyReason =
  | "field_commit_sig_invalid"
  | "field_commit_id_mismatch"
  | "issuer_untrusted"
  | "leaf_commit_mismatch"
  | "merkle_path_invalid"
  | "field_root_mismatch"
  | "malformed";

export interface VerifyResult {
  valid: boolean;
  revealed: Record<string, unknown>;  // path → value, populated only when valid
  issuer: string | null;              // iss_key when valid
  reasons: VerifyReason[];
}
