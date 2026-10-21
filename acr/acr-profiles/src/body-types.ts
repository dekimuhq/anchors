/** Receipt kind discriminator. */
export type AcrKind =
  | "ar.consent.v1"
  | "ar.modification.v1"
  | "ar.withdrawal.v1";

/** Registered v1 regulation profiles. New profiles slot in via registry. */
export type AcrProfile =
  | "gdpr.art7"
  | "aiact.art14"
  | "hipaa.auth"
  | "kyc.consent"
  | "mifid2.suit"
  | "esig.accept"
  | "gdpr.train";

/** Anchor inclusion proof, added post-signature by the anchor log. */
export interface AcrAnchor {
  /** Canonical log URL — e.g. `https://verify.dekimu.com/acr/v1`. */
  log: string;
  /** Leaf index in the Merkle log. */
  leaf_index: number;
  /** Inclusion proof: ordered hashes from leaf to root. */
  inclusion_proof: string[];
  /** Signed tree head root hash this proof was issued against. */
  tree_head_root: string;
  /** Tree size at issuance. */
  tree_size: number;
  /** Log timestamp (RFC 3339). */
  log_time: string;
}

/**
 * Canonical ACR receipt. The same shape covers consent, modification,
 * and withdrawal — disambiguated by `kind`.
 *
 * Encoded with RFC 8785 (JCS) for hashing and signing. `anchor` and `sig`
 * and `countersig` are excluded from the signature scope (set to null
 * when computing the signed hash).
 */
export interface ACRReceipt {
  /** Discriminator. */
  kind: AcrKind;
  /** Regulation profile (drives `lawful_basis` shape and field requirements). */
  profile: AcrProfile;
  /** Issuer DID (v1 supports `did:web:<domain>` only). */
  iss: string;
  /** Issuer public key fingerprint: `ed25519:<base64url>`. */
  iss_key: string;
  /** Salted commitment to subject identifier: `sha256:<hex>`. */
  sub_commit: string;
  /** Salted commitments to purpose descriptors. */
  purposes: string[];
  /** Profile-specific structured field. For `gdpr.art7`: one of `6(1)(a)..6(1)(f)`. */
  lawful_basis: string;
  /** SHA-256 of the consented policy document. */
  policy_hash: string;
  /** RFC 3339 timestamp claimed by issuer (verifiers MUST cross-check vs anchor time). */
  granted_at: string;
  /** Optional explicit expiry. */
  expires_at?: string;
  /** `null` for originals; hash of prior receipt for modification/withdrawal. */
  prev: string | null;
  /** Merkle root over salted per-field commitments. */
  field_root: string;
  /** Anchor proof, populated post-signature. `null` until anchored. */
  anchor: AcrAnchor | null;
  /** Ed25519 signature over canonical receipt with `anchor`, `sig`, `countersig` zeroed. */
  sig: string;
  /** Optional subject countersignature (reserved for EUDI Wallet). */
  countersig: string | null;
  /** Cross-sibling QTS attestation hash — references an AAR receipt hash. */
  qts_attestation_hash: string | null;
}

/** A single salted field commitment, kept off-receipt by the holder. */
export interface FieldDisclosure {
  /** Field name (matches the receipt key, e.g. "sub_commit", "purposes[0]"). */
  field: string;
  /** Canonical value (the actual subject ID, purpose text, etc.). */
  value: string;
  /** 32-byte random salt, base64url-encoded. */
  salt: string;
}

/** Selective disclosure proof for one field. */
export interface DisclosureProof {
  disclosure: FieldDisclosure;
  /** Merkle inclusion path from the field commitment up to `field_root`. */
  merkle_path: string[];
  /** Index of this commitment in the sorted leaf list. */
  leaf_index: number;
  /** Total leaves in the tree. */
  leaf_count: number;
}
