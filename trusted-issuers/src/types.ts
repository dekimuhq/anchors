import type {
  TrustedIssuerRecord,
  FamilySlug,
  PqcMandate,
} from "@dekimuhq/did-web-resolver";

export type { TrustedIssuerRecord, FamilySlug, PqcMandate };

/**
 * `ar.trusted_issuers.v1` — standalone signed attestation. Sibling shape to
 * `ar.continuity.v1` (NOT a receipt, NOT wrapped in v=2 envelope).
 *
 * Spec: an internal design record (not published) §2.1.
 * Registered in: meta/REGISTRY.md standalone-attestation subsection.
 * Cross-family invariants: meta/FAMILY-CONSISTENCY.md §8.2.
 */
export interface TrustedIssuerListV1 {
  kind: "ar.trusted_issuers.v1";
  version: number;
  issued_at: string;
  valid_until: string;
  publisher: string;
  publisher_key: string;
  previous_sha256: string | null;
  issuers: TrustedIssuerRecord[];
  sig: string;
}

/**
 * Shape with `sig` cleared — exactly what gets canonicalised and signed.
 */
export type TrustedIssuerListUnsignedV1 = Omit<TrustedIssuerListV1, "sig"> & {
  sig: null;
};
