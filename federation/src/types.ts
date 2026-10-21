import type { FamilySlug } from "@dekimuhq/did-web-resolver";

export type { FamilySlug };

/**
 * Operator metadata — the legal entity behind an issuer DID.
 */
export interface OperatorInfo {
  name: string;
  jurisdiction: string;
  contact_uri: string;
}

/**
 * Per-family membership declaration within an issuer manifest.
 */
export interface IssuerMembership {
  family: FamilySlug;
  claim_types: string[];
  profiles: string[];
  spec_versions: string[];
}

/**
 * Cross-issuer trust anchors — observational metadata, NOT trust grants.
 *
 * `endorses` = "this issuer endorses these DIDs' trusted-issuers lists".
 * `endorsed_by` = reciprocal, populated post-handshake.
 * Neither field confers trust — the actual trust mechanism is the signed
 * allowlist in `@dekimuhq/anchors-trusted-issuers`.
 */
export interface TrustAnchors {
  endorses: string[];
  endorsed_by: string[];
}

/**
 * `ar.issuer_manifest.v1` — standalone signed attestation. Sibling shape to
 * `ar.trusted_issuers.v1` and `ar.continuity.v1` (NOT a receipt, NOT wrapped
 * in v=2 envelope).
 *
 * Each `did:web` issuer publishes ONE manifest at their own
 * `/.well-known/dekimu-issuer.json` advertising which family memberships
 * they emit, which claim_types they support, which profiles they implement,
 * and a pointer to their key doc.
 *
 * Spec: an internal design record (not published) §3.
 * Registered in: meta/REGISTRY.md standalone-attestation subsection.
 * Cross-family invariants: meta/FAMILY-CONSISTENCY.md §8.3.
 */
export interface IssuerManifestV1 {
  kind: "ar.issuer_manifest.v1";
  version: number;
  issued_at: string;
  valid_until: string;
  iss: string;
  operator: OperatorInfo;
  key_doc_uri: string;
  memberships: IssuerMembership[];
  trust_anchors: TrustAnchors;
  sig: string;
}

/**
 * Shape with `sig` cleared — exactly what gets canonicalised and signed.
 */
export type IssuerManifestUnsignedV1 = Omit<IssuerManifestV1, "sig"> & {
  sig: null;
};
