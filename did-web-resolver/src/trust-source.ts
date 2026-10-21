/**
 * Trust-tier dispatch interface — consumed by `verifyIssuerKey`.
 *
 * The resolver does NOT decide "trusted or not" — that is policy. The resolver
 * decides "this DID resolves to this key, valid in this window". Trust-tier
 * dispatch is done by `verifyIssuerKey` against a pluggable `TrustedIssuersSource`.
 *
 * The default implementation lives in `@dekimuhq/anchors-trusted-issuers` (Phase B
 * of the cross-issuer interop plan). Verifiers that want to roll their own
 * (e.g. self-hosted allowlist for an enterprise deployment) supply their own
 * `TrustedIssuersSource`.
 *
 * Wire-format reference: `meta/FAMILY-CONSISTENCY.md §8.2` (`ar.trusted_issuers.v1`).
 */

/**
 * Family slug. Matches `meta/FAMILY-CONSISTENCY.md §1` chip taxonomy.
 * Loose-typed `string` here so this package does not need to track the full
 * member set — downstream consumers narrow.
 */
export type FamilySlug = string;

/**
 * Issuer-level PQC-migration posture — the issuer-level half of the HNDL
 * (Harvest-Now-Decrypt-Later) defense. The per-receipt half is the envelope
 * `sig_min_alg`; that alone is self-defeating against a CRQC adversary who
 * controls a forged classical-only body (they simply omit the field). This
 * record lets a verifier reject classical-only (or sub-floor) receipts from a
 * migrated issuer REGARDLESS of the receipt's self-described posture.
 *
 * Consumed by the pure policy functions `issuerPqcRequirement` /
 * `satisfiesIssuerPqc` in `@dekimuhq/anchors-trusted-issuers`. Decision:
 * an internal design record (not published).
 */
export interface PqcMandate {
  /**
   * Minimum signature algorithm this issuer's receipts must carry once
   * `mandatory_from` has effectively passed. Loose-typed `string` (like
   * `FamilySlug`): the zero-dep resolver does not track the envelope algorithm
   * registry. The policy consumer validates this against the envelope `SIG_ALGS`
   * set and fails CLOSED on an unrecognised value.
   */
  min_sig_alg: string;
  /**
   * ISO 8601. A receipt whose *trustworthy effective-time* is >= this MUST carry
   * a valid signature of rank >= `min_sig_alg`. The effective-time is the
   * receipt's quantum-trustworthy inclusion time (transparency-log / TSL / anchor
   * inclusion proven against a pre-CRQC-witnessed checkpoint) — NEVER the
   * receipt's self-claimed `issued_at`, which is attacker-controlled in the
   * forgery scenario.
   */
  mandatory_from: string;
}

export interface TrustedIssuerRecord {
  /** "did:web:<domain>" */
  iss: string;
  /** ISO 8601 timestamp when this issuer joined the allowlist. */
  added_at: string;
  /** ISO 8601 timestamp when this issuer was revoked, or null = active. */
  revoked_at: string | null;
  /** Which family members this issuer is trusted for. */
  families: FamilySlug[];
  /**
   * Optional — pin specific profiles to specific claim_types. Used when an
   * issuer is trusted for some claim_types but not others. Null = no pinning.
   */
  profiles_pinned: Record<string, string[]> | null;
  /** Free-text notes for governance audit trail. Null = none. */
  notes: string | null;
  /**
   * Issuer-level PQC-migration posture (the issuer-level half of the HNDL
   * defense; the per-receipt half is the envelope `sig_min_alg`). Optional +
   * additive: absent/null = no mandate (Ed25519 accepted; current behavior).
   * See `PqcMandate` + `@dekimuhq/anchors-trusted-issuers` `issuerPqcRequirement`.
   */
  pqc_mandatory?: PqcMandate | null;
}

export interface TrustedIssuersSource {
  /**
   * Lookup by DID. Returns null if the DID is not on the allowlist.
   *
   * The implementation is responsible for revocation semantics — i.e. it may
   * choose to return a record with `revoked_at` set (so the caller can surface
   * `valid_revoked`) or return null entirely. The default implementation in
   * `@dekimuhq/anchors-trusted-issuers` returns the record either way so the
   * caller can distinguish "never on allowlist" from "previously on allowlist,
   * now revoked".
   */
  lookup(iss: string, now: Date): TrustedIssuerRecord | null;
}
