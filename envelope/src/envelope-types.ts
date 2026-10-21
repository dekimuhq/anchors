/**
 * Canonical types for the Anchored Receipts shared envelope.
 *
 * `ClaimType` is derived from `CLAIM_TYPES` const — the array and the union
 * can never drift from each other.
 *
 * Ref: @dekimuhq/anchors-envelope · Phase A Task 2 real shapes
 *      Spec: meta/REGISTRY.md (source of truth for discriminators)
 *      Plan: an internal design record (not published) §Task 2 + AMENDMENT
 */

// ── ClaimType discriminator union ────────────────────────────────────────────
// 10 shipped + 6 pre-canonical-specced + 4 closure-set + 1 ATokR + 1 AActR + 1 AQR + 1 AGR + 1 AGrR + 2 AgTR (v1 flat + v2 span-tree) + 1 APIIR + 1 ACBR = 29 active members (parked excluded until v1.1+ gates).
// Count corrected 2026-07-22: the tally had missed ar.trace.v2 and ar.compliance.v1. Comment only — the tuple below is unchanged and remains the single source of truth.

export const CLAIM_TYPES = [
  "ar.provenance.v1",
  "ar.consent.v1",
  "ar.withdrawal.v1",
  "ar.modification.v1",
  "ar.erasure.v1",
  "ar.expiry.v1",
  "ar.hold.v1",
  "ar.anonymization.v1",
  "ar.archive.v1",
  "ar.batch.v1",
  "ar.delegation.v1",
  "ar.transfer.v1",
  "ar.purpose.v1",
  "ar.evaluation.v1",
  "ar.attestation.v1",
  "ar.lineage.v1",
  "ar.notice.v1",
  "ar.breach.v1",
  "ar.subject_rights.v1",
  "ar.impact.v1",
  "ar.tokenization.v1",
  "ar.action.v1",
  "ar.quality.v1",
  "ar.guard.v1",
  "ar.grounding.v1",
  "ar.trace.v1",
  "ar.trace.v2",
  "ar.redaction.v1",
  "ar.compliance.v1",
] as const satisfies readonly string[];

/** All active claim_type discriminators. Parked members are excluded. */
export type ClaimType = (typeof CLAIM_TYPES)[number];

// ── Supporting types ──────────────────────────────────────────────────────────

/**
 * RFC 6962 Merkle inclusion proof + anchor tree metadata.
 *
 * Matches the existing ACR `AcrAnchor` on-wire shape (P10 backward-compat).
 * Canonical log URL example: "https://verify.dekimu.com/acr/v1"
 */
export interface AnchorProof {
  /** Canonical anchor log URL, e.g. "https://verify.dekimu.com/acr/v1". */
  log: string;
  /** 0-based position of this receipt in its anchor tree. */
  leaf_index: number;
  /** RFC 6962 audit path; each entry is a "sha256:<hex>" hash. */
  inclusion_proof: string[];
  /** "sha256:<hex>" Merkle root of the anchor tree at this size. */
  tree_head_root: string;
  /** Anchor tree size at the time of inclusion (≥ 1). */
  tree_size: number;
  /** ISO 8601 UTC timestamp, e.g. "2026-05-17T00:00:00Z". */
  log_time: string;
}

/**
 * RFC 3161 timestamp authority block.
 *
 * `tsr` is the base64url-encoded RFC 3161 TimeStampResp.
 * `tsa_cert_chain_sha256` pins the chain at issue time (each entry "sha256:<hex>").
 */
export interface TsaBlock {
  /** Always 1 for this version. */
  v: 1;
  /** Base64url-encoded RFC 3161 TimeStampResp. */
  tsr: string;
  /** Hash algorithm used for the TSA message imprint. */
  alg: "sha-256";
  /** URL of the timestamp authority. */
  tsa_url: string;
  /** Pinned cert chain SHA-256 hashes — each entry "sha256:<hex>". */
  tsa_cert_chain_sha256: string[];
  /** ISO 8601 UTC timestamp when the TSA token was issued. */
  issued_at: string;
}

/**
 * W3C Bitstring Status List 2021 Entry — status pointer embedded in the envelope.
 *
 * v1.1 supports revocation only. The Status List Credential is published
 * by the verify.dekimu.com anchor-log worker (out of this plan scope).
 */
export interface CredentialStatus {
  /** Unique identifier for this status entry (URL form recommended). */
  id: string;
  /** Hardcoded to "StatusList2021Entry". */
  type: "StatusList2021Entry";
  /** v1.1 supports revocation only. */
  statusPurpose: "revocation";
  /** Index into the bitstring, represented as a decimal string. */
  statusListIndex: string;
  /** URL to the Status List 2021 Credential published by the log worker. */
  statusListCredential: string;
}

/**
 * W3C Bitstring Status List 2021 Entry — suspension pointer.
 *
 * Structurally identical to CredentialStatus but with statusPurpose
 * locked to "suspension". Separate type for compile-time safety.
 * Wave 3 addition — optional on the envelope.
 */
export interface SuspensionStatus {
  /** Unique identifier for this status entry (URL form recommended). */
  id: string;
  /** Hardcoded to "StatusList2021Entry". */
  type: "StatusList2021Entry";
  /** Suspension purpose — two-way (can be set and cleared). */
  statusPurpose: "suspension";
  /** Index into the bitstring, represented as a decimal string. */
  statusListIndex: string;
  /** URL to the Status List 2021 Credential published by the log worker. */
  statusListCredential: string;
}

// ── v1.2 envelope additions: kind + cause ────────────────────────────────────
//
// `kind` and `cause` runtime-const arrays + derived string-literal-union types
// so consumers can iterate the allowed values without re-listing.
//
// Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
//       §4.1 (kind) · §4.2 (cause) · L3 + L4 (closed enums)
// JSON Logic types + allowlist live in jsonlogic-types.ts + jsonlogic-allowlist.ts.

/** Receipt classification per spec §4.1 — Art. 22 evidence taxonomy. */
export const KIND_VALUES = ["observation", "decision"] as const satisfies readonly string[];
export type Kind = (typeof KIND_VALUES)[number];

/** Receipt-issuance trigger per spec §4.2 — closed enum, additive-only per L4. */
export const CAUSE_VALUES = [
  "manual",
  "scheduled",
  "event",
  "api",
  "regulatory_request",
  "rectification",
  "erasure_request",
  "portability_request",
  "objection",
  "automated_decision_review",
  "breach",             // D-anchors-7
  "review_cycle",       // D-anchors-7
  "material_change",    // D-anchors-7
] as const satisfies readonly string[];
export type Cause = (typeof CAUSE_VALUES)[number];

// ── v1.3 envelope addition: sig_alg (signature algorithm agility) ─────────────
//
// Closed enum, additive-only (same posture as `cause`, v1.2 L4): a new algorithm
// lands via a documented decision WITHOUT an envelope version bump; removing or
// repurposing a value requires v1.4+.
//
// Phase 1 (2026-06-01) shipped the agility HOOK with `ed25519` as the only
// registered value. Phase 2 (2026-06-04) adds `ml-dsa-65` — the §3.4 provider
// question resolved to native `node:crypto` on Node ≥24.6 (OpenSSL 3.5, nodejs
// #59259), so the "no third-party crypto" invariant holds via a Node-floor bump
// and `liboqs` is not needed. `slh-dsa-sha2-128s` remains spec'd (L5) but
// unregistered until separately wired + tested (additive, same path).
//
// Spec: https://github.com/dekimuhq/anchors-spec/blob/main/rfcs/RFC-001-sig-alg-discriminator.md
// Decision: an internal design record (not published)
//       L1 (hook-first) · L2 (absent ≡ ed25519, byte-equal) · L3 (SIGNED-IN) · L4 (additive enum)
export const SIG_ALGS = ["ed25519", "ml-dsa-65"] as const satisfies readonly string[];
export type SigAlg = (typeof SIG_ALGS)[number];

// Self-describing issuer-key fingerprint: `<sig_alg>:<base64url-raw-key>`. The
// prefix MUST match the governing `sig_alg` (L6) — a verifier rejects a mismatch
// with `sig_alg_key_prefix_mismatch`. Widens the v1.2 `ed25519:${string}` literal
// additively; absent/`ed25519:` keys are unchanged. Enumerates exactly the
// registered `SIG_ALGS` so the prefix and `sig_alg` stay type-consistent.
export type IssuerKeyRef = `ed25519:${string}` | `ml-dsa-65:${string}`;

// Forward-declared so Envelope can reference the JSON Logic AST without a circular
// import. Concrete type lives in jsonlogic-types.ts and is re-exported from index.ts.
import type { JsonLogicAst } from "./jsonlogic-types.ts";

// ── Envelope ─────────────────────────────────────────────────────────────────

/**
 * Shared wire envelope — v2.
 *
 * All Anchored Receipt member packages share this outer shape. The member-
 * specific payload lives in `body` (typed `unknown` here; member verifiers
 * narrow it via Zod). `field_root` stays in the ACR member-specific body
 * (Delta C) and is NOT a top-level envelope field.
 *
 * Field inventory (30 fields — v1.2+countersig_key delta+v1.4 incl+v1.3 sig_alg+v1.3 R3 hybrid):
 *   v, id, iat, iat_ms, claim_type, iss, iss_key, subject, exp, prev,
 *   policy_uri, policy_hash, policy_version,
 *   kind, cause, predicate,
 *   tsa, credentialStatus, suspensionStatus, anchor, sig, countersig, countersig_key, body, incl,
 *   sig_alg, sig2, sig2_alg, sig2_key, sig_min_alg
 *
 * v1.1 → v1.2 additions are all backwards-compatible: receipts minted under
 * v1.1 (without `iat_ms`/`kind`/`cause`/`predicate`) remain byte-equal
 * verifiable. Only v1.2 issuers populate the new fields.
 *
 * Delta D: `countersig` is `string | null` — a raw base64url signature,
 * NOT a wrapping object. The CounterSig stub has been removed.
 */
export interface Envelope {
  /** Envelope version — always `2` for this spec. */
  v: 2;

  /** Unique receipt identifier — ULID Crockford-Base32. */
  id: string;

  /** Issuance timestamp — ISO 8601 UTC, e.g. "2026-05-16T14:00:00Z". Delta B override. */
  iat: string;

  /**
   * v1.2 §4.4: Unix-ms mirror of `iat`. MUST equal `Date.parse(iat)` exactly.
   * Optional on v1.1 receipts (legacy); mandatory whenever v1.2 issuers mint.
   * The verifier rejects `iat_ms !== Date.parse(iat)` with `iat_ms_mismatch`.
   */
  iat_ms?: number;

  /** Member discriminator — one of the 20 active ClaimType literals. */
  claim_type: ClaimType;

  /** Issuer DID or key identifier. */
  iss: string;

  /**
   * Issuer public key fingerprint — `<sig_alg>:<base64url-raw-key>` (`IssuerKeyRef`).
   * `ed25519:<b64url-32B>` (default) or `ml-dsa-65:<b64url-1952B>` (v1.3 PQC).
   * Prefix MUST match `sig_alg` (L6).
   */
  iss_key: IssuerKeyRef;

  /**
   * Envelope-level subject identifier (DID, URN, or opaque string), or `null`
   * for null-subject families (workspace/act-level receipts — AActR/AQR/AGR/
   * AGrR/AgTR/APIIR/ACBR and the event-conditional null cases of ATR/AER/ABR/
   * AIR/APuR/ALR). The subject-presence rule per family is FAMILY-CONSISTENCY §3;
   * verifiers enforce it via each family's `checkSubjectPresence`.
   */
  subject: string | null;

  /** Expiry timestamp ISO 8601 UTC, or null if perpetual. */
  exp: string | null;

  /** Previous receipt ID for chain linkage, or null. */
  prev: string | null;

  /** URI to the applicable policy document, or null. */
  policy_uri: string | null;

  /** Hash of the policy document (hex or base64url), or null. */
  policy_hash: string | null;

  /** Semantic version of the policy document, or null. */
  policy_version: string | null;

  /**
   * v1.2 §4.1: observation vs decision. `null` when the claim type does not
   * distinguish (e.g. `ar.provenance.v1`, `ar.batch.v1`). Optional under v1.2;
   * absent on v1.1 receipts.
   */
  kind?: Kind | null;

  /**
   * v1.2 §4.2: typed trigger (closed enum, additive-only per L4).
   * Optional under v1.2; absent on v1.1 receipts.
   */
  cause?: Cause | null;

  /**
   * v1.2 §4.3: optional JSON Logic AST committed to a verifiable condition.
   * Operators restricted to `JSON_LOGIC_ALLOWLIST_V1_2`. Evaluation root
   * context is the canonicalised envelope itself. Forbidden on
   * `ar.provenance.v1` and `ar.batch.v1` (L9 + spec §6).
   */
  predicate?: JsonLogicAst | null;

  /** RFC 3161 timestamp authority block, or null. */
  tsa: TsaBlock | null;

  /** W3C Bitstring Status List pointer, or null. */
  credentialStatus: CredentialStatus | null;

  /**
   * W3C Bitstring Status List pointer for suspension, or null.
   * Optional — absent on receipts minted before Wave 3.
   * Signed-in: mutating after sign invalidates the signature.
   */
  suspensionStatus?: SuspensionStatus | null;

  /** Anchor proof (RFC 6962 Merkle inclusion + tree metadata). */
  anchor: AnchorProof;

  /** Ed25519 signature over canonicalized envelope — base64url. */
  sig: string;

  /**
   * Optional countersignature from a second issuer key — base64url string, or null.
   * Delta D: plain string (not a wrapping object) per Plan H §6 / §8.
   */
  countersig: string | null;

  /**
   * Public key fingerprint of the countersigning key — `ed25519:<base64url>`.
   * Signed-in: the issuer commits to who may countersign at issuance time.
   * When present + `countersig` present, verifiers can cryptographically verify
   * the countersignature. When absent, only format checking is possible.
   *
   * Added as a v1.2 countersig_key delta (decision 2026-05-21). Widened to
   * `IssuerKeyRef` in v1.3 (L6) — a countersigning key may be ed25519 or ml-dsa-65.
   */
  countersig_key?: IssuerKeyRef | null;

  /**
   * Transparency-log inclusion block (v1.4, signed-out). Absent ⇒ not_logged.
   *
   * Contains the CT-style inclusion promise (fast, non-blocking) and/or the
   * full Merkle inclusion proof (available after log integration window).
   * Signed-out: adding or upgrading this block never perturbs the signature.
   */
  incl?: {
    log_id: string;
    leaf: string;
    promise?: { timestamp: string; sig: string };
    proof?: { index: number; tree_size: number; path: string[]; checkpoint: string };
  };

  /**
   * v1.3 §L2: signature algorithm naming the scheme used for `sig` / `iss_key`.
   * Closed enum (`SigAlg`). SIGNED-IN (§L3) — covered by the signature it names,
   * so it cannot be stripped or downgraded (defeats the JWS `alg`-confusion
   * attack class). Absent ≡ `"ed25519"` (backwards-compat): v1.1/v1.2 receipts
   * carry no `sig_alg` and verify byte-equal, and v1.3 Ed25519 issuers MAY omit
   * it to stay byte-equal to v1.2 minting. A verifier that receives a `sig_alg`
   * it cannot evaluate refuses with `unsupported_sig_alg` — never a silent pass.
   */
  sig_alg?: SigAlg;

  /**
   * v1.3 §L7 hybrid dual-sign: an OPTIONAL second signature over the SAME
   * `preSigCanonical(e)` bytes as `sig`. base64url. SIGNED-OUT — handled by
   * `SIGNED_OUT_EXCLUDED` (deleted, not zeroed) so a receipt that never carried
   * it canonicalizes byte-identically (the C-1 mechanism, already in place for
   * `incl`). Lets an issuer attach an Ed25519+PQC pair during the transition:
   * old verifiers check `sig` and ignore the unknown `sig2*` fields; PQC-aware
   * verifiers also check `sig2`. No path validates NEITHER (§5).
   */
  sig2?: string | null;

  /**
   * v1.3 §L7: algorithm naming the scheme used for `sig2` / `sig2_key`.
   * SIGNED-IN — required (non-null) iff `sig2` is present, absent otherwise.
   * Closed enum (`SigAlg`). For a hybrid pair to add value it MUST differ from
   * `sig_alg` (an Ed25519 `sig` + a PQC `sig2`); the envelope layer does not
   * force this, but a same-algorithm pair carries no quantum benefit.
   */
  sig2_alg?: SigAlg | null;

  /**
   * v1.3 §L7: key fingerprint for `sig2` — `<sig2_alg>:<base64url-raw-key>`
   * (`IssuerKeyRef`). SIGNED-IN. Prefix MUST match `sig2_alg` (§L6) or the
   * `sig2` check fails. Because it is signed-in, the second key cannot be
   * swapped without breaking `sig` (which covers it).
   */
  sig2_key?: IssuerKeyRef | null;

  /**
   * v1.3 §C-2 fix — SIGNED-IN minimum-signature posture commitment. When set, a
   * verifier MUST reject the receipt unless a VALID signature whose algorithm is
   * ≥ `sig_min_alg` in the PQC-migration ordering (`ed25519` < `ml-dsa-65`) is
   * present (either `sig` or `sig2`). Because it is signed-in, stripping the PQC
   * half of a hybrid receipt leaves `sig_min_alg:"ml-dsa-65"` provably present →
   * the verifier sees a posture it can no longer satisfy and rejects, so a
   * single-receipt downgrade is DETECTABLE. Absent ≡ no minimum (classical
   * acceptable).
   *
   * HARD LIMIT (documented, not a bug): this closes per-receipt stripping only.
   * A complete HNDL defense ALSO needs issuer-level PQC-migration trust state in
   * `@dekimuhq/anchors-trusted-issuers` ("issuer X is PQC-mandatory as of date
   * Y") — once a classical key is quantum-broken, an attacker forges a fresh
   * Ed25519 `sig` over a canonical form with `sig_min_alg` absent, producing a
   * syntactically valid classical-only receipt. Only a trust-layer record that
   * rejects ANY classical-only receipt from a migrated issuer closes that. See
   * spec §5 / Open Q #3 (deferred — its manifest field shape is still open).
   */
  sig_min_alg?: SigAlg | null;

  /**
   * Member-specific receipt body. Each member package validates this
   * with its own Zod schema; the envelope layer treats it as `unknown`.
   */
  body: unknown;
}
