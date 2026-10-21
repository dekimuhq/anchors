/**
 * @dekimuhq/aar-tsl — core types.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/aar §4.
 */

import type { AarServiceType } from "@dekimuhq/aar";

// ── Claim type ──────────────────────────────────────────────────────────────

export type AarClaimType = "ar.attestation.v1";

// ── TSL service entry (Merkle leaf unit) ─────────────────────────────────────

/** A single trust service extracted from a national TSL. */
export interface TslServiceEntry {
  /** ISO 3166-1 alpha-2 country code of the listing member state. */
  country: string;
  /** QTSP provider name (cleartext, from TSL). */
  provider_name: string;
  /**
   * ETSI service type identifier URI from TSL XML.
   * e.g. "http://uri.etsi.org/TrstSvc/Svctype/QCertESig"
   */
  service_type_identifier: string;
  /** Mapped AAR service type when recognizable; null for unknown URIs. */
  service_type: AarServiceType | null;
  /** Service name from TSL. */
  service_name: string;
  /** Current status URI (e.g. "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"). */
  status: string;
  /** Status start date (ISO 8601). */
  status_starting_time: string;
  /** X.509 certificate fingerprint(s) — SHA-256 hex of DER-encoded cert. */
  certificate_hashes: string[];
}

// ── Merkle leaf ──────────────────────────────────────────────────────────────

export interface TslLeaf {
  /** Index in the Merkle tree (0-based). */
  index: number;
  /** SHA-256 of JCS-canonicalized TslServiceEntry ("sha256:<hex>"). */
  hash: string;
  /** The source entry (retained for lookups). */
  entry: TslServiceEntry;
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

/** Immutable snapshot of one Merkle tree build. */
export interface TslSnapshot {
  /** ISO 8601 UTC timestamp of this snapshot. */
  log_time: string;
  /** Merkle tree root hash ("sha256:<hex>"). */
  root: string;
  /** Number of leaves. */
  tree_size: number;
  /** All leaves (for proof generation + archival). */
  leaves: TslLeaf[];
}

// ── Proof bundle (what AAR issuers embed in receipts) ────────────────────────

export interface TslProofBundle {
  tsl_country: string;
  tsl_entry_hash: string;
  tsl_signed_tree_head_root: string;
  tsl_tree_size: number;
  tsl_inclusion_proof: string[];
  tsl_log_time: string;
}

// ── Tree head (stored in Redis + Blob) ───────────────────────────────────────

export interface TreeHead {
  /** Merkle root ("sha256:<hex>"). */
  root: string;
  /** Leaf count. */
  tree_size: number;
  /** Snapshot timestamp (ISO 8601). */
  log_time: string;
  /** Blob key for the full snapshot JSON. */
  blob_key: string;
}

// ── LOTL pointer ─────────────────────────────────────────────────────────────

export interface NationalTslPointer {
  /** ISO 3166-1 alpha-2. */
  country: string;
  /** URL of the national TSL XML. */
  url: string;
}

// ── Service type URI → AarServiceType mapping ────────────────────────────────

/**
 * ETSI TS 119 612 service type identifier URIs mapped to AAR service types.
 * Unknown URIs → null.
 */
export const SERVICE_TYPE_URI_MAP: ReadonlyMap<string, AarServiceType> = new Map([
  ["http://uri.etsi.org/TrstSvc/Svctype/QCertESig", "qes"],
  ["http://uri.etsi.org/TrstSvc/Svctype/QCertESeal", "qeseal"],
  ["http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST", "qts"],
  ["http://uri.etsi.org/TrstSvc/Svctype/EDS/REM/Q", "qereg"],
  ["http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC", "qcert_natural"],
  ["http://uri.etsi.org/TrstSvc/Svctype/IdV", "qcert_legal"],
]);
