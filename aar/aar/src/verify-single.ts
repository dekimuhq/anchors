/**
 * Per-event-type AAR body verifier (spec §4 + D12-AAR).
 *
 * Validates the discriminated union on `body.event_type` and per-event
 * required-field rules including TSL snapshot fields and service-type-
 * conditional requirements. Called by the factory's body-validation step;
 * also exported for callers that hold a body in hand.
 */

import type {
  AarBody,
  AarServiceType,
  AarSignatureFormat,
  AarRevocationReason,
} from "./types.ts";

// ── Public surface ────────────────────────────────────────────────────────────

export interface VerifyBodyResult {
  /** True iff every structural check in §4 passes. */
  valid: boolean;
  /** Stable, machine-readable failure codes. Empty when `valid === true`. */
  errors: string[];
  /** Narrowed body when valid; null otherwise. */
  body: AarBody | null;
}

/**
 * Validate an AAR `body` against spec §4 per-event-type rules.
 * Returns the narrowed discriminated-union body on success.
 */
export function verifyAarBody(body: unknown): VerifyBodyResult {
  const errors: string[] = [];

  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;

  switch (b.event_type) {
    case "issuance":
      validateIssuance(b, errors);
      break;
    case "revocation":
      validateRevocation(b, errors);
      break;
    default:
      errors.push("event_type.unknown");
  }

  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as AarBody };
}

// ── §4.1 issuance ─────────────────────────────────────────────────────────────

function validateIssuance(b: Record<string, unknown>, errors: string[]): void {
  // service_type: REQUIRED valid enum
  if (!isServiceType(b.service_type)) {
    errors.push("service_type.invalid");
  }

  // service_policy_oid: REQUIRED non-empty string
  if (!isNonEmptyString(b.service_policy_oid)) {
    errors.push("service_policy_oid.missing");
  }

  // service_recipient_commit: REQUIRED sha256
  if (!isSha256(b.service_recipient_commit)) {
    errors.push("service_recipient_commit.invalid");
  }

  // artefact_metadata_commit: REQUIRED sha256
  if (!isSha256(b.artefact_metadata_commit)) {
    errors.push("artefact_metadata_commit.invalid");
  }

  // artefact_hash: REQUIRED for qes, qeseal, qts, qereg; optional otherwise
  const svcType = b.service_type as string;
  if (ARTEFACT_HASH_REQUIRED.has(svcType)) {
    if (!isSha256(b.artefact_hash)) {
      errors.push("artefact_hash.required_for_service_type");
    }
  } else {
    if (b.artefact_hash !== null && b.artefact_hash !== undefined && !isSha256(b.artefact_hash)) {
      errors.push("artefact_hash.invalid");
    }
  }

  // signature_format: REQUIRED for qes, qeseal; optional otherwise
  if (SIGNATURE_FORMAT_REQUIRED.has(svcType)) {
    if (b.signature_format === null || b.signature_format === undefined) {
      errors.push("signature_format.required_for_service_type");
    } else if (!isSignatureFormat(b.signature_format)) {
      errors.push("signature_format.invalid");
    }
  } else {
    if (b.signature_format !== null && b.signature_format !== undefined && !isSignatureFormat(b.signature_format)) {
      errors.push("signature_format.invalid");
    }
  }

  // qcert_serial_commit: REQUIRED sha256 for qcert_natural, qcert_legal, qes, qeseal
  if (QCERT_REQUIRED.has(svcType)) {
    if (!isSha256(b.qcert_serial_commit)) {
      errors.push("qcert_serial_commit.required_for_service_type");
    }
  }

  // TSL fields (always required on issuance)
  validateTslFields(b, errors);

  // atr_transfer_hash: optional (if non-null must be sha256)
  if (b.atr_transfer_hash !== null && b.atr_transfer_hash !== undefined && !isSha256(b.atr_transfer_hash)) {
    errors.push("atr_transfer_hash.invalid");
  }
}

// ── §4.2 revocation ───────────────────────────────────────────────────────────

function validateRevocation(b: Record<string, unknown>, errors: string[]): void {
  // reason: REQUIRED valid enum
  if (!isRevocationReason(b.reason)) {
    errors.push("reason.invalid");
  }

  // reason_ref_hash: optional (if non-null must be sha256)
  if (b.reason_ref_hash !== null && b.reason_ref_hash !== undefined && !isSha256(b.reason_ref_hash)) {
    errors.push("reason_ref_hash.invalid");
  }

  // TSL fields (always required on revocation)
  validateTslFields(b, errors);
}

// ── TSL snapshot fields (shared §4.1 + §4.2) ─────────────────────────────────

function validateTslFields(b: Record<string, unknown>, errors: string[]): void {
  // tsl_country: ISO 3166-1 alpha-2
  if (typeof b.tsl_country !== "string" || !TSL_COUNTRY_RE.test(b.tsl_country)) {
    errors.push("tsl_country.invalid");
  }

  // tsl_entry_hash: sha256
  if (!isSha256(b.tsl_entry_hash)) {
    errors.push("tsl_entry_hash.missing");
  }

  // tsl_signed_tree_head_root: sha256
  if (!isSha256(b.tsl_signed_tree_head_root)) {
    errors.push("tsl_signed_tree_head_root.missing");
  }

  // tsl_tree_size: non-negative integer
  if (typeof b.tsl_tree_size !== "number" || !Number.isInteger(b.tsl_tree_size) || b.tsl_tree_size < 0) {
    errors.push("tsl_tree_size.invalid");
  }

  // tsl_inclusion_proof: array of sha256
  if (!Array.isArray(b.tsl_inclusion_proof)) {
    errors.push("tsl_inclusion_proof.invalid");
  } else {
    for (let i = 0; i < b.tsl_inclusion_proof.length; i++) {
      if (!isSha256(b.tsl_inclusion_proof[i])) {
        errors.push(`tsl_inclusion_proof[${i}].invalid`);
      }
    }
  }

  // tsl_log_time: non-empty string + parseable date
  if (!isNonEmptyString(b.tsl_log_time) || isNaN(Date.parse(b.tsl_log_time as string))) {
    errors.push("tsl_log_time.invalid");
  }
}

// ── Service-type conditional sets ─────────────────────────────────────────────

const ARTEFACT_HASH_REQUIRED = new Set<string>(["qes", "qeseal", "qts", "qereg"]);
const SIGNATURE_FORMAT_REQUIRED = new Set<string>(["qes", "qeseal"]);
const QCERT_REQUIRED = new Set<string>(["qcert_natural", "qcert_legal", "qes", "qeseal"]);

// ── Shape predicates ──────────────────────────────────────────────────────────

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const TSL_COUNTRY_RE = /^[A-Z]{2}$/;

function isSha256(v: unknown): v is string {
  return typeof v === "string" && SHA256_RE.test(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

const SERVICE_TYPES = new Set<string>([
  "qes", "qeseal", "qts", "qereg",
  "qcert_natural", "qcert_legal",
  "qwallet", "qattest",
]);

function isServiceType(v: unknown): v is AarServiceType {
  return typeof v === "string" && SERVICE_TYPES.has(v);
}

const SIGNATURE_FORMATS = new Set<string>([
  "pades_b_b", "pades_b_t", "pades_b_lt", "pades_b_lta",
  "xades_b_b", "xades_b_t", "xades_b_lt", "xades_b_lta",
  "cades_b_b", "cades_b_t", "cades_b_lt", "cades_b_lta",
  "jades_b_b", "jades_b_t", "jades_b_lt", "jades_b_lta",
]);

function isSignatureFormat(v: unknown): v is AarSignatureFormat {
  return typeof v === "string" && SIGNATURE_FORMATS.has(v);
}

const REVOCATION_REASONS = new Set<string>([
  "key_compromise", "policy_violation", "recipient_request",
  "controller_decision", "tsl_delisted", "superseded",
]);

function isRevocationReason(v: unknown): v is AarRevocationReason {
  return typeof v === "string" && REVOCATION_REASONS.has(v);
}

// Re-export variant interfaces so callers narrowing on event_type get per-variant
// shapes without reaching into ./types.ts.
export type { AarIssuanceBody, AarRevocationBody } from "./types.ts";
