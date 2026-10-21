/**
 * Per-event-type body verifier for ALR (spec §4 + §4.5).
 *
 * Validates the discriminated union on `body.event_type` and the cross-cutting
 * structural rules (canonical parent sort, no duplicate parents, child hash
 * distinct from parents on derivation). Called by `verifyV2` once envelope-level
 * checks pass; also exported for callers that hold a body in hand.
 *
 * NOT a v=1 legacy verifier — ALR is v=2 only. Profile registration is
 * delegated to `@dekimuhq/alr-profiles`; this module only checks the v1
 * profile string is one of the five spec §5 literals.
 */

import type {
  AlrBody,
  AlrDerivedFromBody,
  AlrDisclosedBody,
  AlrForkedFromBody,
  AlrParentRef,
  AlrSupersededByBody,
} from "./types.ts";

// ── Public surface ────────────────────────────────────────────────────────────

export interface VerifyBodyResult {
  /** True iff every structural check in §4 + §4.5 passes. */
  valid: boolean;
  /** Stable, machine-readable failure codes. Empty when `valid === true`. */
  errors: string[];
  /** Narrowed body when valid; null otherwise. */
  body: AlrBody | null;
}

/**
 * Validate an ALR `body` against spec §4 (per-event-type rules) and §4.5
 * (cross-cutting structural rules). Returns the narrowed body on success.
 */
export function verifyAlrBody(body: unknown): VerifyBodyResult {
  const errors: string[] = [];

  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;

  // ── Base fields shared by every event type ─────────────────────────────────
  if (!isAlrProfile(b.profile)) errors.push("profile.unregistered");
  if (!isSha256Hex(b.artifact_hash)) errors.push("artifact_hash.invalid");
  if (!isIsoTimestamp(b.event_at)) errors.push("event_at.invalid");

  // ── Event-type dispatch ────────────────────────────────────────────────────
  switch (b.event_type) {
    case "derived_from":
      validateDerivedFrom(b, errors);
      break;
    case "forked_from":
      validateForkedFrom(b, errors);
      break;
    case "superseded_by":
      validateSupersededBy(b, errors);
      break;
    case "disclosed":
      validateDisclosed(b, errors);
      break;
    default:
      errors.push("event_type.unknown");
  }

  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as AlrBody };
}

// ── Per-event-type validators (§4.1–4.4) ──────────────────────────────────────

function validateDerivedFrom(b: Record<string, unknown>, errors: string[]): void {
  const parents = readParents(b.parents, errors);
  if (parents !== null) {
    if (parents.length < 1) errors.push("parents.empty");
    validateParentInvariants(parents, errors, /* requireSort */ true);

    // §4.1 — child artifact_hash MUST differ from every parent's.
    if (isSha256Hex(b.artifact_hash)) {
      const childHash = b.artifact_hash as string;
      for (const p of parents) {
        if (p.artifact_hash === childHash) {
          errors.push("derived_from.self_reference");
          break;
        }
      }
    }
  }
  if (b.successor !== null) errors.push("successor.must_be_null");
  if (b.disclosure !== null) errors.push("disclosure.must_be_null");
  validateTransformClaim(b.transform_claim, errors, /* required */ true);
}

function validateForkedFrom(b: Record<string, unknown>, errors: string[]): void {
  const parents = readParents(b.parents, errors);
  if (parents !== null) {
    if (parents.length !== 1) errors.push("parents.must_be_one");
    validateParentInvariants(parents, errors, /* requireSort */ false);
  }
  if (b.successor !== null) errors.push("successor.must_be_null");
  if (b.disclosure !== null) errors.push("disclosure.must_be_null");
  // transform_claim optional but, when present, must be well-formed.
  if (b.transform_claim !== null) {
    validateTransformClaim(b.transform_claim, errors, /* required */ true);
  }
}

function validateSupersededBy(b: Record<string, unknown>, errors: string[]): void {
  const parents = readParents(b.parents, errors);
  if (parents !== null && parents.length !== 0) errors.push("parents.must_be_empty");
  if (b.disclosure !== null) errors.push("disclosure.must_be_null");
  if (!isParentRefShape(b.successor)) {
    errors.push("successor.invalid");
  }
  validateTransformClaim(b.transform_claim, errors, /* required */ true);
}

function validateDisclosed(b: Record<string, unknown>, errors: string[]): void {
  const parents = readParents(b.parents, errors);
  if (parents !== null && parents.length !== 0) errors.push("parents.must_be_empty");
  if (b.successor !== null) errors.push("successor.must_be_null");
  if (b.transform_claim !== null) errors.push("transform_claim.must_be_null");
  if (!isDisclosureShape(b.disclosure)) errors.push("disclosure.invalid");
}

// ── §4.5 cross-cutting parent invariants ──────────────────────────────────────

function validateParentInvariants(
  parents: AlrParentRef[],
  errors: string[],
  requireSort: boolean,
): void {
  // Duplicate artifact_hash detection — §4.5.
  const seen = new Set<string>();
  for (const p of parents) {
    if (seen.has(p.artifact_hash)) {
      errors.push("parents.duplicate_artifact_hash");
      break;
    }
    seen.add(p.artifact_hash);
  }
  // Multi-parent canonical sort order — §4.1 / §4.5.
  if (requireSort && parents.length > 1) {
    for (let i = 1; i < parents.length; i++) {
      if (parents[i - 1]!.artifact_hash >= parents[i]!.artifact_hash) {
        errors.push("parents.not_canonical_sorted");
        break;
      }
    }
  }
}

// ── Shape predicates ──────────────────────────────────────────────────────────

const ALR_PROFILES = new Set<string>([
  "gdpr.art13.transparency",
  "aiact.art13.transparency",
  "aiact.art53.gpai-training",
  "c2pa.non-media",
  "disclosure.recipients",
]);

function isAlrProfile(v: unknown): v is string {
  return typeof v === "string" && ALR_PROFILES.has(v);
}

const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;

function isSha256Hex(v: unknown): v is string {
  return typeof v === "string" && SHA256_HEX_RE.test(v);
}

function isIsoTimestamp(v: unknown): v is string {
  if (typeof v !== "string") return false;
  const ms = Date.parse(v);
  return !Number.isNaN(ms);
}

function isParentRefShape(v: unknown): v is AlrParentRef {
  if (typeof v !== "object" || v === null) return false;
  const r = v as Record<string, unknown>;
  if (!isSha256Hex(r.artifact_hash)) return false;
  if (r.parent_apr_id !== null && typeof r.parent_apr_id !== "string") return false;
  if (r.parent_alr_id !== null && typeof r.parent_alr_id !== "string") return false;
  if (r.uri !== null && typeof r.uri !== "string") return false;
  return true;
}

function isDisclosureShape(v: unknown): boolean {
  if (typeof v !== "object" || v === null) return false;
  const r = v as Record<string, unknown>;
  return (
    typeof r.recipient === "string" && r.recipient.length > 0 &&
    typeof r.recipient_role === "string" && r.recipient_role.length > 0 &&
    typeof r.scope_hash === "string" && r.scope_hash.length > 0 &&
    typeof r.basis === "string" && r.basis.length > 0
  );
}

function readParents(v: unknown, errors: string[]): AlrParentRef[] | null {
  if (!Array.isArray(v)) {
    errors.push("parents.not_array");
    return null;
  }
  const out: AlrParentRef[] = [];
  for (let i = 0; i < v.length; i++) {
    if (!isParentRefShape(v[i])) {
      errors.push(`parents[${i}].invalid`);
      return null;
    }
    out.push(v[i] as AlrParentRef);
  }
  return out;
}

function validateTransformClaim(v: unknown, errors: string[], required: boolean): void {
  if (v === null) {
    if (required) errors.push("transform_claim.required");
    return;
  }
  if (typeof v !== "object") {
    errors.push("transform_claim.invalid");
    return;
  }
  const r = v as Record<string, unknown>;
  if (typeof r.summary !== "string" || r.summary.length === 0) {
    errors.push("transform_claim.summary.empty");
  }
  if (r.uri !== null && typeof r.uri !== "string") {
    errors.push("transform_claim.uri.invalid");
  }
}

// Variants exported for callers that want narrowed bodies after a verify pass.
export type {
  AlrDerivedFromBody,
  AlrDisclosedBody,
  AlrForkedFromBody,
  AlrSupersededByBody,
};
