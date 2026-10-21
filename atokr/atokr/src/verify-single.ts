/**
 * Per-event-type ATokR body verifier (spec §4 + D10-ATokR-1..7).
 *
 * Validates the discriminated union on `body.event_type` and per-event
 * required-field rules. Called by the factory's body-validation step; also
 * exported for callers that hold a body in hand.
 *
 * §C scope: event_type dispatch + token_id + format_class + scope shape +
 * rotation_of pinning. Profile-specific validation lives in
 * `@dekimuhq/atokr-profiles`; this module only confirms base structural shape.
 */

import type {
  AtokrBody,
  AtokrFormatClass,
  AtokrScope,
} from "./types.ts";

// ── Public surface ────────────────────────────────────────────────────────────

export interface VerifyBodyResult {
  /** True iff every structural check in §4 passes. */
  valid: boolean;
  /** Stable, machine-readable failure codes. Empty when `valid === true`. */
  errors: string[];
  /** Narrowed body when valid; null otherwise. */
  body: AtokrBody | null;
}

/**
 * Validate an ATokR `body` against spec §4 per-event-type rules.
 * Returns the narrowed discriminated-union body on success.
 */
export function verifyAtokrBody(body: unknown): VerifyBodyResult {
  const errors: string[] = [];

  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;

  // ── Shared fields (D10-ATokR-1, D10-ATokR-2) ──────────────────────────────
  if (!isNonEmptyString(b.token_id)) errors.push("token_id.missing");

  // ── Event-type dispatch (D10-ATokR-1) ──────────────────────────────────────
  switch (b.event_type) {
    case "token.issued":
      validateIssued(b, errors);
      break;
    case "token.redeemed":
      validateRedeemed(b, errors);
      break;
    case "token.revoked":
      validateRevoked(b, errors);
      break;
    case "token.rotated":
      validateRotated(b, errors);
      break;
    default:
      errors.push("event_type.unknown");
  }

  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as AtokrBody };
}

// ── §4.1 token.issued ─────────────────────────────────────────────────────────

function validateIssued(b: Record<string, unknown>, errors: string[]): void {
  // format_class REQUIRED on issued (D10-ATokR-4)
  if (b.format_class === null || b.format_class === undefined) {
    errors.push("format_class.required_on_issued");
  } else if (!isFormatClass(b.format_class)) {
    errors.push("format_class.invalid");
  }
  // scope REQUIRED (D10-ATokR-3)
  validateScope(b.scope, errors);
  // rotation_of MUST be null (D10-ATokR-5)
  if (b.rotation_of !== null) errors.push("rotation_of.must_be_null");
}

// ── §4.2 token.redeemed ───────────────────────────────────────────────────────

function validateRedeemed(b: Record<string, unknown>, errors: string[]): void {
  // format_class OPTIONAL — if present and non-null, must be valid enum
  if (b.format_class !== null && b.format_class !== undefined) {
    if (!isFormatClass(b.format_class)) errors.push("format_class.invalid");
  }
  // scope REQUIRED (D10-ATokR-3)
  validateScope(b.scope, errors);
  // rotation_of MUST be null (D10-ATokR-5)
  if (b.rotation_of !== null) errors.push("rotation_of.must_be_null");
}

// ── §4.3 token.revoked ────────────────────────────────────────────────────────

function validateRevoked(b: Record<string, unknown>, errors: string[]): void {
  // format_class OPTIONAL — if present and non-null, must be valid enum
  if (b.format_class !== null && b.format_class !== undefined) {
    if (!isFormatClass(b.format_class)) errors.push("format_class.invalid");
  }
  // scope REQUIRED (D10-ATokR-3)
  validateScope(b.scope, errors);
  // rotation_of MUST be null (D10-ATokR-5)
  if (b.rotation_of !== null) errors.push("rotation_of.must_be_null");
}

// ── §4.4 token.rotated ────────────────────────────────────────────────────────

function validateRotated(b: Record<string, unknown>, errors: string[]): void {
  // format_class REQUIRED on rotated (D10-ATokR-4)
  if (b.format_class === null || b.format_class === undefined) {
    errors.push("format_class.required_on_rotated");
  } else if (!isFormatClass(b.format_class)) {
    errors.push("format_class.invalid");
  }
  // scope REQUIRED (D10-ATokR-3)
  validateScope(b.scope, errors);
  // rotation_of REQUIRED (D10-ATokR-5) — must reference prior token_id
  if (!isNonEmptyString(b.rotation_of)) errors.push("rotation_of.required");
}

// ── Scope validator (D10-ATokR-3) ─────────────────────────────────────────────

function validateScope(scope: unknown, errors: string[]): void {
  if (scope === null || scope === undefined) {
    errors.push("scope.required");
    return;
  }
  if (typeof scope !== "object") {
    errors.push("scope.required");
    return;
  }
  const s = scope as Record<string, unknown>;
  if (!isNonEmptyString(s.audience)) errors.push("scope.audience.invalid");
  if (!isNonEmptyString(s.purpose)) errors.push("scope.purpose.invalid");
  if (!isNonEmptyString(s.valid_from)) errors.push("scope.valid_from.invalid");
  if (s.valid_until !== null && typeof s.valid_until !== "string") {
    errors.push("scope.valid_until.invalid");
  }
  if (typeof s.single_use !== "boolean") errors.push("scope.single_use.invalid");
}

// ── Shape predicates ──────────────────────────────────────────────────────────

const FORMAT_CLASSES = new Set<string>([
  "pan",
  "email",
  "iban",
  "phone",
  "national_id",
  "freeform",
]);

function isFormatClass(v: unknown): v is AtokrFormatClass {
  return typeof v === "string" && FORMAT_CLASSES.has(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

// Re-export variant interfaces so callers narrowing on event_type get per-variant
// shapes without reaching into ./types.ts.
export type {
  AtokrIssuedBody,
  AtokrRedeemedBody,
  AtokrRevokedBody,
  AtokrRotatedBody,
} from "./types.ts";
export type { AtokrScope };
