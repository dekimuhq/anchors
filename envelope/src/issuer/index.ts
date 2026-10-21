/**
 * `@dekimuhq/anchors-envelope/issuer` — shared issuer-kit utilities.
 *
 * Groups helpers that every issuer-kit needs: receipt ID generation,
 * key derivation, field-root computation, SHA-256 validation, profile
 * adapter factory, and passthrough body validator.
 *
 * P0 abstraction (2026-05-21).
 */

// Re-export existing mint helpers (also available via barrel for backwards compat).
export {
  generateReceiptId,
  keyObjectFromSeed,
  computeFieldRoot,
  isSha256Hex,
} from "../mint-helpers.ts";

// ── SigningKey ──────────────────────────────────────────────────────────────

/**
 * Minimal signing-key input for issuer-kit mint functions.
 *
 * Every shipped family declares an identical `XxxSigningKey` interface with
 * this exact shape. Using `SigningKey` from envelope avoids the duplication.
 */
export interface SigningKey {
  kid: string;
  /** 32-byte Ed25519 private seed. */
  privateKey: Uint8Array;
}

// ── Profile adapter factory ────────────────────────────────────────────────

import type {
  ProfileValidator,
  ProfileStateEntry,
} from "../profile/types.ts";

export type { ProfileValidator, ProfileStateEntry };

/**
 * Factory that eliminates the per-profile adapter boilerplate.
 *
 * Every profile validator across the anchors family follows the same wrapper
 * pattern: call a pure validate function, map `{ errors }` to
 * `ProfileStateEntry`. This factory parameterizes the two varying parts
 * (profile ID and the validate function).
 */
export function makeProfileAdapter(
  profileId: string,
  validate: (body: unknown) => { errors: string[] },
): ProfileValidator {
  return (_envelope, body, _ctx): ProfileStateEntry => {
    const r = validate(body);
    return {
      profile_id: profileId,
      ok: r.errors.length === 0,
      ...(r.errors.length > 0 ? { reason: r.errors[0] } : {}),
    };
  };
}

// ── Passthrough body validator ─────────────────────────────────────────────

import type { BodyValidator, BodyValidateResult } from "../define-family.ts";

export type { BodyValidator, BodyValidateResult };

/**
 * Generic passthrough `BodyValidator` that always accepts. Used by family
 * verifiers that defer structural body validation to a separate step
 * (e.g. `verifyAbrBody`) rather than running it inside the factory pipeline.
 */
export function passthroughBodyValidator<T = unknown>(): BodyValidator<T> {
  return {
    validate(body: unknown): BodyValidateResult<T> {
      return { ok: true, value: body as T };
    },
  };
}
