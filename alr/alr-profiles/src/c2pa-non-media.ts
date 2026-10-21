/**
 * `c2pa.non-media` profile validator — ALR spec §5.4.
 *
 * Hook: C2PA (Coalition for Content Provenance and Authenticity) covers
 * media — images, audio, video. Documents, datasets, models, code, and
 * configurations have no equivalent. ALR fills the gap with a
 * deliberately C2PA-shaped profile so toolchains can bridge.
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"c2pa.non-media"`.
 *   - `body.event_type` allowed: all four (spec §5.4 row 1).
 *
 * Spec extras `c2pa_action` (enum of 6) and `artifact_mime` (non-media
 * MIME) live in spec §5.4 but are not in `AlrBody` v1.0 — they land in
 * v1.1. The verifier MUST NOT fetch artifacts (spec §10.3 D-alr-3); the
 * MIME-allowlist check therefore stays issuer-side even in v1.1.
 */

import type { AlrBody } from "./body-types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const C2PA_NON_MEDIA_PROFILE_ID = "c2pa.non-media" as const;

export function validateC2paNonMedia(
  body: AlrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== C2PA_NON_MEDIA_PROFILE_ID) {
    errors.push("c2pa.non-media.profile.mismatch");
    return { errors };
  }

  // All four event_types are allowed; no further structural checks at the
  // profile layer for v1.0. AlrBody discriminated-union narrowing already
  // ensures event_type is one of the four.

  return { errors };
}

export const validateC2paNonMediaProfile = makeProfileAdapter(C2PA_NON_MEDIA_PROFILE_ID, (body) => validateC2paNonMedia(body as AlrBody));
