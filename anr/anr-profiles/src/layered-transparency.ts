/**
 * `notice.layered_transparency` profile validator — ANR spec §5.4.
 *
 * Hook: EDPB 03/2020 layered-transparency guidance + GDPR Arts 12–14. A
 * compliant notice is layered: a short summary on top, the full notice
 * underneath, with optional just-in-time disclosures.
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"notice.layered_transparency"`.
 *   - `body.event_type` MUST NOT be `"notice.joint_controller_essence"`.
 *   - When `body.event_type ∈ {notice.presented, notice.re_presented}`:
 *     `body.layer_uris` MUST be a non-empty array.
 *     The first layer (index 0) MUST be `"summary"`.
 *     At least one layer MUST be `"full"`.
 *
 * Per-layer shape (`{layer, uri, hash}` with `layer ∈ {summary, full, jit}`,
 * non-empty `uri`, non-empty `hash`) is enforced by the §C body verifier.
 *
 * Spec §5.4 cross-check that envelope-level `policy_hash` equals SHA-256 over
 * the concatenation of layer hashes (`summary`-first order) is a verifier-
 * pass concern: it requires envelope access plus a normative byte-vs-string
 * pre-image pin that lives in §C / a future hardening pass. This validator
 * enforces the structural ordering only.
 */

import type { AnrBody, AnrEventType, AnrLayerUri } from "./body-types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const LAYERED_TRANSPARENCY_PROFILE_ID =
  "notice.layered_transparency" as const;

const DISALLOWED_EVENT_TYPES: ReadonlySet<AnrEventType> = new Set([
  "notice.joint_controller_essence",
]);

const FIELD_REQUIRED_EVENT_TYPES: ReadonlySet<AnrEventType> = new Set([
  "notice.presented",
  "notice.re_presented",
]);

export function validateLayeredTransparency(
  body: AnrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== LAYERED_TRANSPARENCY_PROFILE_ID) {
    errors.push("notice.layered_transparency.profile.mismatch");
    return { errors };
  }

  if (DISALLOWED_EVENT_TYPES.has(body.event_type)) {
    errors.push("notice.layered_transparency.event_type.disallowed");
    return { errors };
  }

  if (FIELD_REQUIRED_EVENT_TYPES.has(body.event_type)) {
    const layers = (body as { layer_uris: readonly AnrLayerUri[] | null })
      .layer_uris;
    if (layers === null || layers.length === 0) {
      errors.push("notice.layered_transparency.layer_uris.required");
      return { errors };
    }
    if (layers[0]!.layer !== "summary") {
      errors.push("notice.layered_transparency.layer_uris.summary_first");
    }
    if (!layers.some((l) => l.layer === "full")) {
      errors.push("notice.layered_transparency.layer_uris.full_required");
    }
  }

  return { errors };
}

export const validateLayeredTransparencyProfile = makeProfileAdapter(LAYERED_TRANSPARENCY_PROFILE_ID, (body) => validateLayeredTransparency(body as AnrBody));
