/** `quality.release` profile validator — AQR spec §4.3. */
import type { AQRBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";
import { validateQualityCommon } from "./output.ts";

export const QUALITY_RELEASE_PROFILE_ID = "quality.release" as const;
const GATES = new Set(["blocking", "advisory"]);
function isNonEmptyString(v: unknown): v is string { return typeof v === "string" && v.length > 0; }

export function validateQualityRelease(body: AQRBody): ProfileValidationResult {
  const b = body as unknown as Record<string, unknown>;
  const errors = validateQualityCommon(b);
  if (b.profile !== "quality.release") errors.push("quality.release.wrong_profile");
  if (!isNonEmptyString(b.subject_ref)) errors.push("quality.release.subject_ref_missing");
  if (typeof b.gate !== "string" || !GATES.has(b.gate)) errors.push("quality.release.gate_invalid");
  return { errors };
}
export const validateQualityReleaseProfile = makeProfileAdapter(
  QUALITY_RELEASE_PROFILE_ID, (body) => validateQualityRelease(body as AQRBody),
);
