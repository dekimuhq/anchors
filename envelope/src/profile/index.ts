/**
 * `@dekimuhq/anchors-envelope/profile` — profile-validator dispatch surface.
 *
 * Re-exports the universal `ProfileValidator` signature + `dispatchProfiles`
 * helper used by per-family verifiers to run opt-in profile mandate checks
 * after envelope verification succeeds.
 *
 * Phase E Task E.2.
 */

export type {
  ProfileValidatorCtx,
  ProfileStateEntry,
  ProfileValidator,
} from "./types.ts";
export { dispatchProfiles } from "./dispatch.ts";
