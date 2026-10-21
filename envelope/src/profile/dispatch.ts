/**
 * Profile-validator dispatch helper — Phase E Task E.2.
 *
 * Runs each supplied validator against an envelope + body + ctx and collects
 * results. Validators that throw are caught and surfaced as a synthetic
 * ProfileStateEntry with reason `profile_validator_threw:<message>` so a
 * misbehaving validator cannot crash the verifier.
 */

import type { Envelope } from "../envelope-types.ts";
import type {
  ProfileValidator,
  ProfileValidatorCtx,
  ProfileStateEntry,
} from "./types.ts";

/**
 * Run each validator against the envelope + body + ctx and collect results
 * in caller order. Exceptions from validators are caught and surfaced as
 * `ProfileStateEntry { ok: false, reason: "profile_validator_threw:<msg>" }`.
 */
export function dispatchProfiles(
  envelope: Envelope,
  body: unknown,
  ctx: ProfileValidatorCtx,
  validators: readonly ProfileValidator[],
): ProfileStateEntry[] {
  const out: ProfileStateEntry[] = [];
  for (const v of validators) {
    try {
      out.push(v(envelope, body, ctx));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // Best-effort profile_id surfacing — the validator may have thrown
      // before producing one. Fall back to a generic id.
      out.push({
        profile_id: "unknown",
        ok: false,
        reason: `profile_validator_threw:${msg}`,
      });
    }
  }
  return out;
}
