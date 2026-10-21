/**
 * TSA mandate post-step for ARR.
 *
 * Authoritative source: `meta/FAMILY-CONSISTENCY.md` §2 —
 *   ARR | `ar.erasure.v1` under `arr.gdpr.art17.erasure-finalized` | MANDATORY
 *   ARR | other events                                            | RECOMMENDED
 *
 * The MANDATORY case is profile-keyed and enforced by the factory's
 * `tsa_mandate` map (`arr.gdpr.art17.erasure-finalized → mandatory` in
 * `family.ts`), which fires before this post-step and leaves
 * `signature_valid: false` when `tsa` is absent. Every other ARR event is
 * RECOMMENDED — ARR's §2 row has no OPTIONAL tier — so this post-step
 * uniformly upgrades a `tsa_absent` result to `tsa_recommended` for
 * otherwise-valid receipts.
 *
 * Mirrors the per-event post-step in ABR/AIR; ARR's is uniform because its §2
 * row carries no per-event split below the profile-keyed MANDATORY case. Real
 * TSA failure reasons (e.g. `tsa_imprint_mismatch`) win — the guard only
 * upgrades when `tsa_state` is exactly `"tsa_absent"` and the signature is
 * valid, so the MANDATORY hard-fail (`signature_valid: false`) is untouched.
 */

/**
 * Surface used by `applyArrTsaMandate`. Matches the relevant subset of
 * `FamilyVerifyResult` — declared locally so the mandate module does not
 * import the factory result type.
 */
export interface ArrTsaMandateTarget {
  signature_valid: boolean;
  reason?: string;
  tsa_state?: string;
}

/**
 * Upgrade an otherwise-valid `tsa_absent` ARR result to `tsa_recommended`.
 * Mutates `target`. No-op when the signature is already invalid (e.g. the
 * profile-keyed MANDATORY hard-fail) or when `tsa_state` carries a real TSA
 * reason.
 */
export function applyArrTsaMandate(target: ArrTsaMandateTarget): void {
  if (!target.signature_valid) return;
  if (target.tsa_state !== "tsa_absent") return;
  target.tsa_state = "tsa_recommended";
}
