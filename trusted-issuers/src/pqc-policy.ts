/**
 * Issuer-level PQC-migration policy — the issuer-level half of the HNDL
 * (Harvest-Now-Decrypt-Later) defense.
 *
 * The per-receipt half (envelope `sig_min_alg`) cannot close HNDL alone: a CRQC
 * adversary who forges a classical-only body controls the whole receipt and
 * simply omits the posture field. The complete defense is OUT-OF-BAND trust
 * state — a verifier learns "issuer X is PQC-mandatory as of date Y" from the
 * signed `ar.trusted_issuers.v1` manifest and rejects classical-only (or
 * sub-floor) receipts from X REGARDLESS of the receipt's self-described posture.
 *
 * These functions are PURE policy: given an issuer record + a trustworthy
 * effective-time, they decide the minimum acceptable signature algorithm. They
 * do NOT verify signatures and do NOT source the effective-time — that is the
 * verifier integration's responsibility (see the `effectiveTime` contract
 * below).
 *
 * Decision:
 * an internal design record (not published).
 *
 * ## Wiring status (READ THIS)
 *
 * Phase 2 IS wired: `makeVerifyIssuerPqc` (below) composes this policy into the
 * `verifyIssuerPqc` seam consumed by `@dekimuhq/anchors-envelope`'s family verify
 * pipeline (Step 5.6). A verifier that supplies `verifyIssuerPqc` (alongside
 * `verifyIssuerTrust`) DOES reject a migrated issuer's sub-floor receipts.
 *
 * Two honest limits remain, by design — enforcement is conservative, not
 * end-to-end CRQC-complete, until they close:
 *   1. **Time source.** Without a `resolveEffectiveTime` the floor is evaluated at
 *      `now` (fail-toward-rejection): every migrated-issuer classical receipt is
 *      rejected — correct, but a real transparency-log / TSL inclusion-time source
 *      (partly unbuilt) is needed to ACCEPT legitimate pre-cutover receipts.
 *   2. **Manifest list-signing.** The `ar.trusted_issuers.v1` manifest carrying
 *      the mandate must itself migrate to PQC list-signing (deferred R2), else a
 *      CRQC attacker forges a manifest that drops the mandate (recursion hazard).
 *
 * ## The `effectiveTime` contract (security-critical)
 *
 * `effectiveTime` MUST be a *quantum-trustworthy* timestamp — the receipt's
 * transparency-log / TSL / anchor INCLUSION time, proven against a checkpoint
 * witnessed BEFORE any CRQC (hash-based Merkle inclusion is quantum-safe). It
 * MUST NEVER be the receipt's self-claimed `issued_at`: that field is
 * attacker-controlled in the forgery scenario, so comparing the cutover against
 * it is a trivial bypass (set `issued_at` < cutover).
 *
 * When no trustworthy time is available the verifier MUST pass the current
 * verification time (`now`) — i.e. fail toward rejection. For a migrated issuer
 * this rejects classical-only receipts: a forgery has no pre-cutover
 * quantum-safe inclusion proof, so it evaluates at `now >= mandatory_from` and
 * is rejected, while a legitimate pre-migration receipt carries its inclusion
 * proof (`effectiveTime < mandatory_from`) and is accepted.
 */

import { SIG_ALGS, SIG_ALG_RANK, type SigAlg } from "@dekimuhq/anchors-envelope";
import type { VerifyIssuerPqc, VerifyIssuerPqcInput } from "@dekimuhq/anchors-envelope";
import { isIso8601 } from "./iso8601.ts";
import type { TrustedIssuerRecord } from "./types.ts";

/**
 * The minimum-signature-algorithm requirement an issuer's PQC-migration posture
 * imposes at a given effective-time.
 *
 * - `none` — no mandate, or the effective-time is before the cutover. No
 *   constraint; Ed25519 is acceptable (current behavior).
 * - `min` — a recognised floor: the receipt's signature must rank >= `alg`.
 * - `unsatisfiable` — a mandate is in force but its `min_sig_alg` is not a
 *   registered algorithm this verifier can rank. FAIL-CLOSED: a verifier that
 *   cannot even rank the demanded floor cannot prove compliance, so it must
 *   reject. (A `SigAlg | null` return was rejected precisely because it would
 *   map an unknown/forged `min_sig_alg` to "no requirement" — a bypass.)
 */
export type IssuerPqcRequirement =
  | { kind: "none" }
  | { kind: "min"; alg: SigAlg }
  | { kind: "unsatisfiable"; declared: string };

function isRegisteredSigAlg(alg: string): alg is SigAlg {
  return (SIG_ALGS as readonly string[]).includes(alg);
}

/**
 * Resolve an issuer's PQC-migration requirement at `effectiveTime`. Pure; see
 * the module-level `effectiveTime` contract for what callers MUST pass.
 */
export function issuerPqcRequirement(
  record: TrustedIssuerRecord,
  effectiveTime: Date,
): IssuerPqcRequirement {
  const mandate = record.pqc_mandatory;
  if (mandate === undefined || mandate === null) {
    return { kind: "none" };
  }

  // STRICT ISO 8601 — not a bare `Date.parse`. A lenient parse accepts
  // `"2030/01/01"` / zone-less strings as LOCAL time, silently shifting the
  // cutover instant by the host timezone offset (fail-OPEN window drift). A
  // mandate whose cutover we cannot establish unambiguously is fail-closed:
  // reject regardless of `effectiveTime`. (`parseTrustedIssuerList` already
  // rejects this structurally; this guards self-hosted sources that build
  // records bypassing the parser — the explicit reason this guard exists.)
  if (!isIso8601(mandate.mandatory_from)) {
    return { kind: "unsatisfiable", declared: mandate.min_sig_alg };
  }
  const fromMs = Date.parse(mandate.mandatory_from);

  if (effectiveTime.getTime() < fromMs) {
    return { kind: "none" };
  }

  if (isRegisteredSigAlg(mandate.min_sig_alg)) {
    return { kind: "min", alg: mandate.min_sig_alg };
  }
  return { kind: "unsatisfiable", declared: mandate.min_sig_alg };
}

/**
 * Whether a receipt signed with `receiptSigAlg` satisfies the issuer's
 * PQC-migration posture at `effectiveTime`.
 *
 * `receiptSigAlg` is the highest-rank VALID signature algorithm present on the
 * receipt (e.g. the `sig2_alg` of a valid hybrid second signature, else
 * `sig_alg ?? "ed25519"`). By the time PQC policy is evaluated the envelope
 * verifier has already rejected any unsupported/forged `sig_alg`
 * (`resolveVerifier` own-property dispatch), so `receiptSigAlg` is a registered,
 * validly-signed `SigAlg`.
 *
 * Returns a structured verdict so the caller can surface a precise reason:
 *   - `issuer_pqc_mandatory:<alg>` — receipt is below the issuer's required floor.
 *   - `issuer_pqc_unsatisfiable:<declared>` — the issuer demands an algorithm
 *     this verifier cannot rank (fail-closed).
 */
export function satisfiesIssuerPqc(
  record: TrustedIssuerRecord,
  effectiveTime: Date,
  receiptSigAlg: SigAlg,
):
  | { ok: true }
  | { ok: false; reason: string } {
  const req = issuerPqcRequirement(record, effectiveTime);
  if (req.kind === "none") {
    return { ok: true };
  }
  if (req.kind === "unsatisfiable") {
    return { ok: false, reason: `issuer_pqc_unsatisfiable:${req.declared}` };
  }
  // Defense in depth: `receiptSigAlg` is only TS-typed `SigAlg`. Guard it with
  // an OWN-VALUE check before indexing `SIG_ALG_RANK` — never rely on the `>=`
  // coercion (`undefined`/function `>= number` is `false`) to stay fail-closed.
  // An unranked receipt algorithm cannot prove it meets the floor → reject.
  // (Prototype-member dispatch — `SIG_ALG_RANK["toString"]` resolving to a
  // function — was a CRITICAL signature-bypass in the envelope's `resolveVerifier`;
  // do not reintroduce the unsafe-index pattern here.)
  if (!isRegisteredSigAlg(receiptSigAlg)) {
    return { ok: false, reason: `unsupported_receipt_sig_alg:${receiptSigAlg}` };
  }
  if (SIG_ALG_RANK[receiptSigAlg] >= SIG_ALG_RANK[req.alg]) {
    return { ok: true };
  }
  return { ok: false, reason: `issuer_pqc_mandatory:${req.alg}` };
}

/**
 * Options for {@link makeVerifyIssuerPqc}.
 */
export interface MakeVerifyIssuerPqcOptions {
  /**
   * Source a QUANTUM-TRUSTWORTHY effective-time for the receipt — the receipt's
   * transparency-log / TSL / anchor inclusion time, proven against a checkpoint
   * witnessed BEFORE any CRQC (hash-based Merkle inclusion is quantum-safe).
   * Return `null`/`undefined` when no such proof is available; the factory then
   * falls back to `now()` (fail-toward-rejection: a forgery has no pre-cutover
   * inclusion proof, so a migrated issuer's classical receipt is rejected).
   *
   * MUST NEVER return the receipt's self-claimed `issued_at` — that field is
   * attacker-controlled in the forgery scenario, so comparing the cutover
   * against it is a trivial bypass. See the module-level security contract.
   */
  resolveEffectiveTime?: (envelope: unknown) => Date | null | undefined;
  /** Clock for the fail-toward-rejection fallback. Default `() => new Date()`. */
  now?: () => Date;
}

/**
 * Compose the pure {@link satisfiesIssuerPqc} policy into the injected
 * `verifyIssuerPqc` seam consumed by `@dekimuhq/anchors-envelope`'s family
 * verify pipeline (v1.3 R3 Phase 2 — the inert→enforced flip). Drop the result
 * into `FamilyVerifyOptions.verifyIssuerPqc` alongside `verifyIssuerTrust`:
 *
 *   const verifyIssuerPqc = makeVerifyIssuerPqc({
 *     resolveEffectiveTime: (env) => inclusionTimeFromTransparencyLog(env), // or omit
 *   });
 *   const r = await family.verifyReceipt(receipt, {
 *     resolveKey,
 *     verifyIssuerTrust: makeVerifyIssuerTrust({ trustedIssuers }),
 *     verifyIssuerPqc,
 *   });
 *
 * The pipeline only calls this when issuer-trust matched a record, and passes the
 * highest-rank VALID signature algorithm (from the verified signatures, not the
 * receipt's self-described `sig_alg`). With no `resolveEffectiveTime` the floor
 * is evaluated at `now` — correct and inert until an issuer publishes a
 * `pqc_mandatory`, then conservatively rejecting until a trustworthy time source
 * is wired.
 */
export function makeVerifyIssuerPqc(
  opts: MakeVerifyIssuerPqcOptions = {},
): VerifyIssuerPqc {
  const nowFn = opts.now ?? (() => new Date());
  return (input: VerifyIssuerPqcInput) => {
    const t = opts.resolveEffectiveTime?.(input.envelope) ?? nowFn();
    return satisfiesIssuerPqc(input.record, t, input.receiptSigAlg);
  };
}
