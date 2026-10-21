/**
 * Combined credential verification — the SAFE, correct-by-construction entry point.
 *
 * The wrapper proof alone does NOT establish issuer authenticity (see proof.ts):
 * `verificationMethod` and `vc.issuer` are attacker-writable, so a forger can
 * rewrite a receipt and sign the wrapper with their OWN key. The only real root
 * of trust is the embedded envelope `sig` verified against a key resolved from
 * the trust anchor (did:web), whose served key is fingerprint-bound to the
 * envelope `iss_key` by `@dekimuhq/did-web-resolver`.
 *
 * `verifyCredential` enforces the correct ordering:
 *   1. recover the embedded envelope (the cryptographic payload);
 *   2. assert `vc.issuer === envelope.iss` (the lifted field must not diverge);
 *   3. resolve the issuer key from the trust anchor using the ENVELOPE's iss /
 *      iss_key — never the top-level `vc.issuer` in isolation;
 *   4. verify the envelope signature with that resolved key (MANDATORY root);
 *   5. if a wrapper proof is present, verify it with the SAME resolved key.
 *
 * This covers issuer-authenticity + integrity. It does NOT run family-specific
 * body validation (that stays the caller's family verifier) and does NOT check
 * revocation — `credentialStatus` is a pointer that must be dereferenced against
 * its StatusList separately (see the README / spec §5).
 */

import type { Envelope } from "@dekimuhq/anchors-envelope";
import { verifyEnvelopeSignature } from "@dekimuhq/anchors-envelope";
import {
  resolveDidWebKey,
  type ResolveDidWebKeyOptions,
} from "@dekimuhq/did-web-resolver";
import type { AnchoredReceiptCredential } from "./types.ts";
import { extractEnvelope, AnchorsVcError } from "./unwrap.ts";
import { verifyWrapperProof } from "./proof.ts";

const ED25519_SPKI_DER_LEN = 44;
const ED25519_SPKI_PREFIX_LEN = 12;

export interface VerifyCredentialOptions {
  /**
   * Override issuer-key resolution. Given the ENVELOPE's `iss` + `iss_key`, return
   * the issuer public key as SPKI DER (ed25519). Use for non-`did:web` trust roots
   * or in tests. Default: `did:web` via the shared resolver (fingerprint-bound).
   */
  resolveKey?: (iss: string, issKey: string) => Promise<Uint8Array>;
  fetcher?: ResolveDidWebKeyOptions["fetcher"];
  cache?: ResolveDidWebKeyOptions["cache"];
  now?: ResolveDidWebKeyOptions["now"];
}

export type WrapperProofState = "valid" | "absent" | "invalid";

export interface VerifyCredentialResult {
  ok: boolean;
  envelope?: Envelope;
  checks: {
    issuerMatch: boolean;
    envelopeSignature: boolean;
    wrapperProof: WrapperProofState;
  };
  reason?: string;
}

function fail(
  checks: VerifyCredentialResult["checks"],
  reason: string,
  envelope?: Envelope,
): VerifyCredentialResult {
  return envelope
    ? { ok: false, envelope, checks, reason }
    : { ok: false, checks, reason };
}

/**
 * Verify an Anchored Receipt Verifiable Credential: issuer authenticity + envelope
 * signature (mandatory) + optional wrapper proof. Never throws — all failure modes
 * are returned as `{ ok: false, reason }`.
 */
export async function verifyCredential(
  vc: AnchoredReceiptCredential,
  opts: VerifyCredentialOptions = {},
): Promise<VerifyCredentialResult> {
  const checks = {
    issuerMatch: false,
    envelopeSignature: false,
    wrapperProof: "absent" as WrapperProofState,
  };

  let envelope: Envelope;
  try {
    envelope = extractEnvelope(vc);
  } catch {
    return fail(checks, "no_envelope");
  }

  // The lifted issuer must not diverge from the signed envelope's issuer.
  checks.issuerMatch = vc.issuer === envelope.iss;
  if (!checks.issuerMatch) return fail(checks, "issuer_mismatch", envelope);

  // Resolve the issuer key from the trust anchor — keyed on the ENVELOPE issuer.
  let der: Uint8Array;
  try {
    if (opts.resolveKey) {
      der = await opts.resolveKey(envelope.iss, envelope.iss_key);
    } else if (envelope.iss.startsWith("did:web:")) {
      der = await resolveDidWebKey({
        iss: envelope.iss,
        iss_key: envelope.iss_key,
        ...(opts.fetcher ? { fetcher: opts.fetcher } : {}),
        ...(opts.cache ? { cache: opts.cache } : {}),
        ...(opts.now ? { now: opts.now } : {}),
      });
    } else {
      return fail(checks, "issuer_not_trust_rooted", envelope);
    }
  } catch (e) {
    const msg = e instanceof AnchorsVcError || e instanceof Error ? e.message : String(e);
    return fail(checks, `key_resolution_failed:${msg}`, envelope);
  }

  checks.envelopeSignature = verifyEnvelopeSignature(envelope, der);

  if (vc.proof) {
    const raw =
      der.length === ED25519_SPKI_DER_LEN
        ? der.subarray(ED25519_SPKI_PREFIX_LEN)
        : der;
    checks.wrapperProof = verifyWrapperProof(vc, raw).ok ? "valid" : "invalid";
  }

  const ok = checks.issuerMatch && checks.envelopeSignature && checks.wrapperProof !== "invalid";
  return ok
    ? { ok: true, envelope, checks }
    : fail(checks, "verification_failed", envelope);
}
