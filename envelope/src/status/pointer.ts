/**
 * W3C Bitstring Status List 2021 — credentialStatus pointer schema validation.
 *
 * Plan: an internal design record (not published) §Task 15
 *
 * v1.1 supports revocation only. Caller passes the (possibly absent / wrong-shape)
 * envelope.credentialStatus field; this function returns a discriminated result
 * mirroring the `validatePolicyFields` style in `../policy.ts`.
 *
 * Rejection reasons (stable strings — match verifier failure-reason taxonomy):
 *   - schema_invalid:credentialStatus     non-object or null
 *   - unsupported_status_type             type !== "StatusList2021Entry"
 *   - unsupported_status_purpose          statusPurpose !== "revocation"
 *   - invalid_status_list_index           missing / empty / non-decimal
 *   - invalid_status_list_credential      missing or not https://
 *   - missing_status_id                   id missing or empty
 */

import type { CredentialStatus } from "./types.ts";

export interface CredentialStatusPointerResult {
  ok: boolean;
  reason?: string;
}

/**
 * Validate a `credentialStatus` pointer against the v1.1 StatusList2021Entry shape.
 *
 * The function does not fetch the status list credential or check the bit —
 * it validates the on-wire pointer schema only.
 */
export function validateCredentialStatusPointer(
  p: unknown,
): CredentialStatusPointerResult {
  if (typeof p !== "object" || p === null) {
    return { ok: false, reason: "schema_invalid:credentialStatus" };
  }
  const cs = p as Partial<CredentialStatus>;
  if (cs.type !== "StatusList2021Entry") {
    return { ok: false, reason: "unsupported_status_type" };
  }
  if (cs.statusPurpose !== "revocation") {
    return { ok: false, reason: "unsupported_status_purpose" };
  }
  if (!cs.statusListIndex || !/^\d+$/.test(cs.statusListIndex)) {
    return { ok: false, reason: "invalid_status_list_index" };
  }
  if (!cs.statusListCredential || !cs.statusListCredential.startsWith("https://")) {
    return { ok: false, reason: "invalid_status_list_credential" };
  }
  if (!cs.id) {
    return { ok: false, reason: "missing_status_id" };
  }
  return { ok: true };
}
