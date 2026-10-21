/**
 * W3C Bitstring Status List 2021 — suspensionStatus pointer schema validation.
 *
 * Wave 3. Mirrors pointer.ts but validates statusPurpose: "suspension".
 *
 * Rejection reasons (stable strings):
 *   - schema_invalid:suspensionStatus    non-object or null
 *   - unsupported_status_type            type !== "StatusList2021Entry"
 *   - unsupported_suspension_purpose     statusPurpose !== "suspension"
 *   - invalid_status_list_index          missing / empty / non-decimal
 *   - invalid_status_list_credential     missing or not https://
 *   - missing_status_id                  id missing or empty
 */

import type { SuspensionStatus } from "../envelope-types.ts";

export interface SuspensionStatusPointerResult {
  ok: boolean;
  reason?: string;
}

export function validateSuspensionStatusPointer(
  p: unknown,
): SuspensionStatusPointerResult {
  if (typeof p !== "object" || p === null) {
    return { ok: false, reason: "schema_invalid:suspensionStatus" };
  }
  const cs = p as Partial<SuspensionStatus>;
  if (cs.type !== "StatusList2021Entry") {
    return { ok: false, reason: "unsupported_status_type" };
  }
  if (cs.statusPurpose !== "suspension") {
    return { ok: false, reason: "unsupported_suspension_purpose" };
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
