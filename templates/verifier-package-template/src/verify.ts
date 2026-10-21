// @dekimuhq/<member>-verifier — verify entry point
//
// Dispatch order: see CROSS-REFERENCES.md §4 for the canonical 7-step order.
// Member-specific steps go between step 4 (prev chain) and step 7 (composition).

import { verifyEnvelope } from "@dekimuhq/anchors-envelope";
import type {
  <MEMBER>Receipt,
  <MEMBER>VerifyOptions,
  <MEMBER>VerifyResult,
  <MEMBER>VerifyError,
} from "./types.ts";

export async function verify<MEMBER>(
  receipt: <MEMBER>Receipt,
  opts: <MEMBER>VerifyOptions,
): Promise<<MEMBER>VerifyResult> {
  const errors: <MEMBER>VerifyError[] = [];
  const warnings: string[] = [];

  // 1–7: delegate envelope-level steps to @dekimuhq/anchors-envelope.
  const envelopeResult = await verifyEnvelope(receipt, opts);
  if (!envelopeResult.ok) {
    return { ok: false, errors: envelopeResult.errors as <MEMBER>VerifyError[], warnings };
  }

  // Member-specific body validation goes here.
  // TODO: implement per spec §6.

  return {
    ok: errors.length === 0,
    claims: { /* shape per spec §4.2 */ },
    errors,
    warnings,
  };
}
