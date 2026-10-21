// @dekimuhq/<member>-verifier — public API
//
// Verifier for Anchored <Noun> Receipts (<MEMBER>) v1.
// See: anchors/templates/spec-template.md §6 for verifier semantics.

export { verify<MEMBER> } from "./verify.ts";
export type {
  <MEMBER>Receipt,
  <MEMBER>VerifyOptions,
  <MEMBER>VerifyResult,
  <MEMBER>VerifyError,
} from "./types.ts";
