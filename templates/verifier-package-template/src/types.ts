// @dekimuhq/<member>-verifier — type definitions
//
// Member-specific receipt + verify-options shape. Envelope-level types are
// re-exported from @dekimuhq/anchors-envelope.

import type { EnvelopeV2 } from "@dekimuhq/anchors-envelope";

// TODO: define the body schema in 4.2 of the spec.
export interface <MEMBER>Body {
  // member-specific fields
}

export type <MEMBER>Receipt = EnvelopeV2<"ar.<noun>.v1", <MEMBER>Body>;

export interface <MEMBER>VerifyOptions {
  trustedIssuers: string[];
  resolveStatusList: (url: string) => Promise<unknown>;
  resolveAnchor: (logId: string) => Promise<unknown>;
  // member-specific resolvers if any
}

export type <MEMBER>VerifyError =
  | { code: "schema_invalid"; detail: string }
  | { code: "sig_invalid"; detail: string }
  | { code: "anchor_unresolved"; detail: string }
  | { code: "chain.prev_unresolved"; detail: string }
  // add member-specific error codes here
  ;

export interface <MEMBER>VerifyResult {
  ok: boolean;
  claims?: { /* fully resolved member-specific claims */ };
  errors: <MEMBER>VerifyError[];
  warnings: string[];
}
