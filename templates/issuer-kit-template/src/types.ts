// @dekimuhq/<member>-issuer-kit — type definitions

import type { TsaConfig, PolicyRef } from "@dekimuhq/anchors-envelope";

export interface <MEMBER>MintInput {
  iss: string;
  iss_key: string;
  privateKey: string;
  subject: string;
  body: { /* member-specific — see spec §4.2 */ };
  profile: string;
  policy?: PolicyRef;
  prev?: string | null;
  exp?: string | null;
  envelope_v?: 1 | 2;
  tsa?: TsaConfig;
  getNextStatusIndex?: (bucket: string) => Promise<number>;
}

export interface <MEMBER>MintResult {
  receipt: unknown; // typed as <MEMBER>Receipt once the union is defined
}
