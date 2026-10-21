// @dekimuhq/<member>-issuer-kit — mint entry point
//
// Sync at mint, fail-loud when profile mandates TSA or Status List.
// No async queue. Caller retries on failure.

import { mintEnvelope } from "@dekimuhq/anchors-envelope";
import type { <MEMBER>MintInput, <MEMBER>MintResult } from "./types.ts";

export async function mint<MEMBER>(input: <MEMBER>MintInput): Promise<<MEMBER>MintResult> {
  // Validate body against spec §4.2 before signing.
  // TODO: implement member-specific body validation.

  const receipt = await mintEnvelope({
    claim_type: "ar.<noun>.v1",
    iss: input.iss,
    iss_key: input.iss_key,
    privateKey: input.privateKey,
    subject: input.subject,
    body: input.body,
    profile: input.profile,
    policy: input.policy,
    prev: input.prev ?? null,
    exp: input.exp ?? null,
    envelope_v: input.envelope_v ?? 2,
    tsa: input.tsa,
    getNextStatusIndex: input.getNextStatusIndex,
  });

  return { receipt };
}
