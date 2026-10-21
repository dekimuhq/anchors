// test/_fixtures.ts
import type { Envelope, ClaimType } from "@dekimuhq/anchors-envelope";
import type { VerifiedAnchor, AnchorVerdict } from "../src/types.ts";

/** Build a minimal valid v2 Envelope; override any field. `body` defaults to {}. */
export function makeEnvelope(overrides: Partial<Envelope> & { claim_type: ClaimType }): Envelope {
  return {
    v: 2,
    id: "01J0000000000000000000FUND",
    iat: "2026-05-31T12:00:00Z",
    iss: "did:web:buyer.example",
    iss_key: "ed25519:AAAA",
    subject: "deal-42",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    body: {},
    ...overrides,
  } as Envelope;
}

/** Pair an envelope with a verdict. Defaults to signature_valid + status active. */
export function verified(env: Envelope, verdict: Partial<AnchorVerdict> = {}): VerifiedAnchor {
  return {
    envelope: env,
    verdict: { signature_valid: true, status_state: "active", ...verdict },
  };
}
