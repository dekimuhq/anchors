/**
 * APR v=2 mint path — produces a v=2 Envelope with claim_type "ar.provenance.v1".
 *
 * The anchor field is supplied by the caller; post-mint the log worker can
 * replace it with a real inclusion proof (anchor is signed-out, so that
 * replacement does not invalidate the signature).
 *
 * Phase B Task 12b.
 */

import {
  type Envelope,
  type AnchorProof,
  type Kind,
  type Cause,
} from "@dekimuhq/anchors-envelope";
import { TsaMintError, type TsaFetcher, type TsaConfig } from "@dekimuhq/anchors-envelope/tsa";
import { aprFamily } from "../family.ts";
import type { APRBody } from "../types.ts";
import type { SigningKey } from "./mint.ts";

export type { TsaFetcher };

export interface MintAprV2Input {
  /** Issuer DID or short identifier — e.g. "did:web:invoiceup.app" or "invoiceup". */
  issuer: string;
  /** Ed25519 signing key (32-byte seed in `privateKey`) and identifying kid. */
  signingKey: SigningKey;
  /** Envelope-level subject — typically a SHA-256 hash of the asset, "sha256:<hex>". */
  subject: string;
  /** APR-specific body (provenance claims). Same shape as v=1 APRBody. */
  body: APRBody;
  /** Anchor proof (caller supplies; post-mint the log worker replaces with real inclusion). */
  anchor: AnchorProof;
  /** Optional: previous receipt ID for chain linkage. */
  prev?: string | null;
  /** Optional: expiry timestamp ISO 8601 UTC. */
  exp?: string | null;
  /** Optional: policy fields. */
  policy_uri?: string | null;
  policy_hash?: string | null;
  policy_version?: string | null;
  /** Optional: TSA configuration. If present, mint attaches a TSA block. */
  tsa?: TsaConfig;
  /** Optional: TSA fetcher (caller-provided; required if `tsa` is set). */
  tsaFetcher?: TsaFetcher;
  /**
   * v1.2 §4.1: receipt classification. APR is provenance — kind is always
   * `null` per spec §6 (it does not distinguish observation/decision).
   * Accepted in the input only for API symmetry; passing `"observation"`
   * or `"decision"` throws. The minted envelope always sets `kind: null`.
   */
  kind?: Kind | null;
  /**
   * v1.2 §4.2: typed trigger (closed enum). Optional.
   * Plumbed verbatim into the unsigned envelope (`null` when omitted).
   */
  cause?: Cause | null;
}

// ── mintAprV2 ─────────────────────────────────────────────────────────────────

export async function mintAprV2(input: MintAprV2Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintAprV2: issuer required");
  if (!input.subject) throw new Error("mintAprV2: subject required");
  if (!input.body) throw new Error("mintAprV2: body required");
  if (!input.signingKey?.kid) throw new Error("mintAprV2: signingKey.kid required");
  if (!input.anchor) throw new Error("mintAprV2: anchor required");

  // v1.2 §6 + L9: APR carries `kind: null` always — it does not distinguish
  // observation vs decision. Reject explicit `"observation"` / `"decision"`.
  if (input.kind !== undefined && input.kind !== null) {
    throw new Error(
      `mintAprV2: kind must be null on ar.provenance.v1 (spec §6 + L9); got '${input.kind}'`,
    );
  }

  return aprFamily.mintV2({
    body: input.body,
    issuerPrivateKey: input.signingKey.privateKey,
    kid: input.signingKey.kid,
    issuerDid: input.issuer,
    subject: input.subject,
    anchor: input.anchor,
    exp: input.exp ?? null,
    prev: input.prev ?? null,
    policy_uri: input.policy_uri ?? null,
    policy_hash: input.policy_hash ?? null,
    policy_version: input.policy_version ?? null,
    kind: null,
    cause: input.cause ?? null,
    ...(input.tsa !== undefined ? { tsa: input.tsa, tsaFetcher: input.tsaFetcher } : {}),
  });
}

// Re-export TsaMintError so consumers can catch it without importing tsa sub-path.
export { TsaMintError };
