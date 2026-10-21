/**
 * ar.compliance.v1 mint. subject MUST be null (FAMILY-CONSISTENCY). Non-consumer
 * of Status List 2021 (non-revocable this slice). TSA optional. Verify-before-sign.
 */
import {
  generateReceiptId, keyObjectFromSeed, computeFieldRoot, signEnvelope,
  type Envelope, type AnchorProof, type Kind, type Cause,
} from "@dekimuhq/anchors-envelope";
import { TsaMintError, attachTsaBlock, type TsaFetcher, type TsaConfig } from "@dekimuhq/anchors-envelope/tsa";
import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
import type { ComplianceBundleBody } from "../types.ts";
import { verifyComplianceBundleBody } from "../verify-single.ts";
import { complianceFamily } from "../family.ts";

const COMPLIANCE_CLAIM_TYPE = complianceFamily.meta.claim_types[0]!;
export type { TsaFetcher, SigningKey };
export { TsaMintError };

export interface MintComplianceV1Input {
  issuer: string;
  signingKey: SigningKey;
  anchor: AnchorProof;
  body: ComplianceBundleBody;       // pre-assembled by the Hub layer (Plan 2)
  prev?: string | null;
  exp?: string | null;
  tsa?: TsaConfig;
  tsaFetcher?: TsaFetcher;
  envelope_kind?: Kind | null;
  cause?: Cause | null;
}

export async function mintComplianceV1(input: MintComplianceV1Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintComplianceV1: issuer required");
  if (!input.signingKey?.kid) throw new Error("mintComplianceV1: signingKey.kid required");
  if (input.signingKey.privateKey.length !== 32) throw new Error("mintComplianceV1: signingKey.privateKey must be 32 bytes");
  if (!input.anchor) throw new Error("mintComplianceV1: anchor required");
  if (input.tsa !== undefined && input.tsaFetcher === undefined) throw new Error("mintComplianceV1: tsaFetcher required when tsa config is provided");

  const check = verifyComplianceBundleBody(input.body);
  if (!check.valid) throw new Error(`mintComplianceV1: invalid body — ${check.errors.join(",")}`);

  const id = generateReceiptId();
  const iat = new Date().toISOString();
  const { privateKey, issKey } = keyObjectFromSeed(input.signingKey.privateKey);
  const field_root = computeFieldRoot(input.body);
  const bodyOut = { ...input.body, field_root };
  const envelopeKindOut: Kind | null = input.envelope_kind === undefined ? "observation" : input.envelope_kind;

  const preSign: Envelope = {
    v: 2, id, iat, iat_ms: Date.parse(iat),
    claim_type: COMPLIANCE_CLAIM_TYPE,
    iss: input.issuer, iss_key: issKey,
    subject: null as unknown as string,
    exp: input.exp ?? null, prev: input.prev ?? null,
    policy_uri: null, policy_hash: null, policy_version: null,
    kind: envelopeKindOut, cause: input.cause ?? null, predicate: null,
    tsa: null, credentialStatus: null, anchor: input.anchor,
    sig: "", countersig: null, body: bodyOut,
  };

  const signed = await signEnvelope(preSign, privateKey);
  if (input.tsa !== undefined) return attachTsaBlock(signed, input.tsa, input.tsaFetcher!);
  return signed;
}
