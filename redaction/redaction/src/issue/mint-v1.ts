/**
 * APIIR v=2 mint path. Single export: mintRedactionV1(input). subject MUST be
 * null (FAMILY-CONSISTENCY). Non-consumer of Status List 2021. TSA optional.
 * commits are caller-precomputed via the envelope commit() primitive; this mint
 * binds them as-is. ar.redaction.v1. Verify-before-sign.
 */
import {
  generateReceiptId, keyObjectFromSeed, computeFieldRoot, signEnvelope,
  type Envelope, type AnchorProof, type Kind, type Cause,
} from "@dekimuhq/anchors-envelope";
import {
  TsaMintError, attachTsaBlock, type TsaFetcher, type TsaConfig,
} from "@dekimuhq/anchors-envelope/tsa";
import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
import type { RedactionCounts } from "../types.ts";
import { buildRedactionBody } from "../build-body.ts";
import { verifyRedactionBody } from "../verify-single.ts";
import { redactionFamily } from "../family.ts";

const REDACTION_CLAIM_TYPE = redactionFamily.meta.claim_types[0]!;
export type { TsaFetcher, SigningKey };
export { TsaMintError };

export interface MintRedactionV1Input {
  issuer: string;
  signingKey: SigningKey;
  anchor: AnchorProof;
  counts: RedactionCounts;
  ruleset_hash: string;
  input_commit: string;
  output_commit: string;
  redactor: string;
  prev?: string | null;
  exp?: string | null;
  tsa?: TsaConfig;
  tsaFetcher?: TsaFetcher;
  envelope_kind?: Kind | null;
  cause?: Cause | null;
}

export async function mintRedactionV1(input: MintRedactionV1Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintRedactionV1: issuer required");
  if (!input.signingKey?.kid) throw new Error("mintRedactionV1: signingKey.kid required");
  if (input.signingKey.privateKey.length !== 32) throw new Error("mintRedactionV1: signingKey.privateKey must be 32 bytes");
  if (!input.anchor) throw new Error("mintRedactionV1: anchor required");
  if (input.tsa !== undefined && input.tsaFetcher === undefined) throw new Error("mintRedactionV1: tsaFetcher required when tsa config is provided");

  const baseBody = buildRedactionBody({
    counts: input.counts,
    ruleset_hash: input.ruleset_hash,
    input_commit: input.input_commit,
    output_commit: input.output_commit,
    redactor: input.redactor,
  });
  const check = verifyRedactionBody(baseBody);
  if (!check.valid) throw new Error(`mintRedactionV1: invalid body — ${check.errors.join(",")}`);

  const id = generateReceiptId();
  const iat = new Date().toISOString();
  const { privateKey, issKey } = keyObjectFromSeed(input.signingKey.privateKey);
  const field_root = computeFieldRoot(baseBody);
  const bodyOut = { ...baseBody, field_root };
  const envelopeKindOut: Kind | null = input.envelope_kind === undefined ? "observation" : input.envelope_kind;

  const preSign: Envelope = {
    v: 2,
    id,
    iat,
    iat_ms: Date.parse(iat),
    claim_type: REDACTION_CLAIM_TYPE,
    iss: input.issuer,
    iss_key: issKey,
    subject: null as unknown as string,
    exp: input.exp ?? null,
    prev: input.prev ?? null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    kind: envelopeKindOut,
    cause: input.cause ?? null,
    predicate: null,
    tsa: null,
    credentialStatus: null,
    anchor: input.anchor,
    sig: "",
    countersig: null,
    body: bodyOut,
  };

  const signed = await signEnvelope(preSign, privateKey);
  if (input.tsa !== undefined) return attachTsaBlock(signed, input.tsa, input.tsaFetcher!);
  return signed;
}
