/**
 * AQR v=2 mint path. Single export: mintQualityV1(input). subject MUST be null
 * (FAMILY-CONSISTENCY §3). Non-consumer of Status List 2021. TSA optional. The
 * *_commit fields are caller-precomputed via the envelope commit primitive; this
 * mint binds them as-is. Chip 16, ar.quality.v1. Verify-before-sign.
 */
import {
  generateReceiptId,
  keyObjectFromSeed,
  computeFieldRoot,
  signEnvelope,
  type Envelope,
  type AnchorProof,
  type Kind,
  type Cause,
} from "@dekimuhq/anchors-envelope";
import {
  TsaMintError,
  attachTsaBlock,
  type TsaFetcher,
  type TsaConfig,
} from "@dekimuhq/anchors-envelope/tsa";
import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
import type {
  AQRBody,
  AQRProfile,
  QualityScorer,
  QualityResult,
  AQRCaveatsConsumed,
} from "../types.ts";
import { verifyQualityBody } from "../verify-single.ts";
import { qualityFamily } from "../family.ts";

const QUALITY_CLAIM_TYPE = qualityFamily.meta.claim_types[0]!;
export type { TsaFetcher, SigningKey };
export { TsaMintError };

export interface MintQualityV1Input {
  issuer: string;
  signingKey: SigningKey;
  anchor: AnchorProof;
  profile: AQRProfile;
  suite_id: string;
  suite_hash: string;
  scorer: QualityScorer;
  result: QualityResult;
  ran_at: string;
  samples_commit?: string;
  output_commit?: string;
  request_id_commit?: string;
  credential_id?: string;
  caveats_consumed?: AQRCaveatsConsumed;
  subject_ref?: string;
  gate?: "blocking" | "advisory";
  policy_uri?: string;
  policy_hash?: string;
  policy_version?: string;
  prev?: string | null;
  exp?: string | null;
  tsa?: TsaConfig;
  tsaFetcher?: TsaFetcher;
  envelope_kind?: Kind | null;
  cause?: Cause | null;
}

function buildBody(input: MintQualityV1Input): AQRBody {
  const common = {
    suite_id: input.suite_id,
    suite_hash: input.suite_hash,
    scorer: input.scorer,
    result: input.result,
    ran_at: input.ran_at,
    ...(input.samples_commit !== undefined ? { samples_commit: input.samples_commit } : {}),
    ...(input.policy_uri !== undefined ? { policy_uri: input.policy_uri } : {}),
    ...(input.policy_hash !== undefined ? { policy_hash: input.policy_hash } : {}),
    ...(input.policy_version !== undefined ? { policy_version: input.policy_version } : {}),
  };
  if (input.profile === "quality.output") {
    return {
      profile: "quality.output",
      ...common,
      output_commit: input.output_commit!,
      ...(input.request_id_commit !== undefined ? { request_id_commit: input.request_id_commit } : {}),
      ...(input.credential_id !== undefined ? { credential_id: input.credential_id } : {}),
      ...(input.caveats_consumed !== undefined ? { caveats_consumed: input.caveats_consumed } : {}),
    };
  }
  return { profile: "quality.release", ...common, subject_ref: input.subject_ref!, gate: input.gate! };
}

export async function mintQualityV1(input: MintQualityV1Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintQualityV1: issuer required");
  if (!input.signingKey?.kid) throw new Error("mintQualityV1: signingKey.kid required");
  if (input.signingKey.privateKey.length !== 32) throw new Error("mintQualityV1: signingKey.privateKey must be 32 bytes");
  if (!input.anchor) throw new Error("mintQualityV1: anchor required");
  if (input.tsa !== undefined && input.tsaFetcher === undefined) throw new Error("mintQualityV1: tsaFetcher required when tsa config is provided");

  const baseBody = buildBody(input);
  const check = verifyQualityBody(baseBody);
  if (!check.valid) throw new Error(`mintQualityV1: invalid body — ${check.errors.join(",")}`);

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
    claim_type: QUALITY_CLAIM_TYPE,
    iss: input.issuer,
    iss_key: issKey,
    subject: null as unknown as string,
    exp: input.exp ?? null,
    prev: input.prev ?? null,
    policy_uri: input.policy_uri ?? null,
    policy_hash: input.policy_hash ?? null,
    policy_version: input.policy_version ?? null,
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
