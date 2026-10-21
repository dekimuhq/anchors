/**
 * AgTR v=2 mint path. Single export: mintTraceV1(input). subject MUST be null.
 * Non-consumer of Status List 2021. TSA optional. The *_commit fields are
 * caller-precomputed; this mint binds them as-is. Chip 18, ar.trace.v1. Verify-before-sign.
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
import type { AgTRBody, AgTRCaveatsConsumed, TraceStage, TraceOutcome } from "../types.ts";
import { verifyTraceBody } from "../verify-single.ts";
import { traceFamily } from "../family.ts";

const TRACE_CLAIM_TYPE = traceFamily.meta.claim_types[0]!;
export type { TsaFetcher, SigningKey };
export { TsaMintError };

export interface MintTraceV1Input {
  issuer: string;
  signingKey: SigningKey;
  anchor: AnchorProof;
  request_id_commit: string;
  stages: TraceStage[];
  outcome: TraceOutcome;
  trace_commit: string;
  started_at: string;
  total_ms: number;
  capability?: string;
  error_stage?: string;
  credential_id?: string;
  caveats_consumed?: AgTRCaveatsConsumed;
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

function buildBody(input: MintTraceV1Input): AgTRBody {
  return {
    profile: "agent.trace",
    request_id_commit: input.request_id_commit,
    stages: input.stages,
    outcome: input.outcome,
    trace_commit: input.trace_commit,
    started_at: input.started_at,
    total_ms: input.total_ms,
    ...(input.capability !== undefined ? { capability: input.capability } : {}),
    ...(input.error_stage !== undefined ? { error_stage: input.error_stage } : {}),
    ...(input.credential_id !== undefined ? { credential_id: input.credential_id } : {}),
    ...(input.caveats_consumed !== undefined ? { caveats_consumed: input.caveats_consumed } : {}),
    ...(input.policy_uri !== undefined ? { policy_uri: input.policy_uri } : {}),
    ...(input.policy_hash !== undefined ? { policy_hash: input.policy_hash } : {}),
    ...(input.policy_version !== undefined ? { policy_version: input.policy_version } : {}),
  };
}

export async function mintTraceV1(input: MintTraceV1Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintTraceV1: issuer required");
  if (!input.signingKey?.kid) throw new Error("mintTraceV1: signingKey.kid required");
  if (input.signingKey.privateKey.length !== 32) throw new Error("mintTraceV1: signingKey.privateKey must be 32 bytes");
  if (!input.anchor) throw new Error("mintTraceV1: anchor required");
  if (input.tsa !== undefined && input.tsaFetcher === undefined) throw new Error("mintTraceV1: tsaFetcher required when tsa config is provided");

  const baseBody = buildBody(input);
  const check = verifyTraceBody(baseBody);
  if (!check.valid) throw new Error(`mintTraceV1: invalid body — ${check.errors.join(",")}`);

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
    claim_type: TRACE_CLAIM_TYPE,
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
