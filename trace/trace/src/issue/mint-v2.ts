/**
 * AgTR v2 mint path — signed span tree. subject MUST be null. Builds spans_root
 * (Merkle over per-span salted detail) then verifies the full body before signing.
 * Chip 19, ar.trace.v2. Verify-before-sign. Reuses the v1 envelope assembly.
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
import type { AgTRTreeBody, AgTRCaveatsConsumed, Span } from "../types.ts";
import { verifyTraceTreeBody } from "../verify-tree.ts";
import { buildSpansRoot, type SpanSaltSource } from "../spans-root.ts";

const TRACE_V2_CLAIM_TYPE = "ar.trace.v2" as const;
export type { TsaFetcher, SigningKey };
export { TsaMintError };

export interface MintTraceV2Input {
  issuer: string;
  signingKey: SigningKey;
  anchor: AnchorProof;
  trace_id: string;
  request_id_commit: string;
  spans: Span[];
  detail: Record<string, unknown>;
  salts: SpanSaltSource;
  outcome: AgTRTreeBody["outcome"];
  started_at: string;
  total_ms: number;
  capability?: string;
  error_span_id?: string;
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

function buildBody(input: MintTraceV2Input, spans_root: string): AgTRTreeBody {
  return {
    profile: "agent.trace",
    trace_id: input.trace_id,
    request_id_commit: input.request_id_commit,
    spans: input.spans,
    spans_root,
    outcome: input.outcome,
    started_at: input.started_at,
    total_ms: input.total_ms,
    ...(input.capability !== undefined ? { capability: input.capability } : {}),
    ...(input.error_span_id !== undefined ? { error_span_id: input.error_span_id } : {}),
    ...(input.credential_id !== undefined ? { credential_id: input.credential_id } : {}),
    ...(input.caveats_consumed !== undefined ? { caveats_consumed: input.caveats_consumed } : {}),
    ...(input.policy_uri !== undefined ? { policy_uri: input.policy_uri } : {}),
    ...(input.policy_hash !== undefined ? { policy_hash: input.policy_hash } : {}),
    ...(input.policy_version !== undefined ? { policy_version: input.policy_version } : {}),
  };
}

export async function mintTraceV2(input: MintTraceV2Input): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintTraceV2: issuer required");
  if (!input.signingKey?.kid) throw new Error("mintTraceV2: signingKey.kid required");
  if (input.signingKey.privateKey.length !== 32) throw new Error("mintTraceV2: signingKey.privateKey must be 32 bytes");
  if (!input.anchor) throw new Error("mintTraceV2: anchor required");
  if (input.tsa !== undefined && input.tsaFetcher === undefined) throw new Error("mintTraceV2: tsaFetcher required when tsa config is provided");

  const { spans_root } = buildSpansRoot(input.spans, input.detail, input.salts);
  const baseBody = buildBody(input, spans_root);
  const check = verifyTraceTreeBody(baseBody);
  if (!check.valid) throw new Error(`mintTraceV2: invalid body — ${check.errors.join(",")}`);

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
    claim_type: TRACE_V2_CLAIM_TYPE,
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
