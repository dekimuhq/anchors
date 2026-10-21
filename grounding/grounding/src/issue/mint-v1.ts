/**
 * AGrR v=2 mint path. Single export: mintGroundingV1(input). subject MUST be null
 * (FAMILY-CONSISTENCY §3). Verify-before-sign: re-runs the deterministic grounding
 * check over {answer, sources, claims, citations} and, if the caller supplied a
 * `result`, rejects when the supplied reproducible fields disagree with the re-check.
 * The body is always built from the re-check (never the supplied result). Chip 18,
 * ar.grounding.v1.
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
import { check } from "@dekimuhq/grounding-check";
import type {
  CheckSource,
  CheckClaim,
  CheckCitation,
  GroundingResult,
} from "@dekimuhq/grounding-check";
import { validateGroundingRag } from "@dekimuhq/grounding-profiles";
import type {
  GroundingRagBody,
  AGrRCaveatsConsumed,
} from "@dekimuhq/grounding-profiles";
import { groundingFamily } from "../family.ts";

const GROUNDING_CLAIM_TYPE = groundingFamily.meta.claim_types[0]!;
export type { TsaFetcher, SigningKey };
export { TsaMintError };

export interface MintGroundingInput {
  issuer: string;
  signingKey: SigningKey;
  anchor: AnchorProof;
  /** Full answer text — committed (sha-256), never embedded. */
  answer: string;
  /** Engine source inputs (carry `text`). */
  sources: CheckSource[];
  /** Engine claim inputs (carry `text`). */
  claims: CheckClaim[];
  /** Engine citation inputs ({claim_id, source_id, start, end}). */
  citations: CheckCitation[];
  scored_at: string;
  /** Support cutoff (0..1). Defaults to the engine's DEFAULT_THRESHOLD. */
  threshold?: number;
  /** Optional caller-supplied result — verify-before-sign compares it to a re-check. */
  result?: GroundingResult;
  answer_media_type?: string;
  credential_id?: string;
  caveats_consumed?: AGrRCaveatsConsumed;
  exp?: string | null;
  prev?: string | null;
  tsa?: TsaConfig;
  tsaFetcher?: TsaFetcher;
  envelope_kind?: Kind | null;
  cause?: Cause | null;
}

/**
 * Stable comparable projection of the engine result — every reproducible field
 * that the body carries. Order-stable: citations are compared positionally
 * (the engine emits them in input order, deterministically).
 */
function comparable(r: GroundingResult): string {
  return JSON.stringify({
    answer_commit: r.answer_commit,
    sources: r.sources.map((s) => ({
      source_id: s.source_id,
      source_commit: s.source_commit,
      ...(s.media_type !== undefined ? { media_type: s.media_type } : {}),
    })),
    claims: r.claims.map((c) => ({
      claim_id: c.claim_id,
      claim_commit: c.claim_commit,
    })),
    citations: r.citations.map((c) => ({
      claim_id: c.claim_id,
      source_id: c.source_id,
      start: c.start,
      end: c.end,
      span_commit: c.span_commit,
      support: c.support,
      score: c.score,
    })),
    coverage: r.coverage,
    grounded_count: r.grounded_count,
    scorer: {
      method: r.scorer.method,
      name: r.scorer.name,
      version: r.scorer.version,
      threshold: r.scorer.threshold,
    },
  });
}

export async function mintGroundingV1(
  input: MintGroundingInput,
): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintGroundingV1: issuer required");
  if (!input.signingKey?.kid)
    throw new Error("mintGroundingV1: signingKey.kid required");
  if (input.signingKey.privateKey.length !== 32)
    throw new Error("mintGroundingV1: signingKey.privateKey must be 32 bytes");
  if (!input.anchor) throw new Error("mintGroundingV1: anchor required");
  if (!input.scored_at)
    throw new Error("mintGroundingV1: scored_at is required");
  if (input.tsa !== undefined && input.tsaFetcher === undefined)
    throw new Error(
      "mintGroundingV1: tsaFetcher required when tsa config is provided",
    );

  // Verify-before-sign: re-run the deterministic grounding check. The body is
  // always built from THIS result, never the caller's.
  const fresh = check({
    answer: input.answer,
    sources: input.sources,
    claims: input.claims,
    citations: input.citations,
    ...(input.threshold !== undefined ? { threshold: input.threshold } : {}),
  });

  if (input.result !== undefined) {
    if (comparable(input.result) !== comparable(fresh)) {
      throw new Error(
        "mintGroundingV1: supplied result disagrees with re-check",
      );
    }
  }

  const baseBody: GroundingRagBody = {
    profile: "grounding.rag",
    answer_commit: fresh.answer_commit,
    sources: fresh.sources.map((s) => ({
      source_id: s.source_id,
      source_commit: s.source_commit,
      ...(s.media_type !== undefined ? { media_type: s.media_type } : {}),
    })),
    claims: fresh.claims.map((c) => ({
      claim_id: c.claim_id,
      claim_commit: c.claim_commit,
    })),
    citations: fresh.citations.map((c) => ({
      claim_id: c.claim_id,
      source_id: c.source_id,
      start: c.start,
      end: c.end,
      span_commit: c.span_commit,
      support: c.support,
      score: c.score,
    })),
    coverage: fresh.coverage,
    grounded_count: fresh.grounded_count,
    scorer: {
      method: fresh.scorer.method,
      name: fresh.scorer.name,
      version: fresh.scorer.version,
      threshold: fresh.scorer.threshold,
    },
    scored_at: input.scored_at,
    ...(input.answer_media_type !== undefined
      ? { answer_media_type: input.answer_media_type }
      : {}),
    ...(input.credential_id !== undefined
      ? { credential_id: input.credential_id }
      : {}),
    ...(input.caveats_consumed !== undefined
      ? { caveats_consumed: input.caveats_consumed }
      : {}),
  };

  const v = validateGroundingRag(baseBody);
  if (!v.ok)
    throw new Error(
      "mintGroundingV1: grounding body invalid: " + v.errors.join("; "),
    );

  const id = generateReceiptId();
  const iat = new Date().toISOString();
  const { privateKey, issKey } = keyObjectFromSeed(input.signingKey.privateKey);
  const field_root = computeFieldRoot(baseBody);
  const bodyOut = { ...baseBody, field_root };
  const envelopeKindOut: Kind | null =
    input.envelope_kind === undefined ? "observation" : input.envelope_kind;

  const preSign: Envelope = {
    v: 2,
    id,
    iat,
    iat_ms: Date.parse(iat),
    claim_type: GROUNDING_CLAIM_TYPE,
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
  if (input.tsa !== undefined)
    return attachTsaBlock(signed, input.tsa, input.tsaFetcher!);
  return signed;
}
