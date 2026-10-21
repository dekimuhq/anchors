/**
 * AGR v=2 mint path. Single export: mintGuardV1(input). subject MUST be null
 * (FAMILY-CONSISTENCY §3). Verify-before-sign: re-screens content via guard-detect,
 * rejects if a caller-supplied result disagrees with the deterministic re-screen.
 * content_commit = sha256(content, utf8). Chip 17, ar.guard.v1.
 */
import { createHash } from "node:crypto";
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
import { screen } from "@dekimuhq/guard-detect";
import type { GuardScreenResult } from "@dekimuhq/guard-detect";
import { validateGuardInput } from "@dekimuhq/guard-profiles";
import type { GuardInputBody, AGRCaveatsConsumed } from "@dekimuhq/guard-profiles";
import { guardFamily } from "../family.ts";

const GUARD_CLAIM_TYPE = guardFamily.meta.claim_types[0]!;
export type { TsaFetcher, SigningKey };
export { TsaMintError };

export interface MintGuardInput {
  issuer: string;
  signingKey: SigningKey;
  anchor: AnchorProof;
  content: string;
  screened_at: string;
  result?: GuardScreenResult;
  content_media_type?: string;
  credential_id?: string;
  caveats_consumed?: AGRCaveatsConsumed;
  exp?: string | null;
  prev?: string | null;
  tsa?: TsaConfig;
  tsaFetcher?: TsaFetcher;
  envelope_kind?: Kind | null;
  cause?: Cause | null;
}

export async function mintGuardV1(input: MintGuardInput): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintGuardV1: issuer required");
  if (!input.signingKey?.kid) throw new Error("mintGuardV1: signingKey.kid required");
  if (input.signingKey.privateKey.length !== 32) throw new Error("mintGuardV1: signingKey.privateKey must be 32 bytes");
  if (!input.anchor) throw new Error("mintGuardV1: anchor required");
  if (!input.screened_at) throw new Error("mintGuardV1: screened_at is required");
  if (input.tsa !== undefined && input.tsaFetcher === undefined) throw new Error("mintGuardV1: tsaFetcher required when tsa config is provided");

  const fresh = screen(input.content);
  if (input.result !== undefined) {
    const a = JSON.stringify({ d: input.result.decision, m: input.result.matched_rules, h: input.result.ruleset_hash });
    const b = JSON.stringify({ d: fresh.decision, m: fresh.matched_rules, h: fresh.ruleset_hash });
    if (a !== b) throw new Error("mintGuardV1: supplied guard result disagrees with re-screen");
  }

  const content_commit = createHash("sha256").update(input.content, "utf8").digest("hex");

  const baseBody: GuardInputBody = {
    profile: "guard.input",
    ruleset_id: fresh.ruleset_id,
    ruleset_hash: fresh.ruleset_hash,
    ruleset_version: fresh.ruleset_version,
    content_commit,
    decision: fresh.decision,
    matched_rules: fresh.matched_rules,
    detector: { engine: "deterministic", name: fresh.ruleset_id, version: fresh.ruleset_version },
    screened_at: input.screened_at,
    ...(input.content_media_type !== undefined ? { content_media_type: input.content_media_type } : {}),
    ...(input.credential_id !== undefined ? { credential_id: input.credential_id } : {}),
    ...(input.caveats_consumed !== undefined ? { caveats_consumed: input.caveats_consumed } : {}),
  };

  const v = validateGuardInput(baseBody);
  if (!v.ok) throw new Error("mintGuardV1: guard body invalid: " + v.errors.join("; "));

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
    claim_type: GUARD_CLAIM_TYPE,
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
