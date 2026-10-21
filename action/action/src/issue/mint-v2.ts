/**
 * AActR v=2 mint path — produces v=2 Envelopes for Anchored Action Receipts.
 *
 * Single export surface: `mintActionV2(input)`. AActR is v=2 only (no v=1
 * legacy) and single-shape (no event_type discriminator).
 *
 * Per FAMILY-CONSISTENCY §3 and AActR spec §2: `subject` MUST be `null`
 * (workspace/activity-level — the action's target is a body commit). AActR is a
 * non-consumer of Status List 2021 (spec §3, decision 3) — actions are
 * non-revocable events, so this mint exposes NO statusList / suspensionList
 * surface. TSA is OPTIONAL (decision 4).
 *
 * The three `*_commit` fields are pre-computed by the caller via the envelope's
 * `commit(salt, value)` primitive against an app-side reveal map; this mint
 * binds them as-is and never sees the raw target values. `field_root` is
 * computed over the body and embedded for `ar.field_commit.v1` selective
 * disclosure (spec §4.3).
 *
 * Chip 15, ar.action.v1.
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
  AActRBody,
  AActROutcome,
  AActRProfile,
  AActRCaveatsConsumed,
  AActRDelegationChain,
} from "../types.ts";
import { actionFamily } from "../family.ts";

const ACTION_CLAIM_TYPE = actionFamily.meta.claim_types[0]!;

export type { TsaFetcher, SigningKey };
export { TsaMintError };

const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;

// ── v=2 body shape (issuer side adds field_root) ──────────────────────────────

export type ActionV2BodyOut = AActRBody & { field_root: string };

// ── Input ─────────────────────────────────────────────────────────────────────

export interface MintActionV2Input {
  /** Issuer DID or short identifier. */
  issuer: string;
  /** Ed25519 signing key (32-byte seed). */
  signingKey: SigningKey;
  /** Anchor proof (caller supplies; log worker replaces post-mint). */
  anchor: AnchorProof;

  /** Issuing profile. v1: `"hub.automation"`. */
  profile: AActRProfile;
  /** The dispatched verb, `<ns>.<op>`. Plaintext, non-PII. */
  verb: string;
  /** The owner-enabled rule that authorized automation. Plaintext, non-PII. */
  rule_id: string;
  /** The catalog recipe the rule instantiates. Plaintext, non-PII. */
  recipe_id: string;
  /** Terminal outcome. */
  outcome: AActROutcome;
  /** ISO 8601 UTC timestamp the action executed. */
  executed_at: string;
  /** `sha256:<hex>` salted commit to the decision id. */
  decision_commit: string;
  /** `sha256:<hex>` salted commit to the dispatched params. */
  params_commit: string;
  /** `sha256:<hex>` salted commit to the idempotency key `${ruleId}:${decisionId}`. */
  request_id_commit: string;

  /** OPTIONAL: the authorizing mandate's credential id (gateway credentialId / ADR grant claimId). */
  credential_id?: string;
  /** OPTIONAL: the attenuated authority this action spent. Provide iff `credential_id` is provided. */
  caveats_consumed?: AActRCaveatsConsumed;
  /**
   * OPTIONAL: the delegation path when the mandate is a chain (sub-agent). Provide iff
   * `credential_id` is provided AND the mandate delegated ≥1 time; `root_credential_id`
   * MUST equal `credential_id`.
   */
  delegation_chain?: AActRDelegationChain;
  /**
   * OPTIONAL: the stable per-agent principal (`verdict.verifiedAgentId` from a verified
   * mandate). Provide iff `credential_id` is provided AND the mandate carried an agentId.
   */
  agent_id?: string;

  /** Envelope-level policy URI (the automations surface). */
  policy_uri: string;
  /** SHA-256 hash of the recipe-catalog version. */
  policy_hash: string;
  /** Semantic version of the policy (e.g. `"plan-2.v1"`). */
  policy_version: string;

  /** Optional: previous receipt ID for additive emit-side lineage. */
  prev?: string | null;
  /** Optional: expiry ISO 8601 UTC. */
  exp?: string | null;
  /** Optional: TSA configuration. If present, tsaFetcher must also be provided. */
  tsa?: TsaConfig;
  /** Optional: TSA fetcher (caller-provided; required if `tsa` is set). */
  tsaFetcher?: TsaFetcher;
  /** v1.2 §4.1: receipt classification. Default `"observation"`. */
  envelope_kind?: Kind | null;
  /** v1.2 §4.2: typed trigger (closed enum). Optional. */
  cause?: Cause | null;
}

// ── Body builder ──────────────────────────────────────────────────────────────

function buildBody(input: MintActionV2Input): AActRBody {
  return {
    profile: input.profile,
    verb: input.verb,
    rule_id: input.rule_id,
    recipe_id: input.recipe_id,
    outcome: input.outcome,
    executed_at: input.executed_at,
    decision_commit: input.decision_commit,
    params_commit: input.params_commit,
    request_id_commit: input.request_id_commit,
    ...(input.credential_id !== undefined
      ? { credential_id: input.credential_id }
      : {}),
    ...(input.caveats_consumed !== undefined
      ? { caveats_consumed: input.caveats_consumed }
      : {}),
    ...(input.delegation_chain !== undefined
      ? { delegation_chain: input.delegation_chain }
      : {}),
    ...(input.agent_id !== undefined ? { agent_id: input.agent_id } : {}),
  };
}

// ── mintActionV2 ────────────────────────────────────────────────────────────────

export async function mintActionV2(
  input: MintActionV2Input
): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintActionV2: issuer required");
  if (!input.signingKey?.kid) {
    throw new Error("mintActionV2: signingKey.kid required");
  }
  if (input.signingKey.privateKey.length !== 32) {
    throw new Error("mintActionV2: signingKey.privateKey must be 32 bytes");
  }
  if (!input.anchor) throw new Error("mintActionV2: anchor required");

  for (const f of [
    "decision_commit",
    "params_commit",
    "request_id_commit",
  ] as const) {
    if (!SHA256_HEX_RE.test(input[f])) {
      throw new Error(
        `mintActionV2: ${f} must be \`sha256:<64-hex>\` (AActR spec §4.1)`
      );
    }
  }

  if (input.tsa !== undefined && input.tsaFetcher === undefined) {
    throw new Error(
      "mintActionV2: tsaFetcher is required when tsa config is provided"
    );
  }

  const id = generateReceiptId();
  const iat = new Date().toISOString();
  const { privateKey, issKey } = keyObjectFromSeed(input.signingKey.privateKey);

  const baseBody = buildBody(input);
  const field_root = computeFieldRoot(baseBody);
  const bodyOut: ActionV2BodyOut = { ...baseBody, field_root };

  const envelopeKindOut: Kind | null =
    input.envelope_kind === undefined ? "observation" : input.envelope_kind;

  const preSign: Envelope = {
    v: 2,
    id,
    iat,
    iat_ms: Date.parse(iat),
    claim_type: ACTION_CLAIM_TYPE,
    iss: input.issuer,
    iss_key: issKey,
    subject: null as unknown as string,
    exp: input.exp ?? null,
    prev: input.prev ?? null,
    policy_uri: input.policy_uri,
    policy_hash: input.policy_hash,
    policy_version: input.policy_version,
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

  if (input.tsa !== undefined) {
    return attachTsaBlock(signed, input.tsa, input.tsaFetcher!);
  }

  return signed;
}
