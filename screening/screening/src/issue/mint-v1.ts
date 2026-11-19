/**
 * AScR v=2 mint path. subject is null, prev is null (spec §2.1).
 * The caller computes `subject_commit` with `commitScreenedName(name)` and keeps
 * the REVEAL it returns. The reveal is the screened party's personal data: the
 * caller stores it for the receipt's lifetime, exports it to the owner, and
 * erases it on erasure. It is never put in the receipt. Refuses to sign a body
 * that fails validation, so a stale list, an empty list or an incoherent result
 * never gets a signature.
 */
import {
  generateReceiptId, keyObjectFromSeed, computeFieldRoot, signEnvelope, commit, randomSalt,
  type Envelope, type AnchorProof,
} from "@dekimuhq/anchors-envelope";
import { TsaMintError, attachTsaBlock, type TsaFetcher, type TsaConfig } from "@dekimuhq/anchors-envelope/tsa";
import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
import { validateScreeningList } from "@dekimuhq/screening-profiles";
import type {
  ScreeningListBody, ScreeningList, ScreeningMatcher, ScreeningCandidate, ScreeningResult, ScreeningTrigger,
} from "@dekimuhq/screening-profiles";
import { screeningFamily } from "../family.ts";
import { matcherPolicyHash } from "../policy.ts";

const CLAIM_TYPE = screeningFamily.meta.claim_types[0]!;
export type { TsaFetcher, SigningKey };
export { TsaMintError };

export interface MintScreeningInput {
  issuer: string;
  signingKey: SigningKey;
  anchor: AnchorProof;
  screen_id: string;
  /** From `commitScreenedName`. The name itself never enters the mint. */
  subject_commit: string;
  list: ScreeningList;
  matcher: ScreeningMatcher;
  result: ScreeningResult;
  candidates: ScreeningCandidate[];
  trigger: ScreeningTrigger;
  screened_at: string;
  exp?: string | null;
  tsa?: TsaConfig;
  tsaFetcher?: TsaFetcher;
}

export interface ScreenedNameCommitment {
  subject_commit: string;
  /** Personal data of the screened party. Retain, export to the owner, erase on erasure. */
  reveal: { salt: string; name: string };
}

/** Trim, draw a fresh per-screen 256-bit salt, commit. One call per screen; never reuse a salt. */
export function commitScreenedName(name: string): ScreenedNameCommitment {
  const trimmed = name.trim();
  if (!trimmed) throw new Error("commitScreenedName: name required");
  const salt = randomSalt();
  return { subject_commit: commit(salt, trimmed), reveal: { salt, name: trimmed } };
}

export async function mintScreeningV1(input: MintScreeningInput): Promise<Envelope> {
  if (!input.issuer) throw new Error("mintScreeningV1: issuer required");
  if (!input.signingKey?.kid) throw new Error("mintScreeningV1: signingKey.kid required");
  if (input.signingKey.privateKey.length !== 32) throw new Error("mintScreeningV1: signingKey.privateKey must be 32 bytes");
  if (!input.anchor) throw new Error("mintScreeningV1: anchor required");
  if (input.tsa !== undefined && input.tsaFetcher === undefined) throw new Error("mintScreeningV1: tsaFetcher required when tsa config is provided");
  const baseBody: ScreeningListBody = {
    profile: "screening.list",
    screen_id: input.screen_id,
    list: input.list,
    matcher: input.matcher,
    subject_commit: input.subject_commit,
    result: input.result,
    candidates: input.candidates,
    trigger: input.trigger,
    screened_at: input.screened_at,
  };
  const v = validateScreeningList(baseBody);
  if (!v.ok) throw new Error("mintScreeningV1: screening body invalid: " + v.errors.join("; "));

  const iat = new Date().toISOString();
  // A receipt for a screen that has not happened yet is refused (spec §3.3). 5 min clock-skew allowance.
  if (Date.parse(baseBody.screened_at) > Date.parse(iat) + 5 * 60 * 1000) {
    throw new Error("mintScreeningV1: screening.screened_at.in_future");
  }
  const id = generateReceiptId();
  const { privateKey, issKey } = keyObjectFromSeed(input.signingKey.privateKey);
  const bodyOut = { ...baseBody, field_root: computeFieldRoot(baseBody) };

  const preSign: Envelope = {
    v: 2,
    id,
    iat,
    iat_ms: Date.parse(iat),
    claim_type: CLAIM_TYPE,
    iss: input.issuer,
    iss_key: issKey,
    subject: null as unknown as string,
    exp: input.exp ?? null,
    prev: null,
    policy_uri: null,
    policy_hash: matcherPolicyHash(input.matcher),
    policy_version: input.matcher.version,
    kind: "decision",
    cause: null,
    predicate: null,
    tsa: null,
    credentialStatus: null,
    anchor: input.anchor,
    sig: "",
    countersig: null,
    body: bodyOut,
  };
  const signed = await signEnvelope(preSign, privateKey);
  const receipt = input.tsa !== undefined ? await attachTsaBlock(signed, input.tsa, input.tsaFetcher!) : signed;
  return receipt;
}
