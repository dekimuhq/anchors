/**
 * Public types for `apr-verifier`. Mirrors `apr-spec/v1.md` §2 and §3.
 */

export type APRArtifactType =
  | "commander.run.output"
  | "commander.run.codeChange"
  | "commander.run.email"
  | "commander.run.message"
  | "miniterms.document"
  | "lethe.letter"
  | "lethe.document"
  | "hub.sign-offs.deliverable"
  | "hub.time-clock.day";

export type APRAgentKind = "human" | "ai" | "template" | "hybrid";

export type APRDisclosure =
  | "public_minimal"
  | "public_full"
  | "metadata_only";

export type APRInputKind =
  | "prompt"
  | "file"
  | "url"
  | "claim"
  | "schedule";

export interface APRInput {
  kind: APRInputKind;
  hash?: string;
  source?: string;
  claimId?: string;
}

export interface APRBody {
  artifact: {
    type: APRArtifactType;
    id: string;
    hash: string;
    hashAlgorithm: "sha256";
    contentType?: string;
    sizeBytes?: number;
  };
  agent: {
    kind: APRAgentKind;
    model?: string;
    provider?: string;
    humanRole?: "review" | "edit" | "draft" | "approve" | "none";
  };
  authorization: {
    principalId: string;
  };
  inputs?: APRInput[];
  startedAt: number;
  completedAt: number;
  durationMs?: number;
  disclosure: APRDisclosure;
  summary?: string;
  qts_attestation_hash: string | null;
}

export interface APRClaim {
  v: 1;
  id: string;
  kind: "ar.provenance.v1";
  issuer: string;
  subject: string;
  iat: number;
  kid: string;
  body: APRBody;
  sig: string;
  holder?: string;
  audience?: string[];
  exp?: number;
  parent?: string;
}

export interface DailyRoot {
  v: 1;
  date: string;
  rootHash: string;
  count: number;
  kid: string;
  sig: string;
}

export interface ClaimVerifyingKey {
  kid: string;
  publicKey: Uint8Array;
  issuer: string;
  notBefore?: number;
  notAfter?: number;
}

export interface RootVerifyingKey {
  kid: string;
  publicKey: Uint8Array;
}

export type ClaimKeyResolver = (kid: string) => ClaimVerifyingKey | undefined;
export type RootKeyResolver = (kid: string) => RootVerifyingKey | undefined;

export type VerifyStatus = "verified" | "tampered" | "unverified";

export type VerifyReason =
  | "schema_invalid"
  | "unknown_kid"
  | "issuer_kid_mismatch"
  | "kid_not_yet_valid"
  | "kid_no_longer_valid"
  | "expired"
  | "signature_invalid"
  | "root-sig-invalid"
  | "root-hash-mismatch"
  | "missing-from-anchor"
  | "unanchored";

export interface VerifyResult {
  status: VerifyStatus;
  reasons: VerifyReason[];
}

export interface VerifyInput {
  claim: unknown;
  anchor: DailyRoot | null;
  /**
   * Deterministic id list the daily root was built over. Sorted ascending
   * (UTF-8 byte order) is the reference convention; the verifier sorts again
   * defensively. See `apr-spec/conformance/test-vectors/SCHEME.md`.
   */
  anchorIds: readonly string[];
  claimKeyResolver: ClaimKeyResolver;
  rootKeyResolver: RootKeyResolver;
  /**
   * Optional clock injection (unix seconds). Defaults to system clock.
   * Used for testability around `exp`, `notBefore`, `notAfter`.
   */
  now?: () => number;
}
