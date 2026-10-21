import { signCanonical, verifyCanonical } from "@dekimuhq/anchors-envelope";
// NOTE: intentionally NOT importing AActRBody from "./body.ts". body.ts imports
// AActRNonRevocationProof from here; importing back would create a type cycle that
// makes the package's `export *` drop these symbols for external consumers
// (declaration-build resolution). verifyReceiptNonRevocation takes a structural
// view (NonRevocationReceiptView) instead — AActRBody is assignable to it.

/**
 * Stapled, issuer-signed proof that the authorizing mandate (`credential_id`)
 * was NOT revoked at action time. Embedded in the AActR body. Self-verifiable
 * offline forever — the verifier needs only the issuer public key, never the
 * live status list. OCSP-stapling analogue.
 */
export interface AActRNonRevocationProof {
  /** MUST equal the receipt body's `credential_id`. */
  credential_id: string;
  /** v1: only "active" is mintable; a revoked mandate yields no receipt. */
  status: "active";
  /** RFC 3339 UTC. MUST be >= the receipt's `executed_at`. */
  as_of: string;
  /** Mandate status list the issuer checked against (informational + audit). */
  status_list_ref: string;
  /**
   * MUST equal the receipt body's `request_id_commit`; binds this proof to one
   * specific action so it cannot be lifted onto another receipt.
   */
  receipt_commit: string;
  /** base64url Ed25519 signature over the JCS-canonical of the above (sig omitted). */
  sig: string;
}

/** Input to {@link buildNonRevocationProof} (camelCase mirror, pre-signature). */
export interface NonRevocationProofInput {
  credentialId: string;
  asOf: string;
  statusListRef: string;
  receiptCommit: string;
}

/** The exact signed payload — field order is irrelevant (JCS sorts keys). */
function signedPayload(p: {
  credential_id: string;
  status: "active";
  as_of: string;
  status_list_ref: string;
  receipt_commit: string;
}) {
  return {
    credential_id: p.credential_id,
    status: p.status,
    as_of: p.as_of,
    status_list_ref: p.status_list_ref,
    receipt_commit: p.receipt_commit,
  };
}

/**
 * Build + sign a non-revocation proof. Pure: no IO, no clock — the caller
 * supplies `asOf` (the issuer reads it from the same mint operation that set
 * the receipt's `executed_at`). `privateKeySeed` is the issuer's 32-byte seed.
 */
export function buildNonRevocationProof(
  input: NonRevocationProofInput,
  privateKeySeed: Uint8Array,
): AActRNonRevocationProof {
  const payload = signedPayload({
    credential_id: input.credentialId,
    status: "active",
    as_of: input.asOf,
    status_list_ref: input.statusListRef,
    receipt_commit: input.receiptCommit,
  });
  const sigBytes = signCanonical(payload, privateKeySeed);
  return { ...payload, sig: Buffer.from(sigBytes).toString("base64url") };
}

export interface VerifyNonRevocationOpts {
  /** The receipt body's `executed_at` (RFC 3339). */
  executedAt: string;
  /** The receipt body's `credential_id`; the proof's MUST equal it (REQUIRED). */
  expectCredentialId: string;
  /**
   * The receipt body's `request_id_commit`; the proof's `receipt_commit` MUST
   * equal it (REQUIRED — receipt binding closes the replay/lift gap).
   */
  expectReceiptCommit: string;
  /** Max allowed `as_of - executed_at`. Default 5 minutes. */
  maxLagMs?: number;
}

export interface NonRevocationVerifyResult {
  valid: boolean;
  reason?: string;
}

const DEFAULT_MAX_LAG_MS = 5 * 60 * 1000;

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/** Parse a strict RFC-3339 timestamp (mandatory T separator + Z/offset). null if invalid. */
function parseRfc3339(s: string): number | null {
  if (typeof s !== "string" || !RFC3339.test(s)) return null;
  const ms = Date.parse(s);
  return Number.isNaN(ms) ? null : ms;
}

/**
 * Verify a non-revocation proof. Pure, fail-closed: any malformed input,
 * signature failure, credential mismatch, or out-of-window `as_of` → invalid.
 */
export function verifyNonRevocationProof(
  proof: AActRNonRevocationProof,
  issuerPublicKey: Uint8Array,
  opts: VerifyNonRevocationOpts,
): NonRevocationVerifyResult {
  if (!proof || proof.status !== "active") {
    return { valid: false, reason: "status not active" };
  }
  if (!proof.credential_id) {
    return { valid: false, reason: "missing credential_id" };
  }
  if (typeof proof.receipt_commit !== "string" || proof.receipt_commit.length === 0) {
    return { valid: false, reason: "missing receipt_commit" };
  }
  if (proof.credential_id !== opts.expectCredentialId) {
    return { valid: false, reason: "credential_id mismatch with receipt body" };
  }
  if (proof.receipt_commit !== opts.expectReceiptCommit) {
    return { valid: false, reason: "receipt_commit mismatch with receipt body" };
  }
  const asOfMs = parseRfc3339(proof.as_of);
  const execMs = parseRfc3339(opts.executedAt);
  if (asOfMs === null || execMs === null) {
    return { valid: false, reason: "non-RFC3339 timestamp" };
  }
  if (asOfMs < execMs) {
    return { valid: false, reason: "as_of before executed_at" };
  }
  const maxLag = opts.maxLagMs ?? DEFAULT_MAX_LAG_MS;
  if (asOfMs - execMs > maxLag) {
    return { valid: false, reason: "as_of lag exceeds maximum" };
  }
  if (typeof proof.sig !== "string" || proof.sig.length === 0) {
    return { valid: false, reason: "malformed signature encoding" };
  }
  const sigBytes = new Uint8Array(Buffer.from(proof.sig, "base64url"));
  if (sigBytes.length !== 64) {
    return { valid: false, reason: "malformed signature encoding" };
  }
  const payload = signedPayload(proof);
  if (!verifyCanonical(payload, sigBytes, issuerPublicKey)) {
    return { valid: false, reason: "signature verification failed" };
  }
  return { valid: true };
}

/**
 * Verify a receipt's non-revocation proof against the receipt body, binding it
 * to the body's executed_at, credential_id, and request_id_commit. PURE — the
 * caller resolves `issuerPublicKey` (the SAME trusted-issuer key the anchors
 * envelope verification resolves for this receipt's `iss`) and passes it in.
 * Returns valid:false (never throws) when the proof is absent or any check fails.
 */
/**
 * Structural view of the AActR body fields {@link verifyReceiptNonRevocation}
 * reads. `AActRBody` is structurally assignable to this, so callers pass a full
 * body unchanged; defining it here (not importing AActRBody) breaks the
 * body↔non-revocation type cycle.
 */
export interface NonRevocationReceiptView {
  non_revocation_proof?: AActRNonRevocationProof;
  credential_id?: string;
  executed_at: string;
  request_id_commit: string;
}

export function verifyReceiptNonRevocation(
  body: NonRevocationReceiptView,
  issuerPublicKey: Uint8Array,
  opts?: { maxLagMs?: number },
): NonRevocationVerifyResult {
  const proof = body.non_revocation_proof;
  if (!proof) return { valid: false, reason: "no non_revocation_proof present" };
  if (typeof body.credential_id !== "string" || !body.credential_id) {
    return { valid: false, reason: "receipt body has no credential_id to bind to" };
  }
  return verifyNonRevocationProof(proof, issuerPublicKey, {
    executedAt: body.executed_at,
    expectCredentialId: body.credential_id,
    expectReceiptCommit: body.request_id_commit,
    ...(opts?.maxLagMs !== undefined ? { maxLagMs: opts.maxLagMs } : {}),
  });
}
