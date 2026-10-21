/**
 * attachCredentialStatus — mint a W3C Bitstring Status List 2021 pointer and
 * embed it in a v=2 envelope BEFORE signing.
 *
 * Spec: §5.5 — the credentialStatus pointer is included in the signed payload.
 * Callers MUST invoke this function after building the unsigned envelope and
 * BEFORE calling signEnvelope (or attachTsaBlock, which itself calls signEnvelope
 * internally).
 *
 * Bucket convention: `YYYY/MM` (UTC). The Status List Credential URL is
 *   `${baseUrl}/${bucket}`
 * with no trailing slash on baseUrl assumed. Callers MUST ensure baseUrl has
 * no trailing slash.
 *
 * Phase D Task 20.
 */

import type { Envelope, CredentialStatus } from "../envelope-types.ts";

/**
 * Configuration supplied by the issuer at mint time.
 *
 * `baseUrl`            — base URL of the status list endpoint, no trailing slash.
 *                        E.g. "https://verify.dekimu.com/acr/v1/status".
 * `getNextStatusIndex` — async callback that the issuer's status-assignment
 *                        subsystem implements. Receives the bucket string
 *                        (`YYYY/MM` UTC) and MUST return the next available
 *                        zero-based index within that monthly bitstring.
 * `now`                — optional clock override for testing; production
 *                        callers MUST omit this field.
 */
export interface StatusListConfig {
  baseUrl: string;
  getNextStatusIndex: (bucket: string) => Promise<number>;
  now?: () => Date;
}

/**
 * Maximum bit index in a W3C Bitstring Status List 2021 monthly bucket.
 *
 * Bucket size = 2^17 = 131072 bits → zero-based maximum index = 131_071.
 * Matches the recommended bucket cap from the W3C Status List 2021 spec.
 */
export const MAX_STATUS_INDEX = 131_071;

/**
 * Attaches a W3C Bitstring Status List 2021 Entry pointer to the envelope.
 *
 * Returns a new Envelope object (immutable spread) with `credentialStatus`
 * populated. Does NOT mutate the input envelope.
 *
 * @throws If `getNextStatusIndex` returns a non-integer (NaN, Infinity, 1.5)
 *         or an index outside [0, MAX_STATUS_INDEX].
 */
export async function attachCredentialStatus(
  envelope: Envelope,
  cfg: StatusListConfig,
): Promise<Envelope> {
  // T15 pointer-validator rejects non-https statusListCredential URLs. Fail
  // fast at mint rather than producing a receipt that fails its own validator.
  if (!cfg.baseUrl.startsWith("https://")) {
    throw new Error(
      `attachCredentialStatus: baseUrl must start with https:// (got "${cfg.baseUrl}")`,
    );
  }
  const now = cfg.now ? cfg.now() : new Date();
  const bucket = `${now.getUTCFullYear()}/${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
  const idx = await cfg.getNextStatusIndex(bucket);
  if (!Number.isInteger(idx) || idx < 0 || idx > MAX_STATUS_INDEX) {
    throw new Error(
      `attachCredentialStatus: status index ${idx} out of range [0, ${MAX_STATUS_INDEX}]`,
    );
  }
  const listUrl = `${cfg.baseUrl}/${bucket}`;
  const cs: CredentialStatus = {
    id: `${listUrl}#${idx}`,
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: String(idx),
    statusListCredential: listUrl,
  };
  return { ...envelope, credentialStatus: cs };
}
