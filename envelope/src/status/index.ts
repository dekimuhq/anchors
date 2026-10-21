/**
 * Status sub-path barrel — @dekimuhq/anchors-envelope/status
 *
 * Phase D Task 15: `validateCredentialStatusPointer` (W3C Bitstring
 *                  Status List 2021 pointer-schema validation).
 * Phase D Task 16: `InMemoryStatusCache` + `fetchStatusListCredential` —
 *                  verifier-side status-list fetcher with bounded LRU cache
 *                  and stale-tolerant freshness model.
 * Phase D Task 17: `encodedListFromBitstring` + `decodeEncodedList` +
 *                  `readBitAt` — gzip + base64url + MSB-first bit read for
 *                  Status List 2021 bitstrings. Revocation enforcement
 *                  (`isRevoked` + verifier wiring) lands in later Phase D
 *                  tasks.
 * Phase D Task 18: `verifyStatusListCredentialSignature` — W3C VC
 *                  Ed25519Signature2020 over RFC 8785 canonical simplified
 *                  form, with `StatusListCredential` + `RootKeyMaterial`
 *                  shape types.
 * Phase D Task 19: `verifyCredentialStatus` + `StatusCheck` — full
 *                  pointer + fetch + sig + bit + chain reconciliation against
 *                  the local chain successor predicate. Advisory-only.
 * Phase D Task 20: `attachCredentialStatus` + `StatusListConfig` — issuer-side
 *                  helper that mints a W3C Bitstring Status List 2021 pointer
 *                  and embeds it in the envelope BEFORE signing.
 */

export type {
  CredentialStatus,
  StatusListEntry,
  StatusCacheStorage,
  StatusCacheConfig,
  StatusFetchResult,
  StatusListCredential,
  RootKeyMaterial,
  StatusCheck,
} from "./types.ts";
export { validateCredentialStatusPointer } from "./pointer.ts";
export { InMemoryStatusCache } from "./cache.ts";
export { fetchStatusListCredential } from "./fetch.ts";
export type { FetchOpts } from "./fetch.ts";
export {
  encodedListFromBitstring,
  decodeEncodedList,
  readBitAt,
} from "./decode.ts";
export { verifyStatusListCredentialSignature } from "./verify.ts";
export { verifyCredentialStatus } from "./reconcile.ts";
export type { ReconcileOpts } from "./reconcile.ts";
export { attachCredentialStatus, MAX_STATUS_INDEX } from "./attach.ts";
export type { StatusListConfig } from "./attach.ts";
export { attachSuspensionStatus } from "./suspension-attach.ts";
export type { SuspensionListConfig } from "./suspension-attach.ts";
export { validateSuspensionStatusPointer } from "./suspension-pointer.ts";
export type { SuspensionStatusPointerResult } from "./suspension-pointer.ts";
export { verifySuspensionStatus } from "./suspension-verify.ts";
export type { SuspensionVerifyOpts } from "./suspension-verify.ts";
export type { SuspensionCheck } from "./suspension-types.ts";
