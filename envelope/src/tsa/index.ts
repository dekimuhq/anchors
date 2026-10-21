/**
 * TSA sub-path barrel — @dekimuhq/anchors-envelope/tsa
 *
 * RFC 3161 TimeStampReq encoder + TimeStampResp parser + trust-anchor catalog
 * + verify chain (Tasks 9–10). Issuer-kit integration lands in Task 12.
 */

export type { TsaBlock, TsaConfig, TstInfo, SignerInfo, SignerId, ParsedTsr } from "./types.ts";
export type { TrustAnchor } from "./anchors.ts";
export type { TsaReason, TsaState, TsaVerifyResult, TsaVerifyOpts } from "./verify.ts";
export { buildTimeStampReq } from "./request.ts";
export { parseTimeStampResp } from "./response.ts";
export { loadTrustAnchors, defaultTrustAnchorPath } from "./anchors.ts";
export { verifyTsa } from "./verify.ts";
export type { TsaFetcher } from "./attach.ts";
export { TsaMintError, attachTsaBlock } from "./attach.ts";
export { computeTsaImprint } from "./imprint.ts";
// asn1 helpers remain internal — re-export only when a future task needs them
