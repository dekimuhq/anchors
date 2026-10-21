// @dekimuhq/adr — verifier public surface (root export of the consolidated family package).
export {
  ADR_EVENT_TYPES,
  ADR_PROFILES,
  ADR_DEFAULT_CHAIN_DEPTH_LIMIT,
  ADR_CHAIN_DEPTH_LIMIT_MIN,
  ADR_CHAIN_DEPTH_LIMIT_MAX,
  ADR_DEFAULT_TREE_DEPTH_LIMIT,
  ADR_TREE_DEPTH_LIMIT_MIN,
  ADR_TREE_DEPTH_LIMIT_MAX,
  type AdrClaimType,
  type AdrEventType,
  type AdrProfile,
  type AdrScope,
  type AdrAgentDescriptor,
  type AdrAgent,
  type AdrGrantBody,
  type AdrRevokeBody,
  type AdrNarrowBody,
  type AdrRenewBody,
  type AdrSuspendBody,
  type AdrResumeBody,
  type AdrBody,
  type AdrState,
  type AdrChainReceipt,
  type AdrChainSummary,
  type AdrChainWalkResult,
  type AdrTreeIndex,
  type AdrTreeWalkResult,
  type ScopeSubsetResult,
} from "./types.ts";

export { checkAdrSubjectPresence } from "./subject-presence.ts";
export type { AdrSubjectPresenceReason, AdrSubjectPresenceResult } from "./subject-presence.ts";

export { AdrBodySchema } from "./body-schema.ts";
export { isScopeSubset, segmentMatch } from "./scope.ts";

export { buildAdrChainIndex, walkAdrChain } from "./chain.ts";
export type { AdrChainIndex, AdrChainWalkOptions } from "./chain.ts";

export { walkDelegationTree, buildAdrTreeIndex } from "./tree.ts";
export type { AdrTreeWalkOptions } from "./tree.ts";

export { adrFamily } from "./family.ts";
export { composeAdr } from "./compose.ts";
