/**
 * ADR v1 types — spec §4 + §5 + §7.
 *
 * Claim type: ar.delegation.v1
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/adr
 */

import type { AdrClaimType, AdrEventType, AdrProfile, AdrScope, AdrAgentDescriptor, AdrAgent, AdrAuthorizingCredential, AdrGrantBody, AdrRevokeBody, AdrNarrowBody, AdrRenewBody, AdrSuspendBody, AdrResumeBody, AdrBody } from "@dekimuhq/adr-profiles";
export type { AdrClaimType, AdrEventType, AdrProfile, AdrScope, AdrAgentDescriptor, AdrAgent, AdrAuthorizingCredential, AdrGrantBody, AdrRevokeBody, AdrNarrowBody, AdrRenewBody, AdrSuspendBody, AdrResumeBody, AdrBody };

// ── Event types (spec §4.2, D11-ADR) ──────────────────────────────────────────

export const ADR_EVENT_TYPES: readonly AdrEventType[] = [
  "grant",
  "revoke",
  "narrow",
  "renew",
  "suspend",
  "resume",
] as const;

// ── Profiles (spec §5, D15-ADR) ──────────────────────────────────────────────

export const ADR_PROFILES: readonly AdrProfile[] = [
  "aiact.art26.deployer",
  "aiact.art14.oversight",
  "agentops.scoped-delegation",
  "gdpr.art28.processor",
  "gdpr.dsr.authorised-agent",
  "corporate.officer",
] as const;

// ── State machine (spec §7.1) ───────────────────────────────────────────────

export type AdrState = "Active" | "Suspended" | "Revoked" | "Expired";

// ── Chain types (for chain/tree walker consumers) ───────────────────────────

export interface AdrChainReceipt {
  readonly id: string;
  readonly iss: string;
  readonly subject: string | null;
  readonly iat: string;
  readonly prev: string | null;
  readonly body: AdrBody;
}

export interface AdrChainSummary {
  readonly root_id: string;
  readonly depth: number;
  readonly last_event: AdrEventType;
  readonly last_event_at: string;
}

export interface AdrChainWalkResult {
  readonly ok: boolean;
  readonly state: AdrState;
  readonly effective_scope: AdrScope | null;
  readonly hard_invalid_reasons: readonly string[];
  readonly warnings: readonly string[];
  readonly chain_summary: AdrChainSummary | null;
}

// ── Tree types (for sub-delegation tree walker) ─────────────────────────────

export interface AdrTreeIndex {
  readonly byId: ReadonlyMap<string, AdrChainReceipt>;
  readonly childrenOf: ReadonlyMap<string, readonly string[]>;
}

export interface AdrTreeWalkResult {
  readonly ok: boolean;
  readonly effective_state: AdrState;
  readonly effective_scope: AdrScope | null;
  readonly hard_invalid_reasons: readonly string[];
  readonly warnings: readonly string[];
  readonly ancestor_depth: number;
}

// ── Scope subset result ─────────────────────────────────────────────────────

export interface ScopeSubsetResult {
  readonly ok: boolean;
  readonly reasons: readonly string[];
}

// ── Depth limits ────────────────────────────────────────────────────────────

export const ADR_DEFAULT_CHAIN_DEPTH_LIMIT = 64;
export const ADR_CHAIN_DEPTH_LIMIT_MIN = 4;
export const ADR_CHAIN_DEPTH_LIMIT_MAX = 512;

export const ADR_DEFAULT_TREE_DEPTH_LIMIT = 16;
export const ADR_TREE_DEPTH_LIMIT_MIN = 2;
export const ADR_TREE_DEPTH_LIMIT_MAX = 64;
