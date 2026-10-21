/**
 * AActR v1 types — spec §4.
 *
 * Claim type: ar.action.v1
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/action
 *
 * Body types live in `@dekimuhq/action-profiles` (cycle-break — see that
 * package's `body.ts`); the verifier re-exports them so its public API carries
 * the full body surface.
 */

import type {
  AActRClaimType,
  AActRProfile,
  AActROutcome,
  AActRBody,
  AActRCaveatsConsumed,
  AActRDelegationChain,
  AActRArt12,
  AActRArt12RiskEvent,
} from "@dekimuhq/action-profiles";

export type {
  AActRClaimType,
  AActRProfile,
  AActROutcome,
  AActRBody,
  AActRCaveatsConsumed,
  AActRDelegationChain,
  AActRArt12,
  AActRArt12RiskEvent,
};
