/** Public API for @dekimuhq/anchor-contracts (P0). */
export type {
  AnchorVerdict,
  VerifiedAnchor,
  TimeWindow,
  Precondition,
  Transition,
  AnchorContract,
  RefusalReason,
  MatchResult,
  TransitionVerdict,
  MachineDefinition,
  MachineState,
} from "./types.ts";

export { contractHash } from "./contract-hash.ts";
export { matchPrecondition, matchAll, ACCEPTABLE_STATUS_STATES } from "./match.ts";
export type { MatchAllResult } from "./match.ts";
export { buildContext } from "./context.ts";
export type { ContractContext } from "./context.ts";
export { evaluateContract } from "./evaluate.ts";
export { createMachine, fireTransition } from "./machine.ts";
export type { FireResult } from "./machine.ts";
