/**
 * Trust state machine: contracts are transition edges. Firing is pure — it
 * returns a NEW state (never mutates the input) plus the verdict. The trail is
 * the ordered audit log of fired transitions.
 */
import type { MachineDefinition, MachineState, TransitionVerdict, VerifiedAnchor } from "./types.ts";
import { evaluateContract } from "./evaluate.ts";
import { contractHash } from "./contract-hash.ts";

export function createMachine(def: MachineDefinition): MachineState {
  return { current: def.initial, trail: [] };
}

export interface FireResult {
  state: MachineState;
  verdict: TransitionVerdict;
}

export function fireTransition(
  def: MachineDefinition,
  state: MachineState,
  contractId: string,
  pool: VerifiedAnchor[],
): FireResult {
  const contract = def.contracts.find((c) => c.id === contractId);
  if (!contract) {
    return {
      state,
      verdict: { contractId, contractHash: "", from: state.current, to: state.current, fired: false, reason: "unknown_contract" },
    };
  }

  if (contract.transition.from !== state.current) {
    return {
      state,
      verdict: {
        contractId, contractHash: contractHash(contract),
        from: contract.transition.from, to: contract.transition.to,
        fired: false, reason: "wrong_from_state",
        detail: `machine is in '${state.current}', contract requires '${contract.transition.from}'`,
      },
    };
  }

  const verdict = evaluateContract(contract, pool);
  if (!verdict.fired) {
    return { state, verdict };
  }

  return {
    state: { current: contract.transition.to, trail: [...state.trail, verdict] },
    verdict,
  };
}
