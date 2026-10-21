/**
 * Assemble matched envelopes into a `var`-addressable context for the contract
 * predicate. Predicates reference matches as `{ var: "anchors.<key>.<path>" }`.
 */
import type { Envelope } from "@dekimuhq/anchors-envelope";

export interface ContractContext {
  anchors: Record<string, Envelope>;
}

export function buildContext(matched: Record<string, Envelope>): ContractContext {
  return { anchors: { ...matched } };
}
