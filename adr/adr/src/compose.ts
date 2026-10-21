/**
 * composeAdr — compose-warnings callback for ADR.
 *
 * Lightweight stub. ADR delegation chains are verified via `walkAdrChain`
 * and `walkDelegationTree` directly — the compose slot is a no-op that
 * returns `{ ok: true }`.
 */

import type { ComposeCallback } from "@dekimuhq/anchors-envelope";

export const composeAdr: ComposeCallback = (_input) => {
  return { ok: true };
};
