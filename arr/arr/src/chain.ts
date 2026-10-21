import { createHash } from "node:crypto";
import { canonicalize } from "./crypto-reexports.ts";
import type { ARRReceipt, ArrSingleKind, ArrStateSnapshot } from "./types.ts";

const TERMINAL_KINDS: ReadonlySet<ArrSingleKind> = new Set([
  "ar.erasure.v1",
  "ar.anonymization.v1",
]);

export interface ChainResolution {
  errors: string[];
  currentState: ArrStateSnapshot | null;
  terminal: boolean;
  terminalKind: ArrSingleKind | null;
}

function hashOf(r: ARRReceipt): string {
  const stripped: ARRReceipt = { ...r, anchor: null, sig: null };
  const h = createHash("sha256").update(canonicalize(stripped)).digest("hex");
  return `sha256:${h}`;
}

export function resolveTargetChain(chain: ARRReceipt[]): ChainResolution {
  const errors: string[] = [];
  if (chain.length === 0) {
    return { errors: ["chain.empty"], currentState: null, terminal: false, terminalKind: null };
  }

  const target = chain[0]!.target_commit;
  let prevHash: string | null = null;
  let terminalSeen = false;

  for (let i = 0; i < chain.length; i++) {
    const link = chain[i]!;
    if (link.target_commit !== target) errors.push("chain.target_mismatch");

    if (i === 0) {
      if (link.prev !== null) errors.push("chain.prev.first_not_null");
    } else {
      if (link.prev !== prevHash) errors.push(`chain.prev.mismatch[${i}]`);
    }

    if (terminalSeen) errors.push("chain.append_after_terminal");
    if (TERMINAL_KINDS.has(link.kind)) terminalSeen = true;

    prevHash = hashOf(link);
  }

  const last = chain[chain.length - 1]!;
  return {
    errors,
    currentState: last.state_snapshot,
    terminal: TERMINAL_KINDS.has(last.kind),
    terminalKind: TERMINAL_KINDS.has(last.kind) ? last.kind : null,
  };
}
