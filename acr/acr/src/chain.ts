// anchors/acr/acr-verifier/src/chain.ts
import * as crypto from "node:crypto";
import { canonicalize } from "./canonicalize.ts";
import type { ACRReceipt } from "./types.ts";

export type ChainStatus = "active" | "modified" | "withdrawn";

export interface ChainState {
  status: ChainStatus;
  terminal_kind: ACRReceipt["kind"];
  terminal_hash: string;
  /** Time of the terminal receipt's `granted_at`. */
  terminal_granted_at: string;
  /** Hash of the original (first) receipt in the chain. */
  origin_hash: string;
  /** All receipt hashes in chain order. */
  chain_hashes: string[];
}

/**
 * Canonical receipt hash. Uses the same signing-scope view as
 * verifyReceiptSignature, so two receipts that differ only in
 * anchor/sig/countersig hash identically.
 */
export function hashReceipt(receipt: ACRReceipt): string {
  const view = { ...receipt, anchor: null, sig: null, countersig: null };
  const bytes = new TextEncoder().encode(canonicalize(view));
  const h = crypto.createHash("sha256").update(bytes).digest("hex");
  return `sha256:${h}`;
}

/**
 * Walk an ordered chain of receipts (origin first, terminal last),
 * verifying `prev` linkage and computing the current state.
 *
 * Does NOT verify signatures or anchors — callers should run
 * `verifyReceiptSignature` on each receipt separately.
 */
export function resolveChainState(chain: ACRReceipt[]): ChainState {
  if (chain.length === 0) throw new Error("resolveChainState: empty chain");

  const head = chain[0]!;
  if (head.prev !== null) {
    throw new Error("resolveChainState: first receipt must have prev === null");
  }

  const hashes: string[] = [hashReceipt(head)];
  for (let i = 1; i < chain.length; i++) {
    const r = chain[i]!;
    if (r.prev !== hashes[i - 1]) {
      throw new Error(
        `resolveChainState: broken prev pointer at index ${i} (expected ${hashes[i - 1]}, got ${r.prev})`,
      );
    }
    hashes.push(hashReceipt(r));
  }

  const terminal = chain[chain.length - 1]!;
  const status: ChainStatus =
    terminal.kind === "ar.withdrawal.v1"
      ? "withdrawn"
      : terminal.kind === "ar.modification.v1"
        ? "modified"
        : "active";

  return {
    status,
    terminal_kind: terminal.kind,
    terminal_hash: hashes[hashes.length - 1]!,
    terminal_granted_at: terminal.granted_at,
    origin_hash: hashes[0]!,
    chain_hashes: hashes,
  };
}
