/**
 * Quantum-trustworthy effective-time resolution for the issuer PQC-migration
 * policy (anchors v1.3 R3 Phase 2b).
 *
 * `@dekimuhq/anchors-trusted-issuers`'s `makeVerifyIssuerPqc` accepts a
 * `resolveEffectiveTime(envelope) => Date | null` callback. Its module contract
 * is security-critical: the returned instant MUST be a *quantum-trustworthy*
 * upper bound on the receipt's log-inclusion time — NEVER the receipt's
 * self-claimed `issued_at`, and NEVER a value whose trust rests on a signature
 * a CRQC adversary can forge. {@link makeInclusionProofEffectiveTime} is the
 * sound source for that callback.
 *
 * ## Why neither the checkpoint signature nor the promise timestamp is enough
 *
 * - A C2SP **checkpoint note** is signed Ed25519 and, crucially, its signed body
 *   (`origin\nsize\nrootHash\n`) carries NO timestamp. Under a CRQC its signature
 *   is forgeable, so a verifier cannot trust a checkpoint it sees *now*.
 * - An **inclusion promise** (`{timestamp, sig}`) is an Ed25519 SCT over
 *   `(log_id‖leaf‖timestamp)` — its timestamp is exactly the attacker-chosen
 *   value in the forgery scenario. Trusting it is a trivial bypass.
 *
 * The only quantum-safe ingredients are (1) **hash-based RFC 6962 Merkle
 * inclusion** and (2) a checkpoint we **pinned before any CRQC** (a witnessed
 * snapshot recorded while Ed25519 was still trustworthy). Given a pinned
 * checkpoint `(origin, size, root, witnessedAt)`, any leaf with a valid audit
 * path to `root` at `size` provably existed in the log no later than
 * `witnessedAt`. So `witnessedAt` is a sound, quantum-trustworthy UPPER BOUND on
 * the inclusion time — which is the safe direction: the policy accepts a
 * pre-cutover receipt only when the bound itself is < cutover (then real
 * inclusion ≤ bound < cutover, genuinely pre-cutover), and otherwise falls back
 * to requiring the PQC floor.
 *
 * ## What this resolver does (and what it deliberately refuses)
 *
 * It trusts ONLY the pin and the SHA-256 audit path. It does NOT verify, parse,
 * or rely on the proof's embedded `checkpoint` note signature — that note is the
 * (forgeable) thing the pin replaces. It refuses a promise-only inclusion block
 * (returns `null` → caller falls back to `now()` → fail-toward-rejection).
 *
 * Two structural bindings make the bound apply to THIS receipt rather than to
 * "some object that was once logged":
 *   - **Leaf binding.** `incl.leaf` is NOT trusted verbatim — it is recomputed as
 *     the family-canonical `leafHash(receipt \ {incl})` from the envelope and must
 *     match. Otherwise an attacker could staple a genuinely-logged leaf (or a
 *     public pinned root) into a forged receipt's `incl` block and inherit its
 *     early time. (SHA-256 second-preimage resistance makes a chosen leaf
 *     infeasible.)
 *   - **Audit-path completeness.** The path length must EXACTLY equal the RFC 6962
 *     audit-path length for `(index, tree_size)`. A short/empty path must never
 *     validate: `verifyInclusionProof` alone returns `true` for an empty path when
 *     `leaf === root` (index 0), so the length check is load-bearing, not cosmetic.
 *
 * ## Known limit (documented next slice, NOT a bug)
 *
 * A receipt's audit path only reconstructs the exact tree (`size`+`root`) it was
 * issued against, so this v1 resolver matches a proof to a pin of that same tree.
 * Bridging an arbitrary issuance checkpoint to a later pinned one (via an RFC 6962
 * **consistency proof**) is a follow-on; until then the receipt must carry a proof
 * against a checkpoint that is itself pinned.
 */

import { verifyInclusionProof } from "./rfc6962.ts";
import { leafHash } from "./leaf.ts";
import type { InclBlock } from "./types.ts";

const SHA256_SELF_DESCRIBING = /^sha256:[0-9a-f]{64}$/;

// Strict ISO 8601 — mirrors `@dekimuhq/anchors-trusted-issuers`'s `iso8601.ts`
// (kept local to avoid a cross-package dependency). A lone `Date.parse` accepts
// zone-less strings as LOCAL time, silently shifting the pinned instant by the
// host timezone offset; the strict regex pins an unambiguous instant.
const ISO_8601_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

// Upper bound on `index`/`tree_size` (2³¹−1). The underlying RFC 6962 verifier
// (`rfc6962.ts`) navigates the tree with 32-bit bitwise ops (`>>`, `&`), which
// are only well-defined for non-negative values below 2³¹; a larger
// attacker-supplied `tree_size` would both misbehave there and (before this cap)
// could wedge the path-length computation. A log with >2 billion entries is far
// beyond any realistic horizon, so reject above the cap (fail-closed → null).
const MAX_LOG_TREE_SIZE = 0x7fffffff;

/**
 * A transparency-log checkpoint that was witnessed and recorded BEFORE any CRQC.
 * This is the trust anchor: its authenticity rests on having been pinned while
 * the log's Ed25519 signature was still trustworthy, NOT on re-verifying that
 * signature at verification time.
 */
export interface PinnedCheckpoint {
  /** The log's C2SP checkpoint origin string; matched against `InclBlock.log_id`. */
  origin: string;
  /** Tree size the pinned root commits to. */
  size: number;
  /** Base64 SHA-256 Merkle root of the pinned tree. */
  rootHashB64: string;
  /**
   * Strict ISO 8601 instant at which this checkpoint was witnessed (pinned).
   * Returned as the quantum-trustworthy upper bound on inclusion time for any
   * receipt proven to be in this tree. MUST be a genuine pre-CRQC observation.
   */
  witnessedAt: string;
}

/** Options for {@link makeInclusionProofEffectiveTime}. */
export interface InclusionProofEffectiveTimeOptions {
  /**
   * Pre-CRQC-witnessed checkpoints. The trust anchors. An empty list means the
   * resolver can never prove a pre-cutover bound and always returns `null`
   * (caller then fails toward rejection).
   */
  pinnedCheckpoints: readonly PinnedCheckpoint[];
  /**
   * Extract the transparency-log inclusion block from a receipt envelope. The
   * envelope shape is consumer-owned, so the mapping lives with the consumer;
   * return `null`/`undefined` when the receipt carries no inclusion block.
   */
  extractInclusion: (envelope: unknown) => InclBlock | null | undefined;
}

function hexOf(selfDescribing: string): Buffer {
  const [, hex] = selfDescribing.split(":");
  return Buffer.from(hex ?? "", "hex");
}

function isStrictIso8601(s: string): boolean {
  if (!ISO_8601_RE.test(s)) return false;
  return !Number.isNaN(Date.parse(s));
}

function largestPowerOfTwoSmallerThan(n: number): number {
  // Float doubling (not `<<= 1`): the 32-bit shift wraps to negative at 2³¹ and
  // would loop forever for large `n`. Callers also cap `n` at MAX_LOG_TREE_SIZE.
  let k = 1;
  while (k < n) k *= 2;
  return k / 2;
}

/**
 * The exact RFC 6962 audit-path length for leaf `index` in a tree of `treeSize`.
 * Mirrors the recursion of `tree.ts`'s `auditPath` (each split adds one sibling),
 * so a proof whose `path.length` differs is structurally malformed and must be
 * rejected. This closes the empty-/short-path hole in `verifyInclusionProof`,
 * which checks `fn === 0 && hash === root` without validating path completeness.
 */
function auditPathLength(index: number, treeSize: number): number {
  if (treeSize <= 1) return 0;
  const k = largestPowerOfTwoSmallerThan(treeSize);
  return index < k
    ? auditPathLength(index, k) + 1
    : auditPathLength(index - k, treeSize - k) + 1;
}

/**
 * Build a `resolveEffectiveTime` callback that returns a quantum-trustworthy
 * upper bound on a receipt's log-inclusion time, sourced from a pinned-checkpoint
 * store + hash-based Merkle inclusion. Drop it into `makeVerifyIssuerPqc`:
 *
 *   const verifyIssuerPqc = makeVerifyIssuerPqc({
 *     resolveEffectiveTime: makeInclusionProofEffectiveTime({
 *       pinnedCheckpoints,           // pre-CRQC witnessed snapshots
 *       extractInclusion: (env) => (env as MyReceipt).incl ?? null,
 *     }),
 *   });
 *
 * Returns `null` (→ caller's `now()` fallback → fail-toward-rejection) whenever a
 * quantum-trustworthy bound cannot be established: no inclusion block, a
 * promise-only block, a malformed leaf/path, or no pinned checkpoint whose tree
 * the audit path reconstructs. When several pins validate, the EARLIEST
 * `witnessedAt` is returned — the tightest sound bound, most favorable to a
 * legitimate pre-cutover receipt while never understating real inclusion time.
 *
 * Never throws: any structural anomaly resolves to `null`.
 */
export function makeInclusionProofEffectiveTime(
  opts: InclusionProofEffectiveTimeOptions,
): (envelope: unknown) => Date | null {
  const pins = opts.pinnedCheckpoints;
  return (envelope: unknown): Date | null => {
    try {
      const incl = opts.extractInclusion(envelope);
      // Proof-only. A promise is an Ed25519 SCT — forgeable under CRQC; refuse it
      // so the caller fails toward rejection rather than trusting its timestamp.
      const proof = incl?.proof;
      if (!incl || !proof) return null;

      const leaf = incl.leaf;
      if (typeof leaf !== "string" || !SHA256_SELF_DESCRIBING.test(leaf)) return null;

      // LEAF BINDING — the proof must be about THIS receipt. Recompute the
      // family-canonical leaf (JCS over receipt \ {incl}) and require a match;
      // never trust the attacker-suppliable `incl.leaf` on its own.
      if (typeof envelope !== "object" || envelope === null) return null;
      if (leaf !== leafHash(envelope as Record<string, unknown>)) return null;

      if (!Number.isInteger(proof.index) || proof.index < 0) return null;
      if (!Number.isInteger(proof.tree_size) || proof.tree_size <= 0) return null;
      if (proof.tree_size > MAX_LOG_TREE_SIZE) return null; // also bounds index (< tree_size)
      if (proof.index >= proof.tree_size) return null;
      if (
        !Array.isArray(proof.path) ||
        proof.path.some((e) => typeof e !== "string" || !SHA256_SELF_DESCRIBING.test(e))
      ) {
        return null;
      }
      // AUDIT-PATH COMPLETENESS — a short/empty path must never validate.
      if (proof.path.length !== auditPathLength(proof.index, proof.tree_size)) return null;

      const leafBytes = hexOf(leaf);
      const pathBytes = proof.path.map(hexOf);

      let best: number | null = null;
      for (const pin of pins) {
        // The proof's audit path only reconstructs the tree it was issued
        // against, so a pin can match only at the proof's own tree size.
        if (pin.origin !== incl.log_id) continue;
        if (pin.size !== proof.tree_size) continue;
        if (!isStrictIso8601(pin.witnessedAt)) continue;

        const pinRoot = Buffer.from(pin.rootHashB64, "base64");
        // Verify against the PINNED root — never the proof's embedded (forgeable)
        // checkpoint signature. Hash-based reconstruction is quantum-safe.
        if (!verifyInclusionProof(leafBytes, proof.index, pin.size, pathBytes, pinRoot)) {
          continue;
        }
        const t = Date.parse(pin.witnessedAt);
        if (best === null || t < best) best = t;
      }

      return best === null ? null : new Date(best);
    } catch {
      // Fail toward rejection on any unexpected shape.
      return null;
    }
  };
}
