import {
  buildTree,
  inclusionProof,
  verifyInclusion,
  commit,
  base64UrlEncode,
  base64UrlDecode,
} from "@dekimuhq/anchors-envelope";

/**
 * Holder-side selective-disclosure "reveal bundle".
 *
 * A reveal bundle is the transportable half of the disclosure handshake: given a
 * committed receipt (whose `field_root` is a Merkle root over per-field
 * `commit(salt, value)` leaves — the legacy positional scheme shipped by ACR /
 * ARR / ALR), the holder opens a chosen subset of fields by shipping, per field,
 * the `(value, salt)` opening plus the Merkle inclusion path up to `field_root`.
 *
 * The scheme is byte-identical to the family issuer kits: the per-field leaf is
 * `commit(salt, value) = sha256(salt_bytes || value_utf8)` and inclusion is
 * RFC-6962 (`buildTree` / `inclusionProof` / `verifyInclusion` from
 * `@dekimuhq/anchors-envelope`). A bundle entry therefore verifies unchanged
 * under a family's own verifier (e.g. `@dekimuhq/acr`'s `verifyDisclosureProof`).
 */

/** One revealed field inside a bundle. `merkleProof` is the RFC-6962 path. */
export interface RevealBundleEntry {
  /** Resolved JSON-pointer-style path, e.g. "/purposes/0". */
  path: string;
  /** Plaintext value the holder is disclosing. */
  value: string;
  /** base64url salt used to commit the value. */
  salt: string;
  /** Merkle inclusion path (per-node `sha256:<hex>`) up to `field_root`. */
  merkleProof: string[];
  /** Leaf index of this field in the committed tree. */
  leaf_index: number;
}

/** A holder-produced reveal bundle for one receipt. */
export interface RevealBundle {
  kind: "ar.reveal.v1";
  /** The receipt claim id the reveal opens. */
  claimId: string;
  /** `sha256:<hex>` Merkle root the receipt committed (== body.field_root). */
  field_root: string;
  /** Total leaves in the committed field tree. */
  leaf_count: number;
  /** The opened fields. Withheld fields are absent entirely. */
  reveals: RevealBundleEntry[];
}

/**
 * The on-wire field layout of a committed receipt: the ordered per-field
 * commitments (the Merkle leaves, in the exact order the issuer hashed them)
 * plus the path label for each leaf index. Derived from the receipt body — it
 * carries no secrets, only the public commitments.
 */
export interface FieldLayout {
  field_root: string;
  /** On-wire commitments in leaf order (leaves of the `field_root` tree). */
  commitments: string[];
  /** Path label for each leaf index; same length/order as `commitments`. */
  paths: string[];
}

/**
 * Per-field opening material the holder persists at mint time: the plaintext
 * value and the salt used to commit it, keyed by path. This is the "salt
 * material" a holder needs to disclose — a salt alone cannot reconstruct the
 * committed value, so the value travels with it.
 */
export type FieldOpenings = Record<string, { value: string; salt: string }>;

export interface BuildRevealBundleInput {
  claimId: string;
  layout: FieldLayout;
  openings: FieldOpenings;
  /** Paths to reveal. Each must exist in `layout.paths` and `openings`. */
  reveal: string[];
}

/**
 * Build a reveal bundle. Each revealed field's opening is re-committed and
 * checked against the on-wire commitment before a proof is emitted — a bundle
 * can never carry an opening that does not reproduce the committed leaf.
 */
export function buildRevealBundle(input: BuildRevealBundleInput): RevealBundle {
  const { claimId, layout, openings, reveal } = input;
  if (layout.commitments.length !== layout.paths.length) {
    throw new Error("buildRevealBundle: layout commitments/paths length mismatch");
  }
  const tree = buildTree(layout.commitments);
  const reveals: RevealBundleEntry[] = reveal.map((path) => {
    const leaf_index = layout.paths.indexOf(path);
    if (leaf_index < 0) throw new Error(`buildRevealBundle: unknown path ${path}`);
    const opening = openings[path];
    if (!opening) throw new Error(`buildRevealBundle: no opening for ${path}`);
    const recomputed = commit(opening.salt, opening.value);
    if (recomputed !== layout.commitments[leaf_index]) {
      throw new Error(`buildRevealBundle: opening does not reproduce commitment for ${path}`);
    }
    return {
      path,
      value: opening.value,
      salt: opening.salt,
      merkleProof: inclusionProof(tree, leaf_index),
      leaf_index,
    };
  });
  return {
    kind: "ar.reveal.v1",
    claimId,
    field_root: layout.field_root,
    leaf_count: layout.commitments.length,
    reveals,
  };
}

export type VerifyBundleReason =
  | "malformed"
  | "leaf_commit_mismatch"
  | "merkle_path_invalid"
  | "field_root_mismatch"
  | "leaf_count_mismatch"
  | "path_unbound";

export interface VerifyBundleResult {
  valid: boolean;
  /** path -> value, populated only when valid. */
  revealed: Record<string, string>;
  reasons: VerifyBundleReason[];
}

/**
 * The trusted expectations a verifier MUST derive from the SIGNED receipt body
 * (never from the bundle itself) before admitting any reveal:
 *
 * - `expectedFieldRoot` — the receipt's committed `field_root`. A bundle whose
 *   self-declared root differs is rejected.
 * - `expectedLeafCount` — the arity of the committed field tree (`1 + purposes
 *   + 1` for ACR). A self-declared `leaf_count` feeding `verifyInclusion`
 *   unchecked is an RFC-6962 leaf-count / second-preimage ambiguity
 *   (CVE-2012-2459 class); binding it to the body closes that.
 * - `expectedPaths` — the canonical path for every leaf index, in tree order.
 *   Each reveal is rejected unless `path === expectedPaths[leaf_index]`, so an
 *   attacker-chosen `path` can never relabel a valid opening (e.g. present a
 *   `/purposes/0` opening as a `/sub` reveal).
 *
 * There is intentionally no "trust the bundle" mode — safe usage is the only
 * usage. Derive these with {@link acrFieldLayout} + {@link layoutExpectations}.
 */
export interface VerifyBundleExpectations {
  expectedFieldRoot: string;
  expectedLeafCount: number;
  expectedPaths: string[];
}

/** Derive the trusted verifier expectations from a signed-body field layout. */
export function layoutExpectations(layout: FieldLayout): VerifyBundleExpectations {
  return {
    expectedFieldRoot: layout.field_root,
    expectedLeafCount: layout.commitments.length,
    expectedPaths: layout.paths,
  };
}

// ── Input bounds (mirror the verify-side `?reveal=` handler caps) ──────────────
const SHA256_HEX = /^sha256:[0-9a-f]{64}$/;
const SALT_CHARSET = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_REVEALS = 32;
const MAX_MERKLE_PROOF_DEPTH = 24; // 2^24 leaves is far beyond any real field tree
const MAX_LEAF_COUNT = 100_000;
const MAX_VALUE_CHARS = 2_048;
const MAX_PATH_CHARS = 256;
const MAX_CLAIM_ID_CHARS = 512;

function isRevealEntryShape(r: unknown): r is RevealBundleEntry {
  if (r === null || typeof r !== "object") return false;
  const o = r as Record<string, unknown>;
  return (
    typeof o.path === "string" &&
    o.path.length >= 1 &&
    o.path.length <= MAX_PATH_CHARS &&
    typeof o.value === "string" &&
    o.value.length <= MAX_VALUE_CHARS &&
    typeof o.salt === "string" &&
    SALT_CHARSET.test(o.salt) &&
    Array.isArray(o.merkleProof) &&
    o.merkleProof.length <= MAX_MERKLE_PROOF_DEPTH &&
    o.merkleProof.every((p) => typeof p === "string" && SHA256_HEX.test(p)) &&
    Number.isInteger(o.leaf_index) &&
    (o.leaf_index as number) >= 0 &&
    (o.leaf_index as number) <= MAX_LEAF_COUNT
  );
}

function isBundleShape(b: unknown): b is RevealBundle {
  if (b === null || typeof b !== "object") return false;
  const o = b as Record<string, unknown>;
  return (
    o.kind === "ar.reveal.v1" &&
    typeof o.claimId === "string" &&
    o.claimId.length >= 1 &&
    o.claimId.length <= MAX_CLAIM_ID_CHARS &&
    typeof o.field_root === "string" &&
    SHA256_HEX.test(o.field_root) &&
    Number.isInteger(o.leaf_count) &&
    (o.leaf_count as number) >= 1 &&
    (o.leaf_count as number) <= MAX_LEAF_COUNT &&
    Array.isArray(o.reveals) &&
    o.reveals.length >= 1 &&
    o.reveals.length <= MAX_REVEALS &&
    o.reveals.every(isRevealEntryShape)
  );
}

/**
 * Verify a reveal bundle against expectations derived from the SIGNED receipt
 * body. Total function — never throws. Order of checks (fail-closed):
 *
 * 1. shape + input bounds (`isBundleShape`);
 * 2. `field_root` == `expectedFieldRoot`;
 * 3. `leaf_count` == `expectedLeafCount` (BEFORE any inclusion check — H2);
 * 4. per entry: `path` == `expectedPaths[leaf_index]` and index in range (H1);
 * 5. per entry: recompute leaf `commit(salt, value)` + RFC-6962 inclusion.
 */
export function verifyRevealBundle(
  bundle: RevealBundle,
  expected: VerifyBundleExpectations,
): VerifyBundleResult {
  const fail = (...reasons: VerifyBundleReason[]): VerifyBundleResult => ({
    valid: false,
    revealed: {},
    reasons,
  });
  try {
    if (!isBundleShape(bundle)) return fail("malformed");
    if (expected.expectedFieldRoot !== bundle.field_root) {
      return fail("field_root_mismatch");
    }
    if (expected.expectedLeafCount !== bundle.leaf_count) {
      return fail("leaf_count_mismatch");
    }
    const expectedDepth = Math.ceil(Math.log2(Math.max(2, bundle.leaf_count)));
    const revealed: Record<string, string> = {};
    for (const r of bundle.reveals) {
      // H1 — bind path to the canonical layout position; an attacker-chosen
      // `path` can never relabel a valid opening for a different field, and an
      // out-of-range `leaf_index` (past the signed arity) is rejected.
      if (
        r.leaf_index >= expected.expectedPaths.length ||
        r.path !== expected.expectedPaths[r.leaf_index]
      ) {
        return fail("path_unbound");
      }
      const leaf = commit(r.salt, r.value);
      const ok = verifyInclusion(
        leaf,
        r.merkleProof,
        r.leaf_index,
        bundle.leaf_count,
        bundle.field_root,
      );
      if (!ok) {
        return fail(
          r.merkleProof.length === expectedDepth
            ? "leaf_commit_mismatch"
            : "merkle_path_invalid",
        );
      }
      revealed[r.path] = r.value;
    }
    return { valid: true, revealed, reasons: [] };
  } catch {
    return fail("malformed");
  }
}

// ── URL-safe token codec ──────────────────────────────────────────────────────

/** Serialize a bundle to a compact base64url token (URL/query-safe, no padding). */
export function encodeRevealToken(bundle: RevealBundle): string {
  const json = JSON.stringify(bundle);
  return base64UrlEncode(new TextEncoder().encode(json));
}

/** Parse a base64url reveal token back into a bundle. Throws on malformed input. */
export function decodeRevealToken(token: string): RevealBundle {
  const bytes = base64UrlDecode(token);
  const json = new TextDecoder().decode(bytes);
  const parsed: unknown = JSON.parse(json);
  if (!isBundleShape(parsed)) throw new Error("decodeRevealToken: malformed bundle");
  return parsed;
}

// ── ACR family adapter ─────────────────────────────────────────────────────────

/** The commitment-carrying slice of an ACR v2 body. */
export interface AcrCommittedBody {
  sub_commit: string;
  purposes: string[];
  policy_hash: string;
  field_root: string;
}

/**
 * Build the field layout for an ACR receipt. Leaf order is the exact order the
 * ACR issuer kit hashes: `[sub_commit, ...purposes, policy_hash]`. Canonical
 * reveal paths are `/sub`, `/purposes/{i}`, `/policy`.
 */
export function acrFieldLayout(body: AcrCommittedBody): FieldLayout {
  const paths = ["/sub", ...body.purposes.map((_, i) => `/purposes/${i}`), "/policy"];
  const commitments = [body.sub_commit, ...body.purposes, body.policy_hash];
  return { field_root: body.field_root, commitments, paths };
}
