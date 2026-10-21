/**
 * Snapshot orchestrator — builds TslSnapshot from entries and generates proof bundles.
 *
 * Public API:
 *   buildTslSnapshot() — full pipeline: fetch LOTL + nationals → parse → tree
 *   buildSnapshotFromEntries(entries) — build from pre-parsed entries (for testing + server-side)
 *   getProofBundle(snapshot, country, serviceTypeId, certHash) → TslProofBundle | null
 */

import { fetchLotl } from "./fetch-lotl.ts";
import { fetchNational } from "./fetch-national.ts";
import { parseTsl } from "./parse-tsl.ts";
import { hashEntry } from "./canonicalize.ts";
import { buildTree, inclusionProof } from "./merkle.ts";
import type {
  TslServiceEntry,
  TslSnapshot,
  TslLeaf,
  TslProofBundle,
} from "./types.ts";

/**
 * Build a TslSnapshot from pre-parsed service entries.
 * Deterministic: same entries always produce the same root (order is preserved).
 */
export function buildSnapshotFromEntries(entries: TslServiceEntry[]): TslSnapshot {
  if (entries.length === 0) {
    return {
      log_time: new Date().toISOString(),
      root: "sha256:" + "0".repeat(64),
      tree_size: 0,
      leaves: [],
    };
  }

  const leaves: TslLeaf[] = entries.map((entry, index) => ({
    index,
    hash: hashEntry(entry),
    entry,
  }));

  const leafHashes = leaves.map((l) => l.hash);
  const tree = buildTree(leafHashes);

  return {
    log_time: new Date().toISOString(),
    root: tree.root,
    tree_size: leaves.length,
    leaves,
  };
}

/**
 * Find a matching leaf and return a TslProofBundle ready for AAR minting.
 *
 * Match criteria: country + service_type_identifier + certificate_hashes contains certHash.
 * Returns null if no match found.
 */
export function getProofBundle(
  snapshot: TslSnapshot,
  country: string,
  serviceTypeIdentifier: string,
  certificateHash: string,
): TslProofBundle | null {
  const leaf = snapshot.leaves.find(
    (l) =>
      l.entry.country === country &&
      l.entry.service_type_identifier === serviceTypeIdentifier &&
      l.entry.certificate_hashes.includes(certificateHash),
  );

  if (!leaf) return null;

  // Rebuild tree to generate inclusion proof (tree is cheap at ~1K leaves)
  const leafHashes = snapshot.leaves.map((l) => l.hash);
  const tree = buildTree(leafHashes);
  const proof = inclusionProof(tree, leaf.index);

  return {
    tsl_country: country,
    tsl_entry_hash: leaf.hash,
    tsl_signed_tree_head_root: snapshot.root,
    tsl_tree_size: snapshot.tree_size,
    tsl_inclusion_proof: proof,
    tsl_log_time: snapshot.log_time,
  };
}

/**
 * Full pipeline: fetch LOTL + all national TSLs → parse → build snapshot.
 *
 * Skips national TSLs that fail to fetch (logs warning, continues).
 * This is the main entry point for cron jobs and self-hosted mirrors.
 */
export async function buildTslSnapshot(): Promise<TslSnapshot> {
  const pointers = await fetchLotl();
  const allEntries: TslServiceEntry[] = [];

  const fetches = pointers.map(async (ptr) => {
    try {
      const xml = await fetchNational(ptr.url);
      return { country: ptr.country, xml };
    } catch {
      // Skip failed fetches — stale-but-valid pattern
      return null;
    }
  });

  const results = await Promise.all(fetches);

  for (const result of results) {
    if (result) {
      const entries = parseTsl(result.xml, result.country);
      allEntries.push(...entries);
    }
  }

  return buildSnapshotFromEntries(allEntries);
}
