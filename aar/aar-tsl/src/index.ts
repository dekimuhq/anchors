/**
 * @dekimuhq/aar-tsl — EU Trust List snapshot tooling for AAR.
 */

// Types
export type {
  TslServiceEntry,
  TslLeaf,
  TslSnapshot,
  TslProofBundle,
  TreeHead,
  NationalTslPointer,
} from "./types.ts";
export { SERVICE_TYPE_URI_MAP } from "./types.ts";

// Snapshot orchestrator
export { buildTslSnapshot, buildSnapshotFromEntries, getProofBundle } from "./snapshot.ts";

// Proof verification
export { verifyTslInclusionProof } from "./verify-proof.ts";

// Parsing
export { parseTsl } from "./parse-tsl.ts";
export { parseLotl, fetchLotl } from "./fetch-lotl.ts";
export { fetchNational } from "./fetch-national.ts";

// Canonicalization
export { hashEntry } from "./canonicalize.ts";

// Merkle primitives
export { buildTree, inclusionProof, verifyInclusion } from "./merkle.ts";
export type { MerkleTree } from "./merkle.ts";

// ── Remote convenience ───────────────────────────────────────────────────────

import type { TslProofBundle } from "./types.ts";

/**
 * Fetch a TslProofBundle from a remote verify.dekimu.com instance.
 *
 * Hits the /aar/v1/tsl_snapshots/lookup endpoint with query params.
 * The server finds the matching leaf, generates the inclusion proof,
 * and returns the ready-to-embed bundle.
 */
export async function fetchProofBundle(
  baseUrl: string,
  country: string,
  serviceTypeIdentifier: string,
  certificateHash: string,
): Promise<TslProofBundle | null> {
  const params = new URLSearchParams({
    country,
    service_type_identifier: serviceTypeIdentifier,
    cert_hash: certificateHash,
  });
  const url = `${baseUrl}/aar/v1/tsl_snapshots/lookup?${params}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`fetchProofBundle: HTTP ${res.status}`);
  return res.json() as Promise<TslProofBundle>;
}
