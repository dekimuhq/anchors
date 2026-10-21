/**
 * ARR opt-in disclosable mints (Tier A flat-family migration).
 *
 * ARR is the special case: its native `field_root` is a flat SHA-256 over a
 * fixed *subset* of body fields (not a per-field tree), and it has two entry
 * points — `mintArrV2Single` (5 single claim_types) and `mintArrV2Batch`
 * (`ar.batch.v1`) — over two body shapes. So this module ships two sibling
 * mints, `mintArrV2SingleDisclosable` and `mintArrV2BatchDisclosable`, each
 * pairing with its own DisclosureSchema. The disclosable mints discard ARR's
 * subset-hash `field_root` and rebuild a per-field Merkle tree from the schema,
 * so the single/batch split is the only divergence from the ANR pattern.
 *
 * Implementation (per wrapper): mint normally (full validation, body assembly,
 * status-list attach, signature), then rebuild `field_root` from the per-field
 * tree, swap it into the body, and re-sign. `field_root` is inside the signed
 * body, so a re-sign is required. TSA is rejected in v0 — re-signing would
 * invalidate a timestamp taken over the flat-root body.
 *
 * One fresh holder seed per mint call. A batch is a single receipt with a single
 * field tree over its body (not per-target), so one-seed-per-call already gives
 * unlinkability across receipts (L20); no per-target seed is involved.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope (§2, L20/L21/L22)
 */
import { randomBytes } from "node:crypto";
import {
  keyObjectFromSeed,
  signEnvelope,
  issueFieldCommit,
  type Envelope,
  type FieldCommitAttestation,
} from "@dekimuhq/anchors-envelope";
import {
  buildFieldTree,
  seedSaltSource,
  ARR_SINGLE_DISCLOSURE_SCHEMA,
  ARR_BATCH_DISCLOSURE_SCHEMA,
  type DisclosureSchema,
} from "@dekimuhq/anchors-disclosure";
import { mintArrV2Single, mintArrV2Batch, type MintArrV2SingleInput, type MintArrV2BatchInput } from "./mint-v2.ts";

export interface DisclosableMintResult {
  /** The anchored receipt, with `field_root` = per-field disclosure tree root. */
  receipt: Envelope;
  /** Issuer-signed binding of {id, field_root, leaf_count, iss_key}. */
  fieldCommit: FieldCommitAttestation;
  /** 32-byte holder secret. Derives every leaf salt via HKDF. Deliver once; never publish. */
  seed: Uint8Array;
}

/** Shared re-sign + field_commit step over a freshly minted flat receipt. */
async function makeDisclosable(
  flat: Envelope,
  schema: DisclosureSchema,
  signingSeed: Uint8Array,
): Promise<DisclosableMintResult> {
  const seed = new Uint8Array(randomBytes(32));
  const { field_root: _flatRoot, ...bodyNoRoot } = flat.body as Record<string, unknown>;
  const { field_root, leaves } = buildFieldTree(bodyNoRoot, schema, seedSaltSource(seed));

  const { privateKey } = keyObjectFromSeed(signingSeed);
  const reSigned = await signEnvelope(
    { ...flat, body: { ...bodyNoRoot, field_root }, sig: "" },
    privateKey,
  );

  const fieldCommit = issueFieldCommit(
    {
      family: "arr",
      id: reSigned.id,
      field_root,
      leaf_count: leaves.length,
      iss_key: reSigned.iss_key,
      issued_at: reSigned.iat,
    },
    privateKey,
  );

  return { receipt: reSigned, fieldCommit, seed };
}

export async function mintArrV2SingleDisclosable(
  input: MintArrV2SingleInput,
): Promise<DisclosableMintResult> {
  if (input.tsa !== undefined) {
    throw new Error(
      "mintArrV2SingleDisclosable: TSA + disclosable mint not supported in Tier A v0 (re-signing would invalidate the timestamp)",
    );
  }
  const flat = await mintArrV2Single(input);
  return makeDisclosable(flat, ARR_SINGLE_DISCLOSURE_SCHEMA, input.signingKey.privateKey);
}

export async function mintArrV2BatchDisclosable(
  input: MintArrV2BatchInput,
): Promise<DisclosableMintResult> {
  if (input.tsa !== undefined) {
    throw new Error(
      "mintArrV2BatchDisclosable: TSA + disclosable mint not supported in Tier A v0 (re-signing would invalidate the timestamp)",
    );
  }
  const flat = await mintArrV2Batch(input);
  return makeDisclosable(flat, ARR_BATCH_DISCLOSURE_SCHEMA, input.signingKey.privateKey);
}
