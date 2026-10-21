/**
 * ALR opt-in disclosable mint (Tier A flat-family migration).
 *
 * Additive sibling to `mintAlrV2`. Produces a receipt whose `field_root` is the
 * per-field Merkle tree over the ALR DisclosureSchema (not the flat whole-body
 * root), plus an issuer-signed `ar.field_commit.v1` and the 32-byte holder seed.
 * The holder later builds `ar.disclosure.v1` presentations with
 * `@dekimuhq/anchors-disclosure`. Shipped/flat receipts and `mintAlrV2` callers
 * are untouched.
 *
 * Implementation: mint normally (full validation, body assembly, status-list
 * attach, signature), then rebuild `field_root` from the per-field tree, swap it
 * into the body, and re-sign. `field_root` is inside the signed body, so a
 * re-sign is required. This keeps a single source of truth for validation and
 * body assembly. TSA is rejected in v0 — re-signing would invalidate a timestamp
 * taken over the flat-root body.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope (§2, L21/L22)
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
  ALR_DISCLOSURE_SCHEMA,
} from "@dekimuhq/anchors-disclosure";
import { mintAlrV2, type MintAlrV2Input } from "./mint-v2.ts";

export interface DisclosableMintResult {
  /** The anchored receipt, with `field_root` = per-field disclosure tree root. */
  receipt: Envelope;
  /** Issuer-signed binding of {id, field_root, leaf_count, iss_key}. */
  fieldCommit: FieldCommitAttestation;
  /** 32-byte holder secret. Derives every leaf salt via HKDF. Deliver once; never publish. */
  seed: Uint8Array;
}

export async function mintAlrV2Disclosable(
  input: MintAlrV2Input,
): Promise<DisclosableMintResult> {
  if (input.tsa !== undefined) {
    throw new Error(
      "mintAlrV2Disclosable: TSA + disclosable mint not supported in Tier A v0 (re-signing would invalidate the timestamp)",
    );
  }

  // 1. Mint normally — full validation, body assembly, status-list attach, signature.
  const flat = await mintAlrV2(input);

  // 2. Rebuild field_root from the per-field disclosure tree over the body
  //    (minus the flat field_root the normal mint embedded).
  const seed = new Uint8Array(randomBytes(32));
  const { field_root: _flatRoot, ...bodyNoRoot } = flat.body as Record<string, unknown>;
  const { field_root, leaves } = buildFieldTree(
    bodyNoRoot,
    ALR_DISCLOSURE_SCHEMA,
    seedSaltSource(seed),
  );

  // 3. Swap the disclosure field_root into the body and re-sign (field_root is signed).
  const { privateKey } = keyObjectFromSeed(input.signingKey.privateKey);
  const reSigned = await signEnvelope(
    { ...flat, body: { ...bodyNoRoot, field_root }, sig: "" },
    privateKey,
  );

  // 4. Emit the issuer-signed field_commit (L24: leaf_count is signed in).
  const fieldCommit = issueFieldCommit(
    {
      family: "alr",
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
