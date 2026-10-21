import type { DisclosureSchema } from "../types.ts";

/** Disclosure schemas for Anchored Retention Receipts (ARR) v2 bodies.
 *
 *  ARR is special among the flat-`field_root` families: its native `field_root`
 *  is a flat SHA-256 over a fixed *subset* of body fields (not a per-field
 *  Merkle tree), and it has TWO body shapes minted by two entry points
 *  (`mintArrV2Single` over 5 single claim_types, `mintArrV2Batch` over
 *  `ar.batch.v1`). The disclosable mints discard ARR's subset-hash field_root
 *  and rebuild a per-field Merkle tree from the schema below — so the
 *  single/batch body split is the only real divergence, handled with two
 *  schemas.
 *
 *  `claim_type` on a DisclosureSchema is documentary only — `verifyPresentation`
 *  never enforces it — so `ARR_SINGLE_DISCLOSURE_SCHEMA` covers all five single
 *  kinds despite naming one representative claim_type.
 *
 *  v0 leaf sets = the always-present, all-scalar metadata fields on each body.
 *  field_root on a disclosable ARR receipt commits ONLY these leaves; the
 *  envelope signature still ranges over the full body, so every other field
 *  stays issuer-authenticated (design §2). The issuer controls these sets (L19). */

/** Single-target ARR (ar.erasure.v1 / ar.expiry.v1 / ar.hold.v1 /
 *  ar.anonymization.v1 / ar.archive.v1). `target_commit`, `salt_epoch`,
 *  `trigger_receipt`, `effective_until`, `state_snapshot` are deferred to a v1
 *  schema (commitments / object / present-as-null fields). */
export const ARR_SINGLE_DISCLOSURE_SCHEMA: DisclosureSchema = {
  claim_type: "ar.erasure.v1",
  leaves: [
    { path: "/profile" },
    { path: "/target_kind" },
    { path: "/trigger" },
    { path: "/event_at" },
  ],
};

/** Batch ARR (`ar.batch.v1`). `target_root`/`state_snapshot_root` (Merkle roots
 *  over per-target leaves) and `target_count` are deferred to a v1 schema. */
export const ARR_BATCH_DISCLOSURE_SCHEMA: DisclosureSchema = {
  claim_type: "ar.batch.v1",
  leaves: [
    { path: "/profile" },
    { path: "/batch_event_kind" },
    { path: "/target_kind" },
    { path: "/event_at" },
  ],
};
