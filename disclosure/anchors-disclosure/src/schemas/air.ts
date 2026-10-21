import type { DisclosureSchema } from "../types.ts";

/** Disclosure schema for Anchored Impact-Assessment Receipts (AIR) v2 bodies.
 *
 *  v0 leaf set = the always-present, all-scalar metadata fields. AIR's
 *  `baseBodyCommon()` puts `air_receipt_id`, `processing_activity_id` (and a
 *  present `qts_attestation_hash`) plus `event_type` on every one of the eleven
 *  event_type bodies, so each declared pointer resolves on every event. Unlike
 *  ANR/ABR/ALR, AIR carries no `profile` in the body (it is an envelope-level
 *  concern), so it is not a leaf. Event-specific fields (hashes, ids, *_receipt_ids)
 *  are null on some events, so they are deferred to a v1 schema.
 *
 *  field_root on a disclosable AIR receipt commits ONLY these leaves; the
 *  envelope signature still ranges over the full body, so every other field
 *  stays issuer-authenticated (design §2). The issuer controls this set (L19). */
export const AIR_DISCLOSURE_SCHEMA: DisclosureSchema = {
  claim_type: "ar.impact.v1",
  leaves: [
    { path: "/air_receipt_id" },
    { path: "/processing_activity_id" },
    { path: "/event_type" },
  ],
};
