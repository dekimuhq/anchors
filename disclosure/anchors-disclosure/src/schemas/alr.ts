import type { DisclosureSchema } from "../types.ts";

/** Disclosure schema for Anchored Lineage Receipts (ALR) v2 bodies.
 *
 *  v0 leaf set = the always-present, all-scalar metadata fields. ALR's
 *  `buildBody()` puts `profile`, `artifact_hash`, `event_at` (and a present
 *  `qts_attestation_hash`) on every one of the four event_type bodies, so each
 *  declared pointer resolves on every event. The event-specific fields
 *  (`parents`, `successor`, `transform_claim`, `disclosure`) are arrays/objects
 *  that are null on some events, so they are deferred to a v1 schema.
 *
 *  field_root on a disclosable ALR receipt commits ONLY these leaves; the
 *  envelope signature still ranges over the full body, so every other field
 *  stays issuer-authenticated (design §2). The issuer controls this set (L19). */
export const ALR_DISCLOSURE_SCHEMA: DisclosureSchema = {
  claim_type: "ar.lineage.v1",
  leaves: [
    { path: "/profile" },
    { path: "/artifact_hash" },
    { path: "/event_at" },
    { path: "/event_type" },
  ],
};
