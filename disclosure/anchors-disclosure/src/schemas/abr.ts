import type { DisclosureSchema } from "../types.ts";

/** Disclosure schema for Anchored Breach Receipts (ABR) v2 bodies.
 *
 *  v0 leaf set = the always-present, all-scalar metadata fields. ABR's
 *  `buildBody()` sets every event-union field explicitly (value or null), so
 *  each declared pointer resolves on every event_type — including
 *  `/jurisdiction`, which carries a value only on `breach.detected` and is
 *  present-as-null on every other event (the key is still present). Array
 *  fields (affected_data_categories, *_ids) are null on some events, so
 *  `array:true` leaves are deferred to a v1 schema.
 *
 *  field_root on a disclosable ABR receipt commits ONLY these leaves; the
 *  envelope signature still ranges over the full body, so every other field
 *  stays issuer-authenticated (design §2). The issuer controls this set (L19). */
export const ABR_DISCLOSURE_SCHEMA: DisclosureSchema = {
  claim_type: "ar.breach.v1",
  leaves: [
    { path: "/profile" },
    { path: "/incident_correlation_id" },
    { path: "/event_type" },
    { path: "/jurisdiction" },
  ],
};
