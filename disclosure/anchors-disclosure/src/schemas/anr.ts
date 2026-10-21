import type { DisclosureSchema } from "../types.ts";

/** Disclosure schema for Anchored Notice Receipts (ANR) v2 bodies.
 *
 *  v0 leaf set = the always-present, all-scalar metadata fields. ANR's
 *  `buildBody()` sets every event-union field explicitly (value or null), so
 *  each declared pointer resolves on every event_type — including
 *  `notice.translated`, where `jurisdiction` is null (the key is still
 *  present). Array fields (rights_surface, layer_uris, joint_controllers) are
 *  null on some events, so `array:true` leaves are deferred to a v1 schema.
 *
 *  field_root on a disclosable ANR receipt commits ONLY these leaves; the
 *  envelope signature still ranges over the full body, so every other field
 *  stays issuer-authenticated (design §2). The issuer controls this set (L19). */
export const ANR_DISCLOSURE_SCHEMA: DisclosureSchema = {
  claim_type: "ar.notice.v1",
  leaves: [
    { path: "/profile" },
    { path: "/lang_tag" },
    { path: "/event_type" },
    { path: "/jurisdiction" },
  ],
};
