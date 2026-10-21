/**
 * Tests for the breach.gdpr.art33 profile validator (ABR §5.1).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BREACH_GDPR_ART33_PROFILE_ID,
  validateBreachGdprArt33,
  validateBreachGdprArt33Profile,
} from "../src/gdpr-art33.ts";
import { detected, dpaNotified, subjectNotified } from "./_helpers/bodies.ts";

test("art33: detected with ISO 3166-1 alpha-2 jurisdiction passes", () => {
  const out = validateBreachGdprArt33(detected(BREACH_GDPR_ART33_PROFILE_ID));
  assert.deepEqual(out.errors, []);
});

test("art33: detected with EU jurisdiction (cross-border pre-LSA) passes", () => {
  const out = validateBreachGdprArt33(
    detected(BREACH_GDPR_ART33_PROFILE_ID, { jurisdiction: "EU" }),
  );
  assert.deepEqual(out.errors, []);
});

test("art33: detected with lowercase jurisdiction rejected", () => {
  const out = validateBreachGdprArt33(
    detected(BREACH_GDPR_ART33_PROFILE_ID, { jurisdiction: "de" }),
  );
  assert.ok(out.errors.includes("breach.gdpr.art33.jurisdiction.invalid"));
});

test("art33: detected with 3-letter jurisdiction rejected", () => {
  const out = validateBreachGdprArt33(
    detected(BREACH_GDPR_ART33_PROFILE_ID, { jurisdiction: "DEU" }),
  );
  assert.ok(out.errors.includes("breach.gdpr.art33.jurisdiction.invalid"));
});

test("art33: detected with empty jurisdiction rejected", () => {
  const out = validateBreachGdprArt33(
    detected(BREACH_GDPR_ART33_PROFILE_ID, { jurisdiction: "" }),
  );
  assert.ok(out.errors.includes("breach.gdpr.art33.jurisdiction.invalid"));
});

test("art33: detected with empty affected_data_categories rejected", () => {
  const out = validateBreachGdprArt33(
    detected(BREACH_GDPR_ART33_PROFILE_ID, { affected_data_categories: [] }),
  );
  assert.ok(
    out.errors.includes("breach.gdpr.art33.affected_data_categories.empty"),
  );
});

test("art33: detected can fail both jurisdiction AND categories simultaneously", () => {
  const out = validateBreachGdprArt33(
    detected(BREACH_GDPR_ART33_PROFILE_ID, {
      jurisdiction: "bad",
      affected_data_categories: [],
    }),
  );
  assert.equal(out.errors.length, 2);
});

test("art33: dpa_notified with notification_phase=null passes", () => {
  const out = validateBreachGdprArt33(
    dpaNotified(BREACH_GDPR_ART33_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art33: dpa_notified with notification_phase=early_warning rejected (NIS2 territory)", () => {
  const out = validateBreachGdprArt33(
    dpaNotified(BREACH_GDPR_ART33_PROFILE_ID, {
      notification_phase: "early_warning",
    }),
  );
  assert.ok(
    out.errors.includes("breach.gdpr.art33.notification_phase.must_be_null"),
  );
});

test("art33: subject_notified passes (no Art. 33-specific invariant)", () => {
  const out = validateBreachGdprArt33(
    subjectNotified(BREACH_GDPR_ART33_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art33: profile mismatch short-circuits", () => {
  const out = validateBreachGdprArt33(detected("breach.gdpr.art34"));
  assert.deepEqual(out.errors, ["breach.gdpr.art33.profile.mismatch"]);
});

test("art33: empty incident_correlation_id flagged", () => {
  const out = validateBreachGdprArt33(
    detected(BREACH_GDPR_ART33_PROFILE_ID, { incident_correlation_id: "" }),
  );
  assert.ok(
    out.errors.includes("breach.gdpr.art33.incident_correlation_id.empty"),
  );
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("art33 adapter: ok=true on valid", () => {
  const out = validateBreachGdprArt33Profile(
    {} as never,
    detected(BREACH_GDPR_ART33_PROFILE_ID),
    {},
  );
  assert.equal(out.profile_id, BREACH_GDPR_ART33_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("art33 adapter: surfaces first error on reject", () => {
  const out = validateBreachGdprArt33Profile(
    {} as never,
    detected(BREACH_GDPR_ART33_PROFILE_ID, {
      jurisdiction: "bad",
      affected_data_categories: [],
    }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "breach.gdpr.art33.jurisdiction.invalid");
});

test("art33 adapter: profile mismatch surfaces correct reason", () => {
  const out = validateBreachGdprArt33Profile(
    {} as never,
    detected("breach.nis2.art23"),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "breach.gdpr.art33.profile.mismatch");
});
