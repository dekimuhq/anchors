/**
 * Tests for the breach.gdpr.art34 profile validator (ABR §5.2).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BREACH_GDPR_ART34_PROFILE_ID,
  validateBreachGdprArt34,
  validateBreachGdprArt34Profile,
} from "../src/gdpr-art34.ts";
import { detected, dpaNotified, subjectNotified } from "./_helpers/bodies.ts";

test("art34: subject_notified with batch_size>0 passes", () => {
  const out = validateBreachGdprArt34(
    subjectNotified(BREACH_GDPR_ART34_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art34: subject_notified with batch_size=0 rejected", () => {
  const out = validateBreachGdprArt34(
    subjectNotified(BREACH_GDPR_ART34_PROFILE_ID, { subject_batch_size: 0 }),
  );
  assert.ok(
    out.errors.includes("breach.gdpr.art34.subject_batch_size.non_positive"),
  );
});

test("art34: subject_notified with negative batch_size rejected", () => {
  const out = validateBreachGdprArt34(
    subjectNotified(BREACH_GDPR_ART34_PROFILE_ID, { subject_batch_size: -1 }),
  );
  assert.ok(
    out.errors.includes("breach.gdpr.art34.subject_batch_size.non_positive"),
  );
});

test("art34: dpa_notified with notification_phase=null passes", () => {
  const out = validateBreachGdprArt34(
    dpaNotified(BREACH_GDPR_ART34_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("art34: dpa_notified with notification_phase=final_report rejected (NIS2 territory)", () => {
  const out = validateBreachGdprArt34(
    dpaNotified(BREACH_GDPR_ART34_PROFILE_ID, {
      notification_phase: "final_report",
    }),
  );
  assert.ok(
    out.errors.includes("breach.gdpr.art34.notification_phase.must_be_null"),
  );
});

test("art34: detected event under art34 passes (composition via correlation id)", () => {
  // Spec §5.2 — detected/assessed are typically under art33, but art34 doesn't
  // forbid them. Profile validator stays permissive.
  const out = validateBreachGdprArt34(detected(BREACH_GDPR_ART34_PROFILE_ID));
  assert.deepEqual(out.errors, []);
});

test("art34: profile mismatch short-circuits", () => {
  const out = validateBreachGdprArt34(
    subjectNotified("breach.gdpr.art33"),
  );
  assert.deepEqual(out.errors, ["breach.gdpr.art34.profile.mismatch"]);
});

test("art34: empty incident_correlation_id flagged", () => {
  const out = validateBreachGdprArt34(
    subjectNotified(BREACH_GDPR_ART34_PROFILE_ID, {
      incident_correlation_id: "",
    }),
  );
  assert.ok(
    out.errors.includes("breach.gdpr.art34.incident_correlation_id.empty"),
  );
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("art34 adapter: ok=true on valid", () => {
  const out = validateBreachGdprArt34Profile(
    {} as never,
    subjectNotified(BREACH_GDPR_ART34_PROFILE_ID),
    {},
  );
  assert.equal(out.profile_id, BREACH_GDPR_ART34_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("art34 adapter: surfaces first error on reject", () => {
  const out = validateBreachGdprArt34Profile(
    {} as never,
    subjectNotified(BREACH_GDPR_ART34_PROFILE_ID, { subject_batch_size: 0 }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "breach.gdpr.art34.subject_batch_size.non_positive");
});

test("art34 adapter: profile mismatch surfaces correct reason", () => {
  const out = validateBreachGdprArt34Profile(
    {} as never,
    detected("breach.gdpr.art33"),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "breach.gdpr.art34.profile.mismatch");
});
