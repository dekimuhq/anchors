/**
 * Tests for the breach.us_state.attorney_general profile validator (ABR §5.5).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID,
  validateBreachUsStateAttorneyGeneral,
  validateBreachUsStateAttorneyGeneralProfile,
} from "../src/us-state-attorney-general.ts";
import { detected, dpaNotified } from "./_helpers/bodies.ts";

test("us-ag: dpa_notified with notification_phase=null passes", () => {
  const out = validateBreachUsStateAttorneyGeneral(
    dpaNotified(BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("us-ag: dpa_notified with notification_phase=early_warning rejected (single-phase)", () => {
  const out = validateBreachUsStateAttorneyGeneral(
    dpaNotified(BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID, {
      notification_phase: "early_warning",
    }),
  );
  assert.ok(
    out.errors.includes(
      "breach.us_state.attorney_general.notification_phase.must_be_null",
    ),
  );
});

test("us-ag: detected passes regardless of jurisdiction shape (Art33-only invariant)", () => {
  const out = validateBreachUsStateAttorneyGeneral(
    detected(BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID, {
      jurisdiction: "lower",
    }),
  );
  assert.deepEqual(out.errors, []);
});

test("us-ag: profile mismatch short-circuits", () => {
  const out = validateBreachUsStateAttorneyGeneral(
    dpaNotified("breach.gdpr.art33"),
  );
  assert.deepEqual(out.errors, [
    "breach.us_state.attorney_general.profile.mismatch",
  ]);
});

test("us-ag: empty incident_correlation_id flagged", () => {
  const out = validateBreachUsStateAttorneyGeneral(
    dpaNotified(BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID, {
      incident_correlation_id: "",
    }),
  );
  assert.ok(
    out.errors.includes(
      "breach.us_state.attorney_general.incident_correlation_id.empty",
    ),
  );
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("us-ag adapter: ok=true on valid", () => {
  const out = validateBreachUsStateAttorneyGeneralProfile(
    {} as never,
    dpaNotified(BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID),
    {},
  );
  assert.equal(out.profile_id, BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("us-ag adapter: surfaces phase-must-be-null on reject", () => {
  const out = validateBreachUsStateAttorneyGeneralProfile(
    {} as never,
    dpaNotified(BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID, {
      notification_phase: "full_notification",
    }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(
    out.reason,
    "breach.us_state.attorney_general.notification_phase.must_be_null",
  );
});

test("us-ag adapter: profile mismatch surfaces correct reason", () => {
  const out = validateBreachUsStateAttorneyGeneralProfile(
    {} as never,
    detected("breach.gdpr.art33"),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "breach.us_state.attorney_general.profile.mismatch");
});
