/**
 * Tests for the breach.nis2.art23 profile validator (ABR §5.3).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BREACH_NIS2_ART23_PROFILE_ID,
  validateBreachNis2Art23,
  validateBreachNis2Art23Profile,
} from "../src/nis2-art23.ts";
import { detected, dpaNotified } from "./_helpers/bodies.ts";

test("nis2: dpa_notified with notification_phase=early_warning passes", () => {
  const out = validateBreachNis2Art23(
    dpaNotified(BREACH_NIS2_ART23_PROFILE_ID, {
      notification_phase: "early_warning",
    }),
  );
  assert.deepEqual(out.errors, []);
});

test("nis2: dpa_notified with notification_phase=full_notification passes", () => {
  const out = validateBreachNis2Art23(
    dpaNotified(BREACH_NIS2_ART23_PROFILE_ID, {
      notification_phase: "full_notification",
    }),
  );
  assert.deepEqual(out.errors, []);
});

test("nis2: dpa_notified with notification_phase=final_report passes", () => {
  const out = validateBreachNis2Art23(
    dpaNotified(BREACH_NIS2_ART23_PROFILE_ID, {
      notification_phase: "final_report",
    }),
  );
  assert.deepEqual(out.errors, []);
});

test("nis2: dpa_notified with notification_phase=null rejected", () => {
  const out = validateBreachNis2Art23(
    dpaNotified(BREACH_NIS2_ART23_PROFILE_ID),
  );
  assert.deepEqual(out.errors, [
    "breach.nis2.art23.notification_phase.missing",
  ]);
});

test("nis2: detected passes regardless of jurisdiction shape (Art33-only invariant)", () => {
  const out = validateBreachNis2Art23(
    detected(BREACH_NIS2_ART23_PROFILE_ID, { jurisdiction: "lower" }),
  );
  assert.deepEqual(out.errors, []);
});

test("nis2: profile mismatch short-circuits", () => {
  const out = validateBreachNis2Art23(
    dpaNotified("breach.gdpr.art33", { notification_phase: "early_warning" }),
  );
  assert.deepEqual(out.errors, ["breach.nis2.art23.profile.mismatch"]);
});

test("nis2: empty incident_correlation_id flagged", () => {
  const out = validateBreachNis2Art23(
    dpaNotified(BREACH_NIS2_ART23_PROFILE_ID, {
      notification_phase: "final_report",
      incident_correlation_id: "",
    }),
  );
  // Even with valid phase, empty correlation id flags.
  assert.ok(
    out.errors.includes("breach.nis2.art23.incident_correlation_id.empty"),
  );
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("nis2 adapter: ok=true on valid 3-phase notification", () => {
  const out = validateBreachNis2Art23Profile(
    {} as never,
    dpaNotified(BREACH_NIS2_ART23_PROFILE_ID, {
      notification_phase: "full_notification",
    }),
    {},
  );
  assert.equal(out.profile_id, BREACH_NIS2_ART23_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("nis2 adapter: surfaces missing-phase on reject", () => {
  const out = validateBreachNis2Art23Profile(
    {} as never,
    dpaNotified(BREACH_NIS2_ART23_PROFILE_ID),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "breach.nis2.art23.notification_phase.missing");
});

test("nis2 adapter: profile mismatch surfaces correct reason", () => {
  const out = validateBreachNis2Art23Profile(
    {} as never,
    dpaNotified("breach.dora.art19"),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "breach.nis2.art23.profile.mismatch");
});
