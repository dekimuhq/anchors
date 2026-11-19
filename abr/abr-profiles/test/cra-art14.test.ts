/**
 * Tests for the breach.cra.art14 profile validator.
 *
 * Hook: Regulation (EU) 2024/2847 (Cyber Resilience Act) Art. 14(2)/(4) —
 * manufacturer reporting of actively exploited vulnerabilities and severe
 * incidents (early warning 24h, notification 72h, final report).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BREACH_CRA_ART14_PROFILE_ID,
  validateBreachCraArt14,
  validateBreachCraArt14Profile,
} from "../src/cra-art14.ts";
import { assessed, detected, dpaNotified } from "./_helpers/bodies.ts";

test("cra: profile id is breach.cra.art14", () => {
  assert.equal(BREACH_CRA_ART14_PROFILE_ID, "breach.cra.art14");
});

for (const phase of ["early_warning", "full_notification", "final_report"] as const) {
  test(`cra: dpa_notified with notification_phase=${phase} passes`, () => {
    const out = validateBreachCraArt14(
      dpaNotified(BREACH_CRA_ART14_PROFILE_ID, { notification_phase: phase }),
    );
    assert.deepEqual(out.errors, []);
  });
}

test("cra: dpa_notified with notification_phase=null rejected", () => {
  const out = validateBreachCraArt14(dpaNotified(BREACH_CRA_ART14_PROFILE_ID));
  assert.deepEqual(out.errors, ["breach.cra.art14.notification_phase.missing"]);
});

test("cra: detected and assessed pass", () => {
  assert.deepEqual(validateBreachCraArt14(detected(BREACH_CRA_ART14_PROFILE_ID)).errors, []);
  assert.deepEqual(validateBreachCraArt14(assessed(BREACH_CRA_ART14_PROFILE_ID)).errors, []);
});

test("cra: profile mismatch short-circuits", () => {
  const out = validateBreachCraArt14(
    dpaNotified("breach.nis2.art23", { notification_phase: "early_warning" }),
  );
  assert.deepEqual(out.errors, ["breach.cra.art14.profile.mismatch"]);
});

test("cra: empty incident_correlation_id flagged", () => {
  const out = validateBreachCraArt14(
    dpaNotified(BREACH_CRA_ART14_PROFILE_ID, {
      notification_phase: "final_report",
      incident_correlation_id: "",
    }),
  );
  assert.deepEqual(out.errors, ["breach.cra.art14.incident_correlation_id.empty"]);
});

test("cra adapter: ok=true on valid phased notification", () => {
  const out = validateBreachCraArt14Profile(
    {} as never,
    dpaNotified(BREACH_CRA_ART14_PROFILE_ID, { notification_phase: "early_warning" }),
    {},
  );
  assert.equal(out.profile_id, BREACH_CRA_ART14_PROFILE_ID);
  assert.equal(out.ok, true);
});

test("cra adapter: surfaces missing-phase on reject", () => {
  const out = validateBreachCraArt14Profile(
    {} as never,
    dpaNotified(BREACH_CRA_ART14_PROFILE_ID),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "breach.cra.art14.notification_phase.missing");
});

test("cra adapter: profile mismatch surfaces correct reason", () => {
  const out = validateBreachCraArt14Profile({} as never, dpaNotified("breach.dora.art19"), {});
  assert.equal(out.ok, false);
  assert.equal(out.reason, "breach.cra.art14.profile.mismatch");
});
