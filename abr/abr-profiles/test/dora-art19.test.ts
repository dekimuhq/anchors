/**
 * Tests for the breach.dora.art19 profile validator (ABR §5.4).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BREACH_DORA_ART19_PROFILE_ID,
  validateBreachDoraArt19,
  validateBreachDoraArt19Profile,
} from "../src/dora-art19.ts";
import { detected, dpaNotified } from "./_helpers/bodies.ts";

test("dora: dpa_notified with notification_phase=null passes", () => {
  const out = validateBreachDoraArt19(
    dpaNotified(BREACH_DORA_ART19_PROFILE_ID),
  );
  assert.deepEqual(out.errors, []);
});

test("dora: dpa_notified with notification_phase=early_warning rejected (single-phase)", () => {
  const out = validateBreachDoraArt19(
    dpaNotified(BREACH_DORA_ART19_PROFILE_ID, {
      notification_phase: "early_warning",
    }),
  );
  assert.ok(
    out.errors.includes("breach.dora.art19.notification_phase.must_be_null"),
  );
});

test("dora: dpa_notified with notification_phase=full_notification rejected", () => {
  const out = validateBreachDoraArt19(
    dpaNotified(BREACH_DORA_ART19_PROFILE_ID, {
      notification_phase: "full_notification",
    }),
  );
  assert.ok(
    out.errors.includes("breach.dora.art19.notification_phase.must_be_null"),
  );
});

test("dora: detected passes regardless of jurisdiction shape (Art33-only invariant)", () => {
  const out = validateBreachDoraArt19(
    detected(BREACH_DORA_ART19_PROFILE_ID, { jurisdiction: "lower" }),
  );
  assert.deepEqual(out.errors, []);
});

test("dora: detected accepts the recommended QTS policy_oid via ctx (advisory hook)", () => {
  const out = validateBreachDoraArt19(detected(BREACH_DORA_ART19_PROFILE_ID), {
    tsa_state: "tsa_verified",
    tsa_policy_oid: "1.3.6.1.4.1.40128.1.1.0",
  });
  assert.deepEqual(out.errors, []);
});

test("dora: profile mismatch short-circuits", () => {
  const out = validateBreachDoraArt19(dpaNotified("breach.gdpr.art33"));
  assert.deepEqual(out.errors, ["breach.dora.art19.profile.mismatch"]);
});

test("dora: empty incident_correlation_id flagged", () => {
  const out = validateBreachDoraArt19(
    dpaNotified(BREACH_DORA_ART19_PROFILE_ID, {
      incident_correlation_id: "",
    }),
  );
  assert.ok(
    out.errors.includes("breach.dora.art19.incident_correlation_id.empty"),
  );
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("dora adapter: ok=true on valid single-phase notification", () => {
  const out = validateBreachDoraArt19Profile(
    {} as never,
    dpaNotified(BREACH_DORA_ART19_PROFILE_ID),
    {},
  );
  assert.equal(out.profile_id, BREACH_DORA_ART19_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("dora adapter: surfaces phase-must-be-null on reject", () => {
  const out = validateBreachDoraArt19Profile(
    {} as never,
    dpaNotified(BREACH_DORA_ART19_PROFILE_ID, {
      notification_phase: "early_warning",
    }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(
    out.reason,
    "breach.dora.art19.notification_phase.must_be_null",
  );
});

test("dora adapter: profile mismatch surfaces correct reason", () => {
  const out = validateBreachDoraArt19Profile(
    {} as never,
    detected("breach.nis2.art23"),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "breach.dora.art19.profile.mismatch");
});

test("dora adapter: forwards ctx tsa_policy_oid to pure validator (no error)", () => {
  const out = validateBreachDoraArt19Profile(
    {} as never,
    detected(BREACH_DORA_ART19_PROFILE_ID),
    { tsa_policy_oid: "1.3.6.1.4.1.40128.1.1.0", tsa_state: "tsa_verified" },
  );
  assert.equal(out.ok, true);
});
