/**
 * Tests for NIS2 Annex I sectoral sub-profiles (ABR §5.4–§5.7).
 *
 * Four profiles share the same structural invariants as breach.nis2.art23:
 *   - profile field match
 *   - non-empty incident_correlation_id
 *   - notification_phase non-null on breach.dpa_notified
 *
 * Each profile is tested independently with its own error codes.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  BREACH_NIS2_ANNEX1_ENERGY_PROFILE_ID,
  validateBreachNis2Annex1Energy,
  validateBreachNis2Annex1EnergyProfile,
} from "../src/nis2-energy.ts";
import {
  BREACH_NIS2_ANNEX1_TRANSPORT_PROFILE_ID,
  validateBreachNis2Annex1Transport,
  validateBreachNis2Annex1TransportProfile,
} from "../src/nis2-transport.ts";
import {
  BREACH_NIS2_ANNEX1_HEALTH_PROFILE_ID,
  validateBreachNis2Annex1Health,
  validateBreachNis2Annex1HealthProfile,
} from "../src/nis2-health.ts";
import {
  BREACH_NIS2_ANNEX1_DIGITAL_INFRASTRUCTURE_PROFILE_ID,
  validateBreachNis2Annex1DigitalInfrastructure,
  validateBreachNis2Annex1DigitalInfrastructureProfile,
} from "../src/nis2-digital-infrastructure.ts";
import { detected, dpaNotified } from "./_helpers/bodies.ts";

// ── energy ────────────────────────────────────────────────────────────────────

describe("breach.nis2.annex1.energy", () => {
  it("passes on breach.detected with correct profile", () => {
    const out = validateBreachNis2Annex1Energy(
      detected(BREACH_NIS2_ANNEX1_ENERGY_PROFILE_ID),
    );
    assert.deepEqual(out.errors, []);
  });

  it("passes on breach.dpa_notified with notification_phase=early_warning", () => {
    const out = validateBreachNis2Annex1Energy(
      dpaNotified(BREACH_NIS2_ANNEX1_ENERGY_PROFILE_ID, {
        notification_phase: "early_warning",
      }),
    );
    assert.deepEqual(out.errors, []);
  });

  it("passes on breach.dpa_notified with notification_phase=full_notification", () => {
    const out = validateBreachNis2Annex1Energy(
      dpaNotified(BREACH_NIS2_ANNEX1_ENERGY_PROFILE_ID, {
        notification_phase: "full_notification",
      }),
    );
    assert.deepEqual(out.errors, []);
  });

  it("passes on breach.dpa_notified with notification_phase=final_report", () => {
    const out = validateBreachNis2Annex1Energy(
      dpaNotified(BREACH_NIS2_ANNEX1_ENERGY_PROFILE_ID, {
        notification_phase: "final_report",
      }),
    );
    assert.deepEqual(out.errors, []);
  });

  it("rejects when profile mismatches — short-circuits", () => {
    const out = validateBreachNis2Annex1Energy(
      dpaNotified("breach.gdpr.art33", { notification_phase: "early_warning" }),
    );
    assert.deepEqual(out.errors, [
      "breach.nis2.annex1.energy.profile.mismatch",
    ]);
  });

  it("rejects empty incident_correlation_id", () => {
    const out = validateBreachNis2Annex1Energy(
      dpaNotified(BREACH_NIS2_ANNEX1_ENERGY_PROFILE_ID, {
        notification_phase: "final_report",
        incident_correlation_id: "",
      }),
    );
    assert.ok(
      out.errors.includes(
        "breach.nis2.annex1.energy.incident_correlation_id.empty",
      ),
    );
  });

  it("rejects breach.dpa_notified with notification_phase=null", () => {
    const out = validateBreachNis2Annex1Energy(
      dpaNotified(BREACH_NIS2_ANNEX1_ENERGY_PROFILE_ID),
    );
    assert.deepEqual(out.errors, [
      "breach.nis2.annex1.energy.notification_phase.missing",
    ]);
  });

  it("adapter: ok=true on valid notification", () => {
    const out = validateBreachNis2Annex1EnergyProfile(
      {} as never,
      dpaNotified(BREACH_NIS2_ANNEX1_ENERGY_PROFILE_ID, {
        notification_phase: "full_notification",
      }),
      {},
    );
    assert.equal(out.profile_id, BREACH_NIS2_ANNEX1_ENERGY_PROFILE_ID);
    assert.equal(out.ok, true);
    assert.equal(out.reason, undefined);
  });

  it("adapter: ok=false on missing notification_phase", () => {
    const out = validateBreachNis2Annex1EnergyProfile(
      {} as never,
      dpaNotified(BREACH_NIS2_ANNEX1_ENERGY_PROFILE_ID),
      {},
    );
    assert.equal(out.ok, false);
    assert.equal(
      out.reason,
      "breach.nis2.annex1.energy.notification_phase.missing",
    );
  });

  it("adapter: ok=false on profile mismatch", () => {
    const out = validateBreachNis2Annex1EnergyProfile(
      {} as never,
      dpaNotified("breach.dora.art19"),
      {},
    );
    assert.equal(out.ok, false);
    assert.equal(
      out.reason,
      "breach.nis2.annex1.energy.profile.mismatch",
    );
  });
});

// ── transport ─────────────────────────────────────────────────────────────────

describe("breach.nis2.annex1.transport", () => {
  it("passes on breach.detected with correct profile", () => {
    const out = validateBreachNis2Annex1Transport(
      detected(BREACH_NIS2_ANNEX1_TRANSPORT_PROFILE_ID),
    );
    assert.deepEqual(out.errors, []);
  });

  it("passes on breach.dpa_notified with notification_phase=early_warning", () => {
    const out = validateBreachNis2Annex1Transport(
      dpaNotified(BREACH_NIS2_ANNEX1_TRANSPORT_PROFILE_ID, {
        notification_phase: "early_warning",
      }),
    );
    assert.deepEqual(out.errors, []);
  });

  it("passes on breach.dpa_notified with notification_phase=full_notification", () => {
    const out = validateBreachNis2Annex1Transport(
      dpaNotified(BREACH_NIS2_ANNEX1_TRANSPORT_PROFILE_ID, {
        notification_phase: "full_notification",
      }),
    );
    assert.deepEqual(out.errors, []);
  });

  it("passes on breach.dpa_notified with notification_phase=final_report", () => {
    const out = validateBreachNis2Annex1Transport(
      dpaNotified(BREACH_NIS2_ANNEX1_TRANSPORT_PROFILE_ID, {
        notification_phase: "final_report",
      }),
    );
    assert.deepEqual(out.errors, []);
  });

  it("rejects when profile mismatches — short-circuits", () => {
    const out = validateBreachNis2Annex1Transport(
      dpaNotified("breach.gdpr.art33", { notification_phase: "early_warning" }),
    );
    assert.deepEqual(out.errors, [
      "breach.nis2.annex1.transport.profile.mismatch",
    ]);
  });

  it("rejects empty incident_correlation_id", () => {
    const out = validateBreachNis2Annex1Transport(
      dpaNotified(BREACH_NIS2_ANNEX1_TRANSPORT_PROFILE_ID, {
        notification_phase: "final_report",
        incident_correlation_id: "",
      }),
    );
    assert.ok(
      out.errors.includes(
        "breach.nis2.annex1.transport.incident_correlation_id.empty",
      ),
    );
  });

  it("rejects breach.dpa_notified with notification_phase=null", () => {
    const out = validateBreachNis2Annex1Transport(
      dpaNotified(BREACH_NIS2_ANNEX1_TRANSPORT_PROFILE_ID),
    );
    assert.deepEqual(out.errors, [
      "breach.nis2.annex1.transport.notification_phase.missing",
    ]);
  });

  it("adapter: ok=true on valid notification", () => {
    const out = validateBreachNis2Annex1TransportProfile(
      {} as never,
      dpaNotified(BREACH_NIS2_ANNEX1_TRANSPORT_PROFILE_ID, {
        notification_phase: "full_notification",
      }),
      {},
    );
    assert.equal(out.profile_id, BREACH_NIS2_ANNEX1_TRANSPORT_PROFILE_ID);
    assert.equal(out.ok, true);
    assert.equal(out.reason, undefined);
  });

  it("adapter: ok=false on missing notification_phase", () => {
    const out = validateBreachNis2Annex1TransportProfile(
      {} as never,
      dpaNotified(BREACH_NIS2_ANNEX1_TRANSPORT_PROFILE_ID),
      {},
    );
    assert.equal(out.ok, false);
    assert.equal(
      out.reason,
      "breach.nis2.annex1.transport.notification_phase.missing",
    );
  });

  it("adapter: ok=false on profile mismatch", () => {
    const out = validateBreachNis2Annex1TransportProfile(
      {} as never,
      dpaNotified("breach.dora.art19"),
      {},
    );
    assert.equal(out.ok, false);
    assert.equal(
      out.reason,
      "breach.nis2.annex1.transport.profile.mismatch",
    );
  });
});

// ── health ────────────────────────────────────────────────────────────────────

describe("breach.nis2.annex1.health", () => {
  it("passes on breach.detected with correct profile", () => {
    const out = validateBreachNis2Annex1Health(
      detected(BREACH_NIS2_ANNEX1_HEALTH_PROFILE_ID),
    );
    assert.deepEqual(out.errors, []);
  });

  it("passes on breach.dpa_notified with notification_phase=early_warning", () => {
    const out = validateBreachNis2Annex1Health(
      dpaNotified(BREACH_NIS2_ANNEX1_HEALTH_PROFILE_ID, {
        notification_phase: "early_warning",
      }),
    );
    assert.deepEqual(out.errors, []);
  });

  it("passes on breach.dpa_notified with notification_phase=full_notification", () => {
    const out = validateBreachNis2Annex1Health(
      dpaNotified(BREACH_NIS2_ANNEX1_HEALTH_PROFILE_ID, {
        notification_phase: "full_notification",
      }),
    );
    assert.deepEqual(out.errors, []);
  });

  it("passes on breach.dpa_notified with notification_phase=final_report", () => {
    const out = validateBreachNis2Annex1Health(
      dpaNotified(BREACH_NIS2_ANNEX1_HEALTH_PROFILE_ID, {
        notification_phase: "final_report",
      }),
    );
    assert.deepEqual(out.errors, []);
  });

  it("rejects when profile mismatches — short-circuits", () => {
    const out = validateBreachNis2Annex1Health(
      dpaNotified("breach.gdpr.art33", { notification_phase: "early_warning" }),
    );
    assert.deepEqual(out.errors, [
      "breach.nis2.annex1.health.profile.mismatch",
    ]);
  });

  it("rejects empty incident_correlation_id", () => {
    const out = validateBreachNis2Annex1Health(
      dpaNotified(BREACH_NIS2_ANNEX1_HEALTH_PROFILE_ID, {
        notification_phase: "final_report",
        incident_correlation_id: "",
      }),
    );
    assert.ok(
      out.errors.includes(
        "breach.nis2.annex1.health.incident_correlation_id.empty",
      ),
    );
  });

  it("rejects breach.dpa_notified with notification_phase=null", () => {
    const out = validateBreachNis2Annex1Health(
      dpaNotified(BREACH_NIS2_ANNEX1_HEALTH_PROFILE_ID),
    );
    assert.deepEqual(out.errors, [
      "breach.nis2.annex1.health.notification_phase.missing",
    ]);
  });

  it("adapter: ok=true on valid notification", () => {
    const out = validateBreachNis2Annex1HealthProfile(
      {} as never,
      dpaNotified(BREACH_NIS2_ANNEX1_HEALTH_PROFILE_ID, {
        notification_phase: "full_notification",
      }),
      {},
    );
    assert.equal(out.profile_id, BREACH_NIS2_ANNEX1_HEALTH_PROFILE_ID);
    assert.equal(out.ok, true);
    assert.equal(out.reason, undefined);
  });

  it("adapter: ok=false on missing notification_phase", () => {
    const out = validateBreachNis2Annex1HealthProfile(
      {} as never,
      dpaNotified(BREACH_NIS2_ANNEX1_HEALTH_PROFILE_ID),
      {},
    );
    assert.equal(out.ok, false);
    assert.equal(
      out.reason,
      "breach.nis2.annex1.health.notification_phase.missing",
    );
  });

  it("adapter: ok=false on profile mismatch", () => {
    const out = validateBreachNis2Annex1HealthProfile(
      {} as never,
      dpaNotified("breach.dora.art19"),
      {},
    );
    assert.equal(out.ok, false);
    assert.equal(
      out.reason,
      "breach.nis2.annex1.health.profile.mismatch",
    );
  });
});

// ── digital_infrastructure ────────────────────────────────────────────────────

describe("breach.nis2.annex1.digital_infrastructure", () => {
  it("passes on breach.detected with correct profile", () => {
    const out = validateBreachNis2Annex1DigitalInfrastructure(
      detected(BREACH_NIS2_ANNEX1_DIGITAL_INFRASTRUCTURE_PROFILE_ID),
    );
    assert.deepEqual(out.errors, []);
  });

  it("passes on breach.dpa_notified with notification_phase=early_warning", () => {
    const out = validateBreachNis2Annex1DigitalInfrastructure(
      dpaNotified(BREACH_NIS2_ANNEX1_DIGITAL_INFRASTRUCTURE_PROFILE_ID, {
        notification_phase: "early_warning",
      }),
    );
    assert.deepEqual(out.errors, []);
  });

  it("passes on breach.dpa_notified with notification_phase=full_notification", () => {
    const out = validateBreachNis2Annex1DigitalInfrastructure(
      dpaNotified(BREACH_NIS2_ANNEX1_DIGITAL_INFRASTRUCTURE_PROFILE_ID, {
        notification_phase: "full_notification",
      }),
    );
    assert.deepEqual(out.errors, []);
  });

  it("passes on breach.dpa_notified with notification_phase=final_report", () => {
    const out = validateBreachNis2Annex1DigitalInfrastructure(
      dpaNotified(BREACH_NIS2_ANNEX1_DIGITAL_INFRASTRUCTURE_PROFILE_ID, {
        notification_phase: "final_report",
      }),
    );
    assert.deepEqual(out.errors, []);
  });

  it("rejects when profile mismatches — short-circuits", () => {
    const out = validateBreachNis2Annex1DigitalInfrastructure(
      dpaNotified("breach.gdpr.art33", { notification_phase: "early_warning" }),
    );
    assert.deepEqual(out.errors, [
      "breach.nis2.annex1.digital_infrastructure.profile.mismatch",
    ]);
  });

  it("rejects empty incident_correlation_id", () => {
    const out = validateBreachNis2Annex1DigitalInfrastructure(
      dpaNotified(BREACH_NIS2_ANNEX1_DIGITAL_INFRASTRUCTURE_PROFILE_ID, {
        notification_phase: "final_report",
        incident_correlation_id: "",
      }),
    );
    assert.ok(
      out.errors.includes(
        "breach.nis2.annex1.digital_infrastructure.incident_correlation_id.empty",
      ),
    );
  });

  it("rejects breach.dpa_notified with notification_phase=null", () => {
    const out = validateBreachNis2Annex1DigitalInfrastructure(
      dpaNotified(BREACH_NIS2_ANNEX1_DIGITAL_INFRASTRUCTURE_PROFILE_ID),
    );
    assert.deepEqual(out.errors, [
      "breach.nis2.annex1.digital_infrastructure.notification_phase.missing",
    ]);
  });

  it("adapter: ok=true on valid notification", () => {
    const out = validateBreachNis2Annex1DigitalInfrastructureProfile(
      {} as never,
      dpaNotified(BREACH_NIS2_ANNEX1_DIGITAL_INFRASTRUCTURE_PROFILE_ID, {
        notification_phase: "full_notification",
      }),
      {},
    );
    assert.equal(
      out.profile_id,
      BREACH_NIS2_ANNEX1_DIGITAL_INFRASTRUCTURE_PROFILE_ID,
    );
    assert.equal(out.ok, true);
    assert.equal(out.reason, undefined);
  });

  it("adapter: ok=false on missing notification_phase", () => {
    const out = validateBreachNis2Annex1DigitalInfrastructureProfile(
      {} as never,
      dpaNotified(BREACH_NIS2_ANNEX1_DIGITAL_INFRASTRUCTURE_PROFILE_ID),
      {},
    );
    assert.equal(out.ok, false);
    assert.equal(
      out.reason,
      "breach.nis2.annex1.digital_infrastructure.notification_phase.missing",
    );
  });

  it("adapter: ok=false on profile mismatch", () => {
    const out = validateBreachNis2Annex1DigitalInfrastructureProfile(
      {} as never,
      dpaNotified("breach.dora.art19"),
      {},
    );
    assert.equal(out.ok, false);
    assert.equal(
      out.reason,
      "breach.nis2.annex1.digital_infrastructure.profile.mismatch",
    );
  });
});
