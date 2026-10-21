/**
 * Tests for the aiact.art12 profile validator (EU AI Act Article 12 record-keeping).
 * Spec: https://github.com/dekimuhq/anchors-spec/blob/main/action/aiact-art12-mapping.md
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validateAiactArt12,
  validateAiactArt12Profile,
  AIACT_ART12_PROFILE_ID,
} from "../src/aiact-art12.ts";
import type { AActRBody, AActRArt12 } from "../src/body.ts";

const H = (c: string): string => `sha256:${c.repeat(64)}`;

function validArt12(): AActRArt12 {
  return {
    system_id: "hub-operator-agent",
    system_version: "2026.06.0",
    period_start: "2026-06-20T10:00:00.000Z",
  };
}

function validBody(overrides: Partial<AActRBody> = {}): AActRBody {
  return {
    profile: "aiact.art12",
    verb: "operator.remind",
    rule_id: "r1",
    recipe_id: "auto-remind-overdue",
    outcome: "executed",
    executed_at: "2026-06-20T10:00:00.000Z",
    decision_commit: H("a"),
    params_commit: H("b"),
    request_id_commit: H("c"),
    aiact_art12: validArt12(),
    ...overrides,
  };
}

test("A1: valid art12 body → no errors", () => {
  assert.deepEqual(validateAiactArt12(validBody()).errors, []);
});

test("A2: wrong profile → wrong_profile", () => {
  const b = validBody({ profile: "hub.automation" });
  assert.ok(validateAiactArt12(b).errors.includes("aiact.art12.wrong_profile"));
});

test("A3: missing aiact_art12 field → field_missing", () => {
  const b = validBody();
  delete (b as { aiact_art12?: AActRArt12 }).aiact_art12;
  assert.ok(validateAiactArt12(b).errors.includes("aiact.art12.field_missing"));
});

test("A4: field_missing short-circuits (no system_id_missing noise)", () => {
  const b = validBody();
  delete (b as { aiact_art12?: AActRArt12 }).aiact_art12;
  const errs = validateAiactArt12(b).errors;
  assert.ok(!errs.includes("aiact.art12.system_id_missing"));
});

test("A5: missing system_id → system_id_missing", () => {
  const b = validBody({ aiact_art12: { ...validArt12(), system_id: "" } });
  assert.ok(validateAiactArt12(b).errors.includes("aiact.art12.system_id_missing"));
});

test("A6: missing system_version → system_version_missing", () => {
  const b = validBody({ aiact_art12: { ...validArt12(), system_version: "" } });
  assert.ok(
    validateAiactArt12(b).errors.includes("aiact.art12.system_version_missing"),
  );
});

test("A7: malformed period_start → period_start_invalid", () => {
  const b = validBody({ aiact_art12: { ...validArt12(), period_start: "2026-06-20" } });
  assert.ok(validateAiactArt12(b).errors.includes("aiact.art12.period_start_invalid"));
});

test("A8: impossible date (month 13) → period_start_invalid", () => {
  const b = validBody({
    aiact_art12: { ...validArt12(), period_start: "2026-13-01T00:00:00Z" },
  });
  assert.ok(validateAiactArt12(b).errors.includes("aiact.art12.period_start_invalid"));
});

test("A9: valid period_end accepted", () => {
  const b = validBody({
    aiact_art12: { ...validArt12(), period_end: "2026-06-20T12:00:00.000Z" },
  });
  assert.deepEqual(validateAiactArt12(b).errors, []);
});

test("A10: malformed period_end → period_end_invalid", () => {
  const b = validBody({ aiact_art12: { ...validArt12(), period_end: "later" } });
  assert.ok(validateAiactArt12(b).errors.includes("aiact.art12.period_end_invalid"));
});

test("A11: period_end before period_start → period_end_before_start", () => {
  const b = validBody({
    aiact_art12: {
      ...validArt12(),
      period_start: "2026-06-20T12:00:00.000Z",
      period_end: "2026-06-20T10:00:00.000Z",
    },
  });
  assert.ok(
    validateAiactArt12(b).errors.includes("aiact.art12.period_end_before_start"),
  );
});

test("A12: period_end equal to period_start is allowed", () => {
  const b = validBody({
    aiact_art12: {
      ...validArt12(),
      period_start: "2026-06-20T10:00:00.000Z",
      period_end: "2026-06-20T10:00:00.000Z",
    },
  });
  assert.deepEqual(validateAiactArt12(b).errors, []);
});

test("A13: ordering is offset-safe (end Z vs start +02:00, same instant)", () => {
  // 12:00+02:00 == 10:00Z — equal instants, must NOT flag before_start.
  const b = validBody({
    aiact_art12: {
      ...validArt12(),
      period_start: "2026-06-20T12:00:00+02:00",
      period_end: "2026-06-20T10:00:00Z",
    },
  });
  assert.ok(
    !validateAiactArt12(b).errors.includes("aiact.art12.period_end_before_start"),
  );
});

test("A14: risk_event none/risk_flagged/substantial_modification accepted", () => {
  for (const ev of ["none", "risk_flagged", "substantial_modification"] as const) {
    const b = validBody({ aiact_art12: { ...validArt12(), risk_event: ev } });
    assert.deepEqual(validateAiactArt12(b).errors, [], `risk_event=${ev}`);
  }
});

test("A15: unknown risk_event → risk_event_invalid", () => {
  const b = validBody({
    aiact_art12: { ...validArt12(), risk_event: "boom" as never },
  });
  assert.ok(validateAiactArt12(b).errors.includes("aiact.art12.risk_event_invalid"));
});

test("A16: valid oversight_ref accepted", () => {
  const b = validBody({ aiact_art12: { ...validArt12(), oversight_ref: H("d") } });
  assert.deepEqual(validateAiactArt12(b).errors, []);
});

test("A17: malformed oversight_ref → oversight_ref_malformed", () => {
  const b = validBody({ aiact_art12: { ...validArt12(), oversight_ref: "nope" } });
  assert.ok(
    validateAiactArt12(b).errors.includes("aiact.art12.oversight_ref_malformed"),
  );
});

test("A18: oversight_ref uppercase hex → oversight_ref_malformed", () => {
  const b = validBody({ aiact_art12: { ...validArt12(), oversight_ref: H("A") } });
  assert.ok(
    validateAiactArt12(b).errors.includes("aiact.art12.oversight_ref_malformed"),
  );
});

test("A19: missing verb → verb_missing", () => {
  const b = validBody({ verb: "" });
  assert.ok(validateAiactArt12(b).errors.includes("aiact.art12.verb_missing"));
});

test("A20: malformed verb → verb_malformed", () => {
  const b = validBody({ verb: "drafReminder" });
  assert.ok(validateAiactArt12(b).errors.includes("aiact.art12.verb_malformed"));
});

test("A20a: kebab-case op segment is accepted (real verb operator.draft-reminder)", () => {
  const b = validBody({ verb: "operator.draft-reminder" });
  assert.ok(!validateAiactArt12(b).errors.includes("aiact.art12.verb_malformed"));
});

test("A20b: leading/trailing/double hyphen → verb_malformed", () => {
  for (const verb of ["operator.-reminder", "operator.reminder-", "operator.draft--reminder"]) {
    const b = validBody({ verb });
    assert.ok(
      validateAiactArt12(b).errors.includes("aiact.art12.verb_malformed"),
      `expected verb_malformed for ${verb}`,
    );
  }
});

test("A21: multiple errors are collected", () => {
  const b = validBody({
    profile: "hub.automation",
    verb: "",
    aiact_art12: { ...validArt12(), system_id: "", period_start: "x" },
  });
  assert.ok(validateAiactArt12(b).errors.length >= 3);
});

test("A22: profile id constant is aiact.art12", () => {
  assert.equal(AIACT_ART12_PROFILE_ID, "aiact.art12");
});

test("A23: adapter returns profile_id + ok=true for a valid body", () => {
  const r = validateAiactArt12Profile(null as never, validBody(), {} as never);
  assert.equal(r.profile_id, "aiact.art12");
  assert.equal(r.ok, true);
});

test("A24: adapter returns ok=false + reason for an invalid body", () => {
  const bad = validBody({ aiact_art12: { ...validArt12(), system_id: "" } });
  const r = validateAiactArt12Profile(null as never, bad, {} as never);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "aiact.art12.system_id_missing");
});

test("A25: a fully valid body passes the adapter with no reason field", () => {
  const r = validateAiactArt12Profile(null as never, validBody(), {} as never);
  assert.equal(r.ok, true);
  assert.equal("reason" in r, false);
});
