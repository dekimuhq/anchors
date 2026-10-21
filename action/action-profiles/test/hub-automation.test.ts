/**
 * Tests for the hub.automation profile validator (AActR spec §5).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validateHubAutomation,
  validateHubAutomationProfile,
  HUB_AUTOMATION_PROFILE_ID,
} from "../src/hub-automation.ts";
import type { AActRBody } from "../src/body.ts";

const H = (c: string): string => `sha256:${c.repeat(64)}`;

function validBody(): AActRBody {
  return {
    profile: "hub.automation",
    verb: "invoiceup.remind",
    rule_id: "r1",
    recipe_id: "auto-remind-overdue",
    outcome: "executed",
    executed_at: "2026-06-08T10:00:00.000Z",
    decision_commit: H("a"),
    params_commit: H("b"),
    request_id_commit: H("c"),
  };
}

test("P1: valid body → no errors", () => {
  assert.deepEqual(validateHubAutomation(validBody()).errors, []);
});

test("P2: wrong profile → wrong_profile", () => {
  const b = { ...validBody(), profile: "other" } as unknown as AActRBody;
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.wrong_profile"));
});

test("P3: missing verb → verb_missing", () => {
  const b = { ...validBody(), verb: "" };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.verb_missing"));
});

test("P4: verb with no namespace dot → verb_malformed", () => {
  const b = { ...validBody(), verb: "remind" };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.verb_malformed"));
});

test("P5: verb with uppercase → verb_malformed", () => {
  const b = { ...validBody(), verb: "InvoiceUp.Remind" };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.verb_malformed"));
});

test("P6: verb with spaces → verb_malformed", () => {
  const b = { ...validBody(), verb: "invoiceup remind" };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.verb_malformed"));
});

test("P7: verb with leading dot → verb_malformed", () => {
  const b = { ...validBody(), verb: ".remind" };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.verb_malformed"));
});

test("P8: verb with trailing dot → verb_malformed", () => {
  const b = { ...validBody(), verb: "invoiceup." };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.verb_malformed"));
});

test("P9: multi-segment verb (ns.sub.op) is accepted", () => {
  const b = { ...validBody(), verb: "hub.clients.notify" };
  assert.ok(!validateHubAutomation(b).errors.includes("hub.automation.verb_malformed"));
});

test("P10: alphanumeric verb segments are accepted", () => {
  const b = { ...validBody(), verb: "app2.op3" };
  assert.deepEqual(validateHubAutomation(b).errors, []);
});

test("P10a: kebab-case op segment is accepted (real verb operator.draft-reminder)", () => {
  const b = { ...validBody(), verb: "operator.draft-reminder" };
  assert.deepEqual(validateHubAutomation(b).errors, []);
});

test("P10b: leading/trailing/double hyphen → verb_malformed", () => {
  for (const verb of ["operator.-reminder", "operator.reminder-", "operator.draft--reminder", "-op.reminder"]) {
    const b = { ...validBody(), verb };
    assert.ok(
      validateHubAutomation(b).errors.includes("hub.automation.verb_malformed"),
      `expected verb_malformed for ${verb}`,
    );
  }
});

test("P11: invalid outcome → outcome_invalid", () => {
  const b = { ...validBody(), outcome: "pending" } as unknown as AActRBody;
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.outcome_invalid"));
});

test("P12: outcome executed accepted", () => {
  assert.deepEqual(validateHubAutomation({ ...validBody(), outcome: "executed" }).errors, []);
});

test("P13: outcome failed-gave-up accepted", () => {
  assert.deepEqual(
    validateHubAutomation({ ...validBody(), outcome: "failed-gave-up" }).errors,
    [],
  );
});

test("P14: missing rule_id → rule_id_missing", () => {
  const b = { ...validBody(), rule_id: "" };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.rule_id_missing"));
});

test("P15: missing recipe_id → recipe_id_missing", () => {
  const b = { ...validBody(), recipe_id: "" };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.recipe_id_missing"));
});

test("P16: missing executed_at → executed_at_missing", () => {
  const b = { ...validBody(), executed_at: "" };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.executed_at_missing"));
});

test("P17: malformed decision_commit → decision_commit_malformed", () => {
  const b = { ...validBody(), decision_commit: "nope" };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.decision_commit_malformed"));
});

test("P18: decision_commit wrong length → decision_commit_malformed", () => {
  const b = { ...validBody(), decision_commit: "sha256:abcd" };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.decision_commit_malformed"));
});

test("P19: decision_commit uppercase hex → decision_commit_malformed", () => {
  const b = { ...validBody(), decision_commit: H("A") };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.decision_commit_malformed"));
});

test("P20: malformed params_commit → params_commit_malformed", () => {
  const b = { ...validBody(), params_commit: "x" };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.params_commit_malformed"));
});

test("P21: malformed request_id_commit → request_id_commit_malformed", () => {
  const b = { ...validBody(), request_id_commit: "" };
  assert.ok(
    validateHubAutomation(b).errors.includes("hub.automation.request_id_commit_malformed"),
  );
});

test("P22: multiple errors are collected", () => {
  const b = { profile: "x", verb: "", outcome: "z" } as unknown as AActRBody;
  assert.ok(validateHubAutomation(b).errors.length >= 3);
});

test("P23: profile id constant is hub.automation", () => {
  assert.equal(HUB_AUTOMATION_PROFILE_ID, "hub.automation");
});

test("P24: adapter returns profile_id + ok=true for a valid body", () => {
  const r = validateHubAutomationProfile(null as never, validBody(), {} as never);
  assert.equal(r.profile_id, "hub.automation");
  assert.equal(r.ok, true);
});

test("P25: adapter returns ok=false + reason for an invalid body", () => {
  const bad = { ...validBody(), verb: "" };
  const r = validateHubAutomationProfile(null as never, bad, {} as never);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "hub.automation.verb_missing");
});

test("P26: numeric verb-only segment rejected (must start a segment, dot required)", () => {
  const b = { ...validBody(), verb: "123" };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.verb_malformed"));
});

test("P27: underscore in verb segment → verb_malformed (segments are alnum only)", () => {
  const b = { ...validBody(), verb: "invoice_up.remind" };
  assert.ok(validateHubAutomation(b).errors.includes("hub.automation.verb_malformed"));
});

test("P28: a fully valid body passes the adapter with no reason field", () => {
  const r = validateHubAutomationProfile(null as never, validBody(), {} as never);
  assert.equal(r.ok, true);
  assert.equal("reason" in r, false);
});
