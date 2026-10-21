import { test } from "node:test";
import assert from "node:assert/strict";
import { verify30DayWindow } from "../src/index.ts";

test("erasure 5 days after withdrawal -> pass", () => {
  const out = verify30DayWindow({
    erasureEventAt: "2026-05-15T10:00:00Z",
    acrWithdrawalGrantedAt: "2026-05-10T10:00:00Z",
  });
  assert.equal(out.valid, true);
  assert.equal(out.daysElapsed, 5);
});

test("erasure exactly 30 days after withdrawal -> pass (boundary)", () => {
  const out = verify30DayWindow({
    erasureEventAt: "2026-06-09T10:00:00Z",
    acrWithdrawalGrantedAt: "2026-05-10T10:00:00Z",
  });
  assert.equal(out.valid, true);
  assert.equal(out.daysElapsed, 30);
});

test("erasure 31 days after withdrawal -> fail", () => {
  const out = verify30DayWindow({
    erasureEventAt: "2026-06-10T10:00:01Z",
    acrWithdrawalGrantedAt: "2026-05-10T10:00:00Z",
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("gdpr.art12.timeout"));
});

test("erasure before withdrawal -> invalid", () => {
  const out = verify30DayWindow({
    erasureEventAt: "2026-05-01T10:00:00Z",
    acrWithdrawalGrantedAt: "2026-05-10T10:00:00Z",
  });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("event_before_withdrawal"));
});
