/**
 * Assignability tests for the AQR v1 body union (spec §4).
 *
 * These are compile-time guarantees surfaced as runtime smoke checks: a valid
 * `quality.output` body and a valid `quality.release` body must each be
 * assignable to `AQRBody`. `npx tsc --noEmit` is the real gate; the runtime
 * asserts keep the test runner honest.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AQRBody, AQROutputBody, AQRReleaseBody } from "../src/body.ts";

const H = (c: string): string => `sha256:${c.repeat(64)}`;

test("B1: a valid quality.output body is assignable to AQRBody", () => {
  const output: AQROutputBody = {
    profile: "quality.output",
    suite_id: "regression-v3",
    suite_hash: H("a"),
    scorer: { kind: "deterministic" },
    result: {
      score: 0.95,
      verdict: "pass",
      threshold: 0.9,
      cases_total: 100,
      cases_passed: 95,
    },
    ran_at: "2026-06-19T10:00:00.000Z",
    output_commit: H("b"),
  };
  const body: AQRBody = output;
  assert.equal(body.profile, "quality.output");
});

test("B2: a valid quality.release body is assignable to AQRBody", () => {
  const release: AQRReleaseBody = {
    profile: "quality.release",
    suite_id: "release-gate",
    suite_hash: H("c"),
    scorer: { kind: "llm-judge", model: "claude-opus-4-8" },
    result: {
      score: 0.8,
      verdict: "warn",
      threshold: 0.85,
      cases_total: 50,
      cases_passed: 40,
    },
    ran_at: "2026-06-19T11:00:00.000Z",
    subject_ref: "agent@2.1.0",
    gate: "blocking",
  };
  const body: AQRBody = release;
  assert.equal(body.profile, "quality.release");
});
