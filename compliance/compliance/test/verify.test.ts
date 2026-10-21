import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyComplianceBundleBody } from "../src/verify-single.ts";
import type { ComplianceBundleBody } from "../src/types.ts";

const SHA = "sha256:" + "a".repeat(64);

function validBody(): ComplianceBundleBody {
  return {
    profile: "compliance.bundle",
    workspaceId: "ws_1",
    controller: { entityName: "Acme SL", registeredAddress: null, contactEmail: null },
    regulation: { manifestId: "gdpr", manifestVersion: "1.2.0", manifestHash: SHA },
    coverage: { applicable: 8, satisfied: 8, ratio: 1 },
    constituents: {
      ropa: { ref: "ropa:" + "b".repeat(64), contentHash: SHA, satisfiedObligations: ["gdpr.records"] },
      dpia: { status: "not_applicable", reason: "no high-risk processing", basis: "engine:gdpr.dpia=not-applicable" },
      obligations: { ref: "report", contentHash: SHA, satisfiedObligations: [] },
    },
    generated_at: "2026-06-20T10:00:00Z",
  };
}

test("valid bundle body passes", () => {
  const r = verifyComplianceBundleBody(validBody());
  assert.equal(r.valid, true, r.errors.join(","));
});

test("bad coverage ratio fails", () => {
  const b = validBody(); b.coverage.ratio = 2;
  assert.equal(verifyComplianceBundleBody(b).valid, false);
});

test("ropa gap declaration is accepted", () => {
  const b = validBody(); b.constituents.ropa = { status: "gap", reason: "RoPA not generated" };
  assert.equal(verifyComplianceBundleBody(b).valid, true);
});

test("dpia as AIR ref array is accepted", () => {
  const b = validBody();
  b.constituents.dpia = [{ ref: "claim_air1", contentHash: SHA, claimType: "ar.impact.v1", satisfiedObligations: ["gdpr.dpia"] }];
  assert.equal(verifyComplianceBundleBody(b).valid, true);
});

test("satisfied exceeding applicable fails (coverage consistency)", () => {
  const b = validBody(); b.coverage = { applicable: 8, satisfied: 99, ratio: 1 };
  const r = verifyComplianceBundleBody(b);
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("coverage.satisfied_exceeds_applicable"), r.errors.join(","));
});

test("non-object body fails", () => {
  assert.equal(verifyComplianceBundleBody(null).valid, false);
});
