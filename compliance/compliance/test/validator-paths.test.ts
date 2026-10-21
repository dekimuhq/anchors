/**
 * Exhaustive error-path coverage for `verifyComplianceBundleBody`.
 *
 * Written 2026-09-07 to re-apply the ≥99 family test floor to ACBR. The
 * exemption granted 2026-07-06 was conditional — "re-apply the floor at publish
 * time" — and `@dekimuhq/compliance` had already published on 2026-06-21, so its
 * stated premise ("publish is not yet scheduled") was false when written.
 *
 * This is NOT the APIIR case. APIIR stopped at 91 because it has no detection
 * engine of its own and padding would have been test-theater. ACBR's validator
 * has ~30 distinct error codes over a nested body, plus a mint path with five
 * guards, so the coverage below is genuine: every assertion names a branch that
 * exists in the source and fails if that branch is removed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyComplianceBundleBody } from "../src/verify-single.ts";
import type { ComplianceBundleBody } from "../src/types.ts";

const SHA = "sha256:" + "a".repeat(64);
const SHA_B = "sha256:" + "b".repeat(64);

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
      obligations: { ref: "report", contentHash: SHA_B, satisfiedObligations: [] },
    },
    generated_at: "2026-06-20T10:00:00Z",
  };
}

/** Mutate a clone through an escape hatch — these tests deliberately build invalid shapes. */
function broken(mutate: (b: Record<string, unknown>) => void): unknown {
  const b = JSON.parse(JSON.stringify(validBody())) as Record<string, unknown>;
  mutate(b);
  return b;
}

const errsOf = (body: unknown): string[] => verifyComplianceBundleBody(body).errors;
const isValid = (body: unknown): boolean => verifyComplianceBundleBody(body).valid;

// ---------------------------------------------------------------- body shape

test("null body is rejected as not_object", () => {
  assert.deepEqual(errsOf(null), ["body.not_object"]);
});

test("undefined body is rejected as not_object", () => {
  assert.deepEqual(errsOf(undefined), ["body.not_object"]);
});

test("a string body is rejected as not_object", () => {
  assert.deepEqual(errsOf("compliance.bundle"), ["body.not_object"]);
});

test("a number body is rejected as not_object", () => {
  assert.deepEqual(errsOf(42), ["body.not_object"]);
});

test("a boolean body is rejected as not_object", () => {
  assert.deepEqual(errsOf(true), ["body.not_object"]);
});

test("a not_object rejection returns a null body and stops at one error", () => {
  const r = verifyComplianceBundleBody(null);
  assert.equal(r.body, null);
  assert.equal(r.errors.length, 1);
});

test("an ARRAY body passes the typeof guard and fails on fields instead", () => {
  // typeof [] === "object" and [] !== null, so the guard lets it through.
  // Recording the real behaviour: it fails on missing fields, not body.not_object.
  const errs = errsOf([]);
  assert.ok(!errs.includes("body.not_object"), errs.join(","));
  assert.ok(errs.includes("profile.invalid"), errs.join(","));
});

// ------------------------------------------------------------------- profile

test("a valid bundle body passes with no errors", () => {
  const r = verifyComplianceBundleBody(validBody());
  assert.equal(r.valid, true, r.errors.join(","));
  assert.deepEqual(r.errors, []);
});

test("a valid body is returned on the result", () => {
  const r = verifyComplianceBundleBody(validBody());
  assert.equal(r.body?.profile, "compliance.bundle");
});

test("a missing profile is invalid", () => {
  assert.ok(errsOf(broken((b) => { delete b.profile; })).includes("profile.invalid"));
});

test("a wrong profile string is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.profile = "compliance.other"; })).includes("profile.invalid"));
});

test("a null profile is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.profile = null; })).includes("profile.invalid"));
});

test("a numeric profile is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.profile = 1; })).includes("profile.invalid"));
});

// --------------------------------------------------------------- workspaceId

test("a missing workspaceId is invalid", () => {
  assert.ok(errsOf(broken((b) => { delete b.workspaceId; })).includes("workspaceId.missing"));
});

test("an EMPTY workspaceId is invalid — isStr requires length", () => {
  assert.ok(errsOf(broken((b) => { b.workspaceId = ""; })).includes("workspaceId.missing"));
});

test("a numeric workspaceId is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.workspaceId = 7; })).includes("workspaceId.missing"));
});

test("a null workspaceId is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.workspaceId = null; })).includes("workspaceId.missing"));
});

// ---------------------------------------------------------------- controller

test("a non-object controller is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.controller = "Acme"; })).includes("controller.invalid"));
});

test("a null controller is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.controller = null; })).includes("controller.invalid"));
});

test("a controller missing entityName is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    b.controller = { registeredAddress: null, contactEmail: null };
  })).includes("controller.invalid"));
});

test("a controller with an EMPTY entityName is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    b.controller = { entityName: "", registeredAddress: null, contactEmail: null };
  })).includes("controller.invalid"));
});

test("a controller with a non-string entityName is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    b.controller = { entityName: 5, registeredAddress: null, contactEmail: null };
  })).includes("controller.invalid"));
});

test("registeredAddress may be a non-empty string", () => {
  assert.equal(isValid(broken((b) => {
    b.controller = { entityName: "Acme SL", registeredAddress: "Calle Falsa 1", contactEmail: null };
  })), true);
});

test("registeredAddress may be null", () => {
  assert.equal(isValid(broken((b) => {
    b.controller = { entityName: "Acme SL", registeredAddress: null, contactEmail: null };
  })), true);
});

test("an UNDEFINED registeredAddress is invalid — null is required, absence is not", () => {
  assert.ok(errsOf(broken((b) => {
    b.controller = { entityName: "Acme SL", contactEmail: null };
  })).includes("controller.invalid"));
});

test("an EMPTY registeredAddress string is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    b.controller = { entityName: "Acme SL", registeredAddress: "", contactEmail: null };
  })).includes("controller.invalid"));
});

test("contactEmail may be a non-empty string", () => {
  assert.equal(isValid(broken((b) => {
    b.controller = { entityName: "Acme SL", registeredAddress: null, contactEmail: "dpo@acme.example" };
  })), true);
});

test("an UNDEFINED contactEmail is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    b.controller = { entityName: "Acme SL", registeredAddress: null };
  })).includes("controller.invalid"));
});

test("an EMPTY contactEmail string is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    b.controller = { entityName: "Acme SL", registeredAddress: null, contactEmail: "" };
  })).includes("controller.invalid"));
});

// ---------------------------------------------------------------- regulation

test("a missing regulation block is invalid", () => {
  assert.ok(errsOf(broken((b) => { delete b.regulation; })).includes("regulation.missing"));
});

test("a null regulation block is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.regulation = null; })).includes("regulation.missing"));
});

test("a non-object regulation block is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.regulation = "gdpr"; })).includes("regulation.missing"));
});

test("a regulation block that is missing does NOT also emit field errors", () => {
  const errs = errsOf(broken((b) => { delete b.regulation; }));
  assert.ok(!errs.includes("regulation.manifestId"), errs.join(","));
});

test("a manifestId other than gdpr is invalid — this slice is GDPR-only", () => {
  assert.ok(errsOf(broken((b) => {
    (b.regulation as Record<string, unknown>).manifestId = "eprivacy";
  })).includes("regulation.manifestId"));
});

test("a missing manifestId is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    delete (b.regulation as Record<string, unknown>).manifestId;
  })).includes("regulation.manifestId"));
});

test("a missing manifestVersion is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    delete (b.regulation as Record<string, unknown>).manifestVersion;
  })).includes("regulation.manifestVersion"));
});

test("an empty manifestVersion is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.regulation as Record<string, unknown>).manifestVersion = "";
  })).includes("regulation.manifestVersion"));
});

test("a manifestHash without the sha256: prefix is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.regulation as Record<string, unknown>).manifestHash = "a".repeat(64);
  })).includes("regulation.manifestHash"));
});

test("a manifestHash that is too short is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.regulation as Record<string, unknown>).manifestHash = "sha256:" + "a".repeat(63);
  })).includes("regulation.manifestHash"));
});

test("a manifestHash that is too long is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.regulation as Record<string, unknown>).manifestHash = "sha256:" + "a".repeat(65);
  })).includes("regulation.manifestHash"));
});

test("an UPPERCASE-hex manifestHash is invalid — the regex is lowercase-only", () => {
  assert.ok(errsOf(broken((b) => {
    (b.regulation as Record<string, unknown>).manifestHash = "sha256:" + "A".repeat(64);
  })).includes("regulation.manifestHash"));
});

test("a non-hex manifestHash is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.regulation as Record<string, unknown>).manifestHash = "sha256:" + "g".repeat(64);
  })).includes("regulation.manifestHash"));
});

test("a sha512-prefixed hash is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.regulation as Record<string, unknown>).manifestHash = "sha512:" + "a".repeat(64);
  })).includes("regulation.manifestHash"));
});

// ------------------------------------------------------------------ coverage

test("a missing coverage block is invalid", () => {
  assert.ok(errsOf(broken((b) => { delete b.coverage; })).includes("coverage.missing"));
});

test("a null coverage block is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.coverage = null; })).includes("coverage.missing"));
});

test("a fractional applicable count is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.coverage as Record<string, unknown>).applicable = 8.5;
  })).includes("coverage.applicable"));
});

test("a negative applicable count is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.coverage as Record<string, unknown>).applicable = -1;
  })).includes("coverage.applicable"));
});

test("a non-numeric applicable count is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.coverage as Record<string, unknown>).applicable = "8";
  })).includes("coverage.applicable"));
});

test("a fractional satisfied count is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.coverage as Record<string, unknown>).satisfied = 1.5;
  })).includes("coverage.satisfied"));
});

test("a negative satisfied count is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.coverage as Record<string, unknown>).satisfied = -2;
  })).includes("coverage.satisfied"));
});

test("zero applicable and zero satisfied is valid", () => {
  assert.equal(isValid(broken((b) => {
    b.coverage = { applicable: 0, satisfied: 0, ratio: 0 };
  })), true);
});

test("a ratio above 1 is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.coverage as Record<string, unknown>).ratio = 1.01;
  })).includes("coverage.ratio"));
});

test("a negative ratio is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.coverage as Record<string, unknown>).ratio = -0.1;
  })).includes("coverage.ratio"));
});

test("a ratio of exactly 0 is valid", () => {
  assert.equal(isValid(broken((b) => {
    b.coverage = { applicable: 4, satisfied: 0, ratio: 0 };
  })), true);
});

test("a ratio of exactly 1 is valid", () => {
  assert.equal(isValid(broken((b) => {
    b.coverage = { applicable: 4, satisfied: 4, ratio: 1 };
  })), true);
});

test("a mid-range ratio is valid", () => {
  assert.equal(isValid(broken((b) => {
    b.coverage = { applicable: 4, satisfied: 2, ratio: 0.5 };
  })), true);
});

test("a non-numeric ratio is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.coverage as Record<string, unknown>).ratio = "1";
  })).includes("coverage.ratio"));
});

test("satisfied exceeding applicable is a consistency error, not a type error", () => {
  const errs = errsOf(broken((b) => {
    b.coverage = { applicable: 3, satisfied: 4, ratio: 1 };
  }));
  assert.ok(errs.includes("coverage.satisfied_exceeds_applicable"), errs.join(","));
  assert.ok(!errs.includes("coverage.satisfied"), errs.join(","));
});

test("satisfied EQUAL to applicable is not a consistency error", () => {
  const errs = errsOf(broken((b) => {
    b.coverage = { applicable: 3, satisfied: 3, ratio: 1 };
  }));
  assert.ok(!errs.includes("coverage.satisfied_exceeds_applicable"), errs.join(","));
});

test("the consistency check is SKIPPED when either count is already malformed", () => {
  // Guarded by isNonNegInt on both sides — a type error must not also produce
  // a misleading "exceeds" error about a value that is not a number.
  const errs = errsOf(broken((b) => {
    b.coverage = { applicable: "3", satisfied: 4, ratio: 1 };
  }));
  assert.ok(!errs.includes("coverage.satisfied_exceeds_applicable"), errs.join(","));
});

// -------------------------------------------------------------- constituents

test("a missing constituents block is invalid", () => {
  assert.ok(errsOf(broken((b) => { delete b.constituents; })).includes("constituents.missing"));
});

test("a null constituents block is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.constituents = null; })).includes("constituents.missing"));
});

// ropa
test("a ropa gap declaration is accepted in place of a ref", () => {
  assert.equal(isValid(broken((b) => {
    (b.constituents as Record<string, unknown>).ropa = { status: "gap", reason: "RoPA not generated" };
  })), true);
});

test("a ropa gap with an EMPTY reason falls through to ref validation and fails", () => {
  const errs = errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).ropa = { status: "gap", reason: "" };
  }));
  assert.ok(errs.includes("constituents.ropa.ref"), errs.join(","));
});

test("a ropa gap with no reason at all is invalid", () => {
  assert.equal(isValid(broken((b) => {
    (b.constituents as Record<string, unknown>).ropa = { status: "gap" };
  })), false);
});

test("a null ropa is reported as not_object", () => {
  assert.ok(errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).ropa = null;
  })).includes("constituents.ropa.not_object"));
});

test("a string ropa is reported as not_object", () => {
  assert.ok(errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).ropa = "ropa:abc";
  })).includes("constituents.ropa.not_object"));
});

test("a ropa ref with a missing ref field is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).ropa = { contentHash: SHA, satisfiedObligations: [] };
  })).includes("constituents.ropa.ref"));
});

test("a ropa ref with a bad contentHash is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).ropa = { ref: "r", contentHash: "nope", satisfiedObligations: [] };
  })).includes("constituents.ropa.contentHash"));
});

test("a ropa ref with non-array satisfiedObligations is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).ropa = { ref: "r", contentHash: SHA, satisfiedObligations: "gdpr.records" };
  })).includes("constituents.ropa.satisfiedObligations"));
});

test("a ropa ref whose satisfiedObligations contains a non-string is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).ropa = { ref: "r", contentHash: SHA, satisfiedObligations: ["ok", 3] };
  })).includes("constituents.ropa.satisfiedObligations"));
});

test("an EMPTY satisfiedObligations array is valid", () => {
  assert.equal(isValid(broken((b) => {
    (b.constituents as Record<string, unknown>).ropa = { ref: "r", contentHash: SHA, satisfiedObligations: [] };
  })), true);
});

test("an optional claimType may be omitted", () => {
  assert.equal(isValid(broken((b) => {
    (b.constituents as Record<string, unknown>).ropa = { ref: "r", contentHash: SHA, satisfiedObligations: [] };
  })), true);
});

test("a present but non-string claimType is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).ropa = { ref: "r", contentHash: SHA, satisfiedObligations: [], claimType: 7 };
  })).includes("constituents.ropa.claimType"));
});

test("a valid string claimType is accepted", () => {
  assert.equal(isValid(broken((b) => {
    (b.constituents as Record<string, unknown>).ropa = {
      ref: "r", contentHash: SHA, satisfiedObligations: [], claimType: "ar.impact.v1",
    };
  })), true);
});

test("an embedded payload is passed through without validation", () => {
  assert.equal(isValid(broken((b) => {
    (b.constituents as Record<string, unknown>).ropa = {
      ref: "r", contentHash: SHA, satisfiedObligations: [], embedded: { anything: [1, 2, 3] },
    };
  })), true);
});

// dpia
test("a dpia not_applicable declaration is accepted", () => {
  assert.equal(isValid(validBody()), true);
});

test("a dpia not_applicable missing its basis is invalid", () => {
  assert.equal(isValid(broken((b) => {
    (b.constituents as Record<string, unknown>).dpia = { status: "not_applicable", reason: "none" };
  })), false);
});

test("a dpia not_applicable missing its reason is invalid", () => {
  assert.equal(isValid(broken((b) => {
    (b.constituents as Record<string, unknown>).dpia = { status: "not_applicable", basis: "engine" };
  })), false);
});

test("an EMPTY dpia array is accepted", () => {
  assert.equal(isValid(broken((b) => {
    (b.constituents as Record<string, unknown>).dpia = [];
  })), true);
});

test("a dpia array of valid refs is accepted", () => {
  assert.equal(isValid(broken((b) => {
    (b.constituents as Record<string, unknown>).dpia = [
      { ref: "air_1", contentHash: SHA, satisfiedObligations: ["gdpr.dpia"] },
      { ref: "air_2", contentHash: SHA_B, satisfiedObligations: [] },
    ];
  })), true);
});

test("a bad ref inside the dpia array is reported WITH ITS INDEX", () => {
  const errs = errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).dpia = [
      { ref: "air_1", contentHash: SHA, satisfiedObligations: [] },
      { ref: "air_2", contentHash: "nope", satisfiedObligations: [] },
    ];
  }));
  assert.ok(errs.includes("constituents.dpia[1].contentHash"), errs.join(","));
  assert.ok(!errs.includes("constituents.dpia[0].contentHash"), errs.join(","));
});

test("a null entry in the dpia array is reported as an indexed not_object", () => {
  assert.ok(errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).dpia = [null];
  })).includes("constituents.dpia[0].not_object"));
});

test("a dpia that is neither an array nor a not_applicable decl is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).dpia = { status: "gap", reason: "x" };
  })).includes("constituents.dpia.invalid"));
});

test("a null dpia is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).dpia = null;
  })).includes("constituents.dpia.invalid"));
});

// obligations
test("obligations has NO gap escape hatch — a gap decl fails ref validation", () => {
  const errs = errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).obligations = { status: "gap", reason: "none" };
  }));
  assert.ok(errs.includes("constituents.obligations.ref"), errs.join(","));
});

test("a missing obligations ref is reported as not_object", () => {
  assert.ok(errsOf(broken((b) => {
    delete (b.constituents as Record<string, unknown>).obligations;
  })).includes("constituents.obligations.not_object"));
});

test("a bad obligations contentHash is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).obligations = { ref: "report", contentHash: "x", satisfiedObligations: [] };
  })).includes("constituents.obligations.contentHash"));
});

test("a bad obligations satisfiedObligations is invalid", () => {
  assert.ok(errsOf(broken((b) => {
    (b.constituents as Record<string, unknown>).obligations = { ref: "report", contentHash: SHA, satisfiedObligations: {} };
  })).includes("constituents.obligations.satisfiedObligations"));
});

// -------------------------------------------------------------- generated_at

test("a missing generated_at is invalid", () => {
  assert.ok(errsOf(broken((b) => { delete b.generated_at; })).includes("generated_at.missing"));
});

test("an empty generated_at is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.generated_at = ""; })).includes("generated_at.missing"));
});

test("a non-string generated_at is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.generated_at = 1750000000 })).includes("generated_at.missing"));
});

test("a date-only generated_at is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.generated_at = "2026-06-20"; })).includes("generated_at.invalid"));
});

test("a generated_at without a timezone is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.generated_at = "2026-06-20T10:00:00"; })).includes("generated_at.invalid"));
});

test("fractional seconds are accepted", () => {
  assert.equal(isValid(broken((b) => { b.generated_at = "2026-06-20T10:00:00.123Z"; })), true);
});

test("a positive UTC offset is accepted", () => {
  assert.equal(isValid(broken((b) => { b.generated_at = "2026-06-20T10:00:00+02:00"; })), true);
});

test("a negative UTC offset is accepted", () => {
  assert.equal(isValid(broken((b) => { b.generated_at = "2026-06-20T10:00:00-05:00"; })), true);
});

test("a regex-shaped but UNPARSEABLE date is caught by the Date.parse arm", () => {
  // "2026-13-45T99:99:99Z" satisfies the \d{2} groups but is not a real instant.
  // Without the Date.parse check this would pass — that is why the arm exists.
  const errs = errsOf(broken((b) => { b.generated_at = "2026-13-45T99:99:99Z"; }));
  assert.ok(errs.includes("generated_at.invalid"), errs.join(","));
});

test("a lowercase z terminator is invalid", () => {
  assert.ok(errsOf(broken((b) => { b.generated_at = "2026-06-20T10:00:00z"; })).includes("generated_at.invalid"));
});

// -------------------------------------------------------- aggregate behaviour

test("multiple independent errors accumulate rather than short-circuiting", () => {
  const errs = errsOf(broken((b) => {
    b.profile = "wrong";
    delete b.workspaceId;
    b.controller = null;
  }));
  assert.ok(errs.includes("profile.invalid"), errs.join(","));
  assert.ok(errs.includes("workspaceId.missing"), errs.join(","));
  assert.ok(errs.includes("controller.invalid"), errs.join(","));
  assert.ok(errs.length >= 3);
});

test("an invalid body always returns a null body", () => {
  const r = verifyComplianceBundleBody(broken((b) => { b.profile = "wrong"; }));
  assert.equal(r.valid, false);
  assert.equal(r.body, null);
});

test("a valid result carries an empty errors array, not undefined", () => {
  const r = verifyComplianceBundleBody(validBody());
  assert.ok(Array.isArray(r.errors));
  assert.equal(r.errors.length, 0);
});

test("validation does not mutate the input body", () => {
  const b = validBody();
  const before = JSON.stringify(b);
  verifyComplianceBundleBody(b);
  assert.equal(JSON.stringify(b), before);
});

test("an unknown extra field is ignored rather than rejected", () => {
  assert.equal(isValid(broken((b) => { b.somethingNew = "tolerated"; })), true);
});
