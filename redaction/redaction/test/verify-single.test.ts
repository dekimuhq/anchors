import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyRedactionBody } from "../src/verify-single.ts";

const H = "sha256:" + "b".repeat(64);
const good = {
  profile: "redaction.prompt", counts: { EMAIL: 2, CLIENT: 1 },
  ruleset_hash: H, input_commit: H, output_commit: H,
  commit_alg: "sha256", redactor: "@dekimuhq/ai@2.4.0",
};

// ── existing baseline ────────────────────────────────────────────────────────

test("valid body passes", () => {
  const r = verifyRedactionBody(good);
  assert.equal(r.valid, true);
  assert.equal(r.errors.length, 0);
});
test("non-object rejected", () => {
  assert.equal(verifyRedactionBody(null).valid, false);
});
test("bad commit_alg rejected", () => {
  const r = verifyRedactionBody({ ...good, commit_alg: "md5" });
  assert.ok(r.errors.includes("commit_alg.invalid"));
});
test("unknown category rejected", () => {
  const r = verifyRedactionBody({ ...good, counts: { SSN: 1 } });
  assert.ok(r.errors.some((e) => e.startsWith("counts.unknown_category")));
});

// ── non-object input ─────────────────────────────────────────────────────────

test("null returns body.not_object and valid:false", () => {
  const r = verifyRedactionBody(null);
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("body.not_object"));
  assert.equal(r.body, null);
});
test("number input returns body.not_object", () => {
  const r = verifyRedactionBody(42);
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("body.not_object"));
});
test("string input returns body.not_object", () => {
  const r = verifyRedactionBody("hello");
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("body.not_object"));
});

// ── valid body echoes body ────────────────────────────────────────────────────

test("fully valid body returns valid:true and echoes body", () => {
  const r = verifyRedactionBody(good);
  assert.equal(r.valid, true);
  assert.deepEqual(r.body, good);
});

// ── per-category single-field coverage ───────────────────────────────────────

test("EMAIL-only counts accepted", () => {
  const r = verifyRedactionBody({ ...good, counts: { EMAIL: 5 } });
  assert.equal(r.valid, true);
});
test("IBAN-only counts accepted", () => {
  const r = verifyRedactionBody({ ...good, counts: { IBAN: 2 } });
  assert.equal(r.valid, true);
});
test("VAT-only counts accepted", () => {
  const r = verifyRedactionBody({ ...good, counts: { VAT: 1 } });
  assert.equal(r.valid, true);
});
test("PHONE-only counts accepted", () => {
  const r = verifyRedactionBody({ ...good, counts: { PHONE: 7 } });
  assert.equal(r.valid, true);
});
test("CARD-only counts accepted", () => {
  const r = verifyRedactionBody({ ...good, counts: { CARD: 0 } });
  assert.equal(r.valid, true);
});
test("CLIENT-only counts accepted", () => {
  const r = verifyRedactionBody({ ...good, counts: { CLIENT: 3 } });
  assert.equal(r.valid, true);
});
test("all 6 categories at once accepted", () => {
  const r = verifyRedactionBody({
    ...good, counts: { EMAIL: 1, IBAN: 1, VAT: 1, PHONE: 1, CARD: 1, CLIENT: 1 },
  });
  assert.equal(r.valid, true);
});
test("empty counts object accepted (zero-redaction receipt)", () => {
  const r = verifyRedactionBody({ ...good, counts: {} });
  assert.equal(r.valid, true);
});

// ── count value edge cases ───────────────────────────────────────────────────

test("count value 0 accepted", () => {
  const r = verifyRedactionBody({ ...good, counts: { EMAIL: 0 } });
  assert.equal(r.valid, true);
});
test("large count value accepted", () => {
  const r = verifyRedactionBody({ ...good, counts: { EMAIL: 100000 } });
  assert.equal(r.valid, true);
});
test("negative count rejected", () => {
  const r = verifyRedactionBody({ ...good, counts: { EMAIL: -1 } });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.startsWith("counts.invalid")));
});
test("float count rejected", () => {
  const r = verifyRedactionBody({ ...good, counts: { EMAIL: 1.5 } });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.startsWith("counts.invalid")));
});
test("string count rejected", () => {
  const r = verifyRedactionBody({ ...good, counts: { EMAIL: "3" } });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.startsWith("counts.invalid")));
});
test("null count rejected", () => {
  const r = verifyRedactionBody({ ...good, counts: { EMAIL: null } });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.startsWith("counts.invalid")));
});

// ── counts shape errors ──────────────────────────────────────────────────────

test("counts missing entirely → counts.missing", () => {
  const b = { ...good } as Record<string, unknown>;
  delete b.counts;
  const r = verifyRedactionBody(b);
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("counts.missing"));
});
test("counts null → counts.missing", () => {
  const r = verifyRedactionBody({ ...good, counts: null });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("counts.missing"));
});
test("counts as array rejected via counts.missing (Array.isArray guard)", () => {
  const r = verifyRedactionBody({ ...good, counts: [1, 2] });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("counts.missing"));
});

// ── commit field errors ──────────────────────────────────────────────────────

test("input_commit wrong prefix rejected", () => {
  const r = verifyRedactionBody({ ...good, input_commit: "md5:" + "b".repeat(32) });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("input_commit.invalid"));
});
test("output_commit wrong prefix rejected", () => {
  const r = verifyRedactionBody({ ...good, output_commit: "md5:" + "b".repeat(32) });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("output_commit.invalid"));
});
test("ruleset_hash too-short hex rejected", () => {
  const r = verifyRedactionBody({ ...good, ruleset_hash: "sha256:" + "b".repeat(32) });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("ruleset_hash.invalid"));
});
test("output_commit uppercase hex rejected", () => {
  const r = verifyRedactionBody({ ...good, output_commit: "sha256:" + "B".repeat(64) });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("output_commit.invalid"));
});
test("input_commit missing rejected", () => {
  const b = { ...good } as Record<string, unknown>;
  delete b.input_commit;
  const r = verifyRedactionBody(b);
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("input_commit.invalid"));
});

// ── profile errors ───────────────────────────────────────────────────────────

test("wrong profile string rejected", () => {
  const r = verifyRedactionBody({ ...good, profile: "redaction.chat" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("profile.invalid"));
});
test("missing profile rejected", () => {
  const b = { ...good } as Record<string, unknown>;
  delete b.profile;
  const r = verifyRedactionBody(b);
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("profile.invalid"));
});

// ── commit_alg errors ────────────────────────────────────────────────────────

test("commit_alg missing rejected", () => {
  const b = { ...good } as Record<string, unknown>;
  delete b.commit_alg;
  const r = verifyRedactionBody(b);
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("commit_alg.invalid"));
});

// ── redactor errors ──────────────────────────────────────────────────────────

test("empty string redactor rejected", () => {
  const r = verifyRedactionBody({ ...good, redactor: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("redactor.missing"));
});
test("missing redactor rejected", () => {
  const b = { ...good } as Record<string, unknown>;
  delete b.redactor;
  const r = verifyRedactionBody(b);
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("redactor.missing"));
});
test("non-string redactor rejected", () => {
  const r = verifyRedactionBody({ ...good, redactor: 42 });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("redactor.missing"));
});
