import { test } from "node:test";
import assert from "node:assert/strict";
import { validateRedactionPrompt } from "../src/prompt.ts";
import type { APIIRBody } from "../src/body.ts";

const H = "sha256:" + "a".repeat(64);
const good: APIIRBody = {
  profile: "redaction.prompt",
  counts: { EMAIL: 3, IBAN: 1, CARD: 0 },
  ruleset_hash: H, input_commit: H, output_commit: H,
  commit_alg: "sha256", redactor: "@dekimuhq/ai@2.4.0",
};

// ── existing baseline ────────────────────────────────────────────────────────

test("valid redaction.prompt body passes", () => {
  assert.deepEqual(validateRedactionPrompt(good).errors, []);
});
test("unknown category rejected", () => {
  const b = { ...good, counts: { SSN: 1 } } as unknown as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.some((e) => e.startsWith("redaction.counts.unknown_category")));
});
test("malformed commit rejected", () => {
  const b = { ...good, input_commit: "nope" } as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.input_commit_malformed"));
});
test("negative count rejected", () => {
  const b = { ...good, counts: { EMAIL: -1 } } as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.some((e) => e.startsWith("redaction.counts.invalid")));
});

// ── per-category coverage ────────────────────────────────────────────────────

test("EMAIL-only counts accepted", () => {
  assert.deepEqual(validateRedactionPrompt({ ...good, counts: { EMAIL: 5 } }).errors, []);
});
test("IBAN-only counts accepted", () => {
  assert.deepEqual(validateRedactionPrompt({ ...good, counts: { IBAN: 2 } }).errors, []);
});
test("VAT-only counts accepted", () => {
  assert.deepEqual(validateRedactionPrompt({ ...good, counts: { VAT: 1 } }).errors, []);
});
test("PHONE-only counts accepted", () => {
  assert.deepEqual(validateRedactionPrompt({ ...good, counts: { PHONE: 7 } }).errors, []);
});
test("CARD-only counts accepted", () => {
  assert.deepEqual(validateRedactionPrompt({ ...good, counts: { CARD: 0 } }).errors, []);
});
test("CLIENT-only counts accepted", () => {
  assert.deepEqual(validateRedactionPrompt({ ...good, counts: { CLIENT: 3 } }).errors, []);
});
test("all 6 categories at once accepted", () => {
  const b = { ...good, counts: { EMAIL: 1, IBAN: 1, VAT: 1, PHONE: 1, CARD: 1, CLIENT: 1 } };
  assert.deepEqual(validateRedactionPrompt(b).errors, []);
});
test("empty counts object accepted (zero-redaction receipt)", () => {
  assert.deepEqual(validateRedactionPrompt({ ...good, counts: {} }).errors, []);
});

// ── count value edge cases ───────────────────────────────────────────────────

test("count value 0 accepted", () => {
  assert.deepEqual(validateRedactionPrompt({ ...good, counts: { EMAIL: 0 } }).errors, []);
});
test("large count accepted", () => {
  assert.deepEqual(validateRedactionPrompt({ ...good, counts: { EMAIL: 100000 } }).errors, []);
});
test("float count rejected", () => {
  const b = { ...good, counts: { EMAIL: 1.5 } } as unknown as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.some((e) => e.startsWith("redaction.counts.invalid")));
});
test("string count rejected", () => {
  const b = { ...good, counts: { EMAIL: "3" } } as unknown as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.some((e) => e.startsWith("redaction.counts.invalid")));
});
test("null count rejected", () => {
  const b = { ...good, counts: { EMAIL: null } } as unknown as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.some((e) => e.startsWith("redaction.counts.invalid")));
});
test("unknown category key carries the key name in error token", () => {
  const b = { ...good, counts: { PASSPORT: 1 } } as unknown as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.some((e) => e === "redaction.counts.unknown_category:PASSPORT"));
});

// ── counts shape errors ──────────────────────────────────────────────────────

test("counts missing entirely rejected", () => {
  const b = { ...good } as unknown as APIIRBody;
  delete (b as unknown as Record<string, unknown>).counts;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.counts_missing"));
});
test("counts null rejected", () => {
  const b = { ...good, counts: null } as unknown as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.counts_missing"));
});
test("counts as array rejected via redaction.counts_missing (Array.isArray guard)", () => {
  const b = { ...good, counts: [1, 2] } as unknown as APIIRBody;
  const errs = validateRedactionPrompt(b).errors;
  assert.ok(errs.includes("redaction.counts_missing"));
});

// ── commit field errors ──────────────────────────────────────────────────────

test("output_commit wrong prefix rejected", () => {
  const b = { ...good, output_commit: "md5:" + "a".repeat(32) } as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.output_commit_malformed"));
});
test("ruleset_hash wrong prefix rejected", () => {
  const b = { ...good, ruleset_hash: "md5:" + "a".repeat(32) } as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.ruleset_hash_malformed"));
});
test("input_commit too-short hex rejected", () => {
  const b = { ...good, input_commit: "sha256:" + "a".repeat(32) } as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.input_commit_malformed"));
});
test("output_commit uppercase hex rejected", () => {
  const b = { ...good, output_commit: "sha256:" + "A".repeat(64) } as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.output_commit_malformed"));
});
test("input_commit missing rejected", () => {
  const b = { ...good } as unknown as APIIRBody;
  delete (b as unknown as Record<string, unknown>).input_commit;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.input_commit_malformed"));
});

// ── profile errors ───────────────────────────────────────────────────────────

test("wrong profile string rejected", () => {
  const b = { ...good, profile: "redaction.chat" } as unknown as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.wrong_profile"));
});
test("missing profile rejected", () => {
  const b = { ...good } as unknown as APIIRBody;
  delete (b as unknown as Record<string, unknown>).profile;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.wrong_profile"));
});

// ── commit_alg errors ────────────────────────────────────────────────────────

test("commit_alg other than sha256 rejected", () => {
  const b = { ...good, commit_alg: "md5" } as unknown as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.commit_alg_invalid"));
});
test("commit_alg missing rejected", () => {
  const b = { ...good } as unknown as APIIRBody;
  delete (b as unknown as Record<string, unknown>).commit_alg;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.commit_alg_invalid"));
});

// ── redactor errors ──────────────────────────────────────────────────────────

test("empty string redactor rejected", () => {
  const b = { ...good, redactor: "" } as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.redactor_missing"));
});
test("missing redactor rejected", () => {
  const b = { ...good } as unknown as APIIRBody;
  delete (b as unknown as Record<string, unknown>).redactor;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.redactor_missing"));
});
test("non-string redactor rejected", () => {
  const b = { ...good, redactor: 42 } as unknown as APIIRBody;
  assert.ok(validateRedactionPrompt(b).errors.includes("redaction.redactor_missing"));
});
