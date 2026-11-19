import { test } from "node:test";
import assert from "node:assert/strict";
import { validateScreeningList, MAX_CANDIDATES } from "../src/index.ts";

const H = "sha256:" + "a".repeat(64);
const base = () => ({
  profile: "screening.list",
  screen_id: "01J9Z3K4M5N6P7Q8R9S0T1V2W3",
  list: {
    id: "eu-fsf", file_name: "20261119-FULL-1_1.xml", file_date: "2026-11-19T00:00:00.000Z",
    file_sha256: H, parsed_sha256: H, entry_count: 5123, fetched_at: "2026-11-19T03:00:04.000Z",
  },
  matcher: { name: "@dekimuhq/sanctions", version: "0.2.0", threshold: 0.85 },
  subject_commit: H,
  result: "none_at_threshold",
  candidates: [] as Array<{ entry_ref: string; score: number }>,
  trigger: "manual",
  screened_at: "2026-11-19T10:00:00.000Z",
});
type B = ReturnType<typeof base>;
const run = (f: (b: B) => void) => { const b = base(); f(b); return validateScreeningList(b); };
const rejects = (name: string, code: string, f: (b: B) => void) =>
  test(`rejects: ${name}`, () => {
    const r = run(f);
    assert.equal(r.ok, false);
    assert.ok(r.errors.includes(code), `expected ${code}, got ${r.errors.join(",")}`);
  });

test("accepts a none_at_threshold body", () => assert.deepEqual(validateScreeningList(base()), { ok: true, errors: [] }));
test("accepts a candidate body", () => {
  const r = run((b) => { b.result = "candidate"; b.candidates = [{ entry_ref: "EU.1.2", score: 0.95 }, { entry_ref: "EU.3.4", score: 0.9 }]; });
  assert.equal(r.ok, true);
});
test("accepts scheduled trigger", () => assert.equal(run((b) => { b.trigger = "scheduled"; }).ok, true));
test("accepts threshold of exactly 1", () => assert.equal(run((b) => { b.matcher.threshold = 1; }).ok, true));
test("accepts screened_at == fetched_at", () => assert.equal(run((b) => { b.screened_at = b.list.fetched_at; }).ok, true));
test("accepts screened_at == fetched_at + 48h", () => assert.equal(run((b) => { b.screened_at = "2026-11-21T03:00:04.000Z"; }).ok, true));
test("accepts exactly MAX_CANDIDATES", () => {
  const r = run((b) => { b.result = "candidate"; b.candidates = Array.from({ length: MAX_CANDIDATES }, (_, i) => ({ entry_ref: `E${i}`, score: 0.99 })); });
  assert.equal(r.ok, true);
});
test("accepts equal scores (ties)", () => {
  assert.equal(run((b) => { b.result = "candidate"; b.candidates = [{ entry_ref: "a", score: 0.9 }, { entry_ref: "b", score: 0.9 }]; }).ok, true);
});
test("score exactly at threshold is a candidate", () => {
  assert.equal(run((b) => { b.result = "candidate"; b.candidates = [{ entry_ref: "a", score: 0.85 }]; }).ok, true);
});

for (const v of [null, undefined, 5, "x", []]) {
  test(`rejects non-object body ${JSON.stringify(v)}`, () => assert.equal(validateScreeningList(v).ok, false));
}

rejects("wrong profile", "screening.profile.unknown", (b) => { b.profile = "guard.input"; });
for (const id of ["", "not-a-ulid", "01J9Z3K4M5N6P7Q8R9S0T1V2W", "01J9Z3K4M5N6P7Q8R9S0T1V2WIL", "01j9z3k4m5n6p7q8r9s0t1v2w3"]) {
  rejects(`screen_id ${JSON.stringify(id)}`, "screening.screen_id.malformed", (b) => { b.screen_id = id; });
}
test("rejects missing screen_id", () => assert.ok(run((b) => { delete (b as Partial<B>).screen_id; }).errors.includes("screening.screen_id.malformed")));
test("rejects missing list", () => assert.ok(run((b) => { delete (b as Partial<B>).list; }).errors.includes("screening.list.missing")));
rejects("empty list id", "screening.list.id_unknown", (b) => { b.list.id = ""; });
rejects("empty file name", "screening.list.file_name_missing", (b) => { b.list.file_name = ""; });
rejects("bad file_date", "screening.list.file_date_malformed", (b) => { b.list.file_date = "yesterday"; });
rejects("bad fetched_at", "screening.list.fetched_at_malformed", (b) => { b.list.fetched_at = "2026-11-19"; });
for (const h of ["", "a".repeat(64), "sha256:" + "A".repeat(64), "sha256:" + "a".repeat(63), "sha256:" + "g".repeat(64), "sha512:" + "a".repeat(64)]) {
  rejects(`file_sha256 ${h.slice(0, 12)}…`, "screening.list.hash_malformed", (b) => { b.list.file_sha256 = h; });
  rejects(`parsed_sha256 ${h.slice(0, 12)}…`, "screening.list.hash_malformed", (b) => { b.list.parsed_sha256 = h; });
  rejects(`subject_commit ${h.slice(0, 12)}…`, "screening.subject_commit.malformed", (b) => { b.subject_commit = h; });
}
for (const n of [0, -1, 1.5, NaN]) rejects(`entry_count ${n}`, "screening.list.empty", (b) => { b.list.entry_count = n; });
test("rejects string entry_count", () => assert.ok(run((b) => { (b.list as { entry_count: unknown }).entry_count = "5"; }).errors.includes("screening.list.empty")));

rejects("missing matcher", "screening.matcher.missing", (b) => { delete (b as Partial<B>).matcher; });
rejects("empty matcher name", "screening.matcher.missing", (b) => { b.matcher.name = ""; });
rejects("empty matcher version", "screening.matcher.missing", (b) => { b.matcher.version = ""; });
for (const t of [0, -0.1, 1.01, NaN, Infinity]) rejects(`threshold ${t}`, "screening.matcher.threshold_invalid", (b) => { b.matcher.threshold = t; });
test("rejects string threshold", () => assert.ok(run((b) => { (b.matcher as { threshold: unknown }).threshold = "0.9"; }).errors.includes("screening.matcher.threshold_invalid")));

for (const t of ["", "auto", "MANUAL"]) rejects(`trigger ${t}`, "screening.trigger.invalid", (b) => { b.trigger = t; });
rejects("bad screened_at", "screening.screened_at_malformed", (b) => { b.screened_at = "now"; });
rejects("screened_at before fetched_at", "screening.list.stale", (b) => { b.screened_at = "2026-11-19T03:00:03.999Z"; });
rejects("screened_at 1ms past 48h", "screening.list.stale", (b) => { b.screened_at = "2026-11-21T03:00:04.001Z"; });
rejects("screened_at a week later", "screening.list.stale", (b) => { b.screened_at = "2026-11-26T03:00:04.000Z"; });

for (const r of ["clear", "not_sanctioned", "match", ""]) rejects(`result ${JSON.stringify(r)}`, "screening.result.invalid", (b) => { b.result = r; });
rejects("none_at_threshold with candidates", "screening.result.incoherent", (b) => { b.candidates = [{ entry_ref: "a", score: 0.9 }]; });
rejects("candidate without candidates", "screening.result.incoherent", (b) => { b.result = "candidate"; });
rejects("candidates not array", "screening.candidates.not_array", (b) => { (b as { candidates: unknown }).candidates = "x"; });
rejects("too many candidates", "screening.candidates.too_many", (b) => { b.result = "candidate"; b.candidates = Array.from({ length: MAX_CANDIDATES + 1 }, (_, i) => ({ entry_ref: `E${i}`, score: 0.99 })); });
rejects("candidate below threshold", "screening.candidates.below_threshold", (b) => { b.result = "candidate"; b.candidates = [{ entry_ref: "a", score: 0.5 }]; });
rejects("candidates unordered", "screening.candidates.unordered", (b) => { b.result = "candidate"; b.candidates = [{ entry_ref: "a", score: 0.9 }, { entry_ref: "b", score: 0.95 }]; });
rejects("candidate empty ref", "screening.candidates.malformed", (b) => { b.result = "candidate"; b.candidates = [{ entry_ref: "", score: 0.9 }]; });
rejects("candidate score > 1", "screening.candidates.malformed", (b) => { b.result = "candidate"; b.candidates = [{ entry_ref: "a", score: 1.1 }]; });
rejects("candidate non-numeric score", "screening.candidates.malformed", (b) => { b.result = "candidate"; b.candidates = [{ entry_ref: "a", score: "0.9" as unknown as number }]; });
test("reports multiple errors at once, deduplicated", () => {
  const r = run((b) => { b.list.file_sha256 = "x"; b.list.parsed_sha256 = "y"; b.trigger = "z"; });
  assert.equal(r.errors.filter((x) => x === "screening.list.hash_malformed").length, 1);
  assert.ok(r.errors.includes("screening.trigger.invalid"));
});

test("accepts field_root alongside the body keys", () => assert.equal(run((b) => { (b as { field_root?: string }).field_root = "x"; }).ok, true));
rejects("plaintext name field", "screening.body.unknown_field", (b) => { (b as { screened_name?: string }).screened_name = "Jane Doe"; });
rejects("unknown list key", "screening.body.unknown_field", (b) => { (b.list as { owner?: string }).owner = "x"; });
rejects("unknown matcher key", "screening.body.unknown_field", (b) => { (b.matcher as { note?: string }).note = "x"; });
rejects("unknown candidate key", "screening.body.unknown_field", (b) => { b.result = "candidate"; b.candidates = [{ entry_ref: "a", score: 0.9, name: "Jane" } as never]; });
rejects("entry_ref carrying free text", "screening.candidates.malformed", (b) => { b.result = "candidate"; b.candidates = [{ entry_ref: "Jane Doe, DOB 1970-01-01", score: 0.9 }]; });
rejects("entry_ref too long", "screening.candidates.malformed", (b) => { b.result = "candidate"; b.candidates = [{ entry_ref: "a".repeat(65), score: 0.9 }]; });
rejects("unknown list id", "screening.list.id_unknown", (b) => { b.list.id = "all-global-sanctions-lists"; });
rejects("file_date after fetched_at", "screening.list.file_date_after_fetch", (b) => { b.list.file_date = "2030-01-01T00:00:00.000Z"; });
rejects("whitespace-only file name", "screening.list.file_name_missing", (b) => { b.list.file_name = "  "; });
rejects("ULID first char above 7", "screening.screen_id.malformed", (b) => { b.screen_id = "81J9Z3K4M5N6P7Q8R9S0T1V2W3"; });
test("rejects array-coerced strings", () => {
  for (const f of [
    (b: B) => { (b as { subject_commit: unknown }).subject_commit = [H]; },
    (b: B) => { (b as { screen_id: unknown }).screen_id = ["01J9Z3K4M5N6P7Q8R9S0T1V2W3"]; },
    (b: B) => { (b.list as { file_sha256: unknown }).file_sha256 = [H]; },
  ]) assert.equal(run(f).ok, false);
});
