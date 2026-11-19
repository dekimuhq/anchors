import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyScreeningBody, screeningBodyValidator } from "../src/index.ts";
import { mintScreeningV1 } from "../src/issue/index.ts";
import { baseInput } from "./helpers.ts";

test("verifyScreeningBody: non-object", () => {
  for (const v of [null, 3, "s", undefined]) assert.deepEqual(verifyScreeningBody(v), { valid: false, errors: ["body.not_object"], body: null });
});
test("verifyScreeningBody: unknown profile", () => {
  const r = verifyScreeningBody({ profile: "nope" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("screening.profile.unknown"));
});
test("verifyScreeningBody + validator accept a minted body", async () => {
  const receipt = await mintScreeningV1(baseInput());
  assert.equal(verifyScreeningBody(receipt.body).valid, true);
  assert.equal(screeningBodyValidator.validate(receipt.body).ok, true);
});
test("validator surfaces the first error code as reason", () => {
  const r = screeningBodyValidator.validate({ profile: "screening.list" });
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.reason, /^screening\./);
});
