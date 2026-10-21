import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkAerSubjectPresence } from "../src/subject-presence.ts";
import { sha256Hex } from "./_helpers/fixtures.ts";

describe("checkAerSubjectPresence", () => {
  describe("conformity (subject must be null)", () => {
    it("accepts null subject on conformity", () => {
      const r = checkAerSubjectPresence({
        subject: null,
        body: { event_type: "conformity" },
      });
      assert.ok(r.ok);
    });

    it("rejects non-null subject on conformity", () => {
      const r = checkAerSubjectPresence({
        subject: sha256Hex(),
        body: { event_type: "conformity" },
      });
      assert.ok(!r.ok);
      assert.strictEqual(r.reason, "subject_must_be_null");
    });
  });

  describe("transparency (subject must be sha256)", () => {
    it("accepts sha256 subject on transparency", () => {
      const r = checkAerSubjectPresence({
        subject: sha256Hex(),
        body: { event_type: "transparency" },
      });
      assert.ok(r.ok);
    });

    it("rejects null subject on transparency", () => {
      const r = checkAerSubjectPresence({
        subject: null,
        body: { event_type: "transparency" },
      });
      assert.ok(!r.ok);
      assert.strictEqual(r.reason, "subject_must_be_present");
    });

    it("rejects non-sha256 string subject on transparency", () => {
      const r = checkAerSubjectPresence({
        subject: "not-a-hash",
        body: { event_type: "transparency" },
      });
      assert.ok(!r.ok);
      assert.strictEqual(r.reason, "subject_must_be_sha256");
    });
  });

  describe("unknown event_type", () => {
    it("defaults to subject-must-be-null on unknown event_type", () => {
      const r = checkAerSubjectPresence({
        subject: null,
        body: { event_type: "unknown" },
      });
      assert.ok(r.ok);
    });

    it("rejects non-null on unknown event_type", () => {
      const r = checkAerSubjectPresence({
        subject: sha256Hex(),
        body: { event_type: "unknown" },
      });
      assert.ok(!r.ok);
    });
  });
});
