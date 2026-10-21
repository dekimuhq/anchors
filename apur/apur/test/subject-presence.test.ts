import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkApurSubjectPresence } from "../src/subject-presence.ts";

describe("checkApurSubjectPresence", () => {
  it("accepts null subject", () => {
    const r = checkApurSubjectPresence({ subject: null });
    assert.equal(r.ok, true);
    assert.equal(r.reason, undefined);
  });

  it("rejects sha256 subject", () => {
    const r = checkApurSubjectPresence({ subject: "sha256:" + "aa".repeat(32) });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "subject_must_be_null");
  });

  it("rejects empty string subject", () => {
    const r = checkApurSubjectPresence({ subject: "" });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "subject_must_be_null");
  });

  it("rejects undefined subject", () => {
    const r = checkApurSubjectPresence({ subject: undefined });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "subject_must_be_null");
  });

  it("rejects numeric subject", () => {
    const r = checkApurSubjectPresence({ subject: 42 });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "subject_must_be_null");
  });
});
