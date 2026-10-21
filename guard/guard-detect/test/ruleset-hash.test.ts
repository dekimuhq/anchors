import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RULESET_HASH, computeRulesetHash } from "../src/ruleset-hash.ts";

describe("ruleset-hash", () => {
  it("is a 64-char hex string", () => {
    assert.match(RULESET_HASH, /^[0-9a-f]{64}$/);
  });
  it("is stable across calls", () => {
    assert.equal(computeRulesetHash(), RULESET_HASH);
    assert.equal(computeRulesetHash(), computeRulesetHash());
  });
  it("RULESET_HASH is the pinned golden value (bump RULESET_VERSION on any change)", () => {
    assert.equal(RULESET_HASH, "234dd2691d6621b6e971c5db6ef21becff4dba31c47210de61ad06a9816498e9");
  });
});
