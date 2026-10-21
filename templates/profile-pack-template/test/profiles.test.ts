// @dekimuhq/<member>-profiles — descriptor sanity tests

import { test } from "node:test";
import assert from "node:assert/strict";
import { profiles } from "../src/index.ts";

test("profiles: every descriptor has a name matching its key", () => {
  for (const [key, descriptor] of Object.entries(profiles)) {
    assert.equal(descriptor.name, key, `profile ${key} name mismatch`);
  }
});

test("profiles: every descriptor with requires_tsa_listed has requires_tsa", () => {
  for (const descriptor of Object.values(profiles)) {
    if (descriptor.requires_tsa_listed) {
      assert.equal(descriptor.requires_tsa, true);
    }
  }
});
