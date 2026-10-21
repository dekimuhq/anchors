import { test } from "node:test";
import assert from "node:assert/strict";
import { buildTree, inclusionProof, verifyInclusion, commit, canonicalize } from "@dekimuhq/anchors-envelope";
import { resolveLayout, buildFieldTree } from "../src/tree.ts";
import { bundleSaltSource } from "../src/salt.ts";
import type { DisclosureSchema } from "../src/types.ts";

const body = { sub: "alice", purposes: ["mkt", "analytics"], policy: "p-7" };
const schema: DisclosureSchema = {
  claim_type: "ar.consent.v1",
  leaves: [{ path: "/sub" }, { path: "/purposes", array: true }, { path: "/policy" }],
};

test("resolveLayout expands arrays in declared order with stable indices", () => {
  const layout = resolveLayout(body, schema);
  assert.deepEqual(layout.map((l) => l.path), ["/sub", "/purposes/0", "/purposes/1", "/policy"]);
  assert.deepEqual(layout.map((l) => l.leaf_index), [0, 1, 2, 3]);
  assert.deepEqual(layout.map((l) => l.value), ["alice", "mkt", "analytics", "p-7"]);
});

test("buildFieldTree is deterministic for the same salts", () => {
  const salts = bundleSaltSource({ "/sub": "AAAA", "/purposes/0": "BBBB", "/purposes/1": "CCCC", "/policy": "DDDD" });
  const a = buildFieldTree(body, schema, salts);
  const b = buildFieldTree(body, schema, salts);
  assert.equal(a.field_root, b.field_root);
  assert.match(a.field_root, /^sha256:[0-9a-f]{64}$/);
  assert.equal(a.leaves.length, 4);
});

test("buildFieldTree throws when a declared scalar path is missing", () => {
  const salts = bundleSaltSource({});
  assert.throws(() => buildFieldTree({ purposes: [] }, schema, salts));
});

test("single-leaf schema: buildFieldTree produces 1 leaf with valid field_root", () => {
  const singleSchema: DisclosureSchema = {
    claim_type: "ar.consent.v1",
    leaves: [{ path: "/sub" }],
  };
  const salts = bundleSaltSource({ "/sub": "AAAA" });
  const { leaves, field_root } = buildFieldTree({ sub: "alice" }, singleSchema, salts);
  assert.equal(leaves.length, 1);
  assert.match(field_root, /^sha256:[0-9a-f]{64}$/);
});

test("empty array leaf contributes zero leaves; total excludes it", () => {
  const schemaWithArray: DisclosureSchema = {
    claim_type: "ar.consent.v1",
    leaves: [{ path: "/sub" }, { path: "/purposes", array: true }, { path: "/policy" }],
  };
  // purposes is [] → no leaves from that spec
  const salts = bundleSaltSource({ "/sub": "AAAA", "/policy": "DDDD" });
  const { leaves, layout } = buildFieldTree({ sub: "alice", purposes: [], policy: "p-7" }, schemaWithArray, salts);
  // Only /sub and /policy produce leaves
  assert.equal(leaves.length, 2);
  assert.deepEqual(layout.map((l) => l.path), ["/sub", "/policy"]);
});

test("nested object value is treated as an atomic leaf (round-trips via canonicalize)", () => {
  const nestedSchema: DisclosureSchema = {
    claim_type: "ar.consent.v1",
    leaves: [{ path: "/meta" }],
  };
  const nestedBody = { meta: { kind: "gdpr", version: 2 } };
  const salts = bundleSaltSource({ "/meta": "AAAA" });
  // Should not throw — the object is canonicalised and committed atomically.
  const { leaves, layout } = buildFieldTree(nestedBody, nestedSchema, salts);
  assert.equal(leaves.length, 1);
  assert.deepEqual(layout[0]!.value, { kind: "gdpr", version: 2 });
  assert.match(leaves[0]!, /^sha256:[0-9a-f]{64}$/);
});

test("escaped JSON-pointer token a~1b resolves to key 'a/b'", () => {
  const escapedSchema: DisclosureSchema = {
    claim_type: "ar.consent.v1",
    leaves: [{ path: "/a~1b" }],
  };
  const escapedBody = { "a/b": "x" };
  const layout = resolveLayout(escapedBody, escapedSchema);
  assert.equal(layout[0]!.value, "x");
});

test("odd leaf counts (3 and 5): inclusionProof+verifyInclusion round-trip for all indices", () => {
  for (const count of [3, 5]) {
    // Build N synthetic leaf commits (sha256-shaped strings).
    const leaves: string[] = Array.from({ length: count }, (_, i) =>
      commit("AAAA", canonicalize({ path: `/f/${i}`, value: i }))
    );
    const tree = buildTree(leaves);
    assert.equal(tree.leafCount, count);
    for (let idx = 0; idx < count; idx++) {
      const proof = inclusionProof(tree, idx);
      assert.equal(
        verifyInclusion(leaves[idx]!, proof, idx, count, tree.root),
        true,
        `leaf ${idx} of ${count}: expected verifyInclusion to return true`,
      );
    }
  }
});
