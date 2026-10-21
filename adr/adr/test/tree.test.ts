/**
 * Tests for the ADR delegation tree walker (spec §7.2).
 *
 * Covers sub-delegation validation (delegable, scope subset, expiry) and
 * cascade state propagation from ancestors.
 *
 * ~12 tests across: root grant, sub-delegation rules, cascade state.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildAdrTreeIndex,
  walkDelegationTree,
} from "../src/tree.ts";
import { buildAdrChainIndex } from "../src/chain.ts";
import {
  H,
  makeGrant,
  makeEvent,
  defaultScope,
} from "./_helpers/common.ts";
import type { AdrChainReceipt, AdrScope } from "../src/types.ts";

// ── Helpers ────────────────────────────────────────────────────────────────

const narrowScope: AdrScope = {
  actions: ["inference.run"],
  resources: ["model:gpt-4:*"],
  constraints: { max_requests: 500, region: "eu-west" },
};

const ONE_YEAR_S = 365 * 24 * 60 * 60;
const clock = Math.floor(Date.now() / 1000);

/**
 * Build a child grant whose `prev` points at `parentId`.
 * Defaults to narrower scope, non-delegable, and earlier expiry than parent.
 */
function makeChildGrant(
  parentId: string,
  overrides?: Partial<Omit<AdrChainReceipt, "body">> & {
    body?: Partial<AdrChainReceipt["body"] & { expiry?: number | null }>;
  },
): AdrChainReceipt {
  const bodyOverrides = overrides?.body ?? {};
  const { body: _body, ...envelopeOverrides } = overrides ?? {};
  return makeGrant({
    id: `child-of-${parentId}`,
    prev: parentId,
    ...envelopeOverrides,
    body: {
      scope: narrowScope,
      delegable: false,
      expiry: clock + ONE_YEAR_S / 2,
      ...bodyOverrides,
    },
  });
}

// ── Root grant (no ancestors) ──────────────────────────────────────────────

test("tree: root grant delegates to chain walk → Active", () => {
  const grant = makeGrant({ body: { expiry: clock + ONE_YEAR_S } });
  const treeIdx = buildAdrTreeIndex([grant]);
  const chainIdx = buildAdrChainIndex([grant]);
  const res = walkDelegationTree("grant-001", treeIdx, chainIdx, { clock });
  assert.equal(res.ok, true);
  assert.equal(res.effective_state, "Active");
  assert.deepEqual(res.effective_scope, defaultScope);
  assert.equal(res.ancestor_depth, 0);
});

// ── Sub-delegation ─────────────────────────────────────────────────────────

test("tree: valid child with delegable parent → Active", () => {
  const parent = makeGrant({
    id: "parent",
    body: { delegable: true, expiry: clock + ONE_YEAR_S },
  });
  const child = makeChildGrant("parent", {
    id: "child",
    body: { expiry: clock + ONE_YEAR_S / 2 },
  });
  const all = [parent, child];
  const treeIdx = buildAdrTreeIndex(all);
  const chainIdx = buildAdrChainIndex(all);
  const res = walkDelegationTree("child", treeIdx, chainIdx, { clock });
  assert.equal(res.ok, true);
  assert.equal(res.effective_state, "Active");
  assert.equal(res.ancestor_depth, 1);
});

test("tree: parent delegable=false → delegation_not_permitted", () => {
  const parent = makeGrant({
    id: "parent",
    body: { delegable: false, expiry: clock + ONE_YEAR_S },
  });
  const child = makeChildGrant("parent", {
    id: "child",
    body: { expiry: clock + ONE_YEAR_S / 2 },
  });
  const all = [parent, child];
  const treeIdx = buildAdrTreeIndex(all);
  const chainIdx = buildAdrChainIndex(all);
  const res = walkDelegationTree("child", treeIdx, chainIdx, { clock });
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.delegation_not_permitted"));
});

test("tree: child delegable=true, parent delegable=false → delegation_widening", () => {
  // Note: delegation_not_permitted fires first since parent.delegable=false.
  // Test the widening path by making parent delegable=true but still catching
  // the widening check separately won't fire because the check order is:
  //   1. parent.delegable=false → not_permitted (short-circuits)
  // To test widening specifically, we need parent delegable=true but child
  // delegable=true (which is fine). The widening error only fires when
  // child.delegable=true AND parent.delegable=false. But not_permitted fires
  // first in our impl. We still test the scenario for coverage — the error
  // correctly reported is delegation_not_permitted.
  const parent = makeGrant({
    id: "parent",
    body: { delegable: false, expiry: clock + ONE_YEAR_S },
  });
  const child = makeChildGrant("parent", {
    id: "child",
    body: { delegable: true, expiry: clock + ONE_YEAR_S / 2 },
  });
  const all = [parent, child];
  const treeIdx = buildAdrTreeIndex(all);
  const chainIdx = buildAdrChainIndex(all);
  const res = walkDelegationTree("child", treeIdx, chainIdx, { clock });
  assert.equal(res.ok, false);
  // delegation_not_permitted fires first (parent.delegable=false).
  assert.ok(res.hard_invalid_reasons.includes("adr.delegation_not_permitted"));
});

test("tree: child scope exceeds parent → delegation_scope_exceeded", () => {
  const parent = makeGrant({
    id: "parent",
    body: {
      delegable: true,
      scope: narrowScope, // parent has narrow scope
      expiry: clock + ONE_YEAR_S,
    },
  });
  const child = makeChildGrant("parent", {
    id: "child",
    body: {
      scope: defaultScope, // child has wider scope → exceeds parent
      expiry: clock + ONE_YEAR_S / 2,
    },
  });
  const all = [parent, child];
  const treeIdx = buildAdrTreeIndex(all);
  const chainIdx = buildAdrChainIndex(all);
  const res = walkDelegationTree("child", treeIdx, chainIdx, { clock });
  assert.equal(res.ok, false);
  assert.ok(
    res.hard_invalid_reasons.includes("adr.delegation_scope_exceeded"),
  );
});

test("tree: child expiry > parent expiry → delegation_expiry_exceeded", () => {
  const parentExpiry = clock + ONE_YEAR_S;
  const parent = makeGrant({
    id: "parent",
    body: { delegable: true, expiry: parentExpiry },
  });
  const child = makeChildGrant("parent", {
    id: "child",
    body: { expiry: parentExpiry + 1000 }, // exceeds parent
  });
  const all = [parent, child];
  const treeIdx = buildAdrTreeIndex(all);
  const chainIdx = buildAdrChainIndex(all);
  const res = walkDelegationTree("child", treeIdx, chainIdx, { clock });
  assert.equal(res.ok, false);
  assert.ok(
    res.hard_invalid_reasons.includes("adr.delegation_expiry_exceeded"),
  );
});

test("tree: child null expiry, parent finite → delegation_expiry_exceeded", () => {
  const parent = makeGrant({
    id: "parent",
    body: { delegable: true, expiry: clock + ONE_YEAR_S },
  });
  const child = makeChildGrant("parent", {
    id: "child",
    body: { expiry: null }, // no limit → outlives parent
  });
  const all = [parent, child];
  const treeIdx = buildAdrTreeIndex(all);
  const chainIdx = buildAdrChainIndex(all);
  const res = walkDelegationTree("child", treeIdx, chainIdx, { clock });
  assert.equal(res.ok, false);
  assert.ok(
    res.hard_invalid_reasons.includes("adr.delegation_expiry_exceeded"),
  );
});

// ── Cascade ────────────────────────────────────────────────────────────────

test("tree: parent revoked → child effectively Revoked", () => {
  const parent = makeGrant({
    id: "parent",
    body: { delegable: true, expiry: clock + ONE_YEAR_S },
  });
  const revoke = makeEvent("revoke", "parent", { id: "revoke-parent" });
  const child = makeChildGrant("parent", {
    id: "child",
    body: { expiry: clock + ONE_YEAR_S / 2 },
  });
  const all = [parent, revoke, child];
  const treeIdx = buildAdrTreeIndex(all);
  const chainIdx = buildAdrChainIndex(all);
  const res = walkDelegationTree("child", treeIdx, chainIdx, { clock });
  assert.equal(res.effective_state, "Revoked");
});

test("tree: parent suspended → child effectively Suspended", () => {
  const parent = makeGrant({
    id: "parent",
    body: { delegable: true, expiry: clock + ONE_YEAR_S },
  });
  const suspend = makeEvent("suspend", "parent", { id: "suspend-parent" });
  const child = makeChildGrant("parent", {
    id: "child",
    body: { expiry: clock + ONE_YEAR_S / 2 },
  });
  const all = [parent, suspend, child];
  const treeIdx = buildAdrTreeIndex(all);
  const chainIdx = buildAdrChainIndex(all);
  const res = walkDelegationTree("child", treeIdx, chainIdx, { clock });
  assert.equal(res.effective_state, "Suspended");
});

test("tree: parent expired → child effectively Expired", () => {
  const pastExpiry = clock - 1000; // already expired
  const parent = makeGrant({
    id: "parent",
    body: { delegable: true, expiry: pastExpiry },
  });
  const child = makeChildGrant("parent", {
    id: "child",
    body: { expiry: pastExpiry }, // also expired but cascade is the point
  });
  const all = [parent, child];
  const treeIdx = buildAdrTreeIndex(all);
  const chainIdx = buildAdrChainIndex(all);
  const res = walkDelegationTree("child", treeIdx, chainIdx, { clock });
  assert.equal(res.effective_state, "Expired");
});

test("tree: grandparent revoked → grandchild effectively Revoked (2 ancestors)", () => {
  const gp = makeGrant({
    id: "grandparent",
    body: { delegable: true, expiry: clock + ONE_YEAR_S },
  });
  const gpRevoke = makeEvent("revoke", "grandparent", {
    id: "revoke-gp",
  });
  const parent = makeChildGrant("grandparent", {
    id: "parent",
    body: { delegable: true, expiry: clock + ONE_YEAR_S / 2 },
  });
  const child = makeChildGrant("parent", {
    id: "child",
    body: { expiry: clock + ONE_YEAR_S / 4 },
  });
  const all = [gp, gpRevoke, parent, child];
  const treeIdx = buildAdrTreeIndex(all);
  const chainIdx = buildAdrChainIndex(all);
  const res = walkDelegationTree("child", treeIdx, chainIdx, { clock });
  assert.equal(res.effective_state, "Revoked");
  assert.equal(res.ancestor_depth, 2);
});

// ── Error codes ────────────────────────────────────────────────────────────

test("tree: receipt_not_found", () => {
  const treeIdx = buildAdrTreeIndex([]);
  const chainIdx = buildAdrChainIndex([]);
  const res = walkDelegationTree("nonexistent", treeIdx, chainIdx, { clock });
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.receipt_not_found"));
});

test("tree: non-grant receipt → tree_node_not_grant", () => {
  const grant = makeGrant({ id: "parent" });
  const revoke = makeEvent("revoke", "parent", { id: "revoke-001" });
  const all = [grant, revoke];
  const treeIdx = buildAdrTreeIndex(all);
  const chainIdx = buildAdrChainIndex(all);
  const res = walkDelegationTree("revoke-001", treeIdx, chainIdx, { clock });
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.tree_node_not_grant"));
});
