import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isScopeSubset, segmentMatch } from "../src/scope.ts";
import type { AdrScope } from "../src/types.ts";

const parent: AdrScope = {
  actions: ["invoice.create", "invoice.send", "invoice.void"],
  resources: ["acme:customer:*"],
  constraints: {
    max_amount_eur: 5000,
    tool_allowlist: ["resend", "stripe"],
    sub_processing_allowed: true,
  },
};

describe("segmentMatch", () => {
  it("exact match", () => assert.equal(segmentMatch("invoice.create", "invoice.create", "."), true));
  it("trailing wildcard matches all", () => {
    assert.equal(segmentMatch("invoice.*", "invoice.create", "."), true);
    assert.equal(segmentMatch("invoice.*", "invoice.send", "."), true);
  });
  it("trailing wildcard matches deeper", () => assert.equal(segmentMatch("acme:*", "acme:customer:123", ":"), true));
  it("non-trailing wildcard matches one segment", () => {
    assert.equal(segmentMatch("acme:*:123", "acme:customer:123", ":"), true);
    assert.equal(segmentMatch("acme:*:123", "acme:dept:sub:123", ":"), false);
  });
  it("no match when too few segments", () => assert.equal(segmentMatch("a.b.c", "a.b", "."), false));
  it("no match when segments differ", () => assert.equal(segmentMatch("a.b", "a.c", "."), false));
});

describe("isScopeSubset", () => {
  describe("actions", () => {
    it("exact subset passes", () => {
      const r = isScopeSubset({ ...parent, actions: ["invoice.create"] }, parent);
      assert.equal(r.ok, true);
    });
    it("action not in parent fails", () => {
      const r = isScopeSubset({ ...parent, actions: ["invoice.delete"] }, parent);
      assert.equal(r.ok, false);
    });
    it("parent wildcard covers child", () => {
      const wParent: AdrScope = { ...parent, actions: ["invoice.*"] };
      const r = isScopeSubset({ ...parent, actions: ["invoice.create", "invoice.send"] }, wParent);
      assert.equal(r.ok, true);
    });
  });
  describe("resources", () => {
    it("resource covered by glob passes", () => {
      const r = isScopeSubset({ ...parent, resources: ["acme:customer:123"] }, parent);
      assert.equal(r.ok, true);
    });
    it("resource not covered fails", () => {
      const r = isScopeSubset({ ...parent, resources: ["other:dept:456"] }, parent);
      assert.equal(r.ok, false);
    });
  });
  describe("constraints", () => {
    it("numeric child <= parent passes", () => {
      const r = isScopeSubset({ ...parent, constraints: { ...parent.constraints, max_amount_eur: 3000 } }, parent);
      assert.equal(r.ok, true);
    });
    it("numeric child > parent fails", () => {
      const r = isScopeSubset({ ...parent, constraints: { ...parent.constraints, max_amount_eur: 10000 } }, parent);
      assert.equal(r.ok, false);
    });
    it("allowlist subset passes", () => {
      const r = isScopeSubset({ ...parent, constraints: { ...parent.constraints, tool_allowlist: ["stripe"] } }, parent);
      assert.equal(r.ok, true);
    });
    it("allowlist not subset fails", () => {
      const r = isScopeSubset({ ...parent, constraints: { ...parent.constraints, tool_allowlist: ["paypal"] } }, parent);
      assert.equal(r.ok, false);
    });
    it("boolean widening fails", () => {
      const narrow = { ...parent, constraints: { ...parent.constraints, sub_processing_allowed: false } };
      const r = isScopeSubset({ ...parent, constraints: { ...parent.constraints, sub_processing_allowed: true } }, narrow);
      assert.equal(r.ok, false);
    });
    it("child introducing new constraint is allowed", () => {
      const r = isScopeSubset({ ...parent, constraints: { ...parent.constraints, new_limit: 100 } }, parent);
      assert.equal(r.ok, true);
    });
  });
  it("equal scopes pass", () => {
    const r = isScopeSubset(parent, parent);
    assert.equal(r.ok, true);
  });
});
