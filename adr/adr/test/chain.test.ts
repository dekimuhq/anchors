/**
 * Tests for the ADR chain walker + state machine (spec §7.1).
 *
 * Builds in-memory chain fixtures via AdrChainReceipt projections (no
 * envelope-level cryptography needed — the walker treats receipts as
 * already body-verified).
 *
 * ~20 tests covering: grant root, state transitions, invalid transitions,
 * narrow scope-subset, expiry, structural errors, renew.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildAdrChainIndex,
  walkAdrChain,
} from "../src/chain.ts";
import { H, makeGrant, makeEvent, defaultScope } from "./_helpers/common.ts";
import type { AdrScope } from "../src/types.ts";

// ── Grant (root) ────────────────────────────────────────────────────────────

test("chain: single grant → Active", () => {
  const grant = makeGrant();
  const idx = buildAdrChainIndex([grant]);
  const res = walkAdrChain("grant-001", idx);
  assert.equal(res.ok, true);
  assert.equal(res.state, "Active");
  assert.deepEqual(res.effective_scope, defaultScope);
  assert.deepEqual(res.hard_invalid_reasons, []);
  assert.equal(res.chain_summary?.root_id, "grant-001");
  assert.equal(res.chain_summary?.depth, 1);
  assert.equal(res.chain_summary?.last_event, "grant");
});

// ── State transitions ───────────────────────────────────────────────────────

test("chain: grant → suspend → Suspended", () => {
  const grant = makeGrant();
  const suspend = makeEvent("suspend", "grant-001");
  const idx = buildAdrChainIndex([grant, suspend]);
  const res = walkAdrChain("suspend-grant-001", idx);
  assert.equal(res.ok, true);
  assert.equal(res.state, "Suspended");
});

test("chain: grant → suspend → resume → Active", () => {
  const grant = makeGrant();
  const suspend = makeEvent("suspend", "grant-001");
  const resume = makeEvent("resume", "suspend-grant-001", {
    id: "resume-001",
  });
  const idx = buildAdrChainIndex([grant, suspend, resume]);
  const res = walkAdrChain("resume-001", idx);
  assert.equal(res.ok, true);
  assert.equal(res.state, "Active");
});

test("chain: grant → revoke → Revoked (terminal)", () => {
  const grant = makeGrant();
  const revoke = makeEvent("revoke", "grant-001");
  const idx = buildAdrChainIndex([grant, revoke]);
  const res = walkAdrChain("revoke-grant-001", idx);
  assert.equal(res.ok, true);
  assert.equal(res.state, "Revoked");
});

test("chain: grant → suspend → revoke → Revoked", () => {
  const grant = makeGrant();
  const suspend = makeEvent("suspend", "grant-001");
  const revoke = makeEvent("revoke", "suspend-grant-001", {
    id: "revoke-001",
  });
  const idx = buildAdrChainIndex([grant, suspend, revoke]);
  const res = walkAdrChain("revoke-001", idx);
  assert.equal(res.ok, true);
  assert.equal(res.state, "Revoked");
});

// ── Invalid transitions ─────────────────────────────────────────────────────

test("chain: resume from Active → adr.state_machine_invalid", () => {
  const grant = makeGrant();
  const resume = makeEvent("resume", "grant-001");
  const idx = buildAdrChainIndex([grant, resume]);
  const res = walkAdrChain("resume-grant-001", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.state_machine_invalid"));
});

test("chain: suspend from Suspended → adr.state_machine_invalid", () => {
  const grant = makeGrant();
  const suspend1 = makeEvent("suspend", "grant-001");
  const suspend2 = makeEvent("suspend", "suspend-grant-001", {
    id: "suspend-002",
  });
  const idx = buildAdrChainIndex([grant, suspend1, suspend2]);
  const res = walkAdrChain("suspend-002", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.state_machine_invalid"));
});

test("chain: event after Revoked → adr.chain_terminal", () => {
  const grant = makeGrant();
  const revoke = makeEvent("revoke", "grant-001");
  const resume = makeEvent("resume", "revoke-grant-001", {
    id: "resume-after-revoke",
  });
  const idx = buildAdrChainIndex([grant, revoke, resume]);
  const res = walkAdrChain("resume-after-revoke", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.chain_terminal"));
});

// ── Narrow ──────────────────────────────────────────────────────────────────

test("chain: valid narrow reduces effective scope", () => {
  const grant = makeGrant();
  const narrowedScope: AdrScope = {
    actions: ["inference.run"],
    resources: ["model:gpt-4:*"],
    constraints: { max_requests: 500, region: "eu-west" },
  };
  const narrow = makeEvent("narrow", "grant-001", {
    body: { scope: narrowedScope },
  });
  const idx = buildAdrChainIndex([grant, narrow]);
  const res = walkAdrChain("narrow-grant-001", idx);
  assert.equal(res.ok, true);
  assert.equal(res.state, "Active");
  assert.deepEqual(res.effective_scope, narrowedScope);
});

test("chain: widening narrow rejected → adr.scope_widening", () => {
  const grant = makeGrant();
  const wideningScope: AdrScope = {
    actions: ["inference.run", "inference.explain", "inference.finetune"],
    resources: ["model:gpt-4:*", "dataset:training:v1"],
    constraints: { max_requests: 1000, region: "eu-west" },
  };
  const narrow = makeEvent("narrow", "grant-001", {
    body: { scope: wideningScope },
  });
  const idx = buildAdrChainIndex([grant, narrow]);
  const res = walkAdrChain("narrow-grant-001", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.scope_widening"));
});

test("chain: narrow from Suspended → adr.state_machine_invalid", () => {
  const grant = makeGrant();
  const suspend = makeEvent("suspend", "grant-001");
  const narrow = makeEvent("narrow", "suspend-grant-001", {
    id: "narrow-susp",
  });
  const idx = buildAdrChainIndex([grant, suspend, narrow]);
  const res = walkAdrChain("narrow-susp", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.state_machine_invalid"));
});

// ── Expiry ──────────────────────────────────────────────────────────────────

test("chain: expired grant → state = Expired", () => {
  const pastExpiry = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
  const grant = makeGrant({ body: { expiry: pastExpiry } });
  const idx = buildAdrChainIndex([grant]);
  const res = walkAdrChain("grant-001", idx);
  assert.equal(res.ok, true);
  assert.equal(res.state, "Expired");
});

test("chain: null expiry → indefinite, stays Active", () => {
  const grant = makeGrant({ body: { expiry: null } });
  const idx = buildAdrChainIndex([grant]);
  const res = walkAdrChain("grant-001", idx);
  assert.equal(res.ok, true);
  assert.equal(res.state, "Active");
});

test("chain: explicit clock triggers expiry", () => {
  const grant = makeGrant({ body: { expiry: 1000 } });
  const idx = buildAdrChainIndex([grant]);
  // clock=2000 → past expiry
  const res = walkAdrChain("grant-001", idx, { clock: 2000 });
  assert.equal(res.state, "Expired");
  // clock=500 → before expiry
  const res2 = walkAdrChain("grant-001", idx, { clock: 500 });
  assert.equal(res2.state, "Active");
});

// ── Structural errors ───────────────────────────────────────────────────────

test("chain: receipt not found → adr.receipt_not_found", () => {
  const idx = buildAdrChainIndex([]);
  const res = walkAdrChain("nonexistent", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.receipt_not_found"));
});

test("chain: cycle detected → adr.chain_cycle_detected", () => {
  const a = makeGrant({ id: "a", prev: "b" as unknown as null });
  // Force cycle: a.prev = "b", b.prev = "a"
  const b = makeEvent("suspend", "a", { id: "b" });
  // Patch a to have prev pointing to b (create cycle)
  const aWithCycle = { ...a, prev: "b" };
  const idx = buildAdrChainIndex([aWithCycle, b]);
  const res = walkAdrChain("a", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.chain_cycle_detected"));
});

test("chain: dangling prev → adr.chain_prev_unresolved", () => {
  const orphan = makeEvent("suspend", "missing-grant", { id: "orphan" });
  const idx = buildAdrChainIndex([orphan]);
  const res = walkAdrChain("orphan", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.chain_prev_unresolved"));
});

test("chain: head not grant → adr.chain_head_not_grant", () => {
  // A suspend with prev=null — structurally wrong head
  const badHead = makeEvent("suspend", "x", { id: "bad-head", prev: null });
  const idx = buildAdrChainIndex([badHead]);
  const res = walkAdrChain("bad-head", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.chain_head_not_grant"));
});

test("chain: issuer inconsistency → adr.issuer_inconsistent", () => {
  const grant = makeGrant();
  const suspend = makeEvent("suspend", "grant-001", {
    iss: "did:web:evil.example",
  });
  const idx = buildAdrChainIndex([grant, suspend]);
  const res = walkAdrChain("suspend-grant-001", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.issuer_inconsistent"));
});

test("chain: subject inconsistency → adr.subject_inconsistent", () => {
  const grant = makeGrant();
  const suspend = makeEvent("suspend", "grant-001", {
    subject: H("x"),
  });
  const idx = buildAdrChainIndex([grant, suspend]);
  const res = walkAdrChain("suspend-grant-001", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.subject_inconsistent"));
});

test("chain: depth exceeded → adr.chain_depth_exceeded", () => {
  // Build a chain longer than the minimum depth limit (4).
  const grant = makeGrant({ id: "g" });
  const receipts = [grant];
  let prevId = "g";
  // 5 more events → total 6 hops, exceeds depthLimit=1 (clamped to 4)
  for (let i = 0; i < 5; i++) {
    const evt = makeEvent("suspend", prevId, {
      id: `s-${i}`,
      // Alternate suspend/resume to stay valid
    });
    // Actually we need valid transitions — use suspend/resume pairs
    // But for depth test, the walker should bail before state machine.
    // Just chain suspends — walker checks depth before event validation.
    receipts.push(evt);
    prevId = `s-${i}`;
  }
  const idx = buildAdrChainIndex(receipts);
  // depthLimit=1 clamps to 4 (MIN); chain has 6 hops → exceeds
  const res = walkAdrChain(prevId, idx, { depthLimit: 1 });
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("adr.chain_depth_exceeded"));
});

// ── Renew ───────────────────────────────────────────────────────────────────

test("chain: renew extends expiry", () => {
  const futureExpiry = Math.floor(Date.now() / 1000) + 365 * 24 * 3600;
  const farFuture = futureExpiry + 365 * 24 * 3600;
  const grant = makeGrant({ body: { expiry: futureExpiry } });
  const renew = makeEvent("renew", "grant-001", {
    body: { expiry: farFuture },
  });
  const idx = buildAdrChainIndex([grant, renew]);
  const res = walkAdrChain("renew-grant-001", idx);
  assert.equal(res.ok, true);
  assert.equal(res.state, "Active");
  assert.deepEqual(res.warnings, []);
});

test("chain: renew with shorter expiry warns", () => {
  const futureExpiry = Math.floor(Date.now() / 1000) + 365 * 24 * 3600;
  const shorterExpiry = futureExpiry - 100;
  const grant = makeGrant({ body: { expiry: futureExpiry } });
  const renew = makeEvent("renew", "grant-001", {
    body: { expiry: shorterExpiry },
  });
  const idx = buildAdrChainIndex([grant, renew]);
  const res = walkAdrChain("renew-grant-001", idx);
  assert.equal(res.ok, true);
  assert.ok(res.warnings.includes("adr.renew_expiry_not_extended"));
});

test("chain: renew from Suspended valid", () => {
  const futureExpiry = Math.floor(Date.now() / 1000) + 365 * 24 * 3600;
  const farFuture = futureExpiry + 365 * 24 * 3600;
  const grant = makeGrant({ body: { expiry: futureExpiry } });
  const suspend = makeEvent("suspend", "grant-001");
  const renew = makeEvent("renew", "suspend-grant-001", {
    id: "renew-susp",
    body: { expiry: farFuture },
  });
  const idx = buildAdrChainIndex([grant, suspend, renew]);
  const res = walkAdrChain("renew-susp", idx);
  assert.equal(res.ok, true);
  assert.equal(res.state, "Suspended"); // renew does not change state
});

// ── Index dedup ─────────────────────────────────────────────────────────────

test("buildAdrChainIndex: duplicate IDs keep first occurrence", () => {
  const a = makeGrant({ id: "a" });
  const aPrime = makeGrant({ id: "a", body: { delegable: true } });
  const idx = buildAdrChainIndex([a, aPrime]);
  const found = idx.byId.get("a");
  assert.equal((found?.body as { delegable: boolean }).delegable, false);
});
