/**
 * Tests for the AER chain walker and transparency-backing check (spec §7).
 *
 * Coverage:
 *   Conformity chain walk: single-receipt root, two-receipt re-assessment,
 *   cycle, dangling prev, issuer inconsistency, non-conformity member.
 *
 *   Transparency backing: in-force conformity (backed), expired conformity,
 *   conformity not yet valid, conformity not found.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AerChainReceipt } from "../src/types.ts";
import {
  buildAerChainIndex,
  walkAerConformityChain,
  checkTransparencyBacking,
} from "../src/chain.ts";
import { makeConformityBody, makeTransparencyBody, sha256Hex } from "./_helpers/fixtures.ts";

const ISS = "did:web:provider.example";
const ISS_OTHER = "did:web:other-provider.example";

// ── Receipt-builder shorthand ─────────────────────────────────────────────────

function makeChainReceipt(
  id: string,
  body: AerChainReceipt["body"],
  opts: { prev?: string | null; iss?: string; iat?: string; subject?: string | null } = {},
): AerChainReceipt {
  return {
    id,
    iss: opts.iss ?? ISS,
    iat: opts.iat ?? "2026-05-21T00:00:00Z",
    prev: opts.prev ?? null,
    subject: opts.subject ?? null,
    body,
  };
}

// ── Conformity chain: single-receipt (root) — ok ─────────────────────────────

test("conformity chain: single-receipt root — ok", () => {
  const r = makeChainReceipt("c-root", makeConformityBody());
  const idx = buildAerChainIndex([r]);
  const res = walkAerConformityChain("c-root", idx);
  assert.equal(res.ok, true);
  assert.deepEqual(res.hard_invalid_reasons, []);
  assert.deepEqual(res.warnings, []);
});

// ── Conformity chain: two-receipt re-assessment — ok ─────────────────────────

test("conformity chain: two-receipt re-assessment — ok", () => {
  const root = makeChainReceipt("c-root", makeConformityBody());
  const reassessment = makeChainReceipt("c-new", makeConformityBody(), { prev: "c-root" });
  const idx = buildAerChainIndex([root, reassessment]);
  const res = walkAerConformityChain("c-new", idx);
  assert.equal(res.ok, true);
  assert.deepEqual(res.hard_invalid_reasons, []);
});

// ── Conformity chain: cycle detected — hard fail ─────────────────────────────

test("conformity chain: cycle detected → aer.chain_cycle_detected", () => {
  const a = makeChainReceipt("c-a", makeConformityBody(), { prev: "c-b" });
  const b = makeChainReceipt("c-b", makeConformityBody(), { prev: "c-a" });
  const idx = buildAerChainIndex([a, b]);
  const res = walkAerConformityChain("c-a", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("aer.chain_cycle_detected"));
});

// ── Conformity chain: dangling prev — hard fail ───────────────────────────────

test("conformity chain: dangling prev → aer.chain_prev_unresolved", () => {
  const r = makeChainReceipt("c-latest", makeConformityBody(), { prev: "c-missing" });
  const idx = buildAerChainIndex([r]);
  const res = walkAerConformityChain("c-latest", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("aer.chain_prev_unresolved"));
});

// ── Conformity chain: issuer inconsistency — hard fail ───────────────────────

test("conformity chain: issuer inconsistency → aer.issuer_inconsistent", () => {
  const root = makeChainReceipt("c-root", makeConformityBody(), { iss: ISS_OTHER });
  const latest = makeChainReceipt("c-latest", makeConformityBody(), {
    prev: "c-root",
    iss: ISS,
  });
  const idx = buildAerChainIndex([root, latest]);
  const res = walkAerConformityChain("c-latest", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("aer.issuer_inconsistent"));
});

// ── Conformity chain: non-conformity member — hard fail ──────────────────────

test("conformity chain: transparency node in chain → aer.non_conformity_in_chain", () => {
  // A transparency receipt sneaked into a conformity chain.
  const root = makeChainReceipt("c-root", makeConformityBody());
  const transparency = makeChainReceipt(
    "t-bad",
    makeTransparencyBody(),
    { prev: "c-root", subject: sha256Hex() },
  );
  const idx = buildAerChainIndex([root, transparency]);
  const res = walkAerConformityChain("t-bad", idx);
  assert.equal(res.ok, false);
  assert.ok(res.hard_invalid_reasons.includes("aer.non_conformity_in_chain"));
});

// ── Transparency backing: conformity in-force — backed ────────────────────────

test("transparency backing: conformity in-force → backed", () => {
  const conformity = makeChainReceipt(
    "c-hash-001",
    makeConformityBody({
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2028-01-01T00:00:00Z",
    }),
  );
  const transparency = makeChainReceipt(
    "t-001",
    makeTransparencyBody({
      conformity_receipt_hash: "c-hash-001",
      interaction_window_start: "2026-09-01T10:00:00Z",
    }),
    { subject: sha256Hex() },
  );
  const result = checkTransparencyBacking(transparency, (hash) =>
    hash === "c-hash-001" ? conformity : undefined,
  );
  assert.equal(result.backed, true);
});

// ── Transparency backing: conformity expired — not backed ─────────────────────

test("transparency backing: conformity expired → not backed", () => {
  const conformity = makeChainReceipt(
    "c-expired",
    makeConformityBody({
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2026-06-01T00:00:00Z",
    }),
  );
  const transparency = makeChainReceipt(
    "t-002",
    makeTransparencyBody({
      conformity_receipt_hash: "c-expired",
      // Interaction is after conformity expired
      interaction_window_start: "2026-09-01T10:00:00Z",
    }),
    { subject: sha256Hex() },
  );
  const result = checkTransparencyBacking(transparency, (hash) =>
    hash === "c-expired" ? conformity : undefined,
  );
  assert.equal(result.backed, false);
  assert.equal(result.reason, "conformity_expired");
});

// ── Transparency backing: conformity not yet valid — not backed ───────────────

test("transparency backing: conformity not yet valid → not backed", () => {
  const conformity = makeChainReceipt(
    "c-future",
    makeConformityBody({
      // Conformity starts after the interaction
      valid_from: "2027-01-01T00:00:00Z",
      valid_until: "2029-01-01T00:00:00Z",
    }),
  );
  const transparency = makeChainReceipt(
    "t-003",
    makeTransparencyBody({
      conformity_receipt_hash: "c-future",
      interaction_window_start: "2026-09-01T10:00:00Z",
    }),
    { subject: sha256Hex() },
  );
  const result = checkTransparencyBacking(transparency, (hash) =>
    hash === "c-future" ? conformity : undefined,
  );
  assert.equal(result.backed, false);
  assert.equal(result.reason, "conformity_not_yet_valid");
});

// ── Transparency backing: conformity not found — not backed ───────────────────

test("transparency backing: conformity not found → not backed", () => {
  const transparency = makeChainReceipt(
    "t-004",
    makeTransparencyBody({
      conformity_receipt_hash: "sha256:" + "d".repeat(64),
    }),
    { subject: sha256Hex() },
  );
  const result = checkTransparencyBacking(transparency, () => undefined);
  assert.equal(result.backed, false);
  assert.equal(result.reason, "conformity_not_found");
});
