import { test } from "node:test";
import assert from "node:assert/strict";
import { makeInclusionProofEffectiveTime } from "../src/effective-time.ts";
import type { PinnedCheckpoint } from "../src/effective-time.ts";
import type { InclBlock } from "../src/types.ts";
import { merkleRoot, auditPath } from "../src/tree.ts";
import { leafHash } from "../src/leaf.ts";
import { hashLeaf } from "../src/rfc6962.ts";

// --- fixtures -------------------------------------------------------------
// Leaves are the family-canonical leafHash() of REAL receipt bodies, because the
// resolver binds incl.leaf to leafHash(receipt \ {incl}). A leaf untied to a body
// can never validate, so fixtures must carry the body the leaf hashes from.

const BODIES = Array.from({ length: 5 }, (_, i) => ({ claim_type: "ar.consent.v1", n: i }));

function leafStr(i: number): string {
  const body = BODIES[i];
  if (!body) throw new Error(`body ${i} undefined`);
  return leafHash(body); // "sha256:<hex>"
}
function leafBuf(i: number): Buffer {
  return Buffer.from(leafStr(i).slice("sha256:".length), "hex");
}

const LEAVES = BODIES.map((_, i) => leafBuf(i));
const ROOT_B64 = merkleRoot(LEAVES).toString("base64");

function selfDescribing(b: Buffer): string {
  return `sha256:${b.toString("hex")}`;
}

function proofAt(index: number, treeSize = 5, leaves = LEAVES) {
  return {
    index,
    tree_size: treeSize,
    path: auditPath(leaves, index).map(selfDescribing),
    // Deliberately junk: the resolver MUST NOT trust the embedded checkpoint
    // note — it trusts the pinned root + the hash-based audit path only.
    checkpoint: "junk",
  };
}

/** A full receipt envelope: the body + a canonical top-level `incl` block. */
function envAt(index: number, logId = "L"): Record<string, unknown> {
  return { ...BODIES[index], incl: { log_id: logId, leaf: leafStr(index), proof: proofAt(index) } };
}

function pin(over: Partial<PinnedCheckpoint> = {}): PinnedCheckpoint {
  return { origin: "L", size: 5, rootHashB64: ROOT_B64, witnessedAt: "2026-01-01T00:00:00Z", ...over };
}

const extract = (env: unknown): InclBlock | null =>
  (env as { incl?: InclBlock }).incl ?? null;

function resolver(pins: PinnedCheckpoint[], extractInclusion = extract) {
  return makeInclusionProofEffectiveTime({ pinnedCheckpoints: pins, extractInclusion });
}

// --- happy path -----------------------------------------------------------

test("returns the pinned witnessedAt for a valid, leaf-bound proof — trusting the pin, not the junk checkpoint", () => {
  const got = resolver([pin()])(envAt(3));
  assert.ok(got instanceof Date);
  assert.equal(got.toISOString(), "2026-01-01T00:00:00.000Z");
});

test("works for every leaf index in the tree", () => {
  const resolve = resolver([pin()]);
  for (let i = 0; i < LEAVES.length; i++) {
    assert.ok(resolve(envAt(i)) instanceof Date, `index ${i} should resolve`);
  }
});

test("works for a legitimate single-leaf tree (empty path, leaf === root)", () => {
  const body = { claim_type: "ar.consent.v1", solo: true };
  const lh = leafHash(body);
  const root = merkleRoot([Buffer.from(lh.slice("sha256:".length), "hex")]);
  const env = { ...body, incl: { log_id: "S", leaf: lh, proof: { index: 0, tree_size: 1, path: [], checkpoint: "x" } } };
  const got = resolver([{ origin: "S", size: 1, rootHashB64: root.toString("base64"), witnessedAt: "2026-01-01T00:00:00Z" }])(env);
  assert.equal(got?.toISOString(), "2026-01-01T00:00:00.000Z");
});

test("picks the EARLIEST witnessedAt when several pins of the same tree validate", () => {
  const resolve = resolver([
    pin({ witnessedAt: "2026-03-01T00:00:00Z" }),
    pin({ witnessedAt: "2026-01-01T00:00:00Z" }),
    pin({ witnessedAt: "2026-02-01T00:00:00Z" }),
  ]);
  assert.equal(resolve(envAt(3))?.toISOString(), "2026-01-01T00:00:00.000Z");
});

// --- the critical refusals (quantum-safety / soundness) -------------------

test("CRITICAL: REFUSES a leaf stapled from another logged receipt (leaf-binding)", () => {
  // incl.leaf is a genuinely-logged leaf (index 3), but the body is a DIFFERENT,
  // forged receipt → leafHash(body) !== incl.leaf → must reject.
  const forged = { claim_type: "ar.consent.v1", n: 999, incl: { log_id: "L", leaf: leafStr(3), proof: proofAt(3) } };
  assert.equal(resolver([pin()])(forged), null);
});

test("CRITICAL: REFUSES an empty-path proof with leaf === pinned root (rfc6962 short-path hole)", () => {
  // The classic exploit: empty path, leaf set to the public pinned root, tree_size
  // = pin.size. Blocked twice over — by leaf-binding AND the path-length guard.
  const rootHex = Buffer.from(ROOT_B64, "base64").toString("hex");
  const attack = { n: 1, incl: { log_id: "L", leaf: `sha256:${rootHex}`, proof: { index: 0, tree_size: 5, path: [], checkpoint: "junk" } } };
  assert.equal(resolver([pin()])(attack), null);
});

test("CRITICAL: REFUSES a path that is too short for its (index, tree_size)", () => {
  const env = envAt(3);
  (env.incl as { proof: { path: string[] } }).proof.path = []; // 5-leaf tree needs 3 entries
  assert.equal(resolver([pin()])(env), null);
});

test("CRITICAL: REFUSES a path that is too long for its (index, tree_size)", () => {
  const env = envAt(3);
  const p = (env.incl as { proof: { path: string[] } }).proof;
  p.path = [...p.path, selfDescribing(hashLeaf(Buffer.from("extra")))];
  assert.equal(resolver([pin()])(env), null);
});

test("REFUSES a promise-only inclusion block — never trusts the Ed25519 SCT timestamp", () => {
  const env = { ...BODIES[3], incl: { log_id: "L", leaf: leafStr(3), promise: { timestamp: "2020-01-01T00:00:00Z", sig: "AAAA" } } };
  assert.equal(resolver([pin()])(env), null);
});

test("returns null when no pinned checkpoint matches the log origin", () => {
  assert.equal(resolver([pin({ origin: "OTHER" })])(envAt(3)), null);
});

test("returns null when the pin set is empty", () => {
  assert.equal(resolver([])(envAt(3)), null);
});

test("returns null for a leaf NOT in the pinned tree (valid path, leaf-bound, but different tree)", () => {
  // A real, leaf-bound receipt whose tree the pin does not commit to.
  const otherLeaves = [leafBuf(0), leafBuf(1)];
  const env = { ...BODIES[0], incl: { log_id: "L", leaf: leafStr(0), proof: { index: 0, tree_size: 2, path: auditPath(otherLeaves, 0).map(selfDescribing), checkpoint: "j" } } };
  assert.equal(resolver([pin()])(env), null); // pin.size 5 ≠ proof.tree_size 2
});

test("returns null when the pin's root mismatches the proof (wrong/forged pin)", () => {
  const otherRoot = merkleRoot([leafBuf(0), leafBuf(1), leafBuf(2), leafBuf(3), hashLeaf(Buffer.from("z"))]).toString("base64");
  assert.equal(resolver([pin({ rootHashB64: otherRoot })])(envAt(3)), null);
});

test("returns null when the pin tree size differs from the proof tree size", () => {
  assert.equal(resolver([pin({ size: 4 })])(envAt(3)), null);
});

test("returns null (fail-closed) for a pin with a non-strict-ISO witnessedAt — even on a valid proof", () => {
  assert.equal(resolver([pin({ witnessedAt: "2026-01-01 00:00:00" })])(envAt(3)), null);
});

// --- malformed input (never throws, always fail-closed) -------------------

test("returns null for a leaf without the sha256: prefix", () => {
  const env = { ...BODIES[3], incl: { log_id: "L", leaf: "deadbeef", proof: proofAt(3) } };
  assert.equal(resolver([pin()])(env), null);
});

test("returns null for a path entry without the sha256: prefix", () => {
  const env = envAt(3);
  (env.incl as { proof: { path: string[] } }).proof.path = [LEAVES[4]!.toString("hex")]; // bare hex
  assert.equal(resolver([pin()])(env), null);
});

test("returns null when index >= tree_size", () => {
  const env = { ...BODIES[3], incl: { log_id: "L", leaf: leafStr(3), proof: { ...proofAt(3), index: 5, tree_size: 5 } } };
  assert.equal(resolver([pin()])(env), null);
});

test("returns null for a non-positive tree size", () => {
  const env = { ...BODIES[3], incl: { log_id: "L", leaf: leafStr(3), proof: { ...proofAt(3), tree_size: 0 } } };
  assert.equal(resolver([pin()])(env), null);
});

test("HIGH: returns null PROMPTLY for an oversized tree_size (no 32-bit-shift hang)", () => {
  // If this hung the whole suite would time out; a fast null proves the cap holds.
  for (const tree_size of [2 ** 31, 2 ** 40, Number.MAX_SAFE_INTEGER]) {
    const env = { ...BODIES[3], incl: { log_id: "L", leaf: leafStr(3), proof: { index: 3, tree_size, path: [], checkpoint: "junk" } } };
    assert.equal(resolver([pin({ size: tree_size })])(env), null);
  }
});

test("returns null when extractInclusion yields nothing", () => {
  assert.equal(resolver([pin()], () => null)(envAt(3)), null);
});

test("never throws — extractInclusion that throws resolves to null", () => {
  const resolve = resolver([pin()], () => {
    throw new Error("boom");
  });
  assert.doesNotThrow(() => assert.equal(resolve({}), null));
});

test("never throws on hostile envelope shapes", () => {
  const resolve = resolver([pin()]);
  for (const env of [undefined, null, 42, "str", { incl: { log_id: "L" } }, { incl: { log_id: "L", proof: {} } }]) {
    assert.doesNotThrow(() => resolve(env));
    assert.equal(resolve(env), null);
  }
});
