/**
 * Property / fuzz tests for inclusion.ts (verifyInclusion + logStatus).
 *
 * End-to-end: build real Merkle trees, sign real checkpoints, produce real proofs,
 * then assert correct acceptance/rejection across mutations and fuzz inputs.
 *
 * Deterministic: no Math.random, no Date.now.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { hashLeaf } from "../src/rfc6962.ts";
import { merkleRoot, auditPath } from "../src/tree.ts";
import { signCheckpoint } from "../src/checkpoint.ts";
import { signPromise } from "../src/promise.ts";
import { verifyInclusion, logStatus } from "../src/inclusion.ts";
import type { InclBlock, InclusionProof } from "../src/types.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type KeyPair = { pub: string; priv: string };

function genKey(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    pub: publicKey.export({ type: "spki", format: "pem" }).toString(),
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

// Pre-generate key pool — reused to keep test runtime reasonable
const KEY_POOL: KeyPair[] = Array.from({ length: 5 }, genKey);

function makeLcg(seed: number) {
  let s = seed >>> 0;
  return function next(): number {
    s = Math.imul(s, 1664525) + 1013904223;
    s = s >>> 0;
    return s;
  };
}

function pseudoHex(lcg: () => number, bytes: number): string {
  return Array.from({ length: bytes }, () =>
    (lcg() % 256).toString(16).padStart(2, "0"),
  ).join("");
}

/** Build n deterministic leaf buffers. */
function buildLeaves(n: number, offset = 0): Buffer[] {
  return Array.from({ length: n }, (_, i) =>
    hashLeaf(Buffer.from(`receipt-${offset + i}`)),
  );
}

/** Encode a leaf buffer as the self-describing "sha256:<hex>" string. */
function sd(buf: Buffer): string {
  return `sha256:${buf.toString("hex")}`;
}

/**
 * Build a full valid proof structure for a given tree and leaf index.
 */
function buildProof(
  leaves: Buffer[],
  idx: number,
  keyPair: KeyPair,
  logId: string,
): InclusionProof {
  const root = merkleRoot(leaves);
  const note = signCheckpoint(
    { origin: logId, size: leaves.length, rootHashB64: root.toString("base64") },
    logId,
    keyPair.priv,
  );
  return {
    index: idx,
    tree_size: leaves.length,
    path: auditPath(leaves, idx).map(sd),
    checkpoint: note,
  };
}

// ---------------------------------------------------------------------------
// 1. End-to-end: valid proof → verifyInclusion accepts, logStatus = logged_proven
// ---------------------------------------------------------------------------

test("verifyInclusion accepts every leaf in trees of size 1..20", () => {
  for (let n = 1; n <= 20; n++) {
    const { pub, priv } = KEY_POOL[n % KEY_POOL.length]!;
    const logId = `log-${n}`;
    const leaves = buildLeaves(n);
    for (let i = 0; i < n; i++) {
      const proof = buildProof(leaves, i, { pub, priv }, logId);
      const leaf = sd(leaves[i]!);
      assert.ok(
        verifyInclusion(leaf, proof, { [logId]: pub }),
        `n=${n} i=${i}: valid inclusion proof should verify`,
      );
    }
  }
});

test("logStatus returns logged_proven for every leaf in trees of size 1..12", () => {
  for (let n = 1; n <= 12; n++) {
    const { pub, priv } = KEY_POOL[n % KEY_POOL.length]!;
    const logId = `log-${n}`;
    const leaves = buildLeaves(n);
    for (let i = 0; i < n; i++) {
      const proof = buildProof(leaves, i, { pub, priv }, logId);
      const incl: InclBlock = {
        log_id: logId,
        leaf: sd(leaves[i]!),
        proof,
      };
      assert.equal(
        logStatus(incl, { [logId]: pub }),
        "logged_proven",
        `n=${n} i=${i}: logStatus should return logged_proven`,
      );
    }
  }
});

test("verifyInclusion accepts large trees (50, 100, 128, 200) at boundary and interior indices", () => {
  const sizes = [50, 100, 128, 200];
  for (const n of sizes) {
    const { pub, priv } = KEY_POOL[0]!;
    const logId = `log-large-${n}`;
    const leaves = buildLeaves(n);
    const indices = [0, 1, n >> 1, n - 2, n - 1];
    for (const i of indices) {
      const proof = buildProof(leaves, i, { pub, priv }, logId);
      assert.ok(
        verifyInclusion(sd(leaves[i]!), proof, { [logId]: pub }),
        `n=${n} i=${i}: valid proof should verify`,
      );
    }
  }
});

// ---------------------------------------------------------------------------
// 2. Mutation of proof fields → incl_invalid (never throw)
// ---------------------------------------------------------------------------

function flipBufByte(buf: Buffer, pos: number): Buffer {
  const copy = Buffer.from(buf);
  const idx = pos % copy.length;
  copy[idx] = (copy[idx]! ^ 0xff) & 0xff;
  return copy;
}

test("wrong leaf fails verifyInclusion for trees of size 2..15", () => {
  for (let n = 2; n <= 15; n++) {
    const { pub, priv } = KEY_POOL[n % KEY_POOL.length]!;
    const logId = `log-${n}`;
    const leaves = buildLeaves(n);
    const i = n >> 1;
    const proof = buildProof(leaves, i, { pub, priv }, logId);
    // Use a DIFFERENT leaf buffer (leaf at i+1 mod n)
    const wrongLeaf = sd(leaves[(i + 1) % n]!);
    assert.equal(
      verifyInclusion(wrongLeaf, proof, { [logId]: pub }),
      false,
      `n=${n}: wrong leaf should fail`,
    );
  }
});

test("wrong index fails verifyInclusion for trees of size 2..15", () => {
  for (let n = 2; n <= 15; n++) {
    const { pub, priv } = KEY_POOL[n % KEY_POOL.length]!;
    const logId = `log-${n}`;
    const leaves = buildLeaves(n);
    const i = 0;
    const proof = buildProof(leaves, i, { pub, priv }, logId);
    const leaf = sd(leaves[i]!);
    const badProof = { ...proof, index: (i + 1) % n };
    assert.equal(
      verifyInclusion(leaf, badProof, { [logId]: pub }),
      false,
      `n=${n}: wrong index should fail`,
    );
  }
});

test("truncated path fails verifyInclusion for trees of size 3..16", () => {
  for (let n = 3; n <= 16; n++) {
    const { pub, priv } = KEY_POOL[n % KEY_POOL.length]!;
    const logId = `log-${n}`;
    const leaves = buildLeaves(n);
    const i = n >> 1;
    const proof = buildProof(leaves, i, { pub, priv }, logId);
    if (proof.path.length === 0) continue;
    const truncated = { ...proof, path: proof.path.slice(0, -1) };
    assert.equal(
      verifyInclusion(sd(leaves[i]!), truncated, { [logId]: pub }),
      false,
      `n=${n}: truncated path should fail`,
    );
  }
});

test("flipping a sibling byte fails verifyInclusion for trees of size 3..16", () => {
  const lcg = makeLcg(0x12ab34cd);
  for (let n = 3; n <= 16; n++) {
    const { pub, priv } = KEY_POOL[n % KEY_POOL.length]!;
    const logId = `log-${n}`;
    const leaves = buildLeaves(n);
    const i = n >> 1;
    const proof = buildProof(leaves, i, { pub, priv }, logId);
    if (proof.path.length === 0) continue;
    const sibIdx = lcg() % proof.path.length;
    // The path entries are "sha256:<hex>" — flip one byte in the hex part
    const corrupted = proof.path.map((entry, j): string => {
      if (j !== sibIdx) return entry;
      const hex = entry.slice(7); // strip "sha256:"
      const buf = Buffer.from(hex, "hex");
      return sd(flipBufByte(buf, lcg() % 32));
    });
    assert.equal(
      verifyInclusion(sd(leaves[i]!), { ...proof, path: corrupted }, { [logId]: pub }),
      false,
      `n=${n}: flipped sibling should fail`,
    );
  }
});

test("wrong tree_size fails verifyInclusion for trees of size 2..15", () => {
  for (let n = 2; n <= 15; n++) {
    const { pub, priv } = KEY_POOL[n % KEY_POOL.length]!;
    const logId = `log-${n}`;
    const leaves = buildLeaves(n);
    const i = 0;
    const proof = buildProof(leaves, i, { pub, priv }, logId);
    // tree_size mismatch with checkpoint: checkpoint says n, proof says n+1
    const badProof = { ...proof, tree_size: n + 1 };
    assert.equal(
      verifyInclusion(sd(leaves[i]!), badProof, { [logId]: pub }),
      false,
      `n=${n}: tree_size mismatch with checkpoint should fail`,
    );
  }
});

test("wrong log key fails verifyInclusion (unknown key hint)", () => {
  const n = 8;
  const { pub, priv } = KEY_POOL[0]!;
  const { pub: wrongPub } = KEY_POOL[1]!;
  const logId = "correct-log";
  const leaves = buildLeaves(n);
  const proof = buildProof(leaves, 3, { pub, priv }, logId);
  assert.equal(
    verifyInclusion(sd(leaves[3]!), proof, { [logId]: wrongPub }),
    false,
    "wrong public key should fail",
  );
  assert.equal(
    verifyInclusion(sd(leaves[3]!), proof, { "different-id": pub }),
    false,
    "wrong log id in key map should fail",
  );
});

// ---------------------------------------------------------------------------
// 3. logStatus mutation → incl_invalid (must never throw)
// ---------------------------------------------------------------------------

test("logStatus returns incl_invalid when proof is present but checkpoint is garbage", () => {
  const { pub } = KEY_POOL[0]!;
  const incl: InclBlock = {
    log_id: "L",
    leaf: "sha256:" + "00".repeat(32),
    proof: {
      index: 0,
      tree_size: 1,
      path: [],
      checkpoint: "GARBAGE NOT A CHECKPOINT",
    },
  };
  assert.doesNotThrow(() => {
    assert.equal(logStatus(incl, { L: pub }), "incl_invalid");
  });
});

test("logStatus returns incl_invalid when leaf hash is malformed", () => {
  const { pub } = KEY_POOL[0]!;
  const incl: InclBlock = {
    log_id: "L",
    leaf: "not-sha256-prefixed",
    proof: { index: 0, tree_size: 1, path: [], checkpoint: "a\n1\nYWJj\n\n— L AAAA\n" },
  };
  assert.doesNotThrow(() => {
    assert.equal(logStatus(incl, { L: pub }), "incl_invalid");
  });
});

test("logStatus returns incl_invalid for InclBlock with neither promise nor proof", () => {
  const { pub } = KEY_POOL[0]!;
  const incl: InclBlock = {
    log_id: "L",
    leaf: "sha256:" + "00".repeat(32),
    // no promise, no proof
  };
  assert.doesNotThrow(() => {
    assert.equal(logStatus(incl, { L: pub }), "incl_invalid");
  });
});

test("logStatus without logKeys: present proof → logged_proven, present promise → logged_promised", () => {
  const incl1: InclBlock = {
    log_id: "L",
    leaf: "sha256:" + "aa".repeat(32),
    proof: { index: 0, tree_size: 1, path: [], checkpoint: "any" },
  };
  assert.equal(logStatus(incl1), "logged_proven");

  const incl2: InclBlock = {
    log_id: "L",
    leaf: "sha256:" + "bb".repeat(32),
    promise: { timestamp: "2026-01-01T00:00:00Z", sig: "AAAA" },
  };
  assert.equal(logStatus(incl2), "logged_promised");
});

test("logStatus without logKeys: undefined incl → not_logged", () => {
  assert.equal(logStatus(undefined), "not_logged");
});

// ---------------------------------------------------------------------------
// 4. Fuzz logStatus with malformed incl blocks — never throws, never false-positives
// ---------------------------------------------------------------------------

function fuzzInclBlocks(): InclBlock[] {
  const lcg = makeLcg(0xfeedf00d);
  const goodLeaf = "sha256:" + "ab".repeat(32);
  return [
    // incl_block with completely garbage checkpoint text
    { log_id: "L", leaf: goodLeaf, proof: { index: 0, tree_size: 1, path: [], checkpoint: "" } },
    { log_id: "L", leaf: goodLeaf, proof: { index: 0, tree_size: 1, path: [], checkpoint: "\x00\x00" } },
    { log_id: "L", leaf: goodLeaf, proof: { index: -1, tree_size: 1, path: [], checkpoint: "a\n1\nYWJj\n\n" } },
    { log_id: "L", leaf: goodLeaf, proof: { index: 0, tree_size: 0, path: [], checkpoint: "a\n0\nYWJj\n\n" } },
    { log_id: "L", leaf: goodLeaf, proof: { index: 999, tree_size: 1, path: [], checkpoint: "a\n1\nYWJj\n\n" } },
    // Malformed leaf
    { log_id: "L", leaf: "not-prefixed", proof: { index: 0, tree_size: 1, path: [], checkpoint: "a\n1\nYWJj\n\n" } },
    { log_id: "L", leaf: "", proof: { index: 0, tree_size: 1, path: [], checkpoint: "a\n1\nYWJj\n\n" } },
    { log_id: "L", leaf: "sha256:", proof: { index: 0, tree_size: 1, path: [], checkpoint: "a\n1\nYWJj\n\n" } },
    // Bad path entries
    { log_id: "L", leaf: goodLeaf, proof: { index: 0, tree_size: 2, path: ["noprefix"], checkpoint: "a\n2\nYWJj\n\n" } },
    { log_id: "L", leaf: goodLeaf, proof: { index: 0, tree_size: 2, path: ["sha256:tooshort"], checkpoint: "a\n2\nYWJj\n\n" } },
    // Promise with garbage sig
    { log_id: "L", leaf: goodLeaf, promise: { timestamp: "2026-01-01T00:00:00Z", sig: "notbase64!!!" } },
    { log_id: "L", leaf: goodLeaf, promise: { timestamp: "", sig: "" } },
    // Pseudo-random garbage
    ...Array.from({ length: 10 }, (_, k): InclBlock => ({
      log_id: `log-${k}`,
      leaf: `sha256:${pseudoHex(lcg, 32)}`,
      proof: {
        index: lcg() % 16,
        tree_size: lcg() % 16,
        path: Array.from({ length: lcg() % 4 }, () => `sha256:${pseudoHex(lcg, 32)}`),
        checkpoint: Array.from({ length: 3 + (lcg() % 10) }, () =>
          String.fromCharCode(lcg() % 128),
        ).join(""),
      },
    })),
  ];
}

test("logStatus never throws on 22 fuzz incl blocks (with logKeys)", () => {
  const { pub } = KEY_POOL[2]!;
  const keys = { L: pub };
  for (const incl of fuzzInclBlocks()) {
    assert.doesNotThrow(() => {
      const status = logStatus(incl, keys);
      // Must never produce a false logged_proven or logged_promised on garbage input
      assert.notEqual(status, "logged_proven", `false-positive logged_proven on: ${JSON.stringify(incl).slice(0, 100)}`);
      assert.notEqual(status, "logged_promised", `false-positive logged_promised on: ${JSON.stringify(incl).slice(0, 100)}`);
    });
  }
});

test("logStatus never throws on 22 fuzz incl blocks (without logKeys)", () => {
  for (const incl of fuzzInclBlocks()) {
    assert.doesNotThrow(() => {
      logStatus(incl, undefined);
    });
  }
});

test("verifyInclusion never throws on fuzz proof objects (always returns false)", () => {
  const { pub } = KEY_POOL[3]!;
  const goodLeaf = "sha256:" + "cc".repeat(32);
  const fuzzProofs = [
    { index: 0, tree_size: 1, path: [], checkpoint: "" },
    { index: -1, tree_size: 1, path: [], checkpoint: "a\n1\nYWJj\n\n" },
    { index: 0, tree_size: 0, path: [], checkpoint: "a\n0\nYWJj\n\n" },
    { index: 0, tree_size: 1, path: ["noprefix"], checkpoint: "a\n1\nYWJj\n\n" },
    { index: 0, tree_size: 1, path: [], checkpoint: "\x00garbage\x01\x02" },
    { index: 1000, tree_size: 1, path: [], checkpoint: "a\n1\nYWJj\n\n" },
  ] satisfies InclusionProof[];
  for (const proof of fuzzProofs) {
    assert.doesNotThrow(() => {
      const result = verifyInclusion(goodLeaf, proof, { a: pub });
      assert.equal(result, false, `fuzz proof should not verify`);
    });
  }
});

// ---------------------------------------------------------------------------
// 5. Promise path: logStatus with valid promise → logged_promised
// ---------------------------------------------------------------------------

test("logStatus returns logged_promised for a valid promise for 8 leaves", () => {
  const lcg = makeLcg(0x99aabbcc);
  const { pub, priv } = KEY_POOL[4]!;
  const logId = "promise-log";
  for (let i = 0; i < 8; i++) {
    const leaf = "sha256:" + pseudoHex(lcg, 32);
    const ts = `2026-01-01T0${i}:00:00Z`;
    const sig = signPromise(logId, leaf, ts, priv);
    const incl: InclBlock = {
      log_id: logId,
      leaf,
      promise: { timestamp: ts, sig },
    };
    assert.equal(
      logStatus(incl, { [logId]: pub }),
      "logged_promised",
      `i=${i}: valid promise should yield logged_promised`,
    );
  }
});

test("logStatus returns incl_invalid when promise sig is wrong", () => {
  const { pub, priv } = KEY_POOL[0]!;
  const { pub: wrongPub } = KEY_POOL[1]!;
  const logId = "P";
  const leaf = "sha256:" + "dd".repeat(32);
  const ts = "2026-01-01T00:00:00Z";
  const sig = signPromise(logId, leaf, ts, priv);
  // Correct key
  assert.equal(
    logStatus({ log_id: logId, leaf, promise: { timestamp: ts, sig } }, { [logId]: pub }),
    "logged_promised",
  );
  // Wrong key
  assert.equal(
    logStatus({ log_id: logId, leaf, promise: { timestamp: ts, sig } }, { [logId]: wrongPub }),
    "incl_invalid",
  );
  // Tampered leaf
  assert.equal(
    logStatus({ log_id: logId, leaf: "sha256:" + "ff".repeat(32), promise: { timestamp: ts, sig } }, { [logId]: pub }),
    "incl_invalid",
  );
});

// ---------------------------------------------------------------------------
// 6. Proof vs promise precedence — proof wins when both present
// ---------------------------------------------------------------------------

test("logStatus uses proof (not promise) when both are present on the InclBlock", () => {
  const n = 4;
  const { pub, priv } = KEY_POOL[0]!;
  const logId = "dual-log";
  const leaves = buildLeaves(n);
  const i = 2;
  const proof = buildProof(leaves, i, { pub, priv }, logId);
  const leaf = sd(leaves[i]!);
  const ts = "2026-01-01T00:00:00Z";
  const sig = signPromise(logId, leaf, ts, priv);
  const incl: InclBlock = { log_id: logId, leaf, proof, promise: { timestamp: ts, sig } };
  // logStatus checks proof first when logKeys provided
  assert.equal(logStatus(incl, { [logId]: pub }), "logged_proven");
});
