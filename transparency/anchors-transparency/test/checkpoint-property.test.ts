/**
 * Property / fuzz tests for checkpoint.ts.
 *
 * Exercises: round-trip sign→parse→verify, per-field tamper detection,
 * wrong-key rejection, and a fuzz battery that verifyCheckpoint never throws
 * and never false-positives on garbage input.
 *
 * Deterministic: no Math.random, no Date.now.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  signCheckpoint,
  parseCheckpoint,
  verifyCheckpoint,
  checkpointBody,
} from "../src/checkpoint.ts";

// ---------------------------------------------------------------------------
// Key generation helper (cached to avoid regenerating on every iteration)
// ---------------------------------------------------------------------------

type KeyPair = { pub: string; priv: string };

function genKey(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    pub: publicKey.export({ type: "spki", format: "pem" }).toString(),
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

// Pre-generate a small pool of key pairs — reused across tests to keep runtime low
const KEY_POOL: KeyPair[] = Array.from({ length: 6 }, genKey);

// ---------------------------------------------------------------------------
// Deterministic LCG
// ---------------------------------------------------------------------------
function makeLcg(seed: number) {
  let s = seed >>> 0;
  return function next(): number {
    s = Math.imul(s, 1664525) + 1013904223;
    s = s >>> 0;
    return s;
  };
}

/** Deterministic pseudo-hex using the LCG. */
function pseudoHex(lcg: () => number, bytes: number): string {
  return Array.from({ length: bytes }, () =>
    (lcg() % 256).toString(16).padStart(2, "0"),
  ).join("");
}

// ---------------------------------------------------------------------------
// 1. Round-trip: sign → parse → verify for many checkpoints
// ---------------------------------------------------------------------------

test("checkpoint sign→parse→verify round-trips for 20 varied checkpoints", () => {
  const lcg = makeLcg(0xaabbccdd);
  const origins = [
    "dekimu-anchors-log-2026",
    "example.com/log/v1",
    "transparency.test/log",
    "a",
    "origin-with-dashes-and-numbers-123",
  ];
  for (let i = 0; i < 20; i++) {
    const { pub, priv } = KEY_POOL[i % KEY_POOL.length]!;
    const origin = origins[i % origins.length]!;
    const size = i * 13 + 1; // deterministic, always positive
    const rootHashB64 = Buffer.from(pseudoHex(lcg, 32), "hex").toString("base64");
    const keyHint = `key-hint-${i}`;

    const note = signCheckpoint({ origin, size, rootHashB64 }, keyHint, priv);
    const parsed = parseCheckpoint(note);

    assert.equal(parsed.origin, origin, `i=${i}: origin round-trips`);
    assert.equal(parsed.size, size, `i=${i}: size round-trips`);
    assert.equal(parsed.rootHashB64, rootHashB64, `i=${i}: rootHashB64 round-trips`);
    assert.equal(parsed.signatures.length, 1, `i=${i}: exactly one signature`);
    assert.equal(parsed.signatures[0]?.keyHint, keyHint, `i=${i}: keyHint round-trips`);
    assert.ok(
      verifyCheckpoint(note, { [keyHint]: pub }),
      `i=${i}: verify should pass`,
    );
  }
});

test("checkpointBody produces the three-line format (origin\\nsize\\nroot\\n)", () => {
  const lcg = makeLcg(0x12121212);
  for (let i = 0; i < 10; i++) {
    const origin = `origin-${i}`;
    const size = i * 7 + 1;
    const rootHashB64 = Buffer.from(pseudoHex(lcg, 32), "hex").toString("base64");
    const body = checkpointBody({ origin, size, rootHashB64 });
    const lines = body.split("\n");
    // Three content lines + trailing empty string after final \n
    assert.equal(lines.length, 4, `i=${i}: body should have 3 lines + trailing empty`);
    assert.equal(lines[0], origin, `i=${i}: line 0 is origin`);
    assert.equal(lines[1], String(size), `i=${i}: line 1 is size`);
    assert.equal(lines[2], rootHashB64, `i=${i}: line 2 is rootHashB64`);
    assert.equal(lines[3], "", `i=${i}: line 3 is empty (trailing newline)`);
  }
});

// ---------------------------------------------------------------------------
// 2. Per-field tamper detection
// ---------------------------------------------------------------------------

test("tampered origin fails verify for 10 checkpoints", () => {
  const lcg = makeLcg(0xbeef0001);
  for (let i = 0; i < 10; i++) {
    const { pub, priv } = KEY_POOL[i % KEY_POOL.length]!;
    const origin = `log-${i}`;
    const size = i + 1;
    const rootHashB64 = Buffer.from(pseudoHex(lcg, 32), "hex").toString("base64");
    const note = signCheckpoint({ origin, size, rootHashB64 }, "k", priv);
    // Replace origin on the first line
    const tampered = note.replace(origin, `${origin}-TAMPERED`);
    assert.equal(
      verifyCheckpoint(tampered, { k: pub }),
      false,
      `i=${i}: tampered origin should fail`,
    );
  }
});

test("tampered size fails verify for sizes 1..15", () => {
  const lcg = makeLcg(0xbeef0002);
  const { pub, priv } = KEY_POOL[0]!;
  for (let size = 1; size <= 15; size++) {
    const rootHashB64 = Buffer.from(pseudoHex(lcg, 32), "hex").toString("base64");
    const note = signCheckpoint({ origin: "L", size, rootHashB64 }, "k", priv);
    // Increment size by 1 in the text
    const tampered = note.replace(`\n${size}\n`, `\n${size + 1}\n`);
    assert.equal(
      verifyCheckpoint(tampered, { k: pub }),
      false,
      `size=${size}: tampered size should fail`,
    );
  }
});

test("tampered rootHashB64 fails verify for 10 checkpoints", () => {
  const lcg = makeLcg(0xbeef0003);
  const { pub, priv } = KEY_POOL[1]!;
  for (let i = 0; i < 10; i++) {
    const rootHashB64 = Buffer.from(pseudoHex(lcg, 32), "hex").toString("base64");
    const note = signCheckpoint({ origin: "L", size: i + 1, rootHashB64 }, "k", priv);
    // Replace last char of rootHashB64 with a different char
    const lastChar = rootHashB64.slice(-1);
    const replacement = lastChar === "A" ? "B" : "A";
    const tampered = note.replace(rootHashB64, rootHashB64.slice(0, -1) + replacement);
    assert.equal(
      verifyCheckpoint(tampered, { k: pub }),
      false,
      `i=${i}: tampered root should fail`,
    );
  }
});

test("tampered keyHint fails verify (key lookup returns undefined → false)", () => {
  const { pub, priv } = KEY_POOL[2]!;
  const note = signCheckpoint({ origin: "L", size: 1, rootHashB64: "YWJj" }, "real-key", priv);
  // Key map uses correct pub but wrong hint name
  assert.equal(verifyCheckpoint(note, { "wrong-key": pub }), false);
});

test("tampered signature bytes fail verify for 8 checkpoints", () => {
  const lcg = makeLcg(0xbeef0004);
  for (let i = 0; i < 8; i++) {
    const { pub, priv } = KEY_POOL[i % KEY_POOL.length]!;
    const rootHashB64 = Buffer.from(pseudoHex(lcg, 32), "hex").toString("base64");
    const note = signCheckpoint({ origin: "L", size: i + 1, rootHashB64 }, "k", priv);
    // The signature is the last space-separated token on the "— k <sig>" line
    // Replace the last two chars of the note (before the trailing \n) with different chars
    const lastNl = note.lastIndexOf("\n", note.length - 2);
    const sigLine = note.slice(lastNl + 1, -1); // the "— k <sig>" line
    const tamperedSig = sigLine.slice(0, -2) + (sigLine.slice(-2) === "AA" ? "BB" : "AA");
    const tampered = note.slice(0, lastNl + 1) + tamperedSig + "\n";
    assert.equal(
      verifyCheckpoint(tampered, { k: pub }),
      false,
      `i=${i}: tampered sig should fail`,
    );
  }
});

// ---------------------------------------------------------------------------
// 3. Wrong key rejection
// ---------------------------------------------------------------------------

test("wrong public key fails verify for 10 checkpoints", () => {
  const lcg = makeLcg(0xbeef0005);
  for (let i = 0; i < 10; i++) {
    const { priv } = KEY_POOL[i % KEY_POOL.length]!;
    const { pub: wrongPub } = KEY_POOL[(i + 1) % KEY_POOL.length]!;
    const rootHashB64 = Buffer.from(pseudoHex(lcg, 32), "hex").toString("base64");
    const note = signCheckpoint({ origin: "L", size: i + 1, rootHashB64 }, "k", priv);
    assert.equal(
      verifyCheckpoint(note, { k: wrongPub }),
      false,
      `i=${i}: wrong public key should fail`,
    );
  }
});

test("empty key map always fails verify", () => {
  const { priv } = KEY_POOL[0]!;
  const note = signCheckpoint({ origin: "L", size: 1, rootHashB64: "YWJj" }, "k", priv);
  assert.equal(verifyCheckpoint(note, {}), false);
});

// ---------------------------------------------------------------------------
// 4. Malformed / fuzz battery — must never throw, must never return true
// ---------------------------------------------------------------------------

/** A collection of garbage strings that might trip up a parser. */
function fuzzInputs(): string[] {
  const lcg = makeLcg(0x77889900);
  return [
    // Structural variants
    "",
    "\n",
    "\n\n",
    "\n\n\n",
    "a",
    "a\n",
    "a\nb",
    "a\nb\n",
    "a\nnot-a-number\nc\n\n— k AAAA\n",
    "origin\n0\nroot\n\n",
    "origin\n-1\nroot\n\n— k AAAA\n",
    "origin\n1.5\nroot\n\n— k AAAA\n",
    "origin\nInfinity\nroot\n\n— k AAAA\n",
    "origin\nNaN\nroot\n\n— k AAAA\n",
    // Missing separator
    "origin\n1\nroot\n— k AAAA\n",
    // No signature line
    "origin\n1\nroot\n\n",
    // Signature line with garbage sig
    "origin\n1\nroot\n\n— k notbase64!!!\n",
    // Zero bytes
    "\x00\x00\x00",
    // Very long origin
    `${"x".repeat(500)}\n1\nYWJj\n\n— k AAAA\n`,
    // Unicode
    "ör!gín\n1\nYWJj\n\n— k AAAA\n",
    // Multiple separator blocks
    "origin\n1\nroot\n\n\n\n— k AAAA\n",
    // Pseudo-random bytes
    ...Array.from({ length: 15 }, () =>
      Array.from({ length: 20 + (lcg() % 60) }, () =>
        String.fromCharCode(lcg() % 128),
      ).join(""),
    ),
  ];
}

test("verifyCheckpoint never throws on 40 fuzz inputs (always returns false)", () => {
  const inputs = fuzzInputs();
  for (const input of inputs) {
    assert.doesNotThrow(() => {
      const result = verifyCheckpoint(input, {});
      assert.equal(result, false, `fuzz input should not verify against empty key map`);
    }, `verifyCheckpoint threw on: ${JSON.stringify(input.slice(0, 80))}`);
  }
});

test("verifyCheckpoint never throws with arbitrary non-empty key maps on 20 fuzz inputs", () => {
  const { pub } = KEY_POOL[3]!;
  const inputs = fuzzInputs().slice(0, 20);
  for (const input of inputs) {
    assert.doesNotThrow(() => {
      verifyCheckpoint(input, { k: pub, "other-key": pub });
    }, `verifyCheckpoint threw with non-empty key map on: ${JSON.stringify(input.slice(0, 80))}`);
  }
});

test("parseCheckpoint throws (never silently accepts) on the known-bad inputs", () => {
  const badInputs = [
    "",
    "oneline",
    "a\nb",
    "origin\nNaN\nroot\n\n— k AAAA\n",
    "origin\n-5\nroot\n\n— k AAAA\n",
    "origin\n1.5\nroot\n\n— k AAAA\n",
  ];
  for (const input of badInputs) {
    assert.throws(
      () => parseCheckpoint(input),
      (err) => err instanceof Error,
      `parseCheckpoint should throw on: ${JSON.stringify(input)}`,
    );
  }
});

// ---------------------------------------------------------------------------
// 5. Size-zero checkpoint is valid (m=0 tree)
// ---------------------------------------------------------------------------

test("size=0 checkpoint round-trips and verifies", () => {
  const { pub, priv } = KEY_POOL[4]!;
  const note = signCheckpoint({ origin: "L", size: 0, rootHashB64: "AAAA" }, "k", priv);
  assert.ok(verifyCheckpoint(note, { k: pub }));
  const parsed = parseCheckpoint(note);
  assert.equal(parsed.size, 0);
});

// ---------------------------------------------------------------------------
// 6. Multiple signers — operator (first) must still verify
// ---------------------------------------------------------------------------

test("multi-signer note: operator key verifies; wrong hint in map still fails", () => {
  const { pub: pub1, priv: priv1 } = KEY_POOL[5]!;
  // Single-signer note signed by priv1 under hint "op"
  const note = signCheckpoint({ origin: "L", size: 3, rootHashB64: "AAAA" }, "op", priv1);
  // Correct hint → passes
  assert.ok(verifyCheckpoint(note, { op: pub1 }));
  // Correct key but wrong hint → fails (lookup by hint)
  assert.equal(verifyCheckpoint(note, { "other": pub1 }), false);
  // Manually append a second fake sig line — verifyCheckpoint uses only the first
  const twoSigNote = note.trimEnd() + "\n— witness2 FAKESIG==\n";
  // First sig is still "op" — should still verify with pub1
  assert.ok(verifyCheckpoint(twoSigNote, { op: pub1 }));
});
