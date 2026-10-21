/**
 * Property tests for leaf.ts — leafHash stability, JCS canonicalization invariant,
 * sensitivity to non-incl fields, and output format.
 *
 * Deterministic: no Math.random, no Date.now.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

// Note: leafHash is imported from the public surface so the test exercises the real export path
import { leafHash } from "../src/leaf.ts";

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

/** Generate a deterministic hex string of `bytes` bytes using the LCG. */
function pseudoHex(lcg: () => number, bytes: number): string {
  return Array.from({ length: bytes }, () =>
    (lcg() % 256).toString(16).padStart(2, "0")
  ).join("");
}

// ---------------------------------------------------------------------------
// Build a variety of receipts deterministically
// ---------------------------------------------------------------------------

/** Minimal receipt shapes — vary claim_type, v, iss, and anchor. */
function minimalReceipts(): Array<Record<string, unknown>> {
  const claimTypes = [
    "ar.provenance.v1",
    "ar.consent.v1",
    "ar.retention.v1",
    "ar.lineage.v1",
    "ar.breach.v1",
    "ar.notice.v1",
    "ar.tokenization.v1",
  ];
  return claimTypes.map((ct, i) => ({
    v: 2,
    claim_type: ct,
    iss: `did:web:issuer-${i}.example.com`,
    sig: `sig-${i}`,
    anchor: null,
  }));
}

/**
 * Build a rich receipt and insert an `incl` block with varying content.
 * The incl block content must NOT affect the leaf hash.
 */
function receiptsWithIncl(): Array<{
  base: Record<string, unknown>;
  withIncl: Record<string, unknown>;
}> {
  const lcg = makeLcg(0x11111111);
  return Array.from({ length: 12 }, (_, i) => {
    const base: Record<string, unknown> = {
      v: 2,
      claim_type: `ar.provenance.v1`,
      iss: `did:web:host${i}.example.com`,
      nbf: 1700000000 + i * 3600,
      sig: pseudoHex(lcg, 16),
      anchor: { hash: pseudoHex(lcg, 32) },
    };
    // Varying incl contents — some with promise, some with proof, different log_ids
    const inclVariants: Record<string, unknown>[] = [
      {
        log_id: `log-${i}`,
        leaf: `sha256:${pseudoHex(lcg, 32)}`,
        promise: { timestamp: "2026-01-01T00:00:00Z", sig: pseudoHex(lcg, 16) },
      },
      {
        log_id: `other-log-${i}`,
        leaf: `sha256:${pseudoHex(lcg, 32)}`,
        proof: {
          index: i,
          tree_size: i + 10,
          path: [`sha256:${pseudoHex(lcg, 32)}`],
          checkpoint: `checkpoint-${i}`,
        },
      },
    ];
    const withIncl: Record<string, unknown> = {
      ...base,
      incl: inclVariants[i % 2],
    };
    return { base, withIncl };
  });
}

// ---------------------------------------------------------------------------
// 1. Stability: same receipt always produces the same hash
// ---------------------------------------------------------------------------

test("leafHash is deterministic (same input → same output)", () => {
  for (const r of minimalReceipts()) {
    const h1 = leafHash(r);
    const h2 = leafHash(r);
    assert.equal(h1, h2, `hash should be stable for ${r["claim_type"]}`);
  }
});

// ---------------------------------------------------------------------------
// 2. The incl block must be stripped before hashing
// ---------------------------------------------------------------------------

test("leafHash ignores incl block — 12 varied pairs (different log_ids, promise vs proof)", () => {
  for (const { base, withIncl } of receiptsWithIncl()) {
    assert.equal(
      leafHash(base),
      leafHash(withIncl),
      "incl block must not affect the leaf hash"
    );
  }
});

test("leafHash ignores incl block when incl contains nested objects with many fields", () => {
  const base = {
    v: 2,
    claim_type: "ar.consent.v1",
    iss: "did:web:a.com",
    sig: "S",
  };
  const withDeepIncl = {
    ...base,
    incl: {
      log_id: "L",
      leaf: "sha256:" + "ab".repeat(32),
      proof: {
        index: 7,
        tree_size: 100,
        path: Array.from(
          { length: 7 },
          (_, i) => `sha256:${"0f".repeat(32 - i)}${"f0".repeat(i)}`
        ),
        checkpoint: "origin\n100\naGVsbG8=\n\n— k AAAA\n",
        extra_future_field: "ignored",
      },
    },
  };
  assert.equal(leafHash(base), leafHash(withDeepIncl));
});

test("leafHash is stable when incl is absent vs when incl is explicitly undefined", () => {
  const base = { v: 2, claim_type: "ar.provenance.v1", sig: "X" };
  // JSON.parse / canonicalize won't see 'undefined' as a key, so this should be the same
  const withUndefined = { ...base, incl: undefined };
  // leafHash destructures { incl: _omit, ...rest } — rest is the same in both cases
  // (if incl is undefined, the spread may include the key with value undefined —
  //  but canonicalize(JSON) ignores undefined values per RFC 8785)
  assert.equal(
    leafHash(base),
    leafHash(withUndefined as Record<string, unknown>)
  );
});

// ---------------------------------------------------------------------------
// 3. JCS canonicalization: key order must not matter
// ---------------------------------------------------------------------------

test("leafHash is invariant under JSON key insertion order — 20 varied permutations", () => {
  // Build a receipt with known fields and insert them in different orders
  const fields: [string, unknown][] = [
    ["v", 2],
    ["claim_type", "ar.provenance.v1"],
    ["iss", "did:web:example.com"],
    ["nbf", 1700000000],
    ["sig", "ABCDEF"],
    ["anchor", { hash: "00".repeat(32) }],
  ];

  // Deterministic order permutations using the lcg
  const lcg = makeLcg(0x22222222);
  const canonical = Object.fromEntries(fields);
  const canonicalHash = leafHash(canonical);

  for (let trial = 0; trial < 20; trial++) {
    // Fisher-Yates shuffle with the LCG
    const order = fields.map((_, i) => i);
    for (let i = order.length - 1; i > 0; i--) {
      const j = lcg() % (i + 1);
      [order[i], order[j]] = [order[j]!, order[i]!];
    }
    const shuffled = Object.fromEntries(order.map((idx) => fields[idx]!));
    assert.equal(
      leafHash(shuffled),
      canonicalHash,
      `trial ${trial}: key order should not affect hash`
    );
  }
});

test("leafHash is invariant under key order for receipts with nested anchor object", () => {
  // Two objects where nested anchor keys are also in different order
  const r1 = {
    anchor: { hash: "aabbcc".padEnd(64, "0"), alg: "sha256" },
    claim_type: "ar.provenance.v1",
    iss: "did:web:a.com",
    sig: "S",
    v: 2,
  };
  const r2 = {
    v: 2,
    sig: "S",
    iss: "did:web:a.com",
    claim_type: "ar.provenance.v1",
    anchor: { alg: "sha256", hash: "aabbcc".padEnd(64, "0") },
  };
  assert.equal(
    leafHash(r1),
    leafHash(r2),
    "nested key order should not affect hash"
  );
});

// ---------------------------------------------------------------------------
// 4. Sensitivity: changing any non-incl field must change the hash
// ---------------------------------------------------------------------------

test("leafHash changes when claim_type changes (40 distinct claim types)", () => {
  const base = { v: 2, iss: "did:web:a.com", sig: "S" };
  const hashes = new Set<string>();
  for (let i = 0; i < 40; i++) {
    hashes.add(leafHash({ ...base, claim_type: `ar.type-${i}.v1` }));
  }
  assert.equal(
    hashes.size,
    40,
    "each distinct claim_type should produce a distinct hash"
  );
});

test("leafHash changes when iss changes (20 distinct issuers)", () => {
  const base = { v: 2, claim_type: "ar.provenance.v1", sig: "S" };
  const hashes = new Set<string>();
  for (let i = 0; i < 20; i++) {
    hashes.add(leafHash({ ...base, iss: `did:web:issuer-${i}.example.com` }));
  }
  assert.equal(
    hashes.size,
    20,
    "each distinct iss should produce a distinct hash"
  );
});

test("leafHash changes when sig changes (15 distinct sigs)", () => {
  const lcg = makeLcg(0x33333333);
  const base = { v: 2, claim_type: "ar.provenance.v1", iss: "did:web:a.com" };
  const hashes = new Set<string>();
  for (let i = 0; i < 15; i++) {
    // Embed i to guarantee uniqueness regardless of LCG period
    hashes.add(leafHash({ ...base, sig: `sig-${i}-${pseudoHex(lcg, 16)}` }));
  }
  assert.equal(
    hashes.size,
    15,
    "each distinct sig should produce a distinct hash"
  );
});

test("leafHash changes when v changes (v1 vs v2 vs v3)", () => {
  const base = {
    claim_type: "ar.provenance.v1",
    iss: "did:web:a.com",
    sig: "S",
  };
  const h1 = leafHash({ ...base, v: 1 });
  const h2 = leafHash({ ...base, v: 2 });
  const h3 = leafHash({ ...base, v: 3 });
  assert.notEqual(h1, h2);
  assert.notEqual(h2, h3);
  assert.notEqual(h1, h3);
});

test("leafHash changes when a numeric field changes by 1", () => {
  const base = { v: 2, claim_type: "ar.provenance.v1", nbf: 1700000000 };
  const h1 = leafHash(base);
  const h2 = leafHash({ ...base, nbf: 1700000001 });
  assert.notEqual(h1, h2, "off-by-one change in nbf should change the hash");
});

test("leafHash changes when a boolean field toggles", () => {
  const base = { v: 2, claim_type: "ar.consent.v1", revoked: false };
  const h1 = leafHash(base);
  const h2 = leafHash({ ...base, revoked: true });
  assert.notEqual(h1, h2);
});

test("leafHash changes when anchor hash changes (30 distinct hashes)", () => {
  const lcg = makeLcg(0x44444444);
  const base = {
    v: 2,
    claim_type: "ar.provenance.v1",
    iss: "did:web:a.com",
    sig: "S",
  };
  const hashes = new Set<string>();
  for (let i = 0; i < 30; i++) {
    // Embed i to guarantee uniqueness regardless of LCG period
    hashes.add(leafHash({ ...base, anchor: { hash: `${i.toString(16).padStart(4, "0")}${pseudoHex(lcg, 30)}` } }));
  }
  assert.equal(
    hashes.size,
    30,
    "each distinct anchor hash should produce a distinct leaf hash"
  );
});

// ---------------------------------------------------------------------------
// 5. Output format: must always match /^sha256:[0-9a-f]{64}$/
// ---------------------------------------------------------------------------

test("leafHash output format is always sha256:<64 hex chars> (25 varied receipts)", () => {
  const lcg = makeLcg(0x55555555);
  const receipts: Array<Record<string, unknown>> = [
    {},
    { v: 2 },
    { v: 2, claim_type: "ar.provenance.v1" },
    { v: 2, claim_type: "ar.provenance.v1", iss: "did:web:a.com", sig: "S" },
    ...Array.from({ length: 21 }, (_, i) => ({
      v: 2,
      claim_type: `ar.type-${i}.v1`,
      iss: `did:web:issuer-${i}.com`,
      sig: pseudoHex(lcg, 16),
      nbf: 1700000000 + i,
      anchor: { hash: pseudoHex(lcg, 32) },
    })),
  ];
  for (const r of receipts) {
    assert.match(
      leafHash(r),
      /^sha256:[0-9a-f]{64}$/,
      `malformed output for receipt with claim_type=${r["claim_type"]}`
    );
  }
});

test("leafHash output format holds for deeply nested receipts", () => {
  const nested = {
    v: 2,
    claim_type: "ar.lineage.v1",
    iss: "did:web:a.com",
    sig: "SIG",
    subject: {
      id: "did:web:subject.com",
      lineage: { parent: "did:web:parent.com" },
    },
    policy: { retention_days: 365, purpose: ["analytics"] },
  };
  assert.match(leafHash(nested), /^sha256:[0-9a-f]{64}$/);
});

// ---------------------------------------------------------------------------
// 6. Collision resistance: distinct receipts (non-incl content differs) → distinct hashes
// ---------------------------------------------------------------------------

test("no hash collision among 50 pseudo-random distinct receipts", () => {
  const lcg = makeLcg(0x66666666);
  const hashes = new Set<string>();
  for (let i = 0; i < 50; i++) {
    const r: Record<string, unknown> = {
      v: 2,
      claim_type: `ar.type-${i % 14}.v1`,
      iss: `did:web:issuer-${i}.com`,
      sig: pseudoHex(lcg, 32),
      nbf: 1700000000 + i,
      unique_id: i,
    };
    hashes.add(leafHash(r));
  }
  assert.equal(
    hashes.size,
    50,
    "50 distinct receipts should produce 50 distinct hashes"
  );
});
