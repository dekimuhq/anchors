import { test } from "node:test";
import assert from "node:assert/strict";
import { mintAcrV2, generateKeypair } from "@dekimuhq/acr/issue";
import { verifyDisclosureProof } from "@dekimuhq/acr";
import type { DisclosureProof } from "@dekimuhq/acr";
import { randomSalt } from "@dekimuhq/anchors-envelope";
import {
  buildRevealBundle,
  verifyRevealBundle,
  layoutExpectations,
  encodeRevealToken,
  decodeRevealToken,
  acrFieldLayout,
  type FieldOpenings,
} from "../src/index.ts";

// Mint a REAL ACR receipt via the shipped issuer kit, with holder-controlled
// salts, then exercise the holder reveal-bundle kit against it. Golden vector:
// the bundle's per-field Merkle proof must verify unchanged under ACR's OWN
// `verifyDisclosureProof` — proving the bundle scheme is byte-identical to the
// commitment scheme the family already ships.

const CLAIM_ID = "ar.consent.v1:acr-holder-kit-9";

// Holder opening material — the (value, salt) pairs the holder persists at mint.
const subValue = "client-42";
const purposeValues: [string, string, string] = ["marketing", "analytics", "profiling"];
const policyValue = "sha256:" + "a".repeat(64);

const subSalt = randomSalt();
const purposeSalts: [string, string, string] = [randomSalt(), randomSalt(), randomSalt()];
const policySalt = randomSalt();

const openings: FieldOpenings = {
  "/sub": { value: subValue, salt: subSalt },
  "/purposes/0": { value: purposeValues[0], salt: purposeSalts[0] },
  "/purposes/1": { value: purposeValues[1], salt: purposeSalts[1] },
  "/purposes/2": { value: purposeValues[2], salt: purposeSalts[2] },
  "/policy": { value: policyValue, salt: policySalt },
};

async function mintReal() {
  const kp = generateKeypair("acr-holder-test");
  const env = (await mintAcrV2({
    issuer: "did:web:example.com",
    keypair: { kid: kp.kid, privateKey: kp.privateKey },
    kind: "ar.consent.v1",
    subject: "sha256:" + "b".repeat(64),
    profile: "gdpr.art7",
    fields: {
      sub_commit: { value: subValue, salt: subSalt },
      purposes: [0, 1, 2].map((i) => ({ value: purposeValues[i]!, salt: purposeSalts[i]! })),
      policy_hash: { value: policyValue, salt: policySalt },
    },
    lawful_basis: "6(1)(a)",
    granted_at: "2026-07-06T00:00:00Z",
    anchor: {
      log: "https://verify.dekimu.com/acr/v1",
      leaf_index: 0,
      inclusion_proof: [],
      tree_head_root: "sha256:" + "0".repeat(64),
      tree_size: 1,
      log_time: "2026-07-06T00:00:00Z",
    },
  })) as unknown as {
    body: { sub_commit: string; purposes: string[]; policy_hash: string; field_root: string };
  };
  return env.body;
}

test("golden vector: reveal bundle verifies under ACR's own verifyDisclosureProof", async () => {
  const body = await mintReal();
  const layout = acrFieldLayout(body);

  // Holder discloses ONLY /purposes/1 (hides sub, other purposes, policy).
  const bundle = buildRevealBundle({
    claimId: CLAIM_ID,
    layout,
    openings,
    reveal: ["/purposes/1"],
  });

  assert.equal(bundle.kind, "ar.reveal.v1");
  assert.equal(bundle.field_root, body.field_root);
  assert.equal(bundle.leaf_count, layout.commitments.length);
  assert.equal(bundle.reveals.length, 1);

  // Round-trip self-check against expectations derived from the signed layout.
  const r = verifyRevealBundle(bundle, layoutExpectations(layout));
  assert.equal(r.valid, true);
  assert.deepEqual(r.revealed, { "/purposes/1": "analytics" });

  // Cross-verify: map the bundle entry to ACR's DisclosureProof shape and run
  // the SHIPPED family verifier against the receipt's field_root.
  const entry = bundle.reveals[0]!;
  const acrProof: DisclosureProof = {
    disclosure: { field: "purposes[1]", value: entry.value, salt: entry.salt },
    merkle_path: entry.merkleProof,
    leaf_index: entry.leaf_index,
    leaf_count: bundle.leaf_count,
  };
  assert.equal(verifyDisclosureProof(acrProof, body.field_root), true);
});

test("multi-field reveal: every opened field cross-verifies with the family verifier", async () => {
  const body = await mintReal();
  const layout = acrFieldLayout(body);
  const reveal = ["/sub", "/purposes/0", "/purposes/2", "/policy"];
  const bundle = buildRevealBundle({ claimId: CLAIM_ID, layout, openings, reveal });

  const r = verifyRevealBundle(bundle, layoutExpectations(layout));
  assert.equal(r.valid, true);
  assert.deepEqual(r.revealed, {
    "/sub": "client-42",
    "/purposes/0": "marketing",
    "/purposes/2": "profiling",
    "/policy": policyValue,
  });

  for (const entry of bundle.reveals) {
    const proof: DisclosureProof = {
      disclosure: { field: entry.path, value: entry.value, salt: entry.salt },
      merkle_path: entry.merkleProof,
      leaf_index: entry.leaf_index,
      leaf_count: bundle.leaf_count,
    };
    assert.equal(
      verifyDisclosureProof(proof, body.field_root),
      true,
      `family verifier rejected ${entry.path}`,
    );
  }
});

test("token codec round-trips a bundle byte-for-byte", async () => {
  const body = await mintReal();
  const layout = acrFieldLayout(body);
  const bundle = buildRevealBundle({
    claimId: CLAIM_ID,
    layout,
    openings,
    reveal: ["/sub", "/purposes/1"],
  });
  const token = encodeRevealToken(bundle);
  // URL-safe: no +, /, or = padding.
  assert.equal(/^[A-Za-z0-9_-]+$/.test(token), true);
  const back = decodeRevealToken(token);
  assert.deepEqual(back, bundle);
  assert.equal(verifyRevealBundle(back, layoutExpectations(layout)).valid, true);
});

test("tampered value fails both bundle verify and family verify", async () => {
  const body = await mintReal();
  const layout = acrFieldLayout(body);
  const bundle = buildRevealBundle({
    claimId: CLAIM_ID,
    layout,
    openings,
    reveal: ["/purposes/0"],
  });
  bundle.reveals[0]!.value = "not-the-committed-value";
  const r = verifyRevealBundle(bundle, layoutExpectations(layout));
  assert.equal(r.valid, false);
  assert.deepEqual(r.reasons, ["leaf_commit_mismatch"]);

  const proof: DisclosureProof = {
    disclosure: { field: "purposes[0]", value: bundle.reveals[0]!.value, salt: bundle.reveals[0]!.salt },
    merkle_path: bundle.reveals[0]!.merkleProof,
    leaf_index: bundle.reveals[0]!.leaf_index,
    leaf_count: bundle.leaf_count,
  };
  assert.equal(verifyDisclosureProof(proof, body.field_root), false);
});

test("expectedFieldRoot mismatch is rejected", async () => {
  const body = await mintReal();
  const layout = acrFieldLayout(body);
  const bundle = buildRevealBundle({
    claimId: CLAIM_ID,
    layout,
    openings,
    reveal: ["/policy"],
  });
  const r = verifyRevealBundle(bundle, {
    ...layoutExpectations(layout),
    expectedFieldRoot: "sha256:" + "f".repeat(64),
  });
  assert.equal(r.valid, false);
  assert.deepEqual(r.reasons, ["field_root_mismatch"]);
});

test("H1: a valid opening for /purposes/0 relabeled as /sub is rejected (path_unbound)", async () => {
  const body = await mintReal();
  const layout = acrFieldLayout(body);
  // A legitimate, fully-verifying opening for /purposes/0 (leaf_index 1).
  const bundle = buildRevealBundle({
    claimId: CLAIM_ID,
    layout,
    openings,
    reveal: ["/purposes/0"],
  });
  // Attacker relabels the path to /sub, keeping the valid leaf_index+proof so
  // inclusion still passes — a subject reveal forged from a purpose opening.
  bundle.reveals[0]!.path = "/sub";
  const r = verifyRevealBundle(bundle, layoutExpectations(layout));
  assert.equal(r.valid, false);
  assert.deepEqual(r.reasons, ["path_unbound"]);
  assert.deepEqual(r.revealed, {});
});

test("H1: an out-of-range leaf_index is rejected (path_unbound)", async () => {
  const body = await mintReal();
  const layout = acrFieldLayout(body);
  const bundle = buildRevealBundle({
    claimId: CLAIM_ID,
    layout,
    openings,
    reveal: ["/sub"],
  });
  bundle.reveals[0]!.leaf_index = layout.commitments.length; // past the last leaf
  const r = verifyRevealBundle(bundle, layoutExpectations(layout));
  assert.equal(r.valid, false);
  assert.deepEqual(r.reasons, ["path_unbound"]);
});

test("H2: a self-declared leaf_count that differs from the signed arity is rejected before inclusion", async () => {
  const body = await mintReal();
  const layout = acrFieldLayout(body);
  const bundle = buildRevealBundle({
    claimId: CLAIM_ID,
    layout,
    openings,
    reveal: ["/purposes/1"],
  });
  // Inflate the arity: the signed body commits `layout.commitments.length`
  // leaves; a mismatched leaf_count must fail-closed BEFORE any Merkle check.
  bundle.leaf_count = layout.commitments.length + 1;
  const r = verifyRevealBundle(bundle, layoutExpectations(layout));
  assert.equal(r.valid, false);
  assert.deepEqual(r.reasons, ["leaf_count_mismatch"]);
  assert.deepEqual(r.revealed, {});
});

test("build rejects an opening that does not reproduce the committed leaf", async () => {
  const body = await mintReal();
  const badOpenings: FieldOpenings = {
    ...openings,
    "/sub": { value: "wrong", salt: subSalt },
  };
  assert.throws(
    () =>
      buildRevealBundle({
        claimId: CLAIM_ID,
        layout: acrFieldLayout(body),
        openings: badOpenings,
        reveal: ["/sub"],
      }),
    /opening does not reproduce commitment/,
  );
});

test("decodeRevealToken rejects malformed tokens", () => {
  assert.throws(() => decodeRevealToken("!!!not-base64!!!"));
  assert.throws(() => decodeRevealToken(encodeRevealToken({ kind: "nope" } as never)));
});
