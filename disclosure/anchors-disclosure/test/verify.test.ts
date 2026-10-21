import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { base64UrlEncode, issueFieldCommit } from "@dekimuhq/anchors-envelope";
import { buildFieldTree } from "../src/tree.ts";
import { bundleSaltSource } from "../src/salt.ts";
import { buildPresentation } from "../src/present.ts";
import { verifyPresentation } from "../src/verify.ts";
import type { DisclosureSchema } from "../src/types.ts";

const body = { sub: "alice", purposes: ["mkt", "analytics"], policy: "p-7" };
const schema: DisclosureSchema = {
  claim_type: "ar.consent.v1",
  leaves: [{ path: "/sub" }, { path: "/purposes", array: true }, { path: "/policy" }],
};
const salts = bundleSaltSource({ "/sub": "AAAA", "/purposes/0": "BBBB", "/purposes/1": "CCCC", "/policy": "DDDD" });

function present(reveal: string[]) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const iss_key = `ed25519:${base64UrlEncode(new Uint8Array(spki.subarray(spki.length - 32)))}`;
  const { field_root, leaves } = buildFieldTree(body, schema, salts);
  const fieldCommit = issueFieldCommit(
    { family: "acr", id: "rcpt-1", field_root, leaf_count: leaves.length, iss_key, issued_at: "2026-06-01T00:00:00Z" }, privateKey);
  return { p: buildPresentation({ body, schema, salts, fieldCommit, reveal }), iss_key };
}

test("valid presentation verifies and returns revealed values", () => {
  const { p, iss_key } = present(["/purposes/0", "/policy"]);
  const r = verifyPresentation(p);
  assert.equal(r.valid, true);
  assert.equal(r.issuer, iss_key);
  assert.deepEqual(r.revealed, { "/purposes/0": "mkt", "/policy": "p-7" });
});

test("tampered revealed value → leaf_commit_mismatch", () => {
  const { p } = present(["/policy"]);
  p.revealed[0]!.value = "p-EVIL";
  const r = verifyPresentation(p);
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("leaf_commit_mismatch"));
});

test("receipt_ref ≠ field_commit.id → field_commit_id_mismatch", () => {
  const { p } = present(["/policy"]);
  p.receipt_ref = "other";
  const r = verifyPresentation(p);
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("field_commit_id_mismatch"));
});

test("forged field_commit sig → field_commit_sig_invalid", () => {
  const { p } = present(["/policy"]);
  p.field_commit.field_root = `sha256:${"c".repeat(64)}`; // breaks sig
  const r = verifyPresentation(p);
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("field_commit_sig_invalid"));
});

test("untrusted issuer → issuer_untrusted", () => {
  const { p } = present(["/policy"]);
  const r = verifyPresentation(p, { trustIssuer: () => false });
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("issuer_untrusted"));
});

test("presentation field_root ≠ field_commit.field_root → field_root_mismatch", () => {
  const { p } = present(["/policy"]);
  p.field_root = `sha256:${"d".repeat(64)}`;
  const r = verifyPresentation(p);
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("field_root_mismatch"));
});

test("malformed input never throws", () => {
  // @ts-expect-error deliberate garbage
  const r = verifyPresentation({ kind: "ar.disclosure.v1" });
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("malformed"));
});

test("structurally-invalid merkle_path → merkle_path_invalid", () => {
  const { p } = present(["/purposes/0", "/policy"]);
  p.revealed[0]!.merkle_path = []; // empty path can't reach a 4-leaf root
  const r = verifyPresentation(p);
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("merkle_path_invalid"));
});

test("SECURITY: field-relabel forgery is rejected", () => {
  const { p } = present(["/policy"]);
  // attacker relabels the revealed field's path, keeping value/salt/proof/index
  p.revealed[0]!.path = "/sub";
  const r = verifyPresentation(p);
  assert.equal(r.valid, false);
});

test("SECURITY: NaN leaf_count is rejected (not bypassed)", () => {
  const { p } = present(["/policy"]);
  p.leaf_count = NaN; // NaN satisfies `number` at the type level but must be rejected at runtime
  const r = verifyPresentation(p);
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("malformed"));
});

test("SECURITY: non-integer / zero leaf_count is rejected", () => {
  const { p } = present(["/policy"]);
  p.leaf_count = 0;
  assert.equal(verifyPresentation(p).valid, false);
});

test("opts.schema allowlist rejects a revealed path outside the schema", () => {
  const schemaAllow: DisclosureSchema = { claim_type: "ar.consent.v1", leaves: [{ path: "/policy" }] };
  const { p } = present(["/purposes/0"]); // /purposes not in schemaAllow
  const r = verifyPresentation(p, { schema: schemaAllow });
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("malformed"));
});

test("opts.schema allowlist accepts declared paths incl. array elements", () => {
  const schemaAllow: DisclosureSchema = {
    claim_type: "ar.consent.v1",
    leaves: [{ path: "/sub" }, { path: "/purposes", array: true }, { path: "/policy" }],
  };
  const { p } = present(["/purposes/0", "/policy"]);
  const r = verifyPresentation(p, { schema: schemaAllow });
  assert.equal(r.valid, true);
});

test("ADVERSARIAL: wrong leaf_index (point at different valid index, keep merkle_path) → valid:false", () => {
  // Build with two revealed fields so the indices are distinct and non-trivially swappable.
  const { p } = present(["/sub", "/policy"]);
  // /sub is leaf_index 0, /policy is leaf_index 3.
  // Swap the leaf_index of /sub to point at a different index (e.g. 2), keeping its merkle_path.
  p.revealed[0]!.leaf_index = 2;
  const r = verifyPresentation(p);
  assert.equal(r.valid, false);
});

test("ADVERSARIAL: leaf_count altered to different positive integer (99) → valid:false", () => {
  const { p } = present(["/policy"]);
  p.leaf_count = 99;
  const r = verifyPresentation(p);
  assert.equal(r.valid, false);
});

test("canonicalisation: number value round-trips (honest build+verify)", () => {
  const numSchema: DisclosureSchema = { claim_type: "ar.consent.v1", leaves: [{ path: "/score" }] };
  const numBody = { score: 42 };
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const iss_key = `ed25519:${base64UrlEncode(new Uint8Array(spki.subarray(spki.length - 32)))}`;
  const numSalts = bundleSaltSource({ "/score": "SSSS" });
  const { field_root, leaves: numLeaves } = buildFieldTree(numBody, numSchema, numSalts);
  const fieldCommit = issueFieldCommit(
    { family: "acr", id: "num-rcpt", field_root, leaf_count: numLeaves.length, iss_key, issued_at: "2026-06-01T00:00:00Z" }, privateKey);
  const p = buildPresentation({ body: numBody, schema: numSchema, salts: numSalts, fieldCommit, reveal: ["/score"] });
  const r = verifyPresentation(p);
  assert.equal(r.valid, true);
  assert.equal(r.revealed["/score"], 42);
});

test("canonicalisation: boolean value round-trips (honest build+verify)", () => {
  const boolSchema: DisclosureSchema = { claim_type: "ar.consent.v1", leaves: [{ path: "/active" }] };
  const boolBody = { active: true };
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const iss_key = `ed25519:${base64UrlEncode(new Uint8Array(spki.subarray(spki.length - 32)))}`;
  const boolSalts = bundleSaltSource({ "/active": "BBBB" });
  const { field_root, leaves: boolLeaves } = buildFieldTree(boolBody, boolSchema, boolSalts);
  const fieldCommit = issueFieldCommit(
    { family: "acr", id: "bool-rcpt", field_root, leaf_count: boolLeaves.length, iss_key, issued_at: "2026-06-01T00:00:00Z" }, privateKey);
  const p = buildPresentation({ body: boolBody, schema: boolSchema, salts: boolSalts, fieldCommit, reveal: ["/active"] });
  const r = verifyPresentation(p);
  assert.equal(r.valid, true);
  assert.equal(r.revealed["/active"], true);
});

test("canonicalisation: null value round-trips (honest build+verify)", () => {
  const nullSchema: DisclosureSchema = { claim_type: "ar.consent.v1", leaves: [{ path: "/revoked" }] };
  const nullBody = { revoked: null };
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const iss_key = `ed25519:${base64UrlEncode(new Uint8Array(spki.subarray(spki.length - 32)))}`;
  const nullSalts = bundleSaltSource({ "/revoked": "NNNN" });
  const { field_root, leaves: nullLeaves } = buildFieldTree(nullBody, nullSchema, nullSalts);
  const fieldCommit = issueFieldCommit(
    { family: "acr", id: "null-rcpt", field_root, leaf_count: nullLeaves.length, iss_key, issued_at: "2026-06-01T00:00:00Z" }, privateKey);
  const p = buildPresentation({ body: nullBody, schema: nullSchema, salts: nullSalts, fieldCommit, reveal: ["/revoked"] });
  const r = verifyPresentation(p);
  assert.equal(r.valid, true);
  assert.equal(r.revealed["/revoked"], null);
});

test("linkability (documented behavior): two presentations of same receipt share field_root + receipt_ref and both verify", () => {
  const { p: p1, iss_key } = present(["/sub"]);
  // Build a second presentation from the same fieldCommit — reuse the helper but share the same fieldCommit.
  // We simulate this by building a second presentation from the same data.
  const { p: p2 } = present(["/policy"]);
  // p1 and p2 come from DIFFERENT receipts because `present()` generates fresh keys each call.
  // For the same-receipt test, build both from one fieldCommit directly:
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const iss_key_shared = `ed25519:${base64UrlEncode(new Uint8Array(spki.subarray(spki.length - 32)))}`;
  const { field_root, leaves: sharedLeaves } = buildFieldTree(body, schema, salts);
  const sharedCommit = issueFieldCommit(
    { family: "acr", id: "shared-rcpt", field_root, leaf_count: sharedLeaves.length, iss_key: iss_key_shared, issued_at: "2026-06-01T00:00:00Z" },
    privateKey,
  );
  const pa = buildPresentation({ body, schema, salts, fieldCommit: sharedCommit, reveal: ["/sub"] });
  const pb = buildPresentation({ body, schema, salts, fieldCommit: sharedCommit, reveal: ["/policy"] });

  const ra = verifyPresentation(pa);
  const rb = verifyPresentation(pb);

  // Both verify true.
  assert.equal(ra.valid, true);
  assert.equal(rb.valid, true);
  // Both share the same field_root and receipt_ref (linkability).
  assert.equal(pa.field_root, pb.field_root);
  assert.equal(pa.receipt_ref, pb.receipt_ref);
});

test("trustIssuer ACCEPT path: () => true → valid:true and issuer returned", () => {
  const { p, iss_key } = present(["/policy"]);
  const r = verifyPresentation(p, { trustIssuer: () => true });
  assert.equal(r.valid, true);
  assert.equal(r.issuer, iss_key);
});
