import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { base64UrlEncode, issueFieldCommit } from "@dekimuhq/anchors-envelope";
import { buildFieldTree } from "../src/tree.ts";
import { bundleSaltSource } from "../src/salt.ts";
import { buildPresentation } from "../src/present.ts";
import type { DisclosureSchema } from "../src/types.ts";

const body = { sub: "alice", purposes: ["mkt", "analytics"], policy: "p-7" };
const schema: DisclosureSchema = {
  claim_type: "ar.consent.v1",
  leaves: [{ path: "/sub" }, { path: "/purposes", array: true }, { path: "/policy" }],
};
const salts = bundleSaltSource({ "/sub": "AAAA", "/purposes/0": "BBBB", "/purposes/1": "CCCC", "/policy": "DDDD" });

function fixture() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const iss_key = `ed25519:${base64UrlEncode(new Uint8Array(spki.subarray(spki.length - 32)))}`;
  const { field_root, leaves } = buildFieldTree(body, schema, salts);
  const fieldCommit = issueFieldCommit(
    { family: "acr", id: "rcpt-1", field_root, leaf_count: leaves.length, iss_key, issued_at: "2026-06-01T00:00:00Z" }, privateKey);
  return { field_root, fieldCommit };
}

test("buildPresentation reveals only requested fields", () => {
  const { fieldCommit } = fixture();
  const p = buildPresentation({ body, schema, salts, fieldCommit, reveal: ["/purposes/0", "/policy"] });
  assert.equal(p.kind, "ar.disclosure.v1");
  assert.equal(p.receipt_ref, "rcpt-1");
  assert.equal(p.leaf_count, 4);
  assert.deepEqual(p.revealed.map((r) => r.path).sort(), ["/policy", "/purposes/0"]);
  assert.equal(p.revealed.find((r) => r.path === "/purposes/0")!.value, "mkt");
});

test("buildPresentation throws when field_root != field_commit.field_root", () => {
  const { fieldCommit } = fixture();
  const badCommit = { ...fieldCommit, field_root: `sha256:${"f".repeat(64)}` };
  assert.throws(() => buildPresentation({ body, schema, salts, fieldCommit: badCommit, reveal: ["/policy"] }));
});

test("buildPresentation throws on an unknown reveal path", () => {
  const { fieldCommit } = fixture();
  assert.throws(() => buildPresentation({ body, schema, salts, fieldCommit, reveal: ["/nope"] }));
});

test("reveal-none: empty reveal array → valid shape, revealed.length===0, leaf_count still full", () => {
  const { fieldCommit } = fixture();
  const p = buildPresentation({ body, schema, salts, fieldCommit, reveal: [] });
  assert.equal(p.kind, "ar.disclosure.v1");
  assert.equal(p.revealed.length, 0);
  // leaf_count covers all leaves (4: /sub, /purposes/0, /purposes/1, /policy)
  assert.equal(p.leaf_count, 4);
});

test("reveal-all: every schema path appears in revealed", () => {
  const { fieldCommit } = fixture();
  // All four resolved leaf paths:
  const allPaths = ["/sub", "/purposes/0", "/purposes/1", "/policy"];
  const p = buildPresentation({ body, schema, salts, fieldCommit, reveal: allPaths });
  const revealedPaths = p.revealed.map((r) => r.path).sort();
  assert.deepEqual(revealedPaths, [...allPaths].sort());
  assert.equal(p.revealed.length, 4);
});

test("incl passthrough: present with incl → p.incl deep-equals it; omit → 'incl' not in p", () => {
  const { fieldCommit } = fixture();
  const inclPayload = { some: "proof", entries: [1, 2, 3] };
  const pWith = buildPresentation({ body, schema, salts, fieldCommit, reveal: [], incl: inclPayload });
  assert.deepEqual(pWith.incl, inclPayload);
  const pWithout = buildPresentation({ body, schema, salts, fieldCommit, reveal: [] });
  assert.equal("incl" in pWithout, false);
});
