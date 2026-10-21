import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { base64UrlEncode, issueFieldCommit } from "@dekimuhq/anchors-envelope";
import { buildFieldTree } from "../src/tree.ts";
import { seedSaltSource } from "../src/salt.ts";
import { buildPresentation } from "../src/present.ts";
import { verifyPresentation } from "../src/verify.ts";
import { ACR_DISCLOSURE_SCHEMA } from "../src/schemas/acr.ts";

// A consent-shaped (ACR) receipt body, minted under the generic disclosure scheme.
const body = { sub: "alice", purposes: ["mkt", "analytics"], policy: "p-7" };

function issuer() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const iss_key = `ed25519:${base64UrlEncode(new Uint8Array(spki.subarray(spki.length - 32)))}`;
  return { privateKey, iss_key };
}

test("ACR-shaped receipt: selective disclosure through ar.disclosure.v1 end-to-end", () => {
  const { privateKey, iss_key } = issuer();
  const salts = seedSaltSource(new Uint8Array(32).fill(9)); // per-receipt holder seed
  const { field_root, leaves } = buildFieldTree(body, ACR_DISCLOSURE_SCHEMA, salts);
  const fieldCommit = issueFieldCommit(
    { family: "acr", id: "acr-rcpt-9", field_root, leaf_count: leaves.length, iss_key, issued_at: "2026-06-01T00:00:00Z" },
    privateKey,
  );

  // Holder reveals ONLY /purposes/0, hides sub, purposes/1, policy.
  const p = buildPresentation({ body, schema: ACR_DISCLOSURE_SCHEMA, salts, fieldCommit, reveal: ["/purposes/0"] });

  const r = verifyPresentation(p, { schema: ACR_DISCLOSURE_SCHEMA });
  assert.equal(r.valid, true);
  assert.deepEqual(r.revealed, { "/purposes/0": "mkt" });
  assert.equal(r.issuer, iss_key);
  // hidden fields are absent from the presentation entirely
  assert.equal(p.revealed.length, 1);
});

test("ACR-shaped receipt: tampering the field_commit field_root is rejected", () => {
  const { privateKey, iss_key } = issuer();
  const salts = seedSaltSource(new Uint8Array(32).fill(9));
  const { field_root, leaves: leavesB } = buildFieldTree(body, ACR_DISCLOSURE_SCHEMA, salts);
  const fieldCommit = issueFieldCommit(
    { family: "acr", id: "acr-rcpt-9", field_root, leaf_count: leavesB.length, iss_key, issued_at: "2026-06-01T00:00:00Z" },
    privateKey,
  );
  const p = buildPresentation({ body, schema: ACR_DISCLOSURE_SCHEMA, salts, fieldCommit, reveal: ["/policy"] });
  p.field_commit.field_root = `sha256:${"0".repeat(64)}`;
  assert.equal(verifyPresentation(p).valid, false);
});
