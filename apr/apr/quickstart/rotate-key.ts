/**
 * Key rotation example — adds a new kid as the active signer while leaving
 * the older kid in the verifier catalog so previously-signed receipts keep
 * verifying.
 *
 * Run: node --experimental-strip-types quickstart/rotate-key.ts
 *
 * What this demonstrates:
 *   - Old receipts keep verifying after rotation (catalog still carries old kid).
 *   - New receipts use the new kid.
 *   - Removing the old kid from the catalog later breaks old receipts — this
 *     is a loss you accept when you decide nothing is left signing under it.
 *
 * Production checklist for a real rotation:
 *   1. Generate new keypair (kid `<issuer>-<year+1>` is the convention).
 *   2. Add the new kid to the verifier catalog WITH `notBefore` set to "now",
 *      so receipts signed under the new kid before this moment fail clean.
 *   3. Wait for catalog propagation.
 *   4. Flip your issuer's active kid to the new one.
 *   5. Optionally set `notAfter` on the OLD kid to a future cutoff — older
 *      receipts still verify (signed before notAfter), but freshly forged
 *      ones under the old kid fail with `kid_no_longer_valid`.
 *   6. Months later, when no live workloads sign with the old kid, you may
 *      remove the old kid entirely. Receipts signed under it then fail with
 *      `unknown_kid`.
 */

import * as crypto from "node:crypto";
import {
  mint,
  generateKeypair,
  encodeRaw,
  type APRBody,
} from "../src/issue/index.ts";
import {
  verify,
  canonicalize,
  computeMerkleRoot,
  type ClaimKeyResolver,
  type RootKeyResolver,
  type DailyRoot,
} from "../src/index.ts";

const issuer = "rotation-demo";
const KID_OLD = "rotation-demo-2025";
const KID_NEW = "rotation-demo-2026";

const oldKey = generateKeypair(KID_OLD);
const newKey = generateKeypair(KID_NEW);

function bodyFor(suffix: string): APRBody {
  return {
    artifact: {
      type: "commander.run.output",
      id: `artifact-${suffix}`,
      hash: "0".repeat(64),
      hashAlgorithm: "sha256",
    },
    agent: { kind: "ai" },
    authorization: { principalId: "rotation-principal" },
    startedAt: 1000,
    completedAt: 1001,
    disclosure: "public_minimal",
    qts_attestation_hash: null,
  };
}

// Pre-rotation: mint a receipt under the OLD kid.
const oldReceipt = mint({
  issuer,
  subject: "artifact-old",
  body: bodyFor("old"),
  signingKey: { kid: oldKey.kid, privateKey: oldKey.privateKey },
  newId: () => "01J0ROT00000000000000000A1",
  now: () => 1000,
});

// Post-rotation: mint a fresh receipt under the NEW kid.
const newReceipt = mint({
  issuer,
  subject: "artifact-new",
  body: bodyFor("new"),
  signingKey: { kid: newKey.kid, privateKey: newKey.privateKey },
  newId: () => "01J0ROT00000000000000000A2",
  now: () => 2000,
});

// Verifier catalog carries BOTH kids during the overlap window.
const catalog = new Map([
  [KID_OLD, { kid: KID_OLD, publicKey: oldKey.publicKey, issuer }],
  [KID_NEW, { kid: KID_NEW, publicKey: newKey.publicKey, issuer }],
]);
const claimKeyResolver: ClaimKeyResolver = (kid) => catalog.get(kid);

// Build a daily anchor over both receipt ids, signed by an out-of-band root key.
const rootKey = generateKeypair("rotation-root-2026");
const rootKeyResolver: RootKeyResolver = (kid) =>
  kid === rootKey.kid ? { kid, publicKey: rootKey.publicKey } : undefined;

function signRoot(date: string, rootHash: string): string {
  const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
  const der = Buffer.concat([PKCS8, Buffer.from(rootKey.privateKey)]);
  const sk = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const payload = canonicalize({ v: 1, date, rootHash });
  const sig = crypto.sign(null, Buffer.from(payload, "utf8"), sk);
  return Buffer.from(sig).toString("base64url");
}

function buildAnchor(date: string, ids: string[]): DailyRoot {
  const sorted = [...ids].sort();
  const rootHash = computeMerkleRoot(sorted);
  return {
    v: 1,
    date,
    rootHash,
    count: sorted.length,
    kid: rootKey.kid,
    sig: signRoot(date, rootHash),
  };
}

function checkOne(label: string, receipt: typeof oldReceipt): void {
  const ids = [oldReceipt.id, newReceipt.id];
  const anchor = buildAnchor("2025-01-01", ids);
  const result = verify({
    claim: receipt,
    anchor,
    anchorIds: ids,
    claimKeyResolver,
    rootKeyResolver,
    now: () => 3000,
  });
  const reasons = result.reasons.length ? result.reasons.join(",") : "no reasons";
  console.log(`[${label}] kid=${receipt.kid} → ${result.status} (${reasons})`);
}

console.log("\n# Catalog carries BOTH kids — both receipts MUST verify\n");
checkOne("old receipt", oldReceipt);
checkOne("new receipt", newReceipt);

// Now retire the old kid. The old receipt will fail with unknown_kid.
catalog.delete(KID_OLD);
console.log("\n# Old kid removed from catalog → old receipts no longer verify\n");
checkOne("old receipt (after retire)", oldReceipt);
checkOne("new receipt (after retire)", newReceipt);

console.log("\n# Catalog snippet for the overlap window (both kids present):\n");
console.log(
  JSON.stringify(
    {
      [KID_OLD]: { issuer, publicKey: encodeRaw(oldKey.publicKey) },
      [KID_NEW]: { issuer, publicKey: encodeRaw(newKey.publicKey) },
    },
    null,
    2,
  ),
);
console.log("");
