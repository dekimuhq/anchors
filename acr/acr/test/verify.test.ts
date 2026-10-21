import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { canonicalize, base64UrlEncode } from "../src/canonicalize.ts";
import { verifyReceiptSignature } from "../src/verify.ts";
import type { ACRReceipt } from "../src/types.ts";

function signedReceipt(): { receipt: ACRReceipt; publicKey: Uint8Array } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const skRaw = (privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).subarray(-32);
  const pkRaw = (publicKey.export({ format: "der", type: "spki" }) as Buffer).subarray(-32);
  const pkB64 = base64UrlEncode(new Uint8Array(pkRaw));

  const base: Omit<ACRReceipt, "sig"> & { sig: null } = {
    kind: "ar.consent.v1",
    profile: "gdpr.art7",
    iss: "did:web:bank.example",
    iss_key: `ed25519:${pkB64}`,
    sub_commit: "sha256:" + "a".repeat(64),
    purposes: ["sha256:" + "b".repeat(64)],
    lawful_basis: "6(1)(a)",
    policy_hash: "sha256:" + "c".repeat(64),
    granted_at: "2026-05-15T10:00:00Z",
    prev: null,
    field_root: "sha256:" + "d".repeat(64),
    anchor: null,
    sig: null,
    countersig: null,
    qts_attestation_hash: null,
  };
  const bytes = new TextEncoder().encode(canonicalize(base));
  const skPkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(skRaw),
  ]);
  const skKey = crypto.createPrivateKey({ key: skPkcs8, format: "der", type: "pkcs8" });
  const sig = crypto.sign(null, bytes, skKey);
  const sigB64 = base64UrlEncode(new Uint8Array(sig));

  const receipt: ACRReceipt = { ...base, sig: `ed25519:${sigB64}` };
  return { receipt, publicKey: new Uint8Array(pkRaw) };
}

test("verifyReceiptSignature accepts a valid signature", () => {
  const { receipt } = signedReceipt();
  assert.equal(verifyReceiptSignature(receipt), true);
});

test("verifyReceiptSignature rejects a tampered field", () => {
  const { receipt } = signedReceipt();
  const tampered = { ...receipt, lawful_basis: "6(1)(b)" };
  assert.equal(verifyReceiptSignature(tampered), false);
});

test("verifyReceiptSignature rejects when sig is malformed", () => {
  const { receipt } = signedReceipt();
  const bad = { ...receipt, sig: "ed25519:notbase64url!!!" };
  assert.equal(verifyReceiptSignature(bad), false);
});

test("verifyReceiptSignature ignores anchor field (set after signing)", () => {
  const { receipt } = signedReceipt();
  const anchored = {
    ...receipt,
    anchor: {
      log: "https://verify.dekimu.com/acr/v1",
      leaf_index: 0,
      inclusion_proof: [],
      tree_head_root: "sha256:" + "0".repeat(64),
      tree_size: 1,
      log_time: "2026-05-15T10:00:01Z",
    },
  };
  assert.equal(verifyReceiptSignature(anchored), true);
});
