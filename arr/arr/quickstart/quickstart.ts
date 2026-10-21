/**
 * Quickstart — mint an ARR erasure receipt end-to-end.
 *
 * What this does:
 *   1. Generate a fresh Ed25519 keypair (test only — NOT for production).
 *   2. Mint a `gdpr.art17` erasure receipt for a single subject, triggered
 *      by a subject access request (Art. 12(3)).
 *   3. Self-verify the signature + structural rules via @dekimuhq/arr.
 *   4. Run the `gdpr.art17` profile validator to confirm regulator fitness.
 *
 * Run: node --experimental-strip-types quickstart/quickstart.ts
 *
 * No network, no Dekimu credentials. ARR receipts are self-contained — the
 * issuer's public key is embedded in the receipt (`iss_key`), so verifiers
 * don't need a separate kid → key catalog. Same structural choice as ACR.
 */

import {
  generateIssuerKey,
  encodePublicKey,
  mintErasure,
} from "../src/issue/index.ts";
import { verifySingleReceipt } from "../src/index.ts";
import { validateGdprArt17 } from "@dekimuhq/arr-profiles";

// 1. Generate a fresh keypair. In production this would be issued once and
//    stored in a secrets vault.
const { publicKey, privateKey } = generateIssuerKey();
const issKey = encodePublicKey(publicKey);

// 2. Mint an `ar.erasure.v1` receipt. `target_kind: "subject"` means the
//    target is a data subject (a person); use `"artifact"` for documents
//    or other non-subject records.
//
//    `trigger: "subject_request"` REQUIRES a `trigger_receipt` cross-
//    reference — the hash of the consent / access-request receipt that
//    initiated this erasure. The protocol enforces this so an auditor can
//    walk the Art. 12(3) 30-day-demo end-to-end.
const receipt = mintErasure({
  iss: "did:web:quickstart.example",
  iss_key: issKey,
  privateKey,
  profile: "gdpr.art17",
  target_kind: "subject",
  target_commit: "sha256:" + "ab".repeat(32),
  salt_epoch: "2026Q2",
  policy_hash: "sha256:" + "cd".repeat(32),
  policy_uri: "https://quickstart.example/policy/v3",
  policy_version: "3.1.0",
  trigger: "subject_request",
  trigger_receipt: "sha256:" + "ef".repeat(32),
  event_at: "2026-05-16T09:12:00Z",
  granted_at: "2026-05-16T09:14:00Z",
  state_snapshot: {
    retention_status: "erased",
    current_policy_hash: "sha256:" + "cd".repeat(32),
    hold_active: false,
    hold_reason_commit: null,
    anonymized: false,
    archived: false,
  },
  prev: null,
  extraFields: {
    // `gdpr.art17` requires these two so an auditor can confirm what was
    // erased and from whom they can request controller-side detail.
    subject_data_categories: ["sha256:" + "01".repeat(32)],
    controller_contact_hash: "sha256:" + "02".repeat(32),
  },
});

console.log("\n# Minted ARR erasure receipt\n");
console.log(JSON.stringify(receipt, null, 2));

// 3. Self-verify the signature + structural rules. `anchorInclusionTime`
//    simulates the moment a verifier sees the receipt — anchored after
//    the `granted_at` timestamp.
const verifyResult = verifySingleReceipt(receipt, {
  anchorInclusionTime: "2026-05-16T09:20:00Z",
});
if (!verifyResult.valid) {
  console.error("\n[FAIL] verifySingleReceipt errors:", verifyResult.errors);
  process.exit(1);
}
console.log("\n[OK] verifySingleReceipt passed — signature + structure clean.\n");

// 4. Profile validator. `gdpr.art17` fulfilment requires:
//      - kind ∈ { erasure, anonymization }
//      - state_snapshot.retention_status ∈ { erased, anonymized }
//      - subject_data_categories present (auditor needs to know what was erased)
//      - controller_contact_hash present (auditor needs to know who to ask)
const profile = validateGdprArt17(receipt);
if (profile.errors.length > 0) {
  console.error("\n[FAIL] gdpr.art17 profile validation failed:", profile.errors);
  process.exit(1);
}
console.log("[OK] gdpr.art17 profile validation passed.\n");

console.log("# Next steps:\n");
console.log(
  "#   - Send the receipt JSON to your retention-ledger storage.\n" +
    "#   - To chain further retention events (e.g. a later anonymisation\n" +
    "#     after a partial erasure), use `mintAnonymization()` etc. with\n" +
    "#     `prev: hashReceipt(thisReceipt)`.\n" +
    "#   - For batched retention runs (e.g. nightly expiry jobs), use\n" +
    "#     `mintBatchReceipt()` from this package — same signing key,\n" +
    "#     up to 65,536 targets per batch (RFC 6962 depth ≤ 16).\n" +
    "#   - For real issuance, load the private key from a secrets vault\n" +
    "#     and encode the matching public key with `encodePublicKey()`.\n" +
    "#   - For rotation, see docs/key-rotation.md in this repo.\n",
);
