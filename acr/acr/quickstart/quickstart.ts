/**
 * Quickstart — mint an ACR consent receipt end-to-end.
 *
 * What this does:
 *   1. Generate a fresh Ed25519 keypair (test only — NOT for production).
 *   2. Mint a `gdpr.art7` consent receipt with salted commitments for
 *      sub_commit, purposes, and policy_hash.
 *   3. Self-verify the signature locally using @dekimuhq/acr.
 *   4. Show the JSON shape a downstream consumer (verifier, auditor, DPO tool)
 *      would receive.
 *
 * Run: node --experimental-strip-types quickstart/quickstart.ts
 *
 * No network, no Dekimu credentials. ACR receipts are self-contained — the
 * issuer's public key is embedded in the receipt itself (`iss_key`), so
 * verifiers don't need a separate kid → key catalog. This is a structural
 * difference from APR.
 */

import {
  generateKeypair,
  mintConsent,
} from "../src/issue/index.ts";
import { verifyReceiptSignature } from "../src/index.ts";
import { validateGdprArt7 } from "@dekimuhq/acr-profiles";

// 1. Generate a fresh keypair. In production this would be issued once and
//    stored in a secrets vault. The `kid` is opaque to the protocol; it's
//    a label your operator sees, not a verifier lookup key.
const keypair = generateKeypair("quickstart-issuer-2026");

// 2. Mint a consent receipt. Real fields are commit-then-disclose, but for
//    the quickstart we pass plaintext values and let the kit salt them.
const consent = mintConsent({
  issuerDid: "did:web:quickstart.example",
  signingKey: keypair,
  profile: "gdpr.art7",
  fields: {
    sub_commit: { value: "alice@example.com" },
    purposes: [
      { value: "marketing-emails" },
      { value: "analytics" },
    ],
    policy_hash: { value: "policy-2026-Q2-v3" },
  },
  lawful_basis: "6(1)(a)",
  granted_at: "2026-05-16T10:00:00Z",
  expires_at: "2027-05-16T10:00:00Z",
  // `returnSalts: true` would yield the salts back as part of the result —
  // needed only if you want to later prove a selective disclosure. Omitted
  // here because the quickstart's signature check would fail if salts were
  // present on the canonical view.
});

console.log("\n# Minted ACR consent receipt\n");
console.log(JSON.stringify(consent, null, 2));

// 3. Self-verify the signature locally. This is a sanity check before
//    sending the receipt anywhere — a failure here means your signing
//    code drifted from the canonicalisation contract.
const sigOk = verifyReceiptSignature(consent);
if (!sigOk) {
  console.error("\n[FAIL] self-verify failed — signature does not match canonical bytes");
  process.exit(1);
}
console.log("\n[OK] self-verify passed — signature checks out locally.\n");

// 4. Profile validator. `gdpr.art7` requires lawful basis under Art. 6(1)(a),
//    a `policy_hash`, and at least one purpose. The validator confirms the
//    shape is consistent with what a GDPR auditor would expect.
const profile = validateGdprArt7(consent);
if (!profile.valid) {
  console.error("\n[FAIL] gdpr.art7 profile validation failed:", profile.errors);
  process.exit(1);
}
console.log("[OK] gdpr.art7 profile validation passed.\n");

console.log("# Next steps:\n");
console.log(
  "#   - Send the receipt JSON to your retention / consent-ledger storage.\n" +
    "#   - To later prove a single field (e.g. policy_hash) without revealing\n" +
    "#     the subject identity, re-mint with `returnSalts: true` and pass the\n" +
    "#     salts to `buildDisclosureProof()` from this package.\n" +
    "#   - To modify or withdraw consent, use `mintModification()` /\n" +
    "#     `mintWithdrawal()` with the prior receipt — they chain via `prev`.\n" +
    "#   - For real issuance, replace `generateKeypair()` with a key loaded\n" +
    "#     from a secrets vault. NEVER commit a private seed.\n" +
    "#   - For rotation, see docs/key-rotation.md in this repo.\n",
);
