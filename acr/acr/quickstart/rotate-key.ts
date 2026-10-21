/**
 * Key rotation example for ACR.
 *
 * Run: node --experimental-strip-types quickstart/rotate-key.ts
 *
 * What this demonstrates:
 *   - Each ACR receipt embeds its own issuer public key (`iss_key`), so
 *     verification is self-contained per receipt. There is no central
 *     verifier catalog to update.
 *   - "Rotation" means: future receipts carry the new pubkey. Old receipts
 *     keep verifying because they carry the old pubkey themselves.
 *   - A consent → modification → withdrawal chain CAN cross keys cleanly.
 *     Each receipt's `prev` field hashes the previous receipt (including
 *     its `iss_key`), so chain integrity is preserved across rotations.
 *
 * Production checklist for a real rotation:
 *   1. Generate a new keypair. Convention: `<issuer>-<year+1>`.
 *   2. Store the new private seed in your secrets vault.
 *   3. Flip your issuer's active key pointer. New receipts now carry the
 *      new pubkey in `iss_key` automatically.
 *   4. Keep the OLD private seed alive only as long as you might need to
 *      sign late-arriving operations on receipts already in flight. Once
 *      you're sure nothing live is signing under the old key, the seed
 *      can be destroyed.
 *   5. There is NO catalog to update. There is NO `notBefore` / `notAfter`
 *      window to manage. ACR's self-contained `iss_key` is the design
 *      decision that removes that operational surface.
 */

import {
  generateKeypair,
  mintConsent,
  mintModification,
  mintWithdrawal,
} from "../src/issue/index.ts";
import { verifyReceiptSignature, resolveChainState, hashReceipt } from "../src/index.ts";

const issuerDid = "did:web:rotation-demo.example";

// Two keypairs across a notional 2026 → 2027 rotation boundary.
const oldKey = generateKeypair("rotation-demo-2026");
const newKey = generateKeypair("rotation-demo-2027");

// Pre-rotation: consent receipt under the OLD key.
const consent = mintConsent({
  issuerDid,
  signingKey: oldKey,
  profile: "gdpr.art7",
  fields: {
    sub_commit: { value: "alice@rotation.example" },
    purposes: [{ value: "marketing-emails" }],
    policy_hash: { value: "policy-2026-Q4-v1" },
  },
  lawful_basis: "6(1)(a)",
  granted_at: "2026-12-01T10:00:00Z",
});

// Post-rotation: modification under the NEW key, chained to the prior consent.
const modification = mintModification({
  prior: consent,
  signingKey: newKey,
  fields: {
    sub_commit: { value: "alice@rotation.example" },
    purposes: [
      { value: "marketing-emails" },
      { value: "analytics" },
    ],
    policy_hash: { value: "policy-2027-Q1-v1" },
  },
  lawful_basis: "6(1)(a)",
  granted_at: "2027-01-15T10:00:00Z",
});

// Late withdrawal: also under the new key.
const withdrawal = mintWithdrawal({
  prior: modification,
  signingKey: newKey,
  granted_at: "2027-06-10T10:00:00Z",
});

console.log("\n# Each receipt carries its own issuer public key (`iss_key`)\n");
console.log(`  consent.iss_key       = ${consent.iss_key.slice(0, 30)}…`);
console.log(`  modification.iss_key  = ${modification.iss_key.slice(0, 30)}…`);
console.log(`  withdrawal.iss_key    = ${withdrawal.iss_key.slice(0, 30)}…`);
console.log(
  `  consent vs modification iss_key match? ${consent.iss_key === modification.iss_key ? "yes" : "NO (rotated)"}`,
);
console.log(
  `  modification vs withdrawal iss_key match? ${modification.iss_key === withdrawal.iss_key ? "yes (same key)" : "NO"}`,
);

// Each receipt verifies in isolation — no catalog needed.
console.log("\n# Self-contained signature verification (no catalog)\n");
console.log(`  verifyReceiptSignature(consent)      = ${verifyReceiptSignature(consent)}`);
console.log(`  verifyReceiptSignature(modification) = ${verifyReceiptSignature(modification)}`);
console.log(`  verifyReceiptSignature(withdrawal)   = ${verifyReceiptSignature(withdrawal)}`);

// Chain integrity also survives the rotation.
console.log("\n# Chain integrity across the rotation boundary\n");
console.log(`  modification.prev === hash(consent)?      ${modification.prev === hashReceipt(consent)}`);
console.log(`  withdrawal.prev   === hash(modification)? ${withdrawal.prev === hashReceipt(modification)}`);

const chain = resolveChainState([consent, modification, withdrawal]);
console.log("\n# Resolved chain state\n");
console.log(`  status                = ${chain.status}`);
console.log(`  terminal_kind         = ${chain.terminal_kind}`);
console.log(`  terminal_granted_at   = ${chain.terminal_granted_at}`);

console.log(
  "\n# Takeaway:\n" +
    "#   ACR's self-contained `iss_key` is what makes rotation cheap. There\n" +
    "#   is no overlap window to schedule, no catalog to redeploy, no\n" +
    "#   `notBefore` / `notAfter` semantics to reason about. If you've used\n" +
    "#   APR you'll find this notably simpler.\n",
);
