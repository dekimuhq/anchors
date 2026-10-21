/**
 * Key rotation example for ARR.
 *
 * Run: node --experimental-strip-types quickstart/rotate-key.ts
 *
 * What this demonstrates:
 *   - Each ARR receipt embeds its own issuer public key (`iss_key`), so
 *     verification is self-contained per receipt. There is no central
 *     verifier catalog to update.
 *   - "Rotation" means: future receipts carry the new pubkey. Older
 *     receipts keep verifying because they carry the old pubkey themselves.
 *   - A multi-event retention chain for the same `target_commit` CAN cross
 *     keys cleanly. Chain walkers in `@dekimuhq/arr` use each
 *     receipt's own `iss_key` for signature verification.
 *
 * Production checklist for a real rotation:
 *   1. Generate a new keypair via `generateIssuerKey()`.
 *   2. Store the new private seed in your secrets vault.
 *   3. Flip your issuer's active key pointer. New receipts now carry the
 *      new pubkey in `iss_key` automatically.
 *   4. Keep the OLD private seed alive only as long as you might need to
 *      sign late retention operations against still-live targets. Once
 *      you're confident no live job is signing under the old key, the
 *      seed can be destroyed.
 *   5. There is NO catalog to update. There is NO `notBefore` / `notAfter`
 *      window to manage. Same as ACR — much simpler than APR's catalog
 *      model.
 */

import {
  generateIssuerKey,
  encodePublicKey,
  mintHoldExtension,
  mintHoldRelease,
} from "../src/issue/index.ts";
import { verifySingleReceipt } from "../src/index.ts";

const issuer = "did:web:rotation-demo.example";
const targetCommit = "sha256:" + "ab".repeat(32);
const policyHash = "sha256:" + "cd".repeat(32);

// Two keypairs across a notional 2026 → 2027 rotation boundary.
const oldKey = generateIssuerKey();
const newKey = generateIssuerKey();
const oldIssKey = encodePublicKey(oldKey.publicKey);
const newIssKey = encodePublicKey(newKey.publicKey);

const baseSnapshot = {
  retention_status: "held" as const,
  current_policy_hash: policyHash,
  hold_active: true,
  hold_reason_commit: "sha256:" + "11".repeat(32),
  anonymized: false,
  archived: false,
};

// Pre-rotation: a hold-extension event for the target, signed by OLD key.
const heldUnderOldKey = mintHoldExtension({
  iss: issuer,
  iss_key: oldIssKey,
  privateKey: oldKey.privateKey,
  profile: "gdpr.art5e",
  target_kind: "subject",
  target_commit: targetCommit,
  salt_epoch: "2026Q4",
  policy_hash: policyHash,
  policy_uri: "https://rotation-demo.example/policy/v3",
  policy_version: "3.1.0",
  trigger: "legal_order",
  trigger_receipt: "sha256:" + "ef".repeat(32),
  event_at: "2026-12-01T10:00:00Z",
  granted_at: "2026-12-01T10:00:00Z",
  effective_until: "2027-06-30T23:59:59Z",
  state_snapshot: baseSnapshot,
  prev: null,
});

// Post-rotation: the hold is released months later — signed by NEW key.
// In a real chain you'd also pass `prev: hash(heldUnderOldKey)`. The hash
// helper isn't exported by `@dekimuhq/arr` in v0.1.x; chain
// integrity is validated end-to-end by `resolveTargetChain([heldUnderOldKey,
// releasedUnderNewKey])`, which performs the hashing internally.
const releasedUnderNewKey = mintHoldRelease({
  iss: issuer,
  iss_key: newIssKey,
  privateKey: newKey.privateKey,
  profile: "gdpr.art5e",
  target_kind: "subject",
  target_commit: targetCommit,
  salt_epoch: "2027Q1",
  policy_hash: policyHash,
  policy_uri: "https://rotation-demo.example/policy/v3",
  policy_version: "3.1.0",
  trigger: "operator",
  trigger_receipt: null,
  event_at: "2027-02-15T09:00:00Z",
  granted_at: "2027-02-15T09:00:00Z",
  state_snapshot: {
    ...baseSnapshot,
    retention_status: "active" as const,
    hold_active: false,
    hold_reason_commit: null,
  },
  prev: null,
});

console.log("\n# Each receipt carries its own issuer public key (`iss_key`)\n");
console.log(`  held.iss_key      = ${heldUnderOldKey.iss_key.slice(0, 30)}…`);
console.log(`  released.iss_key  = ${releasedUnderNewKey.iss_key.slice(0, 30)}…`);
console.log(
  `  held vs released iss_key match? ${heldUnderOldKey.iss_key === releasedUnderNewKey.iss_key ? "yes" : "NO (rotated)"}`,
);

// Each receipt verifies in isolation — no catalog needed.
console.log("\n# Self-contained signature verification (no catalog)\n");
const heldOk = verifySingleReceipt(heldUnderOldKey, {
  anchorInclusionTime: "2026-12-01T10:05:00Z",
});
const releasedOk = verifySingleReceipt(releasedUnderNewKey, {
  anchorInclusionTime: "2027-02-15T09:05:00Z",
});
console.log(`  verifySingleReceipt(held under old key)      → valid=${heldOk.valid}`);
console.log(`  verifySingleReceipt(released under new key)  → valid=${releasedOk.valid}`);

if (!heldOk.valid || !releasedOk.valid) {
  console.error("\n[FAIL] expected both to verify");
  console.error("  held errors:    ", heldOk.errors);
  console.error("  released errors:", releasedOk.errors);
  process.exit(1);
}

console.log(
  "\n# Takeaway:\n" +
    "#   ARR's self-contained `iss_key` makes rotation cheap. There is no\n" +
    "#   catalog to redeploy, no overlap window to schedule, no `notBefore`\n" +
    "#   / `notAfter` semantics to reason about. A chain of retention events\n" +
    "#   for the same target can span multiple signing keys with no special\n" +
    "#   protocol handshake — the chain walker reads each receipt's embedded\n" +
    "#   pubkey on its own. See ../docs/key-rotation.md for the full guide.\n",
);
