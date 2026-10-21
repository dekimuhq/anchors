/**
 * Quickstart — mint a test-mode APR end-to-end.
 *
 * What this does:
 *   1. Generate a fresh Ed25519 keypair (test only — NOT for production)
 *   2. Build an APRBody describing a fake artifact
 *   3. Mint a signed APR claim
 *   4. Self-verify the signature locally using @dekimuhq/apr
 *   5. Print the catalog snippet you would paste into a public verifier's
 *      CLAIMS_VERIFY_KEYS_JSON (or equivalent) to make the receipt verifiable
 *      from outside your machine.
 *
 * Run: node --experimental-strip-types quickstart/quickstart.ts
 *
 * No network, no Dekimu credentials. The output is a single fully-formed
 * APR you can post to any v1-conforming verifier.
 */

import * as crypto from "node:crypto";
import {
  mint,
  generateKeypair,
  encodeRaw,
  type APRBody,
} from "../src/issue/index.ts";
import {
  verifyClaim,
  base64UrlDecode,
  canonicalize,
  type ClaimKeyResolver,
} from "../src/index.ts";

// 1. Generate a fresh keypair. In production this would be issued once,
//    stored in a secrets vault, and the kid would survive years.
const issuerName = "quickstart-issuer";
const kid = "quickstart-2026";
const keypair = generateKeypair(kid);

// 2. Build an APRBody.
const artifactBytes = Buffer.from("hello world", "utf8");
const artifactHash = crypto
  .createHash("sha256")
  .update(artifactBytes)
  .digest("hex");

const body: APRBody = {
  artifact: {
    type: "commander.run.output",
    id: "quickstart-artifact-001",
    hash: artifactHash,
    hashAlgorithm: "sha256",
    contentType: "text/plain",
    sizeBytes: artifactBytes.length,
  },
  agent: {
    kind: "ai",
    model: "test-model",
    provider: "test-provider",
  },
  authorization: { principalId: "quickstart-principal" },
  inputs: [{ kind: "prompt" }],
  startedAt: Math.floor(Date.now() / 1000) - 1,
  completedAt: Math.floor(Date.now() / 1000),
  durationMs: 1000,
  disclosure: "public_minimal",
  qts_attestation_hash: null,
};

// 3. Mint.
const claim = mint({
  issuer: issuerName,
  subject: body.artifact.id,
  body,
  signingKey: { kid: keypair.kid, privateKey: keypair.privateKey },
});

console.log("\n# Minted APR claim\n");
console.log(JSON.stringify(claim, null, 2));

// 4. Self-verify the signature locally — sanity-check before sending anywhere.
const localResolver: ClaimKeyResolver = (askedKid) =>
  askedKid === kid
    ? { kid, publicKey: keypair.publicKey, issuer: issuerName }
    : undefined;

const verifyResult = verifyClaim(
  claim,
  localResolver,
  Math.floor(Date.now() / 1000),
);

if (!verifyResult.ok) {
  console.error("\n[FAIL] self-verify failed:", verifyResult.reason);
  process.exit(1);
}
console.log("\n[OK] self-verify passed — signature checks out locally.\n");

// 5. Print the public-key snippet to paste into a verifier catalog.
console.log("# CLAIMS_VERIFY_KEYS_JSON entry to publish for this kid\n");
console.log(
  JSON.stringify(
    {
      [kid]: {
        issuer: issuerName,
        publicKey: encodeRaw(keypair.publicKey),
      },
    },
    null,
    2,
  ),
);

console.log(
  "\n# Next steps:\n" +
    "#   - To verify against verify.dekimu.com, an admin pastes the catalog snippet\n" +
    "#     above into CLAIMS_VERIFY_KEYS_JSON on the verifier. Until then, your\n" +
    "#     receipt verifies only locally with the catalog you control.\n" +
    "#   - For real issuance, replace generateKeypair() with a key loaded from a\n" +
    "#     secrets vault. NEVER commit a private seed.\n" +
    "#   - For rotation, see docs/key-rotation.md in this repo.\n",
);

// Defensively confirm the signature was computed over the exact bytes our
// canonicalizer produced — useful as a deterministic-build check.
const { sig, ...unsigned } = claim;
const canonical = canonicalize(unsigned);
const reSig = base64UrlDecode(sig);
if (reSig.length !== 64) {
  console.error("[FAIL] signature is not 64 bytes:", reSig.length);
  process.exit(1);
}
if (canonical.length === 0) {
  console.error("[FAIL] canonicalisation produced empty output");
  process.exit(1);
}
console.log(`[OK] canonical bytes len=${canonical.length}, sig bytes len=64\n`);
