/**
 * Mint Phase D Task 18 Status List Credential fixtures.
 *
 * Generates three JSON files committed alongside this script:
 *
 *   verify.dekimu.com-root.json  — RootKeyMaterial for the legitimate signer
 *   some-other-root.json         — RootKeyMaterial for an unrelated signer
 *   status-list-signed.json      — StatusListCredential signed by the
 *                                  legitimate root key (Ed25519Signature2020,
 *                                  RFC 8785 canonical, MSB-first bit ordering)
 *
 * Re-runnable: regenerates fresh CSPRNG-backed Ed25519 keypairs and a new
 * proofValue each run. CI and the test suite NEVER execute this script —
 * tests import the committed JSON. Re-run only when intentionally rotating
 * fixtures.
 *
 * Run:  node --experimental-strip-types envelope/test/status/fixtures/_mint-status-list-fixtures.mjs
 */

import {
  generateKeyPairSync,
  sign as edSign,
} from "node:crypto";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { canonicalize } from "../../../src/index.ts";
import { base64UrlEncode } from "../../../src/base64url.ts";
import { encodedListFromBitstring } from "../../../src/status/decode.ts";

const here = dirname(fileURLToPath(import.meta.url));

function makeKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  return {
    publicKey,
    privateKey,
    publicKeyDerB64u: base64UrlEncode(new Uint8Array(publicKeyDer)),
  };
}

const legit = makeKeypair();
const other = makeKeypair();

const legitKid = "did:web:verify.dekimu.com#root";
const otherKid = "did:web:other.example#root";

// 131 072-bit zero-filled bitstring (W3C minimum size) → gzip → base64url
const encodedList = encodedListFromBitstring(new Uint8Array(131072 / 8));

const unsignedCredential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc/status-list/2021/v1",
  ],
  id: "https://verify.dekimu.com/acr/v1/status/2026/05",
  type: ["VerifiableCredential", "StatusList2021Credential"],
  issuer: "did:web:verify.dekimu.com",
  validFrom: "2026-05-01T00:00:00Z",
  credentialSubject: {
    id: "https://verify.dekimu.com/acr/v1/status/2026/05#list",
    type: "StatusList2021",
    statusPurpose: "revocation",
    encodedList,
  },
};

const canonical = canonicalize(unsignedCredential);
const sigBytes = edSign(null, Buffer.from(canonical, "utf8"), legit.privateKey);

const signedCredential = {
  ...unsignedCredential,
  proof: {
    type: "Ed25519Signature2020",
    created: "2026-05-17T00:00:00Z",
    verificationMethod: legitKid,
    proofPurpose: "assertionMethod",
    proofValue: base64UrlEncode(new Uint8Array(sigBytes)),
  },
};

writeFileSync(
  join(here, "verify.dekimu.com-root.json"),
  JSON.stringify(
    { kid: legitKid, publicKeyDer: legit.publicKeyDerB64u },
    null,
    2,
  ) + "\n",
);

writeFileSync(
  join(here, "some-other-root.json"),
  JSON.stringify(
    { kid: otherKid, publicKeyDer: other.publicKeyDerB64u },
    null,
    2,
  ) + "\n",
);

writeFileSync(
  join(here, "status-list-signed.json"),
  JSON.stringify(signedCredential, null, 2) + "\n",
);

console.log("Wrote 3 fixture files in", here);
