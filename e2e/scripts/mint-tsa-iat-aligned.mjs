#!/usr/bin/env node
/**
 * Mint `test/vectors-v1-1/arr-erasure-v2-tsa-iat-aligned.json` — an ARR v=2
 * erasure receipt with a real FreeTSA RFC 3161 token whose genTime sits within
 * the default 300 s drift of the receipt's SIGNED `iat`.
 *
 * The verifier's default TSA reference time is the signed `iat` (not the
 * verifier's wall clock), so this vector must verify `tsa_verified` with NO
 * pinned `tsaReferenceTime`, however long after mint it is checked. It is the
 * fixture for "a genuine MANDATORY receipt does not go invalid ~5 min after
 * mint".
 *
 * Network-dependent (POSTs to https://freetsa.org/tsr). Idempotent: skips when
 * the output file already carries a token. Uses the public all-0x42 test seed
 * shared with mint-vectors.mjs, and the body of arr-erasure-v2-tsa.json.
 *
 * Usage (after `npm run build-all`):  node e2e/scripts/mint-tsa-iat-aligned.mjs
 */

import * as crypto from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import {
  computeTsaImprint,
  buildTimeStampReq,
  parseTimeStampResp,
  loadTrustAnchors,
  defaultTrustAnchorPath,
  verifyTsa,
} from "@dekimuhq/anchors-envelope/tsa";

const VECTORS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "test", "vectors-v1-1");
const OUT = join(VECTORS_DIR, "arr-erasure-v2-tsa-iat-aligned.json");

if (existsSync(OUT) && JSON.parse(readFileSync(OUT, "utf8"))?.receipt?.tsa?.tsr) {
  console.log("arr-erasure-v2-tsa-iat-aligned.json: skipping (already minted)");
  process.exit(0);
}

// PUBLIC TEST KEY — 32-byte Ed25519 seed all-0x42 (same as mint-vectors.mjs).
const SEED = Buffer.alloc(32, 0x42);
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const PRIVATE_KEY = crypto.createPrivateKey({
  key: Buffer.concat([PKCS8_PREFIX, SEED]),
  format: "der",
  type: "pkcs8",
});

const template = JSON.parse(readFileSync(join(VECTORS_DIR, "arr-erasure-v2-tsa.json"), "utf8"));
const iat = new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace(".000Z", "Z");

const signed = await signEnvelope(
  {
    ...template.receipt,
    id: "01HXXARRERASV2TSAIAT0001",
    iat,
    anchor: { ...template.receipt.anchor, log_time: iat },
    tsa: null,
    sig: "",
  },
  PRIVATE_KEY,
);

const imprint = computeTsaImprint(signed);
const res = await fetch("https://freetsa.org/tsr", {
  method: "POST",
  headers: { "Content-Type": "application/timestamp-query" },
  body: buildTimeStampReq(imprint, "sha-256", { certReq: true }),
});
if (!res.ok) throw new Error(`FreeTSA responded with HTTP ${res.status}`);
const tsrBytes = new Uint8Array(await res.arrayBuffer());
const parsed = parseTimeStampResp(tsrBytes);
if (!parsed.granted) throw new Error(`FreeTSA PKI status not granted (status=${parsed.status})`);

const receipt = {
  ...signed,
  tsa: {
    v: 1,
    tsr: base64UrlEncode(tsrBytes),
    alg: "sha-256",
    tsa_url: "https://freetsa.org/tsr",
    tsa_cert_chain_sha256: (parsed.signerInfo.certChainDer ?? []).map(
      (der) => "sha256:" + crypto.createHash("sha256").update(der).digest("hex"),
    ),
    issued_at: parsed.tstInfo.genTime,
  },
};

// Sanity: verifies against the signed iat as reference time.
const check = verifyTsa(tsrBytes, imprint, {
  anchors: loadTrustAnchors([defaultTrustAnchorPath()]),
  driftToleranceSec: 300,
  referenceTime: new Date(iat),
});
if (check.reason !== "tsa_verified") throw new Error(`sanity check failed: ${check.reason}`);

writeFileSync(
  OUT,
  JSON.stringify(
    {
      name: "arr-erasure-v2-tsa-iat-aligned",
      family: "arr",
      envelope_version: 2,
      receipt,
      publicKey_b64url: template.publicKey_b64url,
      expected: { envelope_version: 2, signature_valid: true, tsa_state: "tsa_verified" },
    },
    null,
    2,
  ) + "\n",
);
console.log(`wrote ${OUT} (iat=${iat}, genTime=${parsed.tstInfo.genTime})`);
