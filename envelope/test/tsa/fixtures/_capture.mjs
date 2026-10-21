/**
 * Fixture builder — captures a live FreeTSA timestamp response.
 * Run once: node --experimental-strip-types envelope/test/tsa/fixtures/_capture.mjs
 * (from the repository root)
 *
 * Writes:
 *   freetsa-sample.tsr     — raw DER TimeStampResp bytes
 *   freetsa-sample.imprint — the 32-byte SHA-256 imprint sent in the request
 */

import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { buildTimeStampReq } from "../../../src/tsa/request.ts";

// Deterministic input: SHA-256 of 32 zero bytes
const inputBytes = new Uint8Array(32).fill(0);
const imprint = new Uint8Array(
  createHash("sha256").update(inputBytes).digest()
);

const req = buildTimeStampReq(imprint, "sha-256", { certReq: true });

const res = await fetch("https://freetsa.org/tsr", {
  method: "POST",
  headers: { "Content-Type": "application/timestamp-query" },
  body: req,
});

if (!res.ok) throw new Error(`FreeTSA HTTP ${res.status}`);

const tsr = new Uint8Array(await res.arrayBuffer());

// Files are written relative to the repository root when invoked as documented,
// but the script itself resolves from its own location to be safe.
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
const __dir = dirname(fileURLToPath(import.meta.url));

writeFileSync(join(__dir, "freetsa-sample.tsr"), tsr);
writeFileSync(join(__dir, "freetsa-sample.imprint"), imprint);
console.log(`captured ${tsr.length} bytes`);
