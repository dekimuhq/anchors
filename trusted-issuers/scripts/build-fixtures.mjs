#!/usr/bin/env node
/**
 * Regenerates the fixture hash-chain in `data/chain/v01.json`, `v02.json`,
 * `v03.json` from a deterministic test keypair.
 *
 * Deterministic by construction:
 *  - 32-byte test seed baked below (NOT the production bootstrap key — see
 *    master plan §2 + Task B6 ceremony).
 *  - Ed25519 signatures are deterministic for a given (seed, message), so
 *    re-running this script produces byte-equal output.
 *
 * Run from the package root:
 *   node scripts/build-fixtures.mjs
 *
 * Test asserts byte-equality with checked-in JSON, so any change here MUST
 * be paired with a `data/chain/*.json` regeneration in the same commit.
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import {
  publicKeyFromSeed,
  signCanonical,
  base64UrlEncode,
  canonicalize,
} from "@dekimuhq/anchors-envelope";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(__dirname, "..", "data", "chain");

// Deterministic 32-byte test seed. NOT a production key.
const TEST_SEED = new Uint8Array(32);
for (let i = 0; i < 32; i++) TEST_SEED[i] = i + 1;

const PUBLIC_KEY = publicKeyFromSeed(TEST_SEED);
const PUBLISHER_KEY = `ed25519:${base64UrlEncode(PUBLIC_KEY)}`;
const PUBLISHER = "did:web:test.example";

function sha256Canonical(doc) {
  return `sha256:${createHash("sha256").update(canonicalize(doc), "utf8").digest("hex")}`;
}

function sign(unsigned) {
  const sigBytes = signCanonical(unsigned, TEST_SEED);
  return { ...unsigned, sig: base64UrlEncode(sigBytes) };
}

const v01Unsigned = {
  kind: "ar.trusted_issuers.v1",
  version: 1,
  issued_at: "2026-05-19T00:00:00Z",
  valid_until: "2026-06-19T00:00:00Z",
  publisher: PUBLISHER,
  publisher_key: PUBLISHER_KEY,
  previous_sha256: null,
  issuers: [
    {
      iss: "did:web:test.example",
      added_at: "2026-05-01T00:00:00Z",
      revoked_at: null,
      families: ["apr", "acr"],
      profiles_pinned: null,
      notes: "genesis entry",
    },
  ],
  sig: null,
};
const v01 = sign(v01Unsigned);

const v02Unsigned = {
  kind: "ar.trusted_issuers.v1",
  version: 2,
  issued_at: "2026-06-01T00:00:00Z",
  valid_until: "2026-07-01T00:00:00Z",
  publisher: PUBLISHER,
  publisher_key: PUBLISHER_KEY,
  previous_sha256: sha256Canonical(v01),
  issuers: [
    {
      iss: "did:web:test.example",
      added_at: "2026-05-01T00:00:00Z",
      revoked_at: null,
      families: ["apr", "acr"],
      profiles_pinned: null,
      notes: "genesis entry",
    },
    {
      iss: "did:web:other.example",
      added_at: "2026-06-01T00:00:00Z",
      revoked_at: null,
      families: ["acr"],
      profiles_pinned: null,
      notes: "second issuer joins",
    },
  ],
  sig: null,
};
const v02 = sign(v02Unsigned);

const v03Unsigned = {
  kind: "ar.trusted_issuers.v1",
  version: 3,
  issued_at: "2026-06-15T00:00:00Z",
  valid_until: "2026-07-15T00:00:00Z",
  publisher: PUBLISHER,
  publisher_key: PUBLISHER_KEY,
  previous_sha256: sha256Canonical(v02),
  issuers: [
    {
      iss: "did:web:test.example",
      added_at: "2026-05-01T00:00:00Z",
      revoked_at: null,
      families: ["apr", "acr"],
      profiles_pinned: null,
      notes: "genesis entry",
    },
    {
      iss: "did:web:other.example",
      added_at: "2026-06-01T00:00:00Z",
      revoked_at: "2026-06-14T00:00:00Z",
      families: ["acr"],
      profiles_pinned: null,
      notes: "revoked at v03",
    },
  ],
  sig: null,
};
const v03 = sign(v03Unsigned);

mkdirSync(OUT_DIR, { recursive: true });
for (const [name, doc] of [
  ["v01.json", v01],
  ["v02.json", v02],
  ["v03.json", v03],
]) {
  const path = resolve(OUT_DIR, name);
  writeFileSync(path, JSON.stringify(doc, null, 2) + "\n", "utf8");
  process.stdout.write(`wrote ${path}\n`);
}

process.stdout.write(`\npublisher_key: ${PUBLISHER_KEY}\n`);
process.stdout.write(`SPKI raw pubkey (base64url): ${base64UrlEncode(PUBLIC_KEY)}\n`);
