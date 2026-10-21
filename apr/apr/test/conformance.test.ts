/**
 * Drives `apr-verifier` against the published v1 conformance vectors in
 * `apr-spec/conformance/test-vectors/`. A conforming verifier MUST reach the
 * exact status declared in `expected.json` for every vector group, with no
 * network access.
 *
 * Run: node --experimental-strip-types --test test/conformance.test.ts
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { verify } from "../src/verify.ts";
import { base64UrlDecode } from "../src/base64url.ts";
import type {
  ClaimKeyResolver,
  RootKeyResolver,
  DailyRoot,
  ClaimVerifyingKey,
  RootVerifyingKey,
} from "../src/types.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const VECTORS_DIR = path.resolve(
  __dirname,
  "fixtures",
  "conformance-vectors",
);

interface CatalogClaimEntry {
  issuer: string;
  publicKey: string;
  notBefore?: number;
  notAfter?: number;
}
interface CatalogRootEntry {
  publicKey: string;
}

function buildClaimResolver(
  catalog: Record<string, CatalogClaimEntry>,
): ClaimKeyResolver {
  const map = new Map<string, ClaimVerifyingKey>();
  for (const [kid, entry] of Object.entries(catalog)) {
    map.set(kid, {
      kid,
      publicKey: base64UrlDecode(entry.publicKey),
      issuer: entry.issuer,
      ...(entry.notBefore !== undefined ? { notBefore: entry.notBefore } : {}),
      ...(entry.notAfter !== undefined ? { notAfter: entry.notAfter } : {}),
    });
  }
  return (kid) => map.get(kid);
}

function buildRootResolver(
  catalog: Record<string, CatalogRootEntry>,
): RootKeyResolver {
  const map = new Map<string, RootVerifyingKey>();
  for (const [kid, entry] of Object.entries(catalog)) {
    map.set(kid, { kid, publicKey: base64UrlDecode(entry.publicKey) });
  }
  return (kid) => map.get(kid);
}

function loadJson<T>(p: string): T {
  return JSON.parse(fs.readFileSync(p, "utf8")) as T;
}

const vectorDirs = fs
  .readdirSync(VECTORS_DIR)
  .filter((d) => /^\d{2}-/.test(d))
  .sort();

assert.equal(
  vectorDirs.length,
  5,
  `expected 5 vector groups, found ${vectorDirs.length}`,
);

for (const dirname of vectorDirs) {
  test(`conformance: ${dirname}`, () => {
    const dir = path.join(VECTORS_DIR, dirname);
    const claim = loadJson<unknown>(path.join(dir, "claim.json"));
    const anchor = loadJson<DailyRoot>(path.join(dir, "anchor.json"));
    const anchorIds = loadJson<string[]>(path.join(dir, "anchor-ids.json"));
    const claimKeys = loadJson<Record<string, CatalogClaimEntry>>(
      path.join(dir, "verify-keys.json"),
    );
    const rootKeys = loadJson<Record<string, CatalogRootEntry>>(
      path.join(dir, "root-keys.json"),
    );
    const expected = loadJson<{ status: string; reasons: string[] }>(
      path.join(dir, "expected.json"),
    );

    // Pin clock to 2025-01-15 (after every vector's iat, before any plausible
    // notAfter — vectors don't set kid time bounds, so this is just defensive).
    const now = () => Date.UTC(2025, 0, 15) / 1000;

    const result = verify({
      claim,
      anchor,
      anchorIds,
      claimKeyResolver: buildClaimResolver(claimKeys),
      rootKeyResolver: buildRootResolver(rootKeys),
      now,
    });

    assert.equal(result.status, expected.status, `status for ${dirname}`);
    assert.deepEqual(
      [...result.reasons].sort(),
      [...expected.reasons].sort(),
      `reasons for ${dirname}`,
    );
  });
}
