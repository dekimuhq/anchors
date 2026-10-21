/**
 * Regression tests for the pre-release hardening pass (2026-05-11):
 *
 * - Unknown top-level claim keys MUST be rejected as `tampered` / `schema_invalid`
 *   (v1 spec §2.1 known-key set).
 * - A claim body containing non-canonicalisable values (Infinity, NaN, undefined,
 *   bigint, functions) MUST NOT throw out of `verify()`. The verifier MUST return
 *   `tampered` / `schema_invalid` instead.
 * - An anchor whose `sig` decodes to anything other than 64 bytes MUST be rejected
 *   as `unverified` / `root-sig-invalid` without ever reaching `ed25519Verify`.
 *
 * These are the regression checks for code-review findings HIGH-1, MEDIUM-3, LOW-4
 * (see an internal design record (not published)).
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { verify } from "../src/verify.ts";
import { base64UrlDecode } from "../src/base64url.ts";
import type {
  APRClaim,
  ClaimKeyResolver,
  RootKeyResolver,
  DailyRoot,
} from "../src/types.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const VEC1 = path.resolve(
  __dirname,
  "fixtures",
  "conformance-vectors",
  "01-valid-anchored",
);

function readJson<T>(p: string): T {
  return JSON.parse(fs.readFileSync(p, "utf8")) as T;
}

interface ClaimCatalogEntry {
  issuer: string;
  publicKey: string;
}

function loadFixtures() {
  const claim = readJson<APRClaim>(path.join(VEC1, "claim.json"));
  const anchor = readJson<DailyRoot>(path.join(VEC1, "anchor.json"));
  const anchorIds = readJson<string[]>(path.join(VEC1, "anchor-ids.json"));
  const claimKeys = readJson<Record<string, ClaimCatalogEntry>>(
    path.join(VEC1, "verify-keys.json"),
  );
  const rootKeys = readJson<Record<string, { publicKey: string }>>(
    path.join(VEC1, "root-keys.json"),
  );

  const claimKeyMap = new Map<string, { kid: string; publicKey: Uint8Array; issuer: string }>();
  for (const [kid, entry] of Object.entries(claimKeys)) {
    claimKeyMap.set(kid, {
      kid,
      publicKey: base64UrlDecode(entry.publicKey),
      issuer: entry.issuer,
    });
  }
  const rootKeyMap = new Map<string, { kid: string; publicKey: Uint8Array }>();
  for (const [kid, entry] of Object.entries(rootKeys)) {
    rootKeyMap.set(kid, {
      kid,
      publicKey: base64UrlDecode(entry.publicKey),
    });
  }

  const claimKeyResolver: ClaimKeyResolver = (kid) => claimKeyMap.get(kid);
  const rootKeyResolver: RootKeyResolver = (kid) => rootKeyMap.get(kid);

  return { claim, anchor, anchorIds, claimKeyResolver, rootKeyResolver };
}

test("MEDIUM-3: unknown top-level claim key rejected as schema_invalid", () => {
  const f = loadFixtures();
  const tampered = { ...f.claim, foo: "smuggled" } as unknown;

  const result = verify({
    claim: tampered,
    anchor: f.anchor,
    anchorIds: f.anchorIds,
    claimKeyResolver: f.claimKeyResolver,
    rootKeyResolver: f.rootKeyResolver,
  });

  assert.equal(result.status, "tampered");
  assert.deepEqual(result.reasons, ["schema_invalid"]);
});

test("HIGH-1: claim body with Infinity does not throw; returns schema_invalid", () => {
  const f = loadFixtures();
  const tampered = {
    ...f.claim,
    body: { ...f.claim.body, startedAt: Infinity },
  } as unknown;

  let result;
  assert.doesNotThrow(() => {
    result = verify({
      claim: tampered,
      anchor: f.anchor,
      anchorIds: f.anchorIds,
      claimKeyResolver: f.claimKeyResolver,
      rootKeyResolver: f.rootKeyResolver,
    });
  });
  assert.equal(result!.status, "tampered");
  assert.deepEqual(result!.reasons, ["schema_invalid"]);
});

test("HIGH-1: claim body with NaN does not throw; returns schema_invalid", () => {
  const f = loadFixtures();
  const tampered = {
    ...f.claim,
    body: { ...f.claim.body, completedAt: NaN },
  } as unknown;

  let result;
  assert.doesNotThrow(() => {
    result = verify({
      claim: tampered,
      anchor: f.anchor,
      anchorIds: f.anchorIds,
      claimKeyResolver: f.claimKeyResolver,
      rootKeyResolver: f.rootKeyResolver,
    });
  });
  assert.equal(result!.status, "tampered");
  assert.deepEqual(result!.reasons, ["schema_invalid"]);
});

test("HIGH-1: claim body containing bigint does not throw; returns schema_invalid", () => {
  const f = loadFixtures();
  const tampered = {
    ...f.claim,
    body: { ...f.claim.body, summary: 1n as unknown },
  } as unknown;

  let result;
  assert.doesNotThrow(() => {
    result = verify({
      claim: tampered,
      anchor: f.anchor,
      anchorIds: f.anchorIds,
      claimKeyResolver: f.claimKeyResolver,
      rootKeyResolver: f.rootKeyResolver,
    });
  });
  assert.equal(result!.status, "tampered");
  assert.deepEqual(result!.reasons, ["schema_invalid"]);
});

test("LOW-4: anchor sig with wrong decoded length rejected as root-sig-invalid", () => {
  const f = loadFixtures();
  // 32-byte base64url string (decodes to 24 bytes, not 64)
  const shortSig = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const tamperedAnchor: DailyRoot = { ...f.anchor, sig: shortSig };

  const result = verify({
    claim: f.claim,
    anchor: tamperedAnchor,
    anchorIds: f.anchorIds,
    claimKeyResolver: f.claimKeyResolver,
    rootKeyResolver: f.rootKeyResolver,
  });

  assert.equal(result.status, "unverified");
  assert.deepEqual(result.reasons, ["root-sig-invalid"]);
});
